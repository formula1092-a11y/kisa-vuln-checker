"""PDF 파싱 및 취약점 항목 추출 모듈."""

import logging
import re
from pathlib import Path
from typing import Optional

import pdfplumber

from .models import VulnItem

logger = logging.getLogger(__name__)


class PDFParser:
    """KISA 취약점 점검 가이드 PDF 파서."""

    # 항목코드 패턴: W-01, U-04 등
    ITEM_CODE_PATTERN = re.compile(r"([WU])-(\d{2})")

    def __init__(self, pdf_path: str | Path):
        """
        PDF 파서 초기화.

        Args:
            pdf_path: PDF 파일 경로
        """
        self.pdf_path = Path(pdf_path)
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF 파일을 찾을 수 없습니다: {self.pdf_path}")

        self._pages_cache: dict[int, str] = {}
        self._full_text: str = ""
        self._page_ranges: dict[int, tuple[int, int]] = {}

    def _load_pdf(self) -> None:
        """PDF 전체 텍스트를 로드하고 캐시."""
        if self._full_text:
            return

        logger.info(f"PDF 로드 중: {self.pdf_path}")
        current_pos = 0

        with pdfplumber.open(self.pdf_path) as pdf:
            for page_num, page in enumerate(pdf.pages, start=1):
                text = page.extract_text() or ""
                self._pages_cache[page_num] = text

                start_pos = current_pos
                self._full_text += text + "\n"
                current_pos = len(self._full_text)
                self._page_ranges[page_num] = (start_pos, current_pos)

        logger.info(f"PDF 로드 완료: {len(self._pages_cache)} 페이지")

    def _find_page_for_position(self, char_pos: int) -> int:
        """문자 위치에 해당하는 페이지 번호 반환."""
        for page_num, (start, end) in self._page_ranges.items():
            if start <= char_pos < end:
                return page_num
        return 0

    def find_item_codes(self, prefix: str = "") -> list[str]:
        """
        PDF에서 발견된 모든 항목코드 반환.

        Args:
            prefix: 필터링할 접두어 (W, U 등)

        Returns:
            정렬된 항목코드 리스트
        """
        self._load_pdf()

        codes: set[str] = set()
        for match in self.ITEM_CODE_PATTERN.finditer(self._full_text):
            code = f"{match.group(1)}-{match.group(2)}"
            if not prefix or code.startswith(prefix):
                codes.add(code)

        return sorted(codes, key=lambda x: (x[0], int(x.split("-")[1])))

    def _find_detail_section(self, item_code: str) -> tuple[str, int, int]:
        """
        상세 항목 페이지 섹션 찾기.

        KISA 가이드 형식:
        W-01 Windows 서버 > 1. 계정 관리
        (상) Administrator 계정 이름 변경 등 보안성 강화

        U-04 UNIX > 1. 계정 관리
        (상) 비밀번호 파일 보호
        """
        self._load_pdf()

        # Windows 패턴: "W-01 Windows 서버 > ..."
        if item_code.startswith("W"):
            detail_pattern = re.compile(
                rf"{re.escape(item_code)}\s+Windows\s+서버.*?\n"
                rf"\([상중하]\)\s*(.+?)(?=(?:\nW-\d{{2}}\s+Windows|$))",
                re.DOTALL
            )
        else:
            # Unix 패턴: "U-04 UNIX > ..."
            detail_pattern = re.compile(
                rf"{re.escape(item_code)}\s+UNIX\s*>.*?\n"
                rf"\([상중하]\)\s*(.+?)(?=(?:\nU-\d{{2}}\s+UNIX|$))",
                re.DOTALL
            )

        match = detail_pattern.search(self._full_text)
        if match:
            section_text = match.group(0)
            start_page = self._find_page_for_position(match.start())
            end_page = self._find_page_for_position(match.end())
            return section_text, start_page, end_page

        # 대체 패턴: 좀 더 유연한 매칭
        if item_code.startswith("W"):
            alt_pattern = re.compile(
                rf"(?:^|\n){re.escape(item_code)}\s+Windows.*?"
                rf"(?=(?:\n[W]-\d{{2}}\s+Windows|$))",
                re.DOTALL | re.MULTILINE
            )
        else:
            alt_pattern = re.compile(
                rf"(?:^|\n){re.escape(item_code)}\s+UNIX.*?"
                rf"(?=(?:\nU-\d{{2}}\s+UNIX|$))",
                re.DOTALL | re.MULTILINE
            )

        match = alt_pattern.search(self._full_text)
        if match:
            section_text = match.group(0)
            start_page = self._find_page_for_position(match.start())
            end_page = self._find_page_for_position(match.end())
            return section_text, start_page, end_page

        logger.warning(f"항목코드 {item_code}의 상세 섹션을 찾을 수 없습니다.")
        return "", 0, 0

    def _clean_text(self, text: str) -> str:
        """텍스트 정리."""
        if not text:
            return ""
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _extract_item_name(self, section: str) -> str:
        """항목명 추출 (예: Administrator 계정 이름 변경 등 보안성 강화)."""
        # (상/중/하) 다음에 오는 항목명
        match = re.search(r"\([상중하]\)\s*(.+?)(?:\n|개요)", section)
        if match:
            return self._clean_text(match.group(1))
        return ""

    def _extract_importance(self, section: str) -> str:
        """중요도 추출 (상/중/하)."""
        match = re.search(r"\(([상중하])\)", section)
        if match:
            return match.group(1)
        return ""

    def _extract_check_content(self, section: str) -> str:
        """점검 내용 추출."""
        patterns = [
            re.compile(r"점검\s*내용\s*(.+?)(?=점검\s*목적|판단\s*기준|\n\n)", re.DOTALL),
            re.compile(r"개요\s*(.+?)(?=점검\s*내용|점검\s*목적)", re.DOTALL),
        ]
        for pattern in patterns:
            match = pattern.search(section)
            if match:
                text = self._clean_text(match.group(1))
                if len(text) > 10:
                    return text[:500]
        return ""

    def _extract_check_purpose(self, section: str) -> str:
        """점검 목적 추출."""
        match = re.search(r"점검\s*목적\s*(.+?)(?=보안\s*위협|판단\s*기준|\n\n)", section, re.DOTALL)
        if match:
            return self._clean_text(match.group(1))[:300]
        return ""

    def _extract_security_threat(self, section: str) -> str:
        """보안 위협 추출."""
        match = re.search(r"보안\s*위협\s*(.+?)(?=참고|점검\s*대상|판단\s*기준|\n\n)", section, re.DOTALL)
        if match:
            return self._clean_text(match.group(1))[:500]
        return ""

    def _extract_good_criteria(self, section: str) -> str:
        """양호 판단기준 추출."""
        match = re.search(r"양호\s*[:\-]?\s*(.+?)(?=취약|판단\s*기준|\n)", section, re.DOTALL)
        if match:
            return self._clean_text(match.group(1))[:300]
        return ""

    def _extract_vuln_criteria(self, section: str) -> str:
        """취약 판단기준 추출."""
        match = re.search(r"취약\s*[:\-]?\s*(.+?)(?=조치\s*방법|점검\s*및|\n\n)", section, re.DOTALL)
        if match:
            return self._clean_text(match.group(1))[:300]
        return ""

    def _extract_check_method(self, section: str) -> str:
        """점검방법/절차 추출."""
        patterns = [
            re.compile(r"점검\s*및\s*조치\s*사례\s*(.+?)(?=조치\s*시\s*영향|참고|$)", re.DOTALL),
            re.compile(r"Step\s*1\)(.+?)(?=조치\s*시|참고|$)", re.DOTALL),
        ]
        for pattern in patterns:
            match = pattern.search(section)
            if match:
                text = self._clean_text(match.group(1))
                if len(text) > 20:
                    return text[:800]
        return ""

    def _extract_remediation(self, section: str) -> str:
        """조치방법 추출."""
        match = re.search(r"조치\s*방법\s*(.+?)(?=조치\s*시\s*영향|점검\s*및|\n\n)", section, re.DOTALL)
        if match:
            return self._clean_text(match.group(1))[:500]
        return ""

    def _extract_impact(self, section: str) -> str:
        """조치 시 영향 추출."""
        match = re.search(r"조치\s*시\s*영향\s*(.+?)(?=점검\s*및|\n\n|$)", section, re.DOTALL)
        if match:
            return self._clean_text(match.group(1))[:200]
        return ""

    def _extract_target(self, section: str) -> str:
        """점검 대상 추출."""
        match = re.search(r"대상\s*(.+?)(?=양호|판단\s*기준|\n)", section, re.DOTALL)
        if match:
            return self._clean_text(match.group(1))[:200]
        return ""

    def _extract_evidence(self, section: str) -> str:
        """근거문구 추출 (50자 이내)."""
        # 양호 기준에서 첫 문장
        good_criteria = self._extract_good_criteria(section)
        if good_criteria:
            return good_criteria[:50]

        # 점검 내용에서 추출
        check_content = self._extract_check_content(section)
        if check_content:
            return check_content[:50]
        return ""

    def _determine_asset_type(self, item_code: str) -> str:
        """자산분류 결정."""
        if item_code.startswith("W"):
            return "Windows 서버"
        elif item_code.startswith("U"):
            return "Unix 서버"
        return ""

    def parse_item(self, item_code: str) -> VulnItem:
        """
        특정 항목코드의 취약점 정보 파싱.

        Args:
            item_code: 항목코드 (예: W-01, U-04)

        Returns:
            VulnItem 객체
        """
        section, start_page, end_page = self._find_detail_section(item_code)

        item = VulnItem(항목코드=item_code)
        item.자산분류 = self._determine_asset_type(item_code)

        if not section:
            logger.error(f"[{item_code}] 섹션 추출 실패 - PDF에서 해당 항목을 찾을 수 없음")
            return item

        # 필드 추출
        item.항목명 = self._extract_item_name(section)
        item.중요도 = self._extract_importance(section)
        item.점검내용 = self._extract_check_content(section)
        item.점검목적 = self._extract_check_purpose(section)
        item.보안위협 = self._extract_security_threat(section)
        item.판단기준_양호 = self._extract_good_criteria(section)
        item.판단기준_취약 = self._extract_vuln_criteria(section)
        item.점검방법 = self._extract_check_method(section)
        item.조치방법 = self._extract_remediation(section)
        item.조치시영향 = self._extract_impact(section)
        item.점검대상 = self._extract_target(section)
        item.근거문구 = self._extract_evidence(section)

        # 참조 섹션
        if start_page and end_page:
            if start_page == end_page:
                item.참조섹션 = f"p.{start_page}"
            else:
                item.참조섹션 = f"p.{start_page}-{end_page}"

        # 누락 필드 로깅
        missing_fields = []
        for field_name in ["항목명", "중요도", "점검내용"]:
            if not getattr(item, field_name):
                missing_fields.append(field_name)

        if missing_fields:
            logger.warning(f"[{item_code}] 일부 필드 추출 실패: {', '.join(missing_fields)}")

        return item

    def parse_items(self, item_codes: list[str]) -> list[VulnItem]:
        """
        여러 항목코드의 취약점 정보 파싱.

        Args:
            item_codes: 항목코드 리스트

        Returns:
            VulnItem 객체 리스트
        """
        items = []
        for code in item_codes:
            logger.info(f"파싱 중: {code}")
            item = self.parse_item(code)
            items.append(item)
        return items
