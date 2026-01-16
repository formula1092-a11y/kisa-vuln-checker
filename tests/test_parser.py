"""PDF 파서 단위테스트."""

import re
import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser import PDFParser
from src.models import VulnItem


class TestItemCodeDetection:
    """항목코드 탐지 테스트."""

    def test_item_code_pattern_windows(self):
        """Windows 항목코드 패턴 매칭 테스트."""
        pattern = PDFParser.ITEM_CODE_PATTERN

        # 유효한 Windows 코드
        assert pattern.search("W-01") is not None
        assert pattern.search("W-10") is not None
        assert pattern.search("W-99") is not None

        # 텍스트 내에서 탐지
        text = "이 항목은 W-01 계정관리에 대한 내용입니다."
        match = pattern.search(text)
        assert match is not None
        assert match.group(0) == "W-01"

    def test_item_code_pattern_unix(self):
        """Unix 항목코드 패턴 매칭 테스트."""
        pattern = PDFParser.ITEM_CODE_PATTERN

        # 유효한 Unix 코드
        assert pattern.search("U-04") is not None
        assert pattern.search("U-72") is not None

        # 텍스트 내에서 탐지
        text = "U-04. root 계정 원격 접속 제한"
        match = pattern.search(text)
        assert match is not None
        assert match.group(0) == "U-04"

    def test_item_code_pattern_invalid(self):
        """유효하지 않은 패턴 테스트."""
        pattern = PDFParser.ITEM_CODE_PATTERN

        # 유효하지 않은 코드
        assert pattern.search("X-01") is None  # X 접두어 없음
        assert pattern.search("W-1") is None   # 한 자리 숫자
        assert pattern.search("W01") is None   # 하이픈 없음

    def test_find_multiple_codes_in_text(self):
        """텍스트에서 여러 항목코드 찾기."""
        pattern = PDFParser.ITEM_CODE_PATTERN
        text = """
        W-01. Administrator 계정 관리
        W-02. Guest 계정 비활성화
        U-04. root 계정 원격 접속 제한
        """

        matches = pattern.findall(text)
        assert len(matches) == 3
        codes = [f"{m[0]}-{m[1]}" for m in matches]
        assert "W-01" in codes
        assert "W-02" in codes
        assert "U-04" in codes


class TestSectionSlicing:
    """섹션 슬라이싱 테스트."""

    def test_clean_text(self):
        """텍스트 정리 기능 테스트."""
        parser = PDFParser.__new__(PDFParser)

        # 연속 공백 정리
        result = parser._clean_text("hello   world")
        assert result == "hello world"

        # 줄바꿈 정리
        result = parser._clean_text("hello\n\nworld")
        assert result == "hello world"

        # 앞뒤 공백 제거
        result = parser._clean_text("  hello world  ")
        assert result == "hello world"

        # 빈 문자열
        result = parser._clean_text("")
        assert result == ""

        # None 처리
        result = parser._clean_text(None)
        assert result == ""

    def test_determine_asset_type_windows(self):
        """Windows 자산분류 결정 테스트."""
        parser = PDFParser.__new__(PDFParser)

        result = parser._determine_asset_type("W-01")
        assert result == "Windows 서버"

        result = parser._determine_asset_type("W-10")
        assert result == "Windows 서버"

    def test_determine_asset_type_unix(self):
        """Unix 자산분류 결정 테스트."""
        parser = PDFParser.__new__(PDFParser)

        result = parser._determine_asset_type("U-04")
        assert result == "Unix 서버"

        result = parser._determine_asset_type("U-72")
        assert result == "Unix 서버"

    def test_extract_item_name(self):
        """항목명 추출 테스트."""
        parser = PDFParser.__new__(PDFParser)

        section = "(상) Administrator 계정 이름 변경 등 보안성 강화\n개요"
        result = parser._extract_item_name(section)
        assert result == "Administrator 계정 이름 변경 등 보안성 강화"

    def test_extract_importance(self):
        """중요도 추출 테스트."""
        parser = PDFParser.__new__(PDFParser)

        section = "(상) 테스트 항목"
        result = parser._extract_importance(section)
        assert result == "상"

        section = "(중) 또 다른 항목"
        result = parser._extract_importance(section)
        assert result == "중"

        section = "(하) 낮은 중요도"
        result = parser._extract_importance(section)
        assert result == "하"

    def test_extract_evidence_truncation(self):
        """근거문구 50자 제한 테스트."""
        parser = PDFParser.__new__(PDFParser)

        # _extract_good_criteria와 _extract_check_content 모킹
        section = "양호: " + "가" * 100 + "\n취약: 테스트"
        result = parser._extract_evidence(section)
        assert len(result) <= 50


class TestFieldExtraction:
    """필드 추출 테스트."""

    def test_extract_good_criteria(self):
        """양호 판단기준 추출 테스트."""
        parser = PDFParser.__new__(PDFParser)

        section = "양호: Administrator 기본 계정 이름을 변경한 경우\n취약: 변경하지 않은 경우"
        result = parser._extract_good_criteria(section)
        assert "Administrator" in result

    def test_extract_vuln_criteria(self):
        """취약 판단기준 추출 테스트."""
        parser = PDFParser.__new__(PDFParser)

        section = "양호: 변경한 경우\n취약: 변경하지 않은 경우\n조치 방법"
        result = parser._extract_vuln_criteria(section)
        assert "변경하지" in result

    def test_extract_check_purpose(self):
        """점검 목적 추출 테스트."""
        parser = PDFParser.__new__(PDFParser)

        section = "점검 목적 악의적인 패스워드 추측 공격을 차단하기 위함\n보안 위협 테스트"
        result = parser._extract_check_purpose(section)
        assert "패스워드" in result or "차단" in result
