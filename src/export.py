"""CLI 진입점 - 취약점 점검 항목 추출 및 CSV 내보내기."""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

from .exporter import export_to_csv
from .parser import PDFParser

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# 기본 경로
DEFAULT_PDF_PATH = Path(__file__).parent.parent / "data" / "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf"
DEFAULT_OUTPUT_DIR = Path(__file__).parent.parent / "out"


def generate_codes(prefix: str, start: int, end: int) -> list[str]:
    """항목코드 범위 생성."""
    return [f"{prefix}-{i:02d}" for i in range(start, end + 1)]


def parse_codes_arg(codes_str: str) -> list[str]:
    """쉼표로 구분된 코드 문자열 파싱."""
    codes = []
    for part in codes_str.split(","):
        part = part.strip()
        if "-" in part and not part.startswith(("W-", "U-")):
            # 범위 표현: 01-10
            start, end = part.split("-")
            for i in range(int(start), int(end) + 1):
                codes.append(f"{i:02d}")
        else:
            codes.append(part)
    return codes


@click.command()
@click.option(
    "--target",
    type=click.Choice(["windows", "unix", "all"]),
    default="all",
    help="점검 대상 시스템 유형",
)
@click.option(
    "--codes",
    type=str,
    default=None,
    help="추출할 항목코드 (쉼표 구분, 예: W-01,W-02,W-03)",
)
@click.option(
    "--from",
    "from_code",
    type=str,
    default=None,
    help="시작 항목코드 (해당 코드부터 연속 추출, 예: U-04)",
)
@click.option(
    "--to",
    "to_code",
    type=str,
    default=None,
    help="종료 항목코드 (--from과 함께 사용)",
)
@click.option(
    "--pdf",
    type=click.Path(exists=True),
    default=None,
    help="입력 PDF 파일 경로",
)
@click.option(
    "--output-dir",
    type=click.Path(),
    default=None,
    help="출력 디렉터리 경로",
)
@click.option(
    "--list-codes",
    is_flag=True,
    help="PDF에서 발견된 모든 항목코드 출력",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="상세 로그 출력",
)
def main(
    target: str,
    codes: Optional[str],
    from_code: Optional[str],
    to_code: Optional[str],
    pdf: Optional[str],
    output_dir: Optional[str],
    list_codes: bool,
    verbose: bool,
) -> None:
    """
    KISA 취약점 점검 가이드 PDF에서 항목을 추출하여 CSV로 저장합니다.

    사용 예시:

    \b
    # Windows 서버 W-01 ~ W-10 추출
    python -m src.export --target windows --codes W-01,W-02,W-03,W-04,W-05,W-06,W-07,W-08,W-09,W-10

    \b
    # Unix 서버 U-04부터 연속 추출
    python -m src.export --target unix --from U-04

    \b
    # PDF에서 발견된 모든 항목코드 확인
    python -m src.export --list-codes
    """
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # PDF 경로 결정
    pdf_path = Path(pdf) if pdf else DEFAULT_PDF_PATH
    if not pdf_path.exists():
        logger.error(f"PDF 파일을 찾을 수 없습니다: {pdf_path}")
        sys.exit(1)

    # 출력 디렉터리 결정
    out_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"PDF 파일: {pdf_path}")
    logger.info(f"출력 디렉터리: {out_dir}")

    # 파서 초기화
    try:
        parser = PDFParser(pdf_path)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(1)

    # 항목코드 목록 출력 모드
    if list_codes:
        all_codes = parser.find_item_codes()
        click.echo("\n발견된 항목코드:")
        click.echo("-" * 40)

        w_codes = [c for c in all_codes if c.startswith("W")]
        u_codes = [c for c in all_codes if c.startswith("U")]

        if w_codes:
            click.echo(f"\nWindows ({len(w_codes)}개):")
            click.echo(", ".join(w_codes))

        if u_codes:
            click.echo(f"\nUnix ({len(u_codes)}개):")
            click.echo(", ".join(u_codes))

        return

    # 추출할 항목코드 결정
    target_codes: list[str] = []

    if codes:
        # 명시적 코드 지정
        target_codes = [c.strip() for c in codes.split(",")]
    elif from_code:
        # 시작 코드부터 연속 추출
        prefix = from_code[0]  # W 또는 U
        start_num = int(from_code.split("-")[1])

        # PDF에서 해당 접두어의 모든 코드 찾기
        available_codes = parser.find_item_codes(prefix)

        if to_code:
            end_num = int(to_code.split("-")[1])
            target_codes = [c for c in available_codes
                          if start_num <= int(c.split("-")[1]) <= end_num]
        else:
            # 시작 코드부터 끝까지
            target_codes = [c for c in available_codes
                          if int(c.split("-")[1]) >= start_num]
    else:
        # 기본값: target에 따라 결정
        if target == "windows":
            target_codes = generate_codes("W", 1, 10)
        elif target == "unix":
            # U-04부터 가능한 만큼
            available = parser.find_item_codes("U")
            target_codes = [c for c in available if int(c.split("-")[1]) >= 4]
        else:
            # all: Windows W-01~W-10 + Unix U-04~
            target_codes = generate_codes("W", 1, 10)
            available_u = parser.find_item_codes("U")
            target_codes.extend([c for c in available_u if int(c.split("-")[1]) >= 4])

    if not target_codes:
        logger.warning("추출할 항목코드가 없습니다.")
        sys.exit(0)

    logger.info(f"추출 대상: {len(target_codes)}개 항목")
    logger.info(f"항목코드: {', '.join(target_codes[:10])}{'...' if len(target_codes) > 10 else ''}")

    # 항목 파싱
    items = parser.parse_items(target_codes)

    # 통계
    success_count = sum(1 for item in items if item.항목명)
    fail_count = len(items) - success_count

    logger.info(f"파싱 완료: 성공 {success_count}개, 실패 {fail_count}개")

    # CSV 저장
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if target == "windows":
        filename = f"windows_vuln_{timestamp}.csv"
    elif target == "unix":
        filename = f"unix_vuln_{timestamp}.csv"
    else:
        filename = f"vuln_checklist_{timestamp}.csv"

    output_path = out_dir / filename
    export_to_csv(items, output_path)

    click.echo(f"\n[OK] CSV saved: {output_path}")
    click.echo(f"  - Total items: {len(items)}")
    click.echo(f"  - Success: {success_count}")
    if fail_count > 0:
        click.echo(f"  - Failed: {fail_count} (check logs)")


if __name__ == "__main__":
    main()
