"""CSV 내보내기 모듈."""

import csv
import logging
from pathlib import Path

from .models import CSV_COLUMNS, VulnItem

logger = logging.getLogger(__name__)

# UTF-8 BOM
UTF8_BOM = "\ufeff"


def export_to_csv(
    items: list[VulnItem],
    output_path: str | Path,
    encoding: str = "utf-8-sig",
) -> Path:
    """
    취약점 항목들을 CSV 파일로 내보내기.

    Args:
        items: VulnItem 객체 리스트
        output_path: 출력 파일 경로
        encoding: 파일 인코딩 (기본값: utf-8-sig = UTF-8 with BOM)

    Returns:
        생성된 파일 경로
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding=encoding) as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()

        for item in items:
            row = item.to_dict()
            writer.writerow(row)

    logger.info(f"CSV 저장 완료: {output_path} ({len(items)}개 항목)")
    return output_path


def generate_empty_template(output_path: str | Path) -> Path:
    """
    빈 CSV 템플릿 생성.

    Args:
        output_path: 출력 파일 경로

    Returns:
        생성된 파일 경로
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()

    logger.info(f"빈 템플릿 생성 완료: {output_path}")
    return output_path
