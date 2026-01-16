"""CSV 내보내기 단위테스트."""

import csv
import tempfile
from pathlib import Path

import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.exporter import export_to_csv, generate_empty_template
from src.models import VulnItem, CSV_COLUMNS


class TestCSVExport:
    """CSV 저장 테스트."""

    def test_export_single_item(self):
        """단일 항목 CSV 저장 테스트."""
        item = VulnItem(
            항목코드="W-01",
            항목명="Administrator 계정 관리",
            자산분류="Windows 서버",
            점검대상="Windows Server 2019",
            중요도="상",
            점검내용="관리자 계정의 이름이 변경되어 있는지 점검",
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = Path(f.name)

        try:
            export_to_csv([item], output_path)

            # 파일 존재 확인
            assert output_path.exists()

            # 내용 확인
            with open(output_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 1
            assert rows[0]["항목코드"] == "W-01"
            assert rows[0]["항목명"] == "Administrator 계정 관리"
            assert rows[0]["자산분류"] == "Windows 서버"

        finally:
            output_path.unlink(missing_ok=True)

    def test_export_multiple_items(self):
        """복수 항목 CSV 저장 테스트."""
        items = [
            VulnItem(항목코드="W-01", 항목명="항목1", 중요도="상"),
            VulnItem(항목코드="W-02", 항목명="항목2", 중요도="중"),
            VulnItem(항목코드="W-03", 항목명="항목3", 중요도="하"),
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = Path(f.name)

        try:
            export_to_csv(items, output_path)

            with open(output_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            assert len(rows) == 3
            assert rows[0]["항목코드"] == "W-01"
            assert rows[1]["항목코드"] == "W-02"
            assert rows[2]["항목코드"] == "W-03"

        finally:
            output_path.unlink(missing_ok=True)

    def test_export_utf8_bom(self):
        """UTF-8 BOM 인코딩 테스트."""
        item = VulnItem(항목코드="U-04", 항목명="한글 테스트")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = Path(f.name)

        try:
            export_to_csv([item], output_path, encoding="utf-8-sig")

            # BOM 확인 (UTF-8 BOM은 EF BB BF)
            with open(output_path, "rb") as f:
                bom = f.read(3)
            assert bom == b"\xef\xbb\xbf"

            # 한글 내용 확인
            with open(output_path, "r", encoding="utf-8-sig") as f:
                content = f.read()
            assert "한글 테스트" in content

        finally:
            output_path.unlink(missing_ok=True)

    def test_csv_column_order(self):
        """CSV 컬럼 순서 테스트."""
        item = VulnItem(항목코드="W-01")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = Path(f.name)

        try:
            export_to_csv([item], output_path)

            with open(output_path, "r", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                header = next(reader)

            assert header == CSV_COLUMNS

        finally:
            output_path.unlink(missing_ok=True)

    def test_export_empty_fields(self):
        """빈 필드 처리 테스트."""
        # 일부 필드만 채워진 항목
        item = VulnItem(항목코드="W-01", 항목명="테스트")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = Path(f.name)

        try:
            export_to_csv([item], output_path)

            with open(output_path, "r", encoding="utf-8-sig") as f:
                reader = csv.DictReader(f)
                row = next(reader)

            # 빈 필드가 빈 문자열로 저장되는지 확인
            assert row["항목코드"] == "W-01"
            assert row["항목명"] == "테스트"
            assert row["중요도"] == ""
            assert row["점검내용"] == ""

        finally:
            output_path.unlink(missing_ok=True)

    def test_generate_empty_template(self):
        """빈 템플릿 생성 테스트."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = Path(f.name)

        try:
            generate_empty_template(output_path)

            with open(output_path, "r", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                header = next(reader)
                rows = list(reader)

            assert header == CSV_COLUMNS
            assert len(rows) == 0  # 헤더만 있고 데이터 없음

        finally:
            output_path.unlink(missing_ok=True)

    def test_creates_parent_directory(self):
        """부모 디렉터리 자동 생성 테스트."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "subdir" / "nested" / "output.csv"

            item = VulnItem(항목코드="W-01")
            export_to_csv([item], output_path)

            assert output_path.exists()
            assert output_path.parent.exists()
