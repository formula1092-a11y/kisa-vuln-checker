# KISA 취약점 점검 가이드 CSV 변환 도구

KISA(한국인터넷진흥원)의 "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드" PDF 문서를 파싱하여 구조화된 CSV 템플릿으로 변환하는 CLI 도구입니다.

## 요구사항

- Python 3.11 이상
- uv (권장) 또는 pip

## 설치

### uv 사용 (권장)

```bash
cd kisa-vuln-checker
uv sync
```

### pip 사용

```bash
cd kisa-vuln-checker
pip install -e .
```

### 개발 환경 설치

```bash
# uv
uv sync --all-extras

# pip
pip install -e ".[dev]"
```

## 디렉터리 구조

```
kisa-vuln-checker/
├── data/                    # 입력 PDF 파일 위치
│   └── 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf
├── out/                     # 출력 CSV 파일 위치
├── src/
│   ├── __init__.py
│   ├── __main__.py          # 모듈 실행 진입점
│   ├── export.py            # CLI 메인
│   ├── exporter.py          # CSV 내보내기
│   ├── models.py            # 데이터 모델
│   └── parser.py            # PDF 파싱
├── tests/
│   ├── test_exporter.py
│   └── test_parser.py
├── pyproject.toml
└── README.md
```

## 사용법

### PDF 파일 준비

KISA 취약점 점검 가이드 PDF를 `data/` 디렉터리에 저장합니다.

### 항목코드 목록 확인

```bash
python -m src.export --list-codes
```

### Windows 서버 항목 추출 (W-01 ~ W-10)

```bash
python -m src.export --target windows --codes W-01,W-02,W-03,W-04,W-05,W-06,W-07,W-08,W-09,W-10
```

### Unix 서버 항목 추출 (U-04부터 연속)

```bash
python -m src.export --target unix --from U-04
```

### 특정 범위 추출

```bash
python -m src.export --from U-04 --to U-20
```

### 사용자 지정 PDF 경로

```bash
python -m src.export --pdf /path/to/custom.pdf --target windows
```

### 출력 디렉터리 지정

```bash
python -m src.export --target unix --from U-04 --output-dir ./results
```

## CLI 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--target` | 점검 대상 (windows/unix/all) | all |
| `--codes` | 추출할 항목코드 (쉼표 구분) | - |
| `--from` | 시작 항목코드 | - |
| `--to` | 종료 항목코드 | - |
| `--pdf` | 입력 PDF 파일 경로 | data/*.pdf |
| `--output-dir` | 출력 디렉터리 | out/ |
| `--list-codes` | PDF 내 항목코드 목록 출력 | - |
| `-v, --verbose` | 상세 로그 출력 | - |

## 출력 CSV 컬럼

| 컬럼명 | 설명 |
|--------|------|
| 항목코드 | W-01, U-04 등 |
| 항목명 | 점검 항목의 이름 |
| 자산분류 | Windows 서버, Unix 서버 등 |
| 점검대상(OS/제품) | Windows Server 2019, Linux 등 |
| 중요도 | 상/중/하 |
| 점검내용 | 점검 항목에 대한 설명 |
| 점검목적 | 해당 항목을 점검하는 목적 |
| 보안위협 | 취약 시 발생 가능한 위협 |
| 판단기준(양호) | 양호 판단 조건 |
| 판단기준(취약) | 취약 판단 조건 |
| 점검방법(절차) | 점검 수행 절차 |
| 조치방법 | 취약점 조치 방법 |
| 조치시영향 | 조치 시 주의사항 |
| 참조섹션(페이지/챕터) | PDF 내 해당 페이지 |
| 근거문구(짧은발췌) | 판단 근거가 되는 문구 (50자 이내) |

## 제약사항

1. **텍스트 기반 PDF만 지원**: 스캔된 이미지 PDF는 OCR 처리가 필요합니다.
2. **정규표현식 기반 파싱**: PDF 문서 구조가 변경되면 파싱 실패 가능성이 있습니다.
3. **일부 필드 누락 가능**: PDF 형식에 따라 특정 필드가 추출되지 않을 수 있습니다.

## 추출 정확도 개선 팁

### 1. OCR 적용 (스캔 PDF의 경우)

```bash
# pdf2image + pytesseract 설치
pip install pdf2image pytesseract

# Tesseract OCR 엔진 설치 필요 (시스템별 상이)
# Windows: https://github.com/UB-Mannheim/tesseract/wiki
# macOS: brew install tesseract tesseract-lang
# Linux: apt-get install tesseract-ocr tesseract-ocr-kor
```

### 2. PDF 텍스트 레이어 확인

```python
import pdfplumber

with pdfplumber.open("document.pdf") as pdf:
    page = pdf.pages[0]
    text = page.extract_text()
    if not text:
        print("텍스트 레이어 없음 - OCR 필요")
```

### 3. 수동 검증

추출 후 CSV 파일을 검토하여 누락된 필드나 잘못된 내용을 수동으로 보완하세요.

### 4. 로그 확인

`-v` 옵션으로 상세 로그를 활성화하여 파싱 실패 항목을 확인하세요.

```bash
python -m src.export --target windows -v
```

## 테스트 실행

```bash
# uv
uv run pytest

# pip
pytest
```

## 라이선스

MIT License
