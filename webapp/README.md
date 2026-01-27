# KISA Vulnerability Checker Web Application

KISA "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드(2026년)" 기반 취약점 점검 웹 애플리케이션입니다.

## 기능

- **자산 관리**: 점검 대상 자산 등록/수정/조회/삭제
- **점검 수행**: 항목별 PASS/FAIL/NA/EXCEPTION 판정 및 증적 관리
- **예외 처리**: 예외 요청/승인/반려 워크플로우
- **리포트**: 자산별 요약 및 PDF/CSV 내보내기

## 기술 스택

- **Backend**: FastAPI, SQLAlchemy, SQLite, Pydantic
- **Frontend**: React, TypeScript, Vite, TanStack Query
- **PDF Generation**: ReportLab

## 프로젝트 구조

```
webapp/
├── backend/
│   ├── app/
│   │   ├── api/           # API 엔드포인트
│   │   ├── core/          # 설정, DB, 보안
│   │   ├── models/        # SQLAlchemy 모델
│   │   ├── schemas/       # Pydantic 스키마
│   │   ├── services/      # 비즈니스 로직
│   │   └── main.py        # FastAPI 앱
│   ├── storage/           # 업로드 파일 저장
│   ├── requirements.txt
│   └── .env.example
├── frontend/
│   ├── src/
│   │   ├── components/    # React 컴포넌트
│   │   ├── pages/         # 페이지 컴포넌트
│   │   ├── services/      # API 서비스
│   │   ├── types/         # TypeScript 타입
│   │   └── hooks/         # React hooks
│   ├── package.json
│   └── vite.config.ts
└── README.md
```

## 설치 및 실행

### Backend

```bash
cd webapp/backend

# 가상환경 생성 및 활성화
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 의존성 설치
pip install -r requirements.txt

# 환경변수 설정 (선택)
cp .env.example .env
# .env 파일 수정

# 서버 실행
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd webapp/frontend

# 의존성 설치
npm install

# 개발 서버 실행
npm run dev
```

### 접속

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000/api
- API 문서: http://localhost:8000/api/docs

### 기본 로그인

- Username: `admin`
- Password: `admin123!`

## 데이터베이스 초기화

서버 시작 시 자동으로 SQLite 데이터베이스가 생성됩니다.

### 점검 항목 임포트

기존 CSV 파일을 임포트하려면:

1. 웹 UI의 "Checklist" 메뉴 접속
2. "Import CSV/JSON" 버튼 클릭
3. `kisa-vuln-checker/out/` 폴더의 CSV 파일 선택

또는 API 직접 호출:

```bash
curl -X POST "http://localhost:8000/api/checklist/import/csv" \
  -H "Authorization: Bearer <token>" \
  -F "file=@windows_vuln.csv"
```

## API 명세

### 인증

#### POST /api/auth/login
로그인 및 토큰 발급

**Request:**
```json
{
  "username": "admin",
  "password": "admin123!"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "username": "admin",
  "role": "admin"
}
```

### 자산 (Assets)

#### GET /api/assets
자산 목록 조회

**Query Parameters:**
- `page`: 페이지 번호 (default: 1)
- `size`: 페이지 크기 (default: 20)
- `asset_type`: 자산 유형 필터
- `search`: 검색어

**Response:**
```json
{
  "items": [
    {
      "id": 1,
      "name": "Web Server 01",
      "asset_type": "unix",
      "environment": "production",
      "criticality": "high",
      "assessment_count": 67,
      "pass_count": 50,
      "fail_count": 10
    }
  ],
  "total": 1,
  "page": 1,
  "size": 20
}
```

#### POST /api/assets
자산 생성

**Request:**
```json
{
  "name": "Web Server 01",
  "asset_type": "unix",
  "environment": "production",
  "criticality": "high",
  "owner": "DevOps Team",
  "ip_address": "192.168.1.100"
}
```

#### POST /api/assets/{id}/initialize-assessments
자산에 대한 점검 항목 초기화

### 점검 항목 (Checklist)

#### GET /api/checklist
점검 항목 목록 조회

#### POST /api/checklist/import/csv
CSV 파일로 점검 항목 임포트

#### GET /api/checklist/template/csv
CSV 임포트 템플릿 다운로드

### 점검 (Assessments)

#### GET /api/assessments
점검 결과 목록 조회

**Query Parameters:**
- `asset_id`: 자산 ID 필터
- `status_filter`: 상태 필터 (pass, fail, na, exception, not_assessed)

#### PUT /api/assessments/{id}
점검 결과 수정

**Request:**
```json
{
  "status": "fail",
  "evidence_note": "설정 파일에서 취약점 확인됨",
  "assessor": "admin",
  "remediation_plan": "설정 변경 필요",
  "due_date": "2026-02-01"
}
```

#### POST /api/assessments/{id}/evidence
증적 파일 업로드

### 예외 (Exceptions)

#### GET /api/exceptions
예외 요청 목록 조회

#### POST /api/exceptions
예외 요청 생성

**Request:**
```json
{
  "assessment_id": 1,
  "reason": "레거시 시스템으로 변경 불가",
  "expires_at": "2026-12-31"
}
```

#### PUT /api/exceptions/{id}/decide
예외 승인/반려 (관리자 전용)

**Request:**
```json
{
  "status": "approved",
  "decision_note": "1년간 예외 처리 승인"
}
```

### 리포트 (Reports)

#### GET /api/reports/summary
리포트 요약 데이터 조회

#### GET /api/reports/pdf
PDF 리포트 다운로드

#### GET /api/reports/csv
CSV 리포트 다운로드

## 보안 설정

### 환경변수 (.env)

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your_secure_password
SECRET_KEY=your_secret_key
MAX_UPLOAD_SIZE=10485760
```

### 파일 업로드 제한

- 최대 크기: 10MB (설정 가능)
- 허용 확장자: .pdf, .png, .jpg, .jpeg, .gif, .txt, .doc, .docx, .xls, .xlsx, .csv, .zip

## 주요 화면

1. **자산 목록** (`/assets`): 전체 자산 조회 및 관리
2. **자산 상세-점검** (`/assets/:id`): 자산별 점검 수행
3. **예외 승인함** (`/exceptions`): 예외 요청 관리 및 승인
4. **리포트 다운로드** (`/reports`): 점검 결과 리포트 조회 및 다운로드

## 라이선스

Internal Use Only
