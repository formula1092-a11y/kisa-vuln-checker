# KISA 취약점 점검 시스템

KISA 주요정보통신기반시설 취약점 점검 가이드 기반의 웹 애플리케이션입니다.

## 주요 기능

- **자산 관리**: Windows/Unix 서버 자산 등록 및 관리
- **취약점 점검**: KISA 가이드 기반 점검 항목 (Windows 64개, Unix 67개)
- **자동 점검 스크립트**: 서버에서 실행 가능한 점검 스크립트 다운로드
- **조치 스크립트 생성**: 실패 항목에 대한 자동 조치 스크립트 생성
- **리포트**: 점검 결과 요약 및 PDF/CSV 내보내기
- **예외 처리**: 점검 항목 예외 신청 및 승인 워크플로우

## 빠른 시작

### 방법 1: Docker 사용 (권장)

```bash
cd webapp
docker-compose up -d
```

접속: http://localhost (프론트엔드), http://localhost:8000 (백엔드 API)

### 방법 2: 로컬 실행

**백엔드:**
```bash
cd webapp/backend
pip install -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**프론트엔드:**
```bash
cd webapp/frontend
npm install
npm run dev -- --host 0.0.0.0 --port 3000
```

## 로그인 정보

- **ID**: admin
- **PW**: admin123

## 사용 방법

1. 로그인 후 **Assets** 메뉴에서 자산 등록
2. 자산 상세 페이지에서 **Initialize Assessments** 클릭
3. 각 점검 항목의 상태를 Pass/Fail/N/A로 변경
4. **Agents** 메뉴에서 자동 점검 스크립트 다운로드
5. Fail 항목이 있으면 **Download Fix Script** 버튼으로 조치 스크립트 다운로드

## 디렉토리 구조

```
webapp/
├── backend/           # FastAPI 백엔드
│   ├── app/
│   │   ├── api/       # API 엔드포인트
│   │   ├── core/      # 설정, 보안, DB
│   │   ├── models/    # SQLAlchemy 모델
│   │   ├── schemas/   # Pydantic 스키마
│   │   └── services/  # 비즈니스 로직
│   └── seed_checklist.json  # 초기 체크리스트 데이터
├── frontend/          # React + TypeScript 프론트엔드
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   └── services/
│   └── nginx.conf     # 프로덕션 Nginx 설정
├── agents/            # 자동 점검 스크립트
│   ├── check-windows.ps1
│   └── check-unix.sh
└── docker-compose.yml
```

## API 문서

백엔드 실행 후 http://localhost:8000/docs 에서 Swagger UI로 API 문서 확인 가능

## 기술 스택

- **Backend**: Python, FastAPI, SQLAlchemy, SQLite
- **Frontend**: React, TypeScript, Vite, TanStack Query
- **Deployment**: Docker, Nginx
