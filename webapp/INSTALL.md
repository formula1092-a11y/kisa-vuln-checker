# KISA 취약점 점검 웹앱 설치 가이드

## 1. Docker 설치 (권장)

### Windows
1. [Docker Desktop](https://www.docker.com/products/docker-desktop/) 다운로드 및 설치
2. 설치 후 재부팅
3. Docker Desktop 실행

### Linux (Ubuntu/Debian)
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# 로그아웃 후 다시 로그인
```

## 2. 프로젝트 다운로드

```bash
git clone https://github.com/formula1092-a11y/kisa-vuln-checker.git
cd kisa-vuln-checker/webapp
```

## 3. 환경 설정 (선택)

보안 설정을 변경하려면 `.env` 파일 생성:

```bash
# webapp/.env
SECRET_KEY=your-secret-key-here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=your-secure-password
```

## 4. 실행

```bash
# webapp 폴더에서
docker-compose up -d
```

빌드에 몇 분 소요됩니다. 완료 후:
- **웹 접속**: http://localhost
- **API 문서**: http://localhost:8000/api/docs

## 5. 기본 로그인

- **Username**: `admin`
- **Password**: `admin123!` (또는 .env에서 설정한 값)

## 6. 사용법

### PDF to CSV 변환
1. 좌측 메뉴에서 **PDF Convert** 클릭
2. KISA 취약점 점검 가이드 PDF 업로드
3. 변환 대상 선택 후 **CSV로 변환**

### 취약점 점검
1. **Assets** 메뉴에서 자산 등록
2. **Checklist** 메뉴에서 CSV 임포트
3. 자산 상세 페이지에서 점검 수행

## 7. 종료

```bash
docker-compose down
```

## 8. 업데이트

```bash
git pull
docker-compose down
docker-compose up -d --build
```

## 9. 데이터 백업

데이터는 `webapp/data/` 폴더에 저장됩니다:
- `kisa_vuln.db`: SQLite 데이터베이스
- `storage/`: 업로드된 증적 파일

백업:
```bash
cp -r data/ backup_$(date +%Y%m%d)/
```

## 10. 문제 해결

### 포트 충돌
다른 포트 사용 시 `docker-compose.yml` 수정:
```yaml
ports:
  - "8080:80"    # 프론트엔드를 8080으로 변경
  - "8001:8000"  # 백엔드를 8001로 변경
```

### 로그 확인
```bash
docker-compose logs -f backend
docker-compose logs -f frontend
```

### 컨테이너 재시작
```bash
docker-compose restart
```

## 시스템 요구사항

- **OS**: Windows 10/11, macOS, Linux
- **RAM**: 4GB 이상
- **Disk**: 2GB 이상
- **Docker**: 20.10 이상
