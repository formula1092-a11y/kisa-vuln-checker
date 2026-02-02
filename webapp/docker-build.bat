@echo off
cd /d "%~dp0"

echo Checking Docker installation...
where docker >nul 2>nul
if %errorlevel% neq 0 (
    echo Docker is not found in PATH.
    echo Please make sure Docker Desktop is installed and running.
    echo.
    echo Download Docker Desktop from: https://www.docker.com/products/docker-desktop
    echo After installation, restart this script.
    pause
    exit /b 1
)

echo Docker found. Building images...
echo.

docker compose down 2>nul

echo Building backend...
docker compose build --no-cache backend

echo Building frontend...
docker compose build --no-cache frontend

echo.
echo Starting containers...
docker compose up -d

echo.
echo ========================================
echo  Deployment Complete!
echo ========================================
echo  Frontend: http://localhost
echo  Backend API: http://localhost:8000
echo  Login: admin / admin123
echo ========================================
echo.
docker compose ps

pause
