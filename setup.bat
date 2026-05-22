@echo off
setlocal

echo [*] Mengecek dependensi Go...
go version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Go belum terinstall. Silakan install Go 1.22+ dari https://go.dev/dl/
    pause
    exit /b
)

echo [*] Mengecek dependensi Node.js...
node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js belum terinstall. Silakan install Node.js 18+ dari https://nodejs.org/
    pause
    exit /b
)

echo [*] Membangun extractor engine...
go build -o extractor.exe main.go
if %errorlevel% neq 0 (
    echo [ERROR] Gagal mem-build Go extractor.
    pause
    exit /b
)

echo [*] Menginstall dependensi Node.js...
call npm install
if %errorlevel% neq 0 (
    echo [ERROR] Gagal menginstall dependensi npm.
    pause
    exit /b
)

echo [*] Menjalankan Server Web The Eye Adaptive Engine...
start http://localhost:3000
call npm start
