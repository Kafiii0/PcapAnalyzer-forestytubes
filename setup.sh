#!/bin/bash

echo "[*] Mengecek dependensi Go..."
if ! command -v go &> /dev/null; then
    echo "[ERROR] Go belum terinstall. Silakan install Go 1.22+ dari https://go.dev/dl/"
    exit 1
fi

echo "[*] Mengecek dependensi Node.js..."
if ! command -v node &> /dev/null; then
    echo "[ERROR] Node.js belum terinstall. Silakan install Node.js 18+ dari https://nodejs.org/"
    exit 1
fi

echo "[*] Membangun extractor engine..."
go build -o extractor main.go
if [ $? -ne 0 ]; then
    echo "[ERROR] Gagal mem-build Go extractor."
    exit 1
fi

echo "[*] Menginstall dependensi Node.js..."
npm install
if [ $? -ne 0 ]; then
    echo "[ERROR] Gagal menginstall dependensi npm."
    exit 1
fi

echo "[*] Menjalankan Server Web The Eye..."
if command -v xdg-open &> /dev/null; then
    xdg-open http://localhost:3000 &
elif command -v open &> /dev/null; then
    open http://localhost:3000 &
fi

node server.js
