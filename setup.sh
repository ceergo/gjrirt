#!/bin/bash
# ================================================================
# SETUP SCRIPT ДЛЯ GITHUB ACTIONS (LINUX)
# ================================================================

set -e

echo "Установка зависимостей..."
sudo apt-get update -qq
sudo apt-get install -y curl unzip tar git || true

# 1. СКАЧИВАНИЕ XRAY-CORE
echo "Скачивание Xray-core..."
XRAY_VER="25.2.20" # Твердый fallback

LATEST=$(curl -s --connect-timeout 5 https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name": "\K[^"]+' || echo "")
if [ ! -z "$LATEST" ]; then XRAY_VER=$LATEST; fi
echo "Используем Xray версию: $XRAY_VER"

curl -L "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip" -o /tmp/xray.zip
sudo unzip -o /tmp/xray.zip xray -d /usr/local/bin/
sudo chmod +x /usr/local/bin/xray
rm /tmp/xray.zip

# 2. СКАЧИВАНИЕ LIBRESPEED-CLI
echo "Скачивание Librespeed-cli..."
LS_VER_TAG="v1.0.10" # Fallback

LATEST_LS=$(curl -s --connect-timeout 5 https://api.github.com/repos/librespeed/speedtest-cli/releases/latest | grep -oP '"tag_name": "\K[^"]+' || echo "")
if [ ! -z "$LATEST_LS" ]; then LS_VER_TAG=$LATEST_LS; fi

LS_VER=${LS_VER_TAG#v}
echo "Используем Librespeed версию: $LS_VER"

curl -L "https://github.com/librespeed/speedtest-cli/releases/download/${LS_VER_TAG}/librespeed-cli_${LS_VER}_linux_amd64.tar.gz" -o /tmp/ls.tar.gz
sudo tar -xzf /tmp/ls.tar.gz -C /usr/local/bin/ librespeed-cli || true
sudo chmod +x /usr/local/bin/librespeed-cli || true
rm -f /tmp/ls.tar.gz

echo "Установка завершена!"
xray -version | head -n 1 || echo "Xray installed."
librespeed-cli --version || echo "Librespeed installed."
