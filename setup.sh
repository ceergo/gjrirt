#!/bin/bash
# ================================================================
# SETUP SCRIPT ДЛЯ GITHUB ACTIONS (LINUX)
# ================================================================

set -e

# Функция для запуска команд с sudo или без него
run_cmd() {
    if command -v sudo >/dev/null 2>&1; then
        sudo "$@"
    else
        "$@"
    fi
}

echo "Установка зависимостей..."
run_cmd apt-get update -qq || echo "Skip apt-get update"
run_cmd apt-get install -y curl unzip tar git || echo "Skip apt-get install"

# 1. СКАЧИВАНИЕ XRAY-CORE
echo "Скачивание Xray-core..."
XRAY_VER="25.2.20" 
LATEST=$(curl -s --connect-timeout 5 https://api.github.com/repos/XTLS/Xray-core/releases/latest | grep -oP '"tag_name": "\K[^"]+' || echo "")
if [ ! -z "$LATEST" ]; then XRAY_VER=$LATEST; fi

curl -L "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip" -o /tmp/xray.zip
run_cmd unzip -o /tmp/xray.zip xray -d /usr/local/bin/
run_cmd chmod +x /usr/local/bin/xray
rm -f /tmp/xray.zip

# 2. СКАЧИВАНИЕ LIBRESPEED-CLI
echo "Скачивание Librespeed-cli..."
LS_VER_TAG="v1.0.10"
LATEST_LS=$(curl -s --connect-timeout 5 https://api.github.com/repos/librespeed/speedtest-cli/releases/latest | grep -oP '"tag_name": "\K[^"]+' || echo "")
if [ ! -z "$LATEST_LS" ]; then LS_VER_TAG=$LATEST_LS; fi

LS_VER=${LS_VER_TAG#v}
curl -L "https://github.com/librespeed/speedtest-cli/releases/download/${LS_VER_TAG}/librespeed-cli_${LS_VER}_linux_amd64.tar.gz" -o /tmp/ls.tar.gz
run_cmd tar -xzf /tmp/ls.tar.gz -C /usr/local/bin/ librespeed-cli || echo "Failed to extract librespeed"
run_cmd chmod +x /usr/local/bin/librespeed-cli || echo "Failed to chmod librespeed"
rm -f /tmp/ls.tar.gz

echo "Установка завершена!"
xray -version | head -n 1 || echo "Xray installed."
librespeed-cli --version || echo "Librespeed installed."
