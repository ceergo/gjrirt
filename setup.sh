#!/bin/bash
# ================================================================
# SETUP SCRIPT FOR GITHUB ACTIONS (LINUX)
# ================================================================

set -e

echo "Installing dependencies..."
sudo apt-get update -qq
sudo apt-get install -y curl unzip tar git

# 1. Install XRAY-CORE
echo "Installing Xray-core..."
XRAY_LATEST_JSON=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest)
XRAY_VER=$(echo "$XRAY_LATEST_JSON" | grep -oP '"tag_name": "\K[^"]+')
echo "Using Xray version: $XRAY_VER"

curl -L "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-64.zip" -o /tmp/xray.zip
sudo unzip -o /tmp/xray.zip xray -d /usr/local/bin/
sudo chmod +x /usr/local/bin/xray
rm /tmp/xray.zip

# 2. Install LIBRESPEED-CLI
echo "Installing Librespeed-cli..."
LS_LATEST_JSON=$(curl -s https://api.github.com/repos/librespeed/speedtest-cli/releases/latest)
LS_VER_TAG=$(echo "$LS_LATEST_JSON" | grep -oP '"tag_name": "\K[^"]+')
LS_VER=${LS_VER_TAG#v} # remove 'v' prefix
echo "Using Librespeed version: $LS_VER"

curl -L "https://github.com/librespeed/speedtest-cli/releases/download/${LS_VER_TAG}/librespeed-cli_${LS_VER}_linux_amd64.tar.gz" -o /tmp/ls.tar.gz
sudo tar -xzf /tmp/ls.tar.gz -C /usr/local/bin/ librespeed-cli
sudo chmod +x /usr/local/bin/librespeed-cli
rm /tmp/ls.tar.gz

echo "Setup complete!"
xray -version
librespeed-cli --version

