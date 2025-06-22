#!/bin/bash
set -e

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root. Please use sudo." >&2
   exit 1
fi

echo "[INFO] Fetching the latest HARDN-XDR release..."

# Use GitHub API to get the download URL for the latest .deb package
DOWNLOAD_URL=$(curl -s https://api.github.com/repos/OpenSource-For-Freedom/HARDN-XDR/releases/latest | grep "browser_download_url" | grep ".deb" | cut -d '"' -f 4)

if [ -z "$DOWNLOAD_URL" ]; then
    echo "[ERROR] Could not find the download URL for the latest .deb package. Please check the releases page."
    exit 1
fi

# Get the filename from the URL
FILENAME=$(basename "$DOWNLOAD_URL")
TEMP_DIR=$(mktemp -d)

echo "[INFO] Downloading $FILENAME..."
curl -L -o "$TEMP_DIR/$FILENAME" "$DOWNLOAD_URL"

echo "[INFO] Installing the package..."
dpkg -i "$TEMP_DIR/$FILENAME"

echo "[INFO] Installing dependencies (if any)..."
apt-get install -f -y

echo "[INFO] Cleaning up..."
rm -rf "$TEMP_DIR"

echo ""
echo "-----------------------------------------------------"
echo "HARDN-XDR installed successfully."
echo "Run 'sudo hardn start' to apply security settings."
echo "-----------------------------------------------------"

exit 0
