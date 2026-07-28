#!/usr/bin/env bash
set -euo pipefail

REPO="tawhid2005/TWReconHunter"
BIN_DIR="${HOME}/.local/bin"
ASSET="reconhunter-linux-amd64"
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

mkdir -p "$BIN_DIR"

if command -v curl >/dev/null 2>&1; then
  curl -fsSL "$URL" -o "$BIN_DIR/reconhunter"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$BIN_DIR/reconhunter" "$URL"
else
  echo "curl or wget is required" >&2
  exit 1
fi

chmod +x "$BIN_DIR/reconhunter"
echo "Installed to $BIN_DIR/reconhunter"
echo "Run: reconhunter -u https://example.com --confirm-scope"
