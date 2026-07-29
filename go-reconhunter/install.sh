#!/usr/bin/env bash
set -euo pipefail

REPO="tawhid2005/TWReconHunter"
BIN_DIR="${HOME}/.local/bin"
BIN_PATH="$BIN_DIR/twreconhunter"
ASSET="twreconhunter-linux-amd64"
URL="https://github.com/${REPO}/releases/latest/download/${ASSET}"

mkdir -p "$BIN_DIR"

installed=false
if command -v curl >/dev/null 2>&1; then
  if curl -fsSL "$URL" -o "$BIN_PATH"; then
    installed=true
  fi
elif command -v wget >/dev/null 2>&1; then
  if wget -q -O "$BIN_PATH" "$URL"; then
    installed=true
  fi
fi

if [ "$installed" = false ]; then
  if command -v go >/dev/null 2>&1; then
    echo "Release asset not found; building from source..."
    (cd "$(dirname "$0")" && go build -o "$BIN_PATH" .)
  else
    echo "curl, wget, or go is required" >&2
    exit 1
  fi
fi

chmod +x "$BIN_PATH"
echo "Installed to $BIN_PATH"

if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  echo "Add this to your shell config to run twreconhunter from anywhere:"
  echo "  export PATH=\"$HOME/.local/bin:\$PATH\""
fi

echo "Run: twreconhunter -u https://example.com --confirm-scope"
