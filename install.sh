#!/bin/sh
# fasthands installer: no runtime dependencies, no root, idempotent.
set -eu

TOOL="fasthands"
REPO="3li7alaki/fasthands"
RELEASE="latest"
INSTALL_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/$TOOL"
BIN_DIR="$INSTALL_DIR/bin"
LINK_DIR="$HOME/.local/bin"

NO_PATH=false
UNINSTALL=false
for arg in "$@"; do
  case "$arg" in
    --no-path) NO_PATH=true ;;
    --uninstall) UNINSTALL=true ;;
    *) printf 'error: unknown flag: %s\n' "$arg" >&2; exit 1 ;;
  esac
done

say() { printf '%s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "missing required tool: $1"; }

if [ "$UNINSTALL" = true ]; then
  rm -rf "$INSTALL_DIR"
  rm -f "$LINK_DIR/$TOOL"
  say "uninstalled $TOOL (left PATH line in shell rc, harmless)"
  exit 0
fi

need curl
need uname

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in
  linux|darwin) ;;
  *) err "unsupported OS: $OS ($TOOL ships linux + darwin)" ;;
esac
ARCH=$(uname -m)
case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) err "unsupported architecture: $ARCH ($TOOL ships amd64 + arm64)" ;;
esac
TARGET="${OS}-${ARCH}"
URL="https://github.com/$REPO/releases/download/$RELEASE/${TOOL}-${TARGET}"
say "installing $TOOL ($TARGET) ..."

mkdir -p "$BIN_DIR"
TMP=$(mktemp "$BIN_DIR/.$TOOL.XXXXXX")
trap 'rm -f "$TMP"' EXIT INT TERM
curl -fSL --progress-bar "$URL" -o "$TMP" || err "download failed: $URL"
chmod +x "$TMP"
mv -f "$TMP" "$BIN_DIR/$TOOL"
trap - EXIT INT TERM

mkdir -p "$LINK_DIR"
ln -sf "$BIN_DIR/$TOOL" "$LINK_DIR/$TOOL"

if [ "$NO_PATH" != true ]; then
  LINE="export PATH=\"$LINK_DIR:\$PATH\""
  for RC in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    [ -f "$RC" ] || continue
    grep -qF "$LINK_DIR" "$RC" && continue
    printf '\n# %s\n%s\n' "$TOOL" "$LINE" >> "$RC"
  done
fi

INSTALLED=$("$BIN_DIR/$TOOL" --version 2>/dev/null || echo "installed")
if command -v "$TOOL" >/dev/null 2>&1; then
  say "installed $TOOL $INSTALLED. Run: $TOOL --help"
else
  say "installed $TOOL $INSTALLED to $BIN_DIR/$TOOL"
  say "open a new shell, or run: export PATH=\"$LINK_DIR:\$PATH\""
fi
