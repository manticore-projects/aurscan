#!/bin/bash
# aurscan installer / updater / uninstaller.
#
#   ./install.sh              build (needs Go) and install/update into PREFIX/bin
#   ./install.sh --uninstall  remove aurscan, syay, aurscan-edit from PREFIX/bin
#
# PREFIX defaults to /usr/local. Set SUDO= to install without sudo (e.g. when
# PREFIX is a user-writable dir): SUDO= PREFIX=~/.local ./install.sh
set -euo pipefail
cd "$(dirname "$0")"

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
NAMES=(aurscan syay aurscan-edit)
SUDO="${SUDO-sudo}"   # set SUDO= to disable

uninstall() {
  local removed=0
  for n in "${NAMES[@]}"; do
    if [ -e "$BINDIR/$n" ] || [ -L "$BINDIR/$n" ]; then
      $SUDO rm -f "$BINDIR/$n"
      removed=1
    fi
  done
  if [ "$removed" = 1 ]; then
    echo "Removed ${NAMES[*]} from $BINDIR"
  else
    echo "Nothing to remove in $BINDIR"
  fi
  echo "Note: this does not touch your shell alias. If you ran 'alias yay=syay',"
  echo "remove it too (fish: 'functions -e yay; funcsave yay' or edit config.fish)."
}

install_update() {
  command -v go >/dev/null || { echo "Go is required to build aurscan"; exit 1; }
  local action="Installed"
  [ -e "$BINDIR/aurscan" ] && action="Updated"

  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o aurscan ./cmd/aurscan
  $SUDO install -Dm755 aurscan "$BINDIR/aurscan"
  # Absolute symlinks so they resolve regardless of cwd.
  $SUDO ln -sf "$BINDIR/aurscan" "$BINDIR/syay"
  $SUDO ln -sf "$BINDIR/aurscan" "$BINDIR/aurscan-edit"

  echo "$action aurscan, syay, aurscan-edit -> $BINDIR"
  echo
  if command -v claude >/dev/null; then
    echo "  Backend: Claude Code CLI found — no API key needed."
  elif [ -n "${ANTHROPIC_API_KEY:-}" ]; then
    echo "  Backend: ANTHROPIC_API_KEY is set."
  else
    echo "  Backend: none yet — install Claude Code and log in, or export ANTHROPIC_API_KEY."
  fi
  echo
  echo "Enable the scanner (fish):  alias yay=syay; funcsave yay"
}

case "${1:-}" in
  --uninstall|-u|uninstall) uninstall ;;
  ""|--install|install)     install_update ;;
  -h|--help)
    sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) echo "unknown option: $1 (try --help)"; exit 2 ;;
esac
