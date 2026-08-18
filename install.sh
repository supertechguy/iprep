#!/usr/bin/env bash
# Installs iprep. Prefers pipx (isolated, global `iprep` command); falls back
# to a local .venv/ in this repo if pipx isn't available and can't be set up.
#
# Usage:
#   ./install.sh              interactive: offers to set up pipx if missing
#   ./install.sh --pipx       force the pipx path (fails if pipx unavailable)
#   ./install.sh --venv       force the local-venv path
#   ./install.sh --yes        don't prompt; auto-accept installing pipx

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=""
ASSUME_YES=""

for arg in "$@"; do
    case "$arg" in
        --pipx) MODE="pipx" ;;
        --venv) MODE="venv" ;;
        --yes|-y) ASSUME_YES="1" ;;
        -h|--help)
            sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "error: unknown option '$arg' (see --help)" >&2
            exit 1
            ;;
    esac
done

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required but not found on PATH" >&2
    exit 1
fi

PY_VERSION="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%.*}"
PY_MINOR="${PY_VERSION#*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 11 ]; }; then
    echo "error: iprep requires Python 3.11+, found $PY_VERSION" >&2
    exit 1
fi

install_with_pipx() {
    echo "Installing iprep with pipx..."
    pipx install --force "$SCRIPT_DIR"
    echo
    echo "Done. Run 'iprep --help' to get started."
    echo "(open a new shell first if the 'iprep' command isn't found yet)"
}

install_with_venv() {
    echo "Setting up a local virtualenv at $SCRIPT_DIR/.venv"
    python3 -m venv "$SCRIPT_DIR/.venv"
    "$SCRIPT_DIR/.venv/bin/pip" install -q --upgrade pip
    "$SCRIPT_DIR/.venv/bin/pip" install -e "$SCRIPT_DIR"
    echo
    echo "Done. Activate it with:"
    echo "    source $SCRIPT_DIR/.venv/bin/activate"
    echo "then run 'iprep --help'."
}

try_bootstrap_pipx() {
    python3 -m pip install --user -q pipx 2>/dev/null || return 1
    python3 -m pipx ensurepath >/dev/null 2>&1 || true
    # pipx may have just been installed to a user bin dir not yet on this
    # shell's PATH - add it for the rest of this script run.
    local user_base
    user_base="$(python3 -m site --user-base 2>/dev/null || true)"
    [ -n "$user_base" ] && export PATH="$user_base/bin:$PATH"
    command -v pipx >/dev/null 2>&1
}

if [ "$MODE" = "venv" ]; then
    install_with_venv
    exit 0
fi

if [ "$MODE" = "pipx" ]; then
    if ! command -v pipx >/dev/null 2>&1; then
        echo "error: pipx not found on PATH" >&2
        exit 1
    fi
    install_with_pipx
    exit 0
fi

# No mode forced: prefer pipx, offering to install it if missing.
if command -v pipx >/dev/null 2>&1; then
    install_with_pipx
    exit 0
fi

echo "pipx not found (it gives you a global 'iprep' command in its own isolated environment)."

SHOULD_TRY_PIPX="$ASSUME_YES"
if [ -z "$SHOULD_TRY_PIPX" ] && [ -t 0 ]; then
    read -r -p "Install pipx now and use it? [Y/n] " REPLY
    REPLY="${REPLY:-Y}"
    [[ "$REPLY" =~ ^[Yy] ]] && SHOULD_TRY_PIPX="1"
fi

if [ -n "$SHOULD_TRY_PIPX" ] && try_bootstrap_pipx; then
    install_with_pipx
    exit 0
fi

install_with_venv
