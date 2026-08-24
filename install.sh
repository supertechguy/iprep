#!/usr/bin/env bash
# Installs iprep globally via pipx (isolated, no venv activation needed).
# Bootstraps pipx itself if it isn't already on PATH.
#
# Usage:
#   ./install.sh              default: installs/uses pipx automatically
#   ./install.sh --pipx       same, but errors instead of bootstrapping if pipx is missing
#   ./install.sh --venv       install into a local .venv/ in this repo instead

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE=""

for arg in "$@"; do
    case "$arg" in
        --pipx) MODE="pipx" ;;
        --venv) MODE="venv" ;;
        -h|--help)
            sed -n '2,8p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

# Prefer the OS package manager where one exists - many modern distros
# (Debian/Ubuntu 23.04+ and derivatives, per PEP 668) refuse `pip install
# --user` outside a virtualenv specifically to steer you toward this, so it's
# usually the one that actually works.
pipx_install_command() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "sudo apt-get install -y pipx"
    elif command -v dnf >/dev/null 2>&1; then
        echo "sudo dnf install -y pipx"
    elif command -v pacman >/dev/null 2>&1; then
        echo "sudo pacman -S --noconfirm python-pipx"
    elif command -v brew >/dev/null 2>&1; then
        echo "brew install pipx"
    else
        echo ""
    fi
}

refresh_path_for_pipx() {
    python3 -m pipx ensurepath >/dev/null 2>&1 || true
    # pipx may have just been installed to a user bin dir not yet on this
    # shell's PATH - add it for the rest of this script run.
    local user_base
    user_base="$(python3 -m site --user-base 2>/dev/null || true)"
    [ -n "$user_base" ] && export PATH="$user_base/bin:$PATH"
}

# Actually installs pipx (not just prints a suggestion), trying pip first
# and falling back to the OS package manager. The package-manager path may
# invoke sudo and prompt for your password.
try_bootstrap_pipx() {
    echo "pipx not found - installing it..."

    if python3 -m pip install --user -q pipx 2>/dev/null; then
        refresh_path_for_pipx
        command -v pipx >/dev/null 2>&1 && return 0
    fi

    local cmd
    cmd="$(pipx_install_command)"
    if [ -n "$cmd" ]; then
        echo "pip install --user pipx didn't work (likely PEP 668) - trying: $cmd"
        echo "(you may be prompted for your password)"
        if $cmd; then
            refresh_path_for_pipx
            command -v pipx >/dev/null 2>&1 && return 0
        fi
    fi

    echo "Could not install pipx automatically." >&2
    if [ -n "$cmd" ]; then
        echo "Install it yourself with:  $cmd" >&2
    fi
    echo "...then re-run ./install.sh." >&2
    return 1
}

if [ "$MODE" = "venv" ]; then
    install_with_venv
    exit 0
fi

if command -v pipx >/dev/null 2>&1; then
    install_with_pipx
    exit 0
fi

if [ "$MODE" = "pipx" ]; then
    echo "error: pipx not found on PATH" >&2
    exit 1
fi

# Default: bootstrap pipx automatically, falling back to a local venv only
# if that's genuinely not possible on this system.
if try_bootstrap_pipx; then
    install_with_pipx
    exit 0
fi

install_with_venv
