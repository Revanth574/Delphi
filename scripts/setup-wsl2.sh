#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Delphi OS — WSL2 development environment setup
#
# Run this script INSIDE WSL2 (Ubuntu 24.04) after installing WSL2 from Windows.
# See docs/dev-setup-windows.md for the Windows-side prerequisites.
#
# Usage:
#   chmod +x scripts/setup-wsl2.sh
#   ./scripts/setup-wsl2.sh

set -euo pipefail

# ── Formatting ────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
fail()    { echo -e "${RED}[✗]${NC} $1"; exit 1; }
section() { echo -e "\n${BOLD}── $1 ──${NC}"; }

# Track what we install for the summary.
declare -a INSTALLED=()
declare -a SKIPPED=()

# ── Preflight ─────────────────────────────────────────────────────────────────

section "Preflight checks"

if [[ "$(uname -r)" != *microsoft* ]] && [[ "$(uname -r)" != *WSL* ]]; then
    fail "This script must be run inside WSL2. Detected kernel: $(uname -r)"
fi

if ! grep -q "Ubuntu" /etc/os-release 2>/dev/null; then
    warn "Expected Ubuntu 24.04. Detected: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2)"
    warn "Continuing anyway — some package names may differ."
fi

# Ensure we can use sudo.
if ! sudo -v 2>/dev/null; then
    fail "This script requires sudo access. Please configure sudo for your user."
fi

# ── Helper: install apt packages if not already present ───────────────────────

install_apt() {
    local pkg="$1"
    if dpkg -s "$pkg" &>/dev/null; then
        SKIPPED+=("$pkg")
    else
        sudo apt-get install -y "$pkg" || fail "Failed to install $pkg. Check your apt sources."
        INSTALLED+=("$pkg")
    fi
}

# ── 1. System update ─────────────────────────────────────────────────────────

section "1/10 — Updating system packages"
sudo apt-get update -y || fail "apt-get update failed. Check your network connection."
sudo apt-get upgrade -y
info "System packages updated"

# ── 2. Build essentials ──────────────────────────────────────────────────────

section "2/10 — Build essentials"
for pkg in build-essential pkg-config cmake libssl-dev git curl wget; do
    install_apt "$pkg"
done
info "Build essentials ready"

# ── 3. Wayland development libraries ─────────────────────────────────────────

section "3/10 — Wayland development libraries (for Smithay compositor)"
for pkg in libwayland-dev libxkbcommon-dev libudev-dev libinput-dev libgbm-dev libseat-dev; do
    install_apt "$pkg"
done
info "Wayland dev libraries ready"

# ── 4. GPU / rendering libraries ─────────────────────────────────────────────

section "4/10 — GPU and rendering libraries"
for pkg in libvulkan-dev mesa-vulkan-drivers libglfw3-dev libegl-dev; do
    install_apt "$pkg"
done
info "GPU/rendering libraries ready"

# ── 5. Rust toolchain ────────────────────────────────────────────────────────

section "5/10 — Rust toolchain"
if command -v rustc &>/dev/null; then
    RUST_VER=$(rustc --version | awk '{print $2}')
    SKIPPED+=("rust-$RUST_VER")
    info "Rust already installed: $RUST_VER"
    rustup update stable 2>/dev/null || true
else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    INSTALLED+=("rust-$(rustc --version | awk '{print $2}')")
    info "Rust installed: $(rustc --version)"
fi

# Ensure cargo is on PATH for the rest of this script.
export PATH="$HOME/.cargo/bin:$PATH"

# Verify minimum version (1.85 for edition 2024).
RUST_MINOR=$(rustc --version | grep -oP '\d+\.\d+' | head -1 | cut -d. -f2)
if (( RUST_MINOR < 85 )); then
    warn "Rust $(rustc --version | awk '{print $2}') is below 1.85 (needed for edition 2024)."
    warn "Run: rustup update stable"
fi

# ── 6. Node.js 22 LTS + pnpm ─────────────────────────────────────────────────

section "6/10 — Node.js 22 LTS + pnpm"
if command -v node &>/dev/null; then
    NODE_VER=$(node --version)
    NODE_MAJOR=$(echo "$NODE_VER" | grep -oP '\d+' | head -1)
    if (( NODE_MAJOR >= 22 )); then
        SKIPPED+=("node-$NODE_VER")
        info "Node.js already installed: $NODE_VER"
    else
        warn "Node.js $NODE_VER is below v22. Installing v22 LTS..."
        curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
        sudo apt-get install -y nodejs
        INSTALLED+=("node-$(node --version)")
    fi
else
    curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
    sudo apt-get install -y nodejs
    INSTALLED+=("node-$(node --version)")
    info "Node.js installed: $(node --version)"
fi

if command -v pnpm &>/dev/null; then
    SKIPPED+=("pnpm")
    info "pnpm already installed: $(pnpm --version)"
else
    npm install -g pnpm || corepack enable pnpm 2>/dev/null || fail "Failed to install pnpm"
    INSTALLED+=("pnpm-$(pnpm --version)")
    info "pnpm installed: $(pnpm --version)"
fi

# ── 7. Python 3.12+ ──────────────────────────────────────────────────────────

section "7/10 — Python 3.12+"
if command -v python3 &>/dev/null; then
    PY_VER=$(python3 --version | awk '{print $2}')
    PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
    if (( PY_MINOR >= 12 )); then
        SKIPPED+=("python-$PY_VER")
        info "Python already installed: $PY_VER"
    else
        warn "Python $PY_VER is below 3.12. Installing python3.12..."
        sudo add-apt-repository -y ppa:deadsnakes/ppa
        sudo apt-get update -y
        install_apt python3.12
        install_apt python3.12-venv
        sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1
    fi
else
    install_apt python3
    install_apt python3-pip
    install_apt python3-venv
fi

# Ensure pip is available.
if ! command -v pip3 &>/dev/null; then
    install_apt python3-pip
fi

# ── 8. llama.cpp build dependencies ──────────────────────────────────────────

section "8/10 — llama.cpp build dependencies"
for pkg in cmake libcurl4-openssl-dev libclang-dev libpixman-1-dev; do
    install_apt "$pkg"
done
info "llama.cpp build deps ready"

# ── 9. Protobuf + D-Bus + Flatpak + Podman ──────────────────────────────────

section "9/10 — Protobuf, D-Bus, Flatpak, Podman"
for pkg in protobuf-compiler libdbus-1-dev flatpak podman; do
    install_apt "$pkg"
done
info "IPC and container tools ready"

# ── 10. Verify Delphi workspace compiles ─────────────────────────────────────

section "10/10 — Verifying Delphi workspace compilation"

# Find the Delphi workspace root. Try common locations.
DELPHI_ROOT=""
for candidate in \
    "/mnt/c/Users/$(whoami)/OneDrive/Desktop/Delphi" \
    "/mnt/c/Users/$(whoami)/Desktop/Delphi" \
    "$(pwd)" \
    "$HOME/Delphi"; do
    if [[ -f "$candidate/Cargo.toml" ]]; then
        DELPHI_ROOT="$candidate"
        break
    fi
done

if [[ -z "$DELPHI_ROOT" ]]; then
    warn "Could not find Delphi workspace. Skipping cargo check."
    warn "Navigate to the Delphi workspace and run: cargo check --workspace"
else
    info "Found Delphi workspace at: $DELPHI_ROOT"
    cd "$DELPHI_ROOT"
    if cargo check --workspace 2>&1; then
        info "Full workspace compiles successfully (including compositor!)"
    else
        warn "cargo check had errors. This is expected if some system libraries are still missing."
        warn "Run 'cargo check --workspace' manually to see the full output."
    fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────

section "Setup complete"

if (( ${#INSTALLED[@]} > 0 )); then
    echo -e "${GREEN}Installed:${NC}"
    for item in "${INSTALLED[@]}"; do
        echo "  + $item"
    done
fi

if (( ${#SKIPPED[@]} > 0 )); then
    echo -e "${YELLOW}Already present (skipped):${NC}"
    for item in "${SKIPPED[@]}"; do
        echo "  - $item"
    done
fi

echo ""
info "Development environment ready."
echo ""
echo "Next steps:"
echo "  1. cd to your Delphi workspace"
echo "  2. cargo check --workspace        # verify all crates compile"
echo "  3. cargo test --workspace         # run all tests"
echo "  4. cargo clippy --workspace -- -D warnings  # lint check"
echo ""
echo "If this is your first time, also run:"
echo "  cd shell && pnpm install && pnpm test"
echo ""
