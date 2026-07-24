#!/bin/bash
# C2 build phase — UNPRIVILEGED. Builds the three binaries into installer/staging/,
# which installer/install.sh (ROOT) then copies into place.
#
# Split by privilege on purpose: building as root would leave root-owned artifacts in
# the developer's CARGO_TARGET_DIR (the hygiene lesson from this arc). Run this as
# yourself; run install.sh with sudo.
#
# REAL vs SCAFFOLD (do not confuse — this is the whole point of the split):
#   delphi-runtimed    REAL   — the root runtime daemon
#   delphi-shell       REAL   — the raw-WRY (WebKitGTK) shell host (runtime/shell-host)
#   delphi-minimal-ai  SCAFFOLD — the B1 AI stand-in, NOT the Brain (which does not exist)
set -euo pipefail
cd "$(dirname "$0")/.."   # repo root

STAGE="installer/staging"
# The workspace .cargo/config.toml pins target-dir to a WSL path that does not exist here;
# override it (honour an explicit CARGO_TARGET_DIR if the caller set one).
TARGET="${CARGO_TARGET_DIR:-$HOME/delphi-target}"
mkdir -p "$STAGE"

echo "== [1/2] root daemon + B1 AI scaffold (main workspace, release) =="
CARGO_TARGET_DIR="$TARGET" cargo build --release -p delphi-runtime \
    --bin delphi-runtimed --bin delphi-minimal-ai
cp -f "$TARGET/release/delphi-runtimed"   "$STAGE/delphi-runtimed"
cp -f "$TARGET/release/delphi-minimal-ai" "$STAGE/delphi-minimal-ai"

echo "== [2/2] REAL WRY shell host (decoupled crate — own workspace, own target) =="
# shell-host has its own [workspace]; give it its own target dir so its wry/WebKit tree
# never mixes with the boundary workspace's.
CARGO_TARGET_DIR="$TARGET/shell-host" cargo build --release \
    --manifest-path runtime/shell-host/Cargo.toml
cp -f "$TARGET/shell-host/release/delphi-shell" "$STAGE/delphi-shell"

echo
echo "staged (UNPRIVILEGED build complete):"
ls -la "$STAGE"/delphi-runtimed "$STAGE"/delphi-shell "$STAGE"/delphi-minimal-ai
echo
echo "next, as ROOT:  sudo bash installer/install.sh"
