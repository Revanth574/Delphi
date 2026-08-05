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
# B2A-C-R1-03: stage with NO group/other-write bits so `install.sh`'s trust check (which
# refuses a group/other-writable source, since another local user could swap it before the
# root copy) accepts the staged artifacts. `umask 022` covers newly-created files; the
# explicit `chmod` below covers a staging dir/file that already existed group-writable.
umask 022
cd "$(dirname "$0")/.."   # repo root

STAGE="installer/staging"
# The workspace .cargo/config.toml pins target-dir to a WSL path that does not exist here;
# override it (honour an explicit CARGO_TARGET_DIR if the caller set one).
TARGET="${CARGO_TARGET_DIR:-$HOME/delphi-target}"
mkdir -p "$STAGE"

# Stage a build product and PROVE the staged bytes are the built bytes.
#
# Lane run 2 installed a binary this invocation had not built. THE MECHANISM IS UNKNOWN and
# the stated suspect was ruled out by measurement — see PROGRESS.md "UNEXPLAINED — build.sh
# staged a binary it had not built". This assertion makes the next occurrence self-diagnosing;
# it is not a diagnosis. If it fires, capture the three shas before clearing it.
stage() {  # stage <src> <name-in-staging>
    local src=$1 dst="$STAGE/$2" a b
    [ -f "$src" ] || { echo "MISSING BUILD PRODUCT: $src" >&2; exit 1; }
    cp -f "$src" "$dst"
    a=$(sha256sum "$src" | cut -d" " -f1)
    b=$(sha256sum "$dst" | cut -d" " -f1)
    [ "$a" = "$b" ] || {
        echo "STAGING MISMATCH for $2 — the staged bytes are NOT the built bytes." >&2
        echo "  built  $a  $src" >&2
        echo "  staged $b  $dst" >&2
        exit 1
    }
    printf "  staged %-18s sha256 %s…  <- %s\n" "$2" "${a:0:12}" "$src"
    STAGED_SHAS+=("$2 ${a:0:12}… $src")
}
STAGED_SHAS=()
echo "target-dir: $TARGET   (CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-<unset>})"

echo "== [1/3] root daemon + B1 AI scaffold (main workspace, release) =="
CARGO_TARGET_DIR="$TARGET" cargo build --release -p delphi-runtime \
    --bin delphi-runtimed --bin delphi-minimal-ai
stage "$TARGET/release/delphi-runtimed" delphi-runtimed
stage "$TARGET/release/delphi-minimal-ai" delphi-minimal-ai

echo "== [2/3] REAL WRY shell host (decoupled crate — own workspace, own target) =="
# shell-host has its own [workspace]; give it its own target dir so its wry/WebKit tree
# never mixes with the boundary workspace's.
CARGO_TARGET_DIR="$TARGET/shell-host" cargo build --release \
    --manifest-path runtime/shell-host/Cargo.toml
stage "$TARGET/shell-host/release/delphi-shell" delphi-shell

echo "== [3/3] REAL React shell bundle (P1 — what the WRY host actually draws) =="
# The host loads `file:///usr/share/delphi/shell/index.html`. Without this the host starts
# and renders a WebKit error page: no error reaches the daemon, and `window.__delphiConsent`
# never registers, so the consent injections silently no-op. `shell/vite.config.ts` pins
# `base: "./"` for exactly this reason (RED-proven by
# `shell/src/__tests__/file-protocol-load.test.ts`) — an absolute base resolves to the
# FILESYSTEM ROOT from a `file://` document.
#
# pnpm resolution: PATH first, then the corepack cache (Ubuntu's corepack 0.24 cannot LOAD
# pnpm 11 — its vm loader has no dynamic-import callback — but it does DOWNLOAD it, and the
# downloaded CJS entry runs fine under node directly).
if command -v pnpm >/dev/null 2>&1; then
    PNPM=(pnpm)
else
    # Newest cached pnpm, if corepack has fetched one.
    _pnpm_cjs=$(ls -1d "$HOME"/.cache/node/corepack/pnpm/*/bin/pnpm.cjs 2>/dev/null | sort -V | tail -1)
    [ -n "$_pnpm_cjs" ] || {
        echo "pnpm not found on PATH and none in the corepack cache." >&2
        echo "  Install it, then re-run:  corepack enable pnpm  (or: npm i -g pnpm)" >&2
        exit 1
    }
    PNPM=(node "$_pnpm_cjs")
fi
( cd shell && "${PNPM[@]}" install --frozen-lockfile && "${PNPM[@]}" run build )

# Stage the built tree. `rm -rf` FIRST so a rebuild never leaves stale hashed assets from a
# previous build in staging (vite emits content-hashed filenames, so old ones do not get
# overwritten — they just accumulate and then get installed).
rm -rf "$STAGE/shell"
cp -r shell/dist "$STAGE/shell"

# Stage the UNIT + PAM stack too, so `install.sh` copies EVERYTHING from the single tight
# staging dir and never from the group-writable repo tree (a checkout is `664`/`775` under the
# default `umask 002`, which `install.sh`'s trust check would rightly refuse). Staging is the
# one trust-tight source.
cp -f runtime/systemd/delphi-runtimed@.service "$STAGE/delphi-runtimed@.service"
cp -f installer/pam/delphi-runtime            "$STAGE/delphi-runtime.pam"
# The AppArmor profile for the shell host. NOT A CONFINEMENT MEASURE — see the long header
# in the file itself. It exists solely so the host is a NAMED profile and thus exempt from
# kernel.apparmor_restrict_unprivileged_userns=1, which otherwise denies the user namespace
# glycin's bwrap image loader needs and makes GTK3 abort on the first themed-icon load.
cp -f installer/apparmor/delphi-shell         "$STAGE/delphi-shell.apparmor"

# Tighten perms explicitly (covers a pre-existing group-writable staging dir/file that umask
# alone would not fix, since umask only affects NEWLY created inodes).
chmod 0755 "$STAGE"
chmod 0755 "$STAGE"/delphi-runtimed "$STAGE"/delphi-shell "$STAGE"/delphi-minimal-ai
chmod 0644 "$STAGE"/delphi-runtimed@.service "$STAGE"/delphi-runtime.pam "$STAGE"/delphi-shell.apparmor
# The bundle tree: dirs traversable, files read-only. Same no-group/other-write requirement
# as the binaries — `install.sh` refuses a group/other-writable source inode.
chmod 0755 "$STAGE/shell"
find "$STAGE/shell" -type d -exec chmod 0755 {} +
find "$STAGE/shell" -type f -exec chmod 0644 {} +

echo
echo "staged (UNPRIVILEGED build complete):"
ls -la "$STAGE"
echo
echo "staged from target-dir: $TARGET"
printf "  %s\n" "${STAGED_SHAS[@]}"
echo
echo "If runtime/shell-host's tests then report the installed host DIFFERS from this build,"
echo "compare delphi-shell's sha above against the path the test prints. A mismatch there is"
echo "two DIFFERENT target dirs (e.g. a suite run under sudo without -E resolves \$HOME to"
echo "/root), not a stale install — reinstalling will not fix it."
echo
echo "next, as ROOT:  sudo bash installer/install.sh"
