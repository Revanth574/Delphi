#!/bin/bash
# C2 install phase — ROOT. Copies the staged binaries + the unit + the PAM stack into
# their system locations. Does NOT build (run installer/build.sh unprivileged first).
#
#   REAL, installed at their production addresses:
#     /usr/libexec/delphi-runtimed          the root daemon
#     /usr/libexec/delphi-shell             the raw-WRY shell host
#   SCAFFOLD, installed under its OWN name (NOT the Brain's address):
#     /usr/libexec/delphi-minimal-ai        B1 AI stand-in; the unit's DELPHI_AI_BIN points here
#   DELIBERATELY ABSENT:
#     /usr/libexec/delphi-ai                the Brain's address — left EMPTY so a missing
#                                           override fails LOUD at ENOENT, never silently
#                                           runs scaffolding at the real address.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "must run as root (writes /usr/libexec, /usr/lib/systemd/system, /etc/pam.d)"; exit 1; }
cd "$(dirname "$0")/.."   # repo root

STAGE="installer/staging"
trusted_uid="${SUDO_UID:-0}"   # the human who ran sudo; if run as raw root, only root is trusted
refuse() { echo "REFUSING (no system change made): $1"; exit 1; }

# ══════════════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT — ALL checks BEFORE any system mutation (B2A-C-R1-04). And TOCTOU-free
# (B2A-C-R2-01): the round-1 fix stat'd the leaf paths, but a different local user with write
# on a group-writable ANCESTOR (e.g. `installer/` under a `umask 002` checkout) could rename
# `staging` and substitute a tree between the check and the `install`. So here we OPEN each
# source read-only FIRST — binding an fd to its inode — fstat the OPEN fd (the real inode, not
# the path), and later COPY FROM THE SAME fd. A path/dir swap after the check cannot change
# what those fds point at (verified: `cat <&fd` reads the original inode after a path swap).
# ══════════════════════════════════════════════════════════════════════════════════════

# fstat trust on an OPEN fd: owner ∈ {root, invoking user}, no group/other-write bit, and (for
# files) a regular file. Catches a substituted inode owned by another user, or a symlink to a
# non-regular target, on the actual inode the fd is bound to.
fstat_trust() {   # fd path kind(dir|file)
    local fd="$1" path="$2" kind="$3" owner mode ftype
    owner=$(stat -L -c '%u' "/proc/self/fd/$fd") || refuse "cannot fstat $path"
    mode=$(stat  -L -c '%a' "/proc/self/fd/$fd")
    ftype=$(stat -L -c '%F' "/proc/self/fd/$fd")
    [ "$owner" = "0" ] || [ "$owner" = "$trusted_uid" ] || \
        refuse "$path resolves to an inode owned by uid $owner (not root or the installing user $trusted_uid) — a different local user may have swapped it"
    [ $(( 0$mode & 022 )) -eq 0 ] || \
        refuse "$path resolves to a group/other-writable inode (mode $mode) — another user could swap it"
    [ "$kind" != "file" ] || [ "$ftype" = "regular file" ] || \
        refuse "$path resolves to a $ftype, not a regular file"
}

# RESIDUAL (documented, not hidden): bash cannot `openat(STAGE_FD, f)`, so the file opens below
# still resolve `"$STAGE/$f"` by PATH. A perfectly-timed rename of `staging` BETWEEN the dir
# open and a file open, substituting a dir of SYMLINKS to root-owned regular files, would pass
# the fstat checks (the fd resolves to a root file) and install a WRONG root binary — a DoS, NOT
# attacker code execution (the RCE — installing an attacker-OWNED artifact — IS closed: an
# attacker-owned file or their substituted staging dir fails the owner check). Fully closing the
# residual needs `openat`, i.e. a non-bash helper; out of scope for this shell installer.

# The staging DIR first: bind its inode + verify its owner. If a different user renamed the
# real staging and substituted their own dir, this owner check catches it (their dir is
# owned by THEM, not root/$trusted_uid).
exec {STAGE_FD}< "$STAGE" || refuse "cannot open $STAGE — run installer/build.sh (UNPRIVILEGED) first"
fstat_trust "$STAGE_FD" "$STAGE" dir

# Each staged file: bind its inode + fstat-trust it. build.sh stages the binaries AND the unit
# + PAM here (tight), so this ONE dir is the only source — never the group-writable repo tree.
declare -A FD
for f in delphi-runtimed delphi-shell delphi-minimal-ai delphi-runtimed@.service delphi-runtime.pam; do
    exec {fd}< "$STAGE/$f" || refuse "cannot open $STAGE/$f — run installer/build.sh first"
    fstat_trust "$fd" "$STAGE/$f" file
    FD[$f]=$fd
done

# The Brain's address MUST stay empty — checked BEFORE any mutation (fail-closed, B2A-C-R1-04).
if [ -e /usr/libexec/delphi-ai ]; then
    echo "REFUSING (no system change made): /usr/libexec/delphi-ai exists but must stay EMPTY"
    echo "  (no real Brain yet — a stub at the real address is the lie this refuses)."
    echo "  Remove it by hand if it is stale: rm /usr/libexec/delphi-ai"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════════════
# MUTATE — copy from the BOUND fds (not the paths), then set owner/mode explicitly. Only
# reached when every pre-flight check above passed.
# ══════════════════════════════════════════════════════════════════════════════════════
copy_fd() {   # fd dest mode
    local fd="$1" dest="$2" mode="$3"
    # `install` from the BOUND fd (`/proc/self/fd/$fd`) — reads the same inode the fstat check
    # trusted (TOCTOU-free: verified `install /proc/self/fd/$fd` gets the original after a path
    # swap), and sets owner+mode ATOMICALLY (no `cat >` umask window where the dest is briefly
    # world-readable-but-wrong-mode). The DEST dir is root-owned (see the `install -d` below),
    # so no attacker can pre-plant a symlink at `$dest` for `install` to follow.
    install -o root -g root -m "$mode" "/proc/self/fd/$fd" "$dest" || refuse "failed installing $dest"
}

install -d -m 0755 /usr/libexec
copy_fd "${FD[delphi-runtimed]}"    /usr/libexec/delphi-runtimed    0755
copy_fd "${FD[delphi-shell]}"       /usr/libexec/delphi-shell       0755
copy_fd "${FD[delphi-minimal-ai]}"  /usr/libexec/delphi-minimal-ai  0755

install -d -m 0755 /usr/lib/systemd/system
copy_fd "${FD[delphi-runtimed@.service]}" /usr/lib/systemd/system/delphi-runtimed@.service 0644
copy_fd "${FD[delphi-runtime.pam]}"       /etc/pam.d/delphi-runtime                        0644

systemctl daemon-reload

echo "installed:"
ls -l /usr/libexec/delphi-runtimed /usr/libexec/delphi-shell /usr/libexec/delphi-minimal-ai
echo "Brain address intentionally absent: $(ls /usr/libexec/delphi-ai 2>&1)"
echo "PAM stack: $(ls -l /etc/pam.d/delphi-runtime)"
