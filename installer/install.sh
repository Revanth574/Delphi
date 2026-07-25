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
    local fd="$1" path="$2" kind="$3" owner mode
    owner=$(stat -L -c '%u' "/proc/self/fd/$fd") || refuse "cannot fstat $path"
    mode=$(stat  -L -c '%a' "/proc/self/fd/$fd")
    [ "$owner" = "0" ] || [ "$owner" = "$trusted_uid" ] || \
        refuse "$path resolves to an inode owned by uid $owner (not root or the installing user $trusted_uid) — a different local user may have swapped it"
    [ $(( 0$mode & 022 )) -eq 0 ] || \
        refuse "$path resolves to a group/other-writable inode (mode $mode) — another user could swap it"
    # LOCALE-INDEPENDENT type check (B2A-C-R3-01): `stat -c %F` returns TRANSLATED text under a
    # non-`C` LANG (e.g. "reguläre Datei"), so comparing it to the literal "regular file" would
    # FALSELY refuse a correct build on a translated locale. `test -f`/`-d` on the bound fd is a
    # stat syscall (machine-readable, locale-independent) and still checks the bound inode.
    if [ "$kind" = "file" ]; then
        [ -f "/proc/self/fd/$fd" ] || refuse "$path does not resolve to a regular file"
    else
        [ -d "/proc/self/fd/$fd" ] || refuse "$path does not resolve to a directory"
    fi
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

# ── The shell bundle TREE (P1) — pre-flight ───────────────────────────────────────────
# FIRST directory-tree install. The per-file discipline above (open → fstat_trust the BOUND
# fd → copy from /proc/self/fd) extends here PER ENTRY, unchanged, and carries the same
# documented bash-cannot-openat residual (see the RESIDUAL note above); Class 2 needs nothing
# new. What IS new is Class 12 (reject the invalid CLASS, not the value): above, the 5
# destination names are LITERALS in this script, but a tree takes its names FROM THE SOURCE.
# So `..`, absolute paths, newlines, and non-regular entries become INPUTS, and each must be
# gated as a class — fail-closed — rather than spot-checked.
SHELL_SRC="$STAGE/shell"
MAX_TREE_DEPTH=4      # dist/ is index.html + assets/<file>; 4 is slack, not a prediction
MAX_TREE_ENTRIES=256  # bounded so the held-fd set cannot approach the per-process fd limit

exec {SHELL_FD}< "$SHELL_SRC" || refuse "cannot open $SHELL_SRC — run installer/build.sh (UNPRIVILEGED) first"
fstat_trust "$SHELL_FD" "$SHELL_SRC" dir

declare -a TREE_DIRS=() TREE_FILES=() TREE_FILE_FD=()
tree_count=0
while IFS= read -r -d '' entry; do
    rel="${entry#"$SHELL_SRC"/}"

    tree_count=$((tree_count + 1))
    if [ "$tree_count" -gt "$MAX_TREE_ENTRIES" ]; then
        refuse "$SHELL_SRC has more than $MAX_TREE_ENTRIES entries — refusing rather than exhausting the fd table"
    fi

    # A symlink ANYWHERE in the tree is refused outright: copying THROUGH one would read an
    # inode outside the staged tree (a symlink to /etc/shadow would be installed into a
    # world-readable /usr/share path), and copying it AS one would plant a dangling or
    # escaping link under a root-owned directory. The bundle legitimately contains neither.
    if [ -L "$entry" ]; then
        refuse "$rel is a symlink — the bundle tree must contain only regular files and directories"
    fi

    # Name gating, per component: the allowlist admits exactly what vite emits (including
    # content-hashed names like index-DhCw579K.js) and excludes `/`, newline, whitespace, and
    # shell metacharacters by construction. `..` matches the allowlist (dots are legal in
    # filenames), so it is rejected explicitly — that is the traversal case.
    IFS='/' read -ra parts <<< "$rel"
    if [ "${#parts[@]}" -gt "$MAX_TREE_DEPTH" ]; then
        refuse "$rel exceeds the maximum tree depth of $MAX_TREE_DEPTH"
    fi
    for part in "${parts[@]}"; do
        if ! [[ "$part" =~ ^[A-Za-z0-9._-]+$ ]]; then
            refuse "$rel contains a path component ('$part') outside the allowed name class [A-Za-z0-9._-]"
        fi
        if [ "$part" = "." ] || [ "$part" = ".." ]; then
            refuse "$rel contains a '$part' component — path traversal refused"
        fi
    done

    if [ -d "$entry" ]; then
        TREE_DIRS+=("$rel")
    elif [ -f "$entry" ]; then
        # Bind the inode NOW and fstat-trust it, exactly as the fixed-name files above.
        exec {tfd}< "$entry" || refuse "cannot open $entry"
        fstat_trust "$tfd" "$entry" file
        TREE_FILES+=("$rel")
        TREE_FILE_FD+=("$tfd")
    else
        refuse "$rel is neither a regular file nor a directory — refusing (device/FIFO/socket)"
    fi
done < <(find "$SHELL_SRC" -mindepth 1 -print0 | sort -z)

# An empty tree would "install" successfully and leave the host with no page to load — the
# blank-page failure this whole increment exists to prevent. Refuse it.
if [ "${#TREE_FILES[@]}" -eq 0 ]; then
    refuse "$SHELL_SRC contains no regular files — run installer/build.sh first"
fi
# The host loads index.html by name; without it the install is vacuous.
if [ ! -f "$SHELL_SRC/index.html" ]; then
    refuse "$SHELL_SRC/index.html is missing — the host loads it by name (shell-host/src/main.rs:200)"
fi

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

# ── The shell bundle TREE (P1) — mutate, via a two-rename replace ─────────────────────
# `install` replaces ONE file atomically; a TREE has no atomic equivalent. So build the new
# tree beside the live one under a DETERMINISTIC name, then swap by rename.
#
# WHY DETERMINISTIC, NOT PID-SUFFIXED: a pid-suffixed staging dir left behind by a crashed
# run is invisible — the next run cannot tell it from a live one, so leftovers ACCUMULATE
# silently and are rediscovered later as a mystery disk-usage leak (this project already paid
# for that lesson once: 113 stale /run/delphi-*-<pid> dirs, ~24MB each). A fixed name is a
# NAMED STATE the next run can detect, report, and clear — the same reasoning as the
# systemd_smoke fixed-name backup.
DEST_PARENT=/usr/share/delphi
CUR="$DEST_PARENT/shell"
NEW="$DEST_PARENT/shell.new"
OLD="$DEST_PARENT/shell.old"

install -d -m 0755 "$DEST_PARENT"

# Leftover states from a crashed previous run — each is HANDLED and REPORTED, never silently
# stepped over:
#
#   shell.new exists            -> a run died before the swap. Pure scratch, nothing depends
#                                  on it. Remove it.
#   shell.old exists + shell    -> a run died after the swap but before cleanup. shell.old is
#                                  the superseded tree. Remove it.
#   shell.old exists, NO shell  -> a run died BETWEEN the two renames. shell.old holds the
#                                  last-good tree and the live path is currently ABSENT. We
#                                  are about to install a fresh tree, so it is recoverable —
#                                  but say so LOUDLY rather than quietly papering over the
#                                  fact that the system was found in a broken state.
if [ -e "$NEW" ]; then
    echo "NOTE: clearing leftover $NEW (a previous run died before the swap)."
    rm -rf "$NEW"
fi
if [ -e "$OLD" ]; then
    if [ -e "$CUR" ]; then
        echo "NOTE: clearing leftover $OLD (a previous run died after the swap, before cleanup)."
    else
        echo "WARNING: found $OLD with NO $CUR — a previous run died BETWEEN the two renames,"
        echo "         leaving the shell bundle UNINSTALLED. Recovering by installing fresh."
    fi
    rm -rf "$OLD"
fi

# Build the new tree from the BOUND fds (never re-resolving the staged paths).
install -d -m 0755 "$NEW"
for rel in "${TREE_DIRS[@]}"; do
    install -d -m 0755 "$NEW/$rel"
done
for i in "${!TREE_FILES[@]}"; do
    copy_fd "${TREE_FILE_FD[$i]}" "$NEW/${TREE_FILES[$i]}" 0644
done

# The swap. Between the two renames `$CUR` does not exist — a brief window in which the host
# would fail to load the page. That is UNAVAILABILITY, not corruption, and it is the accepted
# cost of not putting a symlink at a root-owned path the host resolves. Both renames are
# within one filesystem, so each is a single atomic rename(2).
if [ -e "$CUR" ]; then
    mv "$CUR" "$OLD"
fi
mv "$NEW" "$CUR"
rm -rf "$OLD"

systemctl daemon-reload

echo "installed:"
ls -l /usr/libexec/delphi-runtimed /usr/libexec/delphi-shell /usr/libexec/delphi-minimal-ai
echo "Brain address intentionally absent: $(ls /usr/libexec/delphi-ai 2>&1)"
echo "PAM stack: $(ls -l /etc/pam.d/delphi-runtime)"
echo "shell bundle: $(find "$CUR" -type f | wc -l) files under $CUR"
echo "  the host loads: file://$CUR/index.html"
