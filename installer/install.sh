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
for f in delphi-runtimed delphi-drop delphi-shell delphi-minimal-ai delphi-runtimed@.service delphi-runtime.pam delphi-shell.apparmor; do
    exec {fd}< "$STAGE/$f" || refuse "cannot open $STAGE/$f — run installer/build.sh first"
    fstat_trust "$fd" "$STAGE/$f" file
    FD[$f]=$fd
done

# ── D0A-R10-11 / R11-07: every staged BINARY must be RUNNABLE ON THIS MACHINE ─────────
# runtime/build.rs builds `delphi-drop` with a bare `rustc`, and `delphi-shell` comes from a
# separate cargo invocation with its own target dir, so neither is guaranteed to have been
# built for the target the daemon was. The first version compared 20 header bytes of the
# three binaries against delphi-runtimed's — which R11-07 showed establishes almost nothing:
# four mutually-matching FOREIGN binaries pass it, and a fabricated 20-byte header followed
# by garbage passes it (this installer's own test fixtures were exactly that).
#
# So: compare against a TRUSTED NATIVE reference — /proc/self/exe, the interpreter running
# this script, which by construction executes on this machine — and validate the whole
# identification header plus the fields that decide loadability.
#
#   magic, class, data, version, OSABI     from the reference, not from a table
#   e_type                                 EXEC (2) or DYN (3); anything else is not a program
#   e_machine                              the reference's
#   PT_INTERP                              if the program names a dynamic loader, that loader
#                                          must EXIST — a missing one fails at exec, which is
#                                          the failure this check exists to pre-empt
#
# `delphi-drop` additionally must have NO PT_INTERP: it is handed to bwrap by fd into a jail
# that binds nothing, so a dynamically linked helper cannot find its loader there. That is a
# documented property of the helper (runtime/helper/delphi-drop.rs), asserted here rather
# than assumed.
#
# Reads the ALREADY-BOUND fds, so it inspects the same inodes that will be copied.
#
# RESIDUAL, STATED RATHER THAN IMPLIED: this establishes LOADABILITY PRECONDITIONS, not
# executability. A file with a well-formed native header, a valid e_type and no PT_INTERP —
# followed by garbage — still passes. Proving executability means executing it, and running
# an unvalidated staged binary as root is worse than the risk this check reduces. R11-07's
# phrasing is right and the fix does not reach it; what it does reach is every mismatch that
# a build or a transfer produces, which is the class that actually occurs.

# THE PARSING BELOW IS THE MOST INTRICATE CODE IN THIS ROOT SCRIPT, so its limits are
# declared rather than discovered. It handles **ELF64, little-endian, ELF version 1** and
# REFUSES anything else instead of misreading it: the offsets are hard-coded for that layout
# (`e_phoff` at 32, `e_phentsize` at 54, `e_phnum` at 56), and a 32-bit or big-endian file
# parsed with them yields garbage that would either refuse a valid install or accept a bad
# one. The reference is /proc/self/exe, so on a host this installer does not support, the
# refusal names the host rather than the artifact.

# Read a little-endian unsigned integer of <width> bytes at <offset> from an open fd.
# Empty (offset past EOF) reads as 0; every caller treats 0 as "absent", never as valid.
elf_u() {   # fd offset width -> value on stdout
    local bytes v=0 i=0
    bytes=$(od -An -tu1 -j"$2" -N"$3" "/proc/self/fd/$1" | tr -s ' ' '\n' | grep -E '^[0-9]+$')
    for b in $bytes; do v=$(( v + b * (1 << (8 * i)) )); i=$((i+1)); done
    printf '%s' "$v"
}

# The identification header (first 16 bytes) as decimal, space separated.
elf_ident() {   # fd -> "b0 b1 … b15"
    od -An -tu1 -N16 "/proc/self/fd/$1" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//'
}

# The layout this parser can read at all. Checked on the REFERENCE once; every subject is
# then required to have a byte-identical identification header, so this covers them too.
elf_layout_supported() {   # fd -> 0 if ELF64 little-endian version 1
    local -a b
    read -r -a b < <(elf_ident "$1") || true
    [ "${#b[@]}" -eq 16 ] || return 1
    [ "${b[0]} ${b[1]} ${b[2]} ${b[3]}" = "127 69 76 70" ] || return 1
    [ "${b[4]}" = "2" ] || return 1   # EI_CLASS  ELFCLASS64
    [ "${b[5]}" = "1" ] || return 1   # EI_DATA   ELFDATA2LSB
    [ "${b[6]}" = "1" ] || return 1   # EI_VERSION
}

# The PT_INTERP path, or empty if the program has none (statically linked).
#
# BOUNDED IN THREE WAYS, because this walks attacker-influenced numbers in a root script:
#   * `e_phnum` is capped — the field is 16-bit, so an unbounded loop is up to 65535
#     iterations each spawning `od`, which is a stall the installer would present as a hang.
#     NOT INDEPENDENTLY PROVEN: two attempts to construct an input where only this bound
#     decides both failed — the other bounds refuse the same files first. It bounds WORK,
#     not the verdict, and the test leg says so rather than claiming a cause;
#   * the program-header TABLE must lie inside the file, so a truncated binary cannot read
#     as "no PT_INTERP" (which for delphi-drop is the PASSING answer);
#   * the interpreter string is length-bounded and used ONLY as an argument to `[ -e ]` —
#     never evaluated, never expanded into a command.
MAX_PHNUM=256
elf_interp() {   # fd -> path or ""; refuses (exit 1) on a header it will not walk
    local phoff phentsize phnum size i off p_type p_offset p_filesz
    phoff=$(elf_u "$1" 32 8); phentsize=$(elf_u "$1" 54 2); phnum=$(elf_u "$1" 56 2)
    [ "$phentsize" -ge 56 ] || return 0        # no usable program headers
    [ "$phnum" -le "$MAX_PHNUM" ] || return 1
    size=$(stat -L -c '%s' "/proc/self/fd/$1")
    [ $(( phoff + phnum * phentsize )) -le "$size" ] || return 1
    for (( i = 0; i < phnum; i++ )); do
        off=$(( phoff + i * phentsize ))
        p_type=$(elf_u "$1" "$off" 4)
        [ "$p_type" = "3" ] || continue          # PT_INTERP
        p_offset=$(elf_u "$1" $(( off + 8 )) 8)
        p_filesz=$(elf_u "$1" $(( off + 32 )) 8)
        [ "$p_filesz" -gt 1 ] && [ "$p_filesz" -lt 4096 ] || return 1
        [ $(( p_offset + p_filesz )) -le "$size" ] || return 1
        dd if="/proc/self/fd/$1" bs=1 skip="$p_offset" count=$(( p_filesz - 1 )) 2>/dev/null
        return 0
    done
}

exec {REF_FD}< /proc/self/exe || refuse "cannot open /proc/self/exe as a native ELF reference"
REF_IDENT=$(elf_ident "$REF_FD")
REF_MACHINE=$(elf_u "$REF_FD" 18 2)
elf_layout_supported "$REF_FD" || refuse "this installer's ELF checks support ELF64 little-endian only,
  and /proc/self/exe on this host is not that (ident: $REF_IDENT). Refusing rather than
  misreading every staged binary with offsets that do not apply."

for bin in delphi-runtimed delphi-drop delphi-shell delphi-minimal-ai; do
    fd="${FD[$bin]}"
    ident=$(elf_ident "$fd")
    # A 16-byte identification header must be PRESENT and match the reference in every
    # field: magic, class (32/64), data (endianness), ELF version, OSABI, ABI version, pad.
    [ "$(printf '%s' "$ident" | wc -w)" -eq 16 ] || refuse "$bin is shorter than an ELF identification header"
    [ "$ident" = "$REF_IDENT" ] || refuse "$bin's ELF identification header differs from this machine's
  reference (/proc/self/exe): $REF_IDENT
  $bin: $ident
  Rebuild everything for one target (installer/build.sh) and re-run."
    machine=$(elf_u "$fd" 18 2)
    [ "$machine" = "$REF_MACHINE" ] || refuse "$bin was built for machine $machine; this system runs $REF_MACHINE (e_machine). It would install and then fail at exec."
    etype=$(elf_u "$fd" 16 2)
    case "$etype" in
        2|3) ;;   # ET_EXEC, ET_DYN
        *) refuse "$bin has ELF type $etype — not an executable or PIE, so it is not a program this installer may place in /usr/libexec" ;;
    esac
    interp=$(elf_interp "$fd") || refuse "$bin has a program-header table this installer will not walk
  (absurd e_phnum, or a table/interpreter string extending past the end of the file).
  A binary whose headers do not describe itself is not one to install at /usr/libexec."
    if [ "$bin" = "delphi-drop" ]; then
        # The helper enters a jail that binds NOTHING; a dynamic loader would be absent there.
        [ -z "$interp" ] || refuse "delphi-drop names a dynamic loader ($interp), but it is exec'd inside a jail that binds nothing — it must be statically linked (crt-static). See runtime/helper/delphi-drop.rs."
    elif [ -n "$interp" ]; then
        [ -e "$interp" ] || refuse "$bin needs the dynamic loader $interp, which does not exist on this system — it would install and fail at exec."
    fi
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
        # B2A-COMP-R1-01 (P1): SUBDIRECTORIES MUST BE TRUST-CHECKED TOO.
        # Before this, only the staging ROOT and the regular FILES were fstat_trust'ed;
        # nested dirs got nothing but a name check. That left a real attack: a subdirectory
        # (e.g. `assets/`) owned or group-writable by another local user means that user
        # controls its CONTENTS, so they can race the `-L` symlink check below against the
        # by-name `exec {tfd}<` open — swapping `assets/foo.js` for a symlink to a
        # root-owned regular file. The symlink test passed while it was still a regular
        # file; the open then FOLLOWS the link; `fstat_trust` sees a root-owned regular file
        # on the followed fd and passes; and `copy_fd` installs that content world-readable
        # under /usr/share/delphi/shell.
        #
        # Trust-checking every directory forecloses the race rather than narrowing it: if no
        # unprivileged user can write any directory on the path, no unprivileged user can
        # create or replace the entry being opened. (The documented bash-cannot-`openat`
        # residual is unchanged — but it is only exploitable by someone who can write one of
        # these directories, which this check now denies.)
        exec {dfd}< "$entry" || refuse "cannot open directory $entry"
        fstat_trust "$dfd" "$entry" dir
        exec {dfd}<&-
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

# ── B2A-COMP-R3-01 (P2): APPARMOR PRECONDITIONS BELONG IN PRE-FLIGHT ──────────────────
# The round-1 fix put both apparmor checks AFTER the binaries/unit/PAM were already copied, so
# a failure left a mixed old/new install while claiming "everything else IS installed" — false
# at that point. `command -v` and "does this profile even parse" are PURE PRECONDITIONS: they
# depend on nothing this script has done, so per B2A-C-R1-04 they belong before the first
# mutation, where `refuse`'s "no system change made" is TRUE.
#
# What CANNOT be hoisted is the actual `-r` load: it mutates kernel policy, so it is a
# mutation by definition and has to happen in the mutate phase. Validating with `-QK`
# (skip-kernel-load, skip-cache) here reduces the post-mutation failure to a genuine
# kernel-load refusal rather than the far more likely "missing tool" or "malformed profile".
if ! command -v apparmor_parser >/dev/null 2>&1; then
    refuse "apparmor_parser not found — the shell host needs its AppArmor profile LOADED or it
  SIGABRTs on the first themed-icon load (glycin's bwrap loader needs a user namespace, which
  an UNPROFILED process is denied under kernel.apparmor_restrict_unprivileged_userns=1).
  Install the apparmor userspace tools and re-run."
fi
if ! apparmor_parser -QK "$STAGE/delphi-shell.apparmor" >/dev/null 2>&1; then
    refuse "the staged AppArmor profile does not parse:
$(apparmor_parser -QK "$STAGE/delphi-shell.apparmor" 2>&1 | head -3)"
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
# B2A-COMP-R3-01 (P2): once mutation has begun, `refuse` is a LIE — it prints "no system
# change made". Anything failing from here on must say what state the system is actually in.
# This is not only about the apparmor block: `copy_fd` below has called `refuse` since the
# original single-file installer, so the false message PREDATES this round's change.
fail_after_mutation() {   # what  consequence  remedy
    echo "FAILED MID-INSTALL: $1"
    echo "  THE SYSTEM IS IN A PARTIAL STATE — this is not a clean 'no change made' failure."
    echo "  Consequence: $2"
    echo "  Remedy:      $3"
    echo "  Then re-run: sudo bash installer/install.sh   (it is idempotent)"
    exit 1
}

copy_fd() {   # fd dest mode
    local fd="$1" dest="$2" mode="$3"
    # `install` from the BOUND fd (`/proc/self/fd/$fd`) — reads the same inode the fstat check
    # trusted (TOCTOU-free: verified `install /proc/self/fd/$fd` gets the original after a path
    # swap), and sets owner+mode ATOMICALLY (no `cat >` umask window where the dest is briefly
    # world-readable-but-wrong-mode). The DEST dir is root-owned (see the `install -d` below),
    # so no attacker can pre-plant a symlink at `$dest` for `install` to follow.
    install -o root -g root -m "$mode" "/proc/self/fd/$fd" "$dest" || \
        fail_after_mutation "failed installing $dest" \
            "some artifacts are updated and others are not — versions may be mixed" \
            "fix the cause (disk space, permissions, read-only mount)"
}

# ── D0A-R9-01: the dedicated account approved actions run as ──────────────────
# NOT root (the defect), and NOT the session user — SO_PEERCRED equality against the
# session uid is exactly what would let the sandboxed tool answer its own approval
# request. A third, dedicated identity is the only value that is neither.
#
# Static, because DynamicUser= is structurally unavailable: it applies to a systemd
# UNIT, and the tool is a child the root daemon forks inside bwrap. See
# docs/CONFORMANCE_REGISTER.md.
#
# --system keeps it below UID_MIN, so delphi-runtimed's own R9-11 guard would refuse
# to serve a SESSION for it — correct, and deliberate: this account exists to be
# dropped TO, never to be logged in as.
TOOL_ACCOUNT=delphi-tool
if getent passwd "$TOOL_ACCOUNT" >/dev/null; then
    echo "  tool account $TOOL_ACCOUNT: already present"
else
    # This is the FIRST mutation the script performs, so a failure here has changed
    # nothing — `refuse`, not `fail_after_mutation`. Re-running is safe: the getent
    # check above makes account creation idempotent.
    useradd --system --no-create-home --shell /usr/sbin/nologin "$TOOL_ACCOUNT" || \
        refuse "could not create the tool account $TOOL_ACCOUNT — approved actions have no unprivileged identity to run as. Create it manually: useradd --system --no-create-home --shell /usr/sbin/nologin $TOOL_ACCOUNT"
    echo "  tool account $TOOL_ACCOUNT: created (uid $(id -u "$TOOL_ACCOUNT"))"
fi

install -d -m 0755 /usr/libexec
copy_fd "${FD[delphi-runtimed]}"    /usr/libexec/delphi-runtimed    0755
# D0A-R9-01: the credential-drop helper. 0755 and root-owned like the daemon — it is in
# the same trust class (installer-placed, never named by an action), and its substitution
# would grant uid control, so it must not be writable by anyone the daemon is not.
copy_fd "${FD[delphi-drop]}"        /usr/libexec/delphi-drop        0755
copy_fd "${FD[delphi-shell]}"       /usr/libexec/delphi-shell       0755
copy_fd "${FD[delphi-minimal-ai]}"  /usr/libexec/delphi-minimal-ai  0755

install -d -m 0755 /usr/lib/systemd/system
copy_fd "${FD[delphi-runtimed@.service]}" /usr/lib/systemd/system/delphi-runtimed@.service 0644
copy_fd "${FD[delphi-runtime.pam]}"       /etc/pam.d/delphi-runtime                        0644

# ── AppArmor profile for the shell host ──────────────────────────────────────────────
# ⚠ THIS IS NOT A CONFINEMENT MEASURE AND CONFINES NOTHING. A file in /etc/apparmor.d/
# named after a component LOOKS like hardening; this one provides none. `flags=(unconfined)`
# permits every access. Its ONLY effect is to give the host a NAMED profile, which exempts
# it from kernel.apparmor_restrict_unprivileged_userns=1 — the sysctl that denies user
# namespaces to UNPROFILED processes. Without that exemption, glycin's bwrap image loader
# cannot start, every GTK3 themed-icon load fails, the `image-missing` fallback fails too,
# and gtkiconhelper.c:495 ASSERTS — SIGABRT'ing the shell.
#
# THE RENDERER REMAINS UNCONFINED. delphi-shell embeds WebKitGTK and hosts the UNTRUSTED
# renderer (docs/TRUST_MODEL.md). This profile adds NOTHING to the controls on it: the
# security property is enforced natively (fail-closed CLOEXEC channel containment before any
# WebKit exists; the consent relay's renderer-cannot-forge keystone; the mint-confirm sent
# from the host's own held digest). Do not read this file's existence as sandboxing.
# A genuinely confining profile is a recorded follow-up increment, not this.
install -d -m 0755 /etc/apparmor.d
copy_fd "${FD[delphi-shell.apparmor]}"    /etc/apparmor.d/delphi-shell                     0644
# B2A-COMP-R1-02 (P2): a profile that does not LOAD is a profile that does nothing — the
# install must not report success for a system it has left unable to render.
# B2A-COMP-R3-01 (P2): the PRECONDITIONS for this (tool present, profile parses) moved to
# pre-flight, so what remains here is only the kernel load, which is genuinely a mutation.
if ! apparmor_parser -r -W /etc/apparmor.d/delphi-shell; then
    fail_after_mutation "the kernel refused to load /etc/apparmor.d/delphi-shell" \
        "the shell will SIGABRT on its first themed-icon load until the profile loads" \
        "sudo apparmor_parser -r -W /etc/apparmor.d/delphi-shell"
fi

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
# B2A-COMP-R6-01: RESTORE BEFORE CLEARING — never delete the only good copy.
# The previous version printed a WARNING for the died-between-renames state and then
# `rm -rf "$OLD"` regardless. In that state `shell.old` IS the only good bundle, so clearing
# it first meant any later failure in this run left NEITHER a live bundle NOR a previous one:
# the self-heal destroying the state it heals from. (Same family as the .smoke-bak window,
# and the same fix shape: restore first, clear only what is genuinely superseded.)
#
# THE INVARIANT this establishes, and which the regression test asserts by SAMPLING rather
# than by trusting the sequence: at every instant there is at least one of `shell` or
# `shell.old`. It is never the case that both are absent.
if [ -e "$OLD" ]; then
    if [ -e "$CUR" ]; then
        echo "NOTE: clearing leftover $OLD (a previous run died after the swap, before cleanup)."
        rm -rf "$OLD"      # genuinely superseded — $CUR is live
    else
        echo "RECOVERING: found $OLD with NO $CUR — a previous run died BETWEEN the two"
        echo "            renames. $OLD is the ONLY good bundle, so it is RESTORED to $CUR"
        echo "            before anything else. If this run then fails, the system still has"
        echo "            a working bundle instead of none."
        mv "$OLD" "$CUR"
    fi
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
ls -l /usr/libexec/delphi-runtimed /usr/libexec/delphi-drop /usr/libexec/delphi-shell /usr/libexec/delphi-minimal-ai
echo "Brain address intentionally absent: $(ls /usr/libexec/delphi-ai 2>&1)"
echo "PAM stack: $(ls -l /etc/pam.d/delphi-runtime)"
echo "shell bundle: $(find "$CUR" -type f | wc -l) files under $CUR"
echo "  the host serves it over: delphi://shell/index.html (from its startup snapshot)"
