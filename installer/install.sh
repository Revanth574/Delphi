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

# ══════════════════════════════════════════════════════════════════════════════════════
# PRE-FLIGHT — ALL checks BEFORE any system mutation (B2A-C-R1-04: the earlier version ran
# the delphi-ai guard AFTER copying the binaries, leaving a partially-updated system on the
# guarded path). Nothing below this block writes; nothing above it does either.
# ══════════════════════════════════════════════════════════════════════════════════════

# B2A-C-R1-03: this phase runs as ROOT and copies files the UNPRIVILEGED build produced.
# If any source (a staged binary, the unit, the PAM file) — or a directory on the way to it —
# is writable by a user OTHER than root or the person who invoked sudo, that user can swap the
# file between `build.sh` and `sudo install.sh` and get attacker-controlled code installed and
# executed as root. Refuse any source that is not trust-tight. `SUDO_UID` is the human who ran
# sudo; if run as raw root it is unset and only root-owned sources are trusted.
trusted_uid="${SUDO_UID:-0}"
refuse() { echo "REFUSING (no system change made): $1"; exit 1; }
trust_source() {
    local f="$1" owner mode
    [ -e "$f" ] || refuse "$f is missing — run installer/build.sh (UNPRIVILEGED) first"
    owner=$(stat -c '%u' "$f") || refuse "cannot stat $f"
    mode=$(stat -c '%a' "$f")  || refuse "cannot stat $f"
    # Owner must be root or the invoking (sudo) user.
    [ "$owner" = "0" ] || [ "$owner" = "$trusted_uid" ] || \
        refuse "$f is owned by uid $owner (not root or the installing user $trusted_uid) — a different local user could have planted it"
    # No group- or other-write bit (octal 022): another user could swap it before the root copy.
    [ $(( 0$mode & 022 )) -eq 0 ] || \
        refuse "$f is group/other-writable (mode $mode) — another user could swap it before the root copy"
}

# EVERYTHING is copied from the single staging dir (build.sh stages the binaries AND the
# unit + PAM there, tight), so this is the ONLY source tree to trust-check — never the
# group-writable repo checkout. The containing dir matters too: a writable dir lets a
# different user replace a file inside it even if the file itself is tight.
trust_source "$STAGE"
for f in delphi-runtimed delphi-shell delphi-minimal-ai delphi-runtimed@.service delphi-runtime.pam; do
    trust_source "$STAGE/$f"
done

# B2A-C-R1-04: the Brain's address MUST stay empty. Check it BEFORE any mutation, so the
# refusal leaves the system entirely unchanged (fail-closed), not partially installed.
if [ -e /usr/libexec/delphi-ai ]; then
    echo "REFUSING (no system change made): /usr/libexec/delphi-ai exists but must stay EMPTY"
    echo "  (no real Brain yet — a stub at the real address is the lie this refuses)."
    echo "  Remove it by hand if it is stale: rm /usr/libexec/delphi-ai"
    exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════════════
# MUTATE — only reached when every pre-flight check above passed.
# ══════════════════════════════════════════════════════════════════════════════════════
install -d -m 0755 /usr/libexec
install -o root -g root -m 0755 "$STAGE/delphi-runtimed"    /usr/libexec/delphi-runtimed
install -o root -g root -m 0755 "$STAGE/delphi-shell"       /usr/libexec/delphi-shell
install -o root -g root -m 0755 "$STAGE/delphi-minimal-ai"  /usr/libexec/delphi-minimal-ai

install -d -m 0755 /usr/lib/systemd/system
install -o root -g root -m 0644 "$STAGE/delphi-runtimed@.service" \
    /usr/lib/systemd/system/delphi-runtimed@.service
install -o root -g root -m 0644 "$STAGE/delphi-runtime.pam" /etc/pam.d/delphi-runtime

systemctl daemon-reload

echo "installed:"
ls -l /usr/libexec/delphi-runtimed /usr/libexec/delphi-shell /usr/libexec/delphi-minimal-ai
echo "Brain address intentionally absent: $(ls /usr/libexec/delphi-ai 2>&1)"
echo "PAM stack: $(ls -l /etc/pam.d/delphi-runtime)"
