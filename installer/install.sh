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
for b in delphi-runtimed delphi-shell delphi-minimal-ai; do
    [ -f "$STAGE/$b" ] || { echo "MISSING $STAGE/$b — run installer/build.sh (UNPRIVILEGED) first"; exit 1; }
done

install -d -m 0755 /usr/libexec
install -o root -g root -m 0755 "$STAGE/delphi-runtimed"    /usr/libexec/delphi-runtimed
install -o root -g root -m 0755 "$STAGE/delphi-shell"       /usr/libexec/delphi-shell
install -o root -g root -m 0755 "$STAGE/delphi-minimal-ai"  /usr/libexec/delphi-minimal-ai

# The Brain's address stays empty ON PURPOSE (see header). Refuse to proceed if some
# earlier run left a binary there — a stub at the real address is exactly the lie refused.
if [ -e /usr/libexec/delphi-ai ]; then
    echo "REFUSING: /usr/libexec/delphi-ai exists but must stay EMPTY (no real Brain yet)."
    echo "Remove it by hand if it is stale: rm /usr/libexec/delphi-ai"
    exit 1
fi

install -d -m 0755 /usr/lib/systemd/system
install -o root -g root -m 0644 runtime/systemd/delphi-runtimed@.service \
    /usr/lib/systemd/system/delphi-runtimed@.service
install -o root -g root -m 0644 installer/pam/delphi-runtime /etc/pam.d/delphi-runtime

systemctl daemon-reload

echo "installed:"
ls -l /usr/libexec/delphi-runtimed /usr/libexec/delphi-shell /usr/libexec/delphi-minimal-ai
echo "Brain address intentionally absent: $(ls /usr/libexec/delphi-ai 2>&1)"
echo "PAM stack: $(ls -l /etc/pam.d/delphi-runtime)"
