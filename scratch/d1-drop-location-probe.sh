#!/bin/bash
# SPDX-License-Identifier: MIT
#
# D0A-R9-01, second measurement — WHERE can the credential change happen?
#
# The pre_exec drop broke the sandbox: bwrap starts already dropped and fails with
#   bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
# But an all-along-unprivileged bwrap with the SAME profile succeeds (measured
# 2026-08-13, leg A: rc=0). So "dropped bwrap cannot set up namespaces" is not yet
# established — setuid-from-root may differ from never-having-been-root, and which it
# is decides whether the fix is small or changes the ratified profile.
#
# Each leg reports TWO facts, and both matter: did bwrap SET UP, and what uid does an
# outside listener actually READ. A leg that sandboxes but reports uid 0 is useless;
# so is one that reports the tool uid but cannot build the jail.
#
#   sudo ./scratch/d1-drop-location-probe.sh
set -u

TOOL=${TOOL:-delphi-tool}
[ "$(id -u)" = 0 ] || { echo "REFUSING: needs root (measuring a drop FROM root)"; exit 1; }
command -v setpriv >/dev/null || { echo "REFUSING: setpriv absent (util-linux)"; exit 1; }
TUID=$(id -u "$TOOL" 2>/dev/null) || { echo "REFUSING: no such account $TOOL"; exit 1; }
TGID=$(id -g "$TOOL")
echo "tool=$TOOL uid=$TUID gid=$TGID"

DIR=$(mktemp -d); trap 'rm -rf "$DIR"' EXIT
chmod 0777 "$DIR"   # traversable by the dropped uid
SOCK=$DIR/probe.sock

cat >"$DIR/listen.py" <<'PY'
import os, socket, struct, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1]); s.listen(1); s.settimeout(15)
open(sys.argv[1] + ".ready", "w").close()
try:
    c, _ = s.accept()
except socket.timeout:
    print("  SO_PEERCRED: (no peer connected)", flush=True); sys.exit(3)
pid, uid, gid = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
print(f"  SO_PEERCRED uid={uid} gid={gid}", flush=True)
PY

# The payload is passed INLINE (`python3 -c`), never as a file. A dropped uid that must
# first OPEN a script adds a failure mode that has nothing to do with what is measured —
# it is what made leg E inconclusive on the first run.
PAYLOAD='
import os, socket, sys, time
print("  INNER id: %d:%d" % (os.getuid(), os.getgid()), flush=True)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print("  PAYLOAD could not connect: %s" % e, flush=True); sys.exit(4)
s.send(b"x"); time.sleep(1)
'


# The profile under test — sandbox.rs:118-130 verbatim, plus an interpreter.
BASE=(--die-with-parent --new-session --clearenv --proc /proc --dev /dev
      --ro-bind /usr /usr --symlink usr/lib /lib --symlink usr/lib64 /lib64
      --symlink usr/bin /bin --symlink usr/sbin /sbin --bind "$DIR" "$DIR" --chdir /)

ONLY=${1:-}
RAN=0
leg() {
  case "$ONLY" in "") ;; "${1%%:*}") ;; *) return 0 ;; esac
  RAN=$((RAN + 1))
  echo "── $1"; shift
  rm -f "$SOCK" "$SOCK.ready"
  python3 "$DIR/listen.py" "$SOCK" & local lp=$!
  for _ in $(seq 1 40); do [ -e "$SOCK.ready" ] && break; sleep 0.1; done
  # World-accessible so a dropped uid can reach it; this is a probe, not production.
  chmod 0666 "$SOCK" 2>/dev/null || true
  "$@" 2>&1 | sed 's/^/  /'
  echo "  BWRAP/CHAIN rc=${PIPESTATUS[0]}"
  wait $lp 2>/dev/null
  echo
}

# C — REPRODUCE. Drop BEFORE bwrap, exactly as pre_exec does today.
leg "C: drop THEN bwrap (today's pre_exec shape) — expect the RTM_NEWADDR failure" \
  setpriv --reuid="$TUID" --regid="$TGID" --clear-groups -- \
  bwrap --unshare-all "${BASE[@]}" -- /usr/bin/python3 -c "$PAYLOAD" "$SOCK"

# D — bwrap keeps root and builds the jail; the PAYLOAD drops inside it. If bwrap made
# a userns, only one uid is mapped and this setpriv should fail (EINVAL) — that is the
# result that would force the profile change.
leg "D: bwrap as root --unshare-all, payload drops INSIDE the userns" \
  bwrap --unshare-all "${BASE[@]}" -- \
  setpriv --reuid="$TUID" --regid="$TGID" --clear-groups -- /usr/bin/python3 -c "$PAYLOAD" "$SOCK"

# E — same, but NO user namespace (root does not need one for the other namespaces), so
# the payload can setuid to a REAL host uid. Costs the userns; buys a real credential.
leg "E: bwrap as root, every namespace EXCEPT user, payload drops to the real uid" \
  bwrap --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup-try --unshare-net \
  "${BASE[@]}" -- \
  setpriv --reuid="$TUID" --regid="$TGID" --clear-groups -- /usr/bin/python3 -c "$PAYLOAD" "$SOCK"

# A mistyped leg name must not look like a clean run: no output and exit 0 is the
# silent-no-op shape this project treats as a false green.
[ "$RAN" -gt 0 ] || { echo "REFUSING: leg '$ONLY' matched nothing (legs are C, D, E)"; exit 1; }

echo "READ IT AS: the fix is the first leg that BOTH built the jail (rc=0) AND reported"
echo "SO_PEERCRED uid=$TUID. Leg C failing reproduces today; D failing at setpriv means"
echo "the userns blocks any in-jail drop; E is the profile-changing fallback."
