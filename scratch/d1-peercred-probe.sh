#!/bin/bash
# SPDX-License-Identifier: MIT
#
# D1 measurement 1+2 — what SO_PEERCRED triple does the daemon's listener actually
# read from a peer inside the jail, and what is the uid map that sets it?
#
# Measured AT THE SOCKET, never inferred from the bwrap invocation, because the
# invocation is exactly what the inference would have to interpret. The listener
# prints what it read; nothing here computes what it "should" be.
#
# Run BOTH ways — the root leg is the one that decides the keystone, because the
# daemon is root:
#     ./scratch/d1-peercred-probe.sh          # unprivileged
#     sudo ./scratch/d1-peercred-probe.sh     # the production uid
set -u

DIR=$(mktemp -d) || exit 2
trap 'rm -rf "$DIR"' EXIT
SOCK=$DIR/probe.sock

cat >"$DIR/listen.py" <<'PY'
import os, socket, struct, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1]); s.listen(1)
s.settimeout(20)
print(f"LISTENER outer_uid={os.getuid()} pid={os.getpid()}", flush=True)
open(sys.argv[1] + ".ready", "w").close()
try:
    c, _ = s.accept()
except socket.timeout:
    print("LISTENER TIMEOUT: no peer connected", flush=True); sys.exit(3)
cred = c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
pid, uid, gid = struct.unpack("3i", cred)
print(f"SO_PEERCRED pid={pid} uid={uid} gid={gid}", flush=True)
PY

cat >"$DIR/peer.py" <<'PY'
import os, socket, sys
print("INNER uid=%d euid=%d" % (os.getuid(), os.geteuid()), flush=True)
print("INNER uid_map: %s" % open("/proc/self/uid_map").read().strip(), flush=True)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(sys.argv[1])
print("INNER connected", flush=True)
s.send(b"x"); import time; time.sleep(1)
PY

# Leg A measures TODAY. Leg B measures THE PROPOSED FIX, and is the one that decides
# the design: bwrap's `--uid` sets the id INSIDE the namespace, which is not obviously
# the id an outside listener reads. If leg B's SO_PEERCRED still reports the launcher,
# then `--uid` does not implement R9-01 and a real credential drop is required.
leg() {
  local name=$1; shift
  echo "── LEG $name ─────────────────────────────────────────"
  rm -f "$SOCK" "$SOCK.ready"
  python3 "$DIR/listen.py" "$SOCK" &
  local lpid=$!
  for _ in $(seq 1 40); do [ -e "$SOCK.ready" ] && break; sleep 0.1; done
  # THE PRODUCT'S OWN PROFILE (runtime/src/sandbox.rs:45-56) verbatim, plus only what
  # is needed to have an interpreter inside; the base is the thing under test.
  bwrap \
    --unshare-all --die-with-parent --new-session --clearenv \
    --proc /proc --dev /dev \
    --ro-bind /usr /usr \
    --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
    --symlink usr/bin /bin --symlink usr/sbin /sbin \
    --bind "$DIR" "$DIR" \
    --chdir / \
    "$@" \
    -- /usr/bin/python3 "$DIR/peer.py" "$SOCK"
  echo "BWRAP rc=$?"
  wait $lpid
  echo "LISTENER rc=$?"
}

echo "OUTER uid=$(id -u)"
leg "A — the profile as it ships (no --uid)"
# 65534 stands in for a DEDICATED SERVICE UID: not root, and not the session uid.
leg "B — the proposed fix shape (--uid 65534 --gid 65534)" --uid 65534 --gid 65534
