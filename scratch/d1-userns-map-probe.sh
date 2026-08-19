#!/bin/bash
# SPDX-License-Identifier: MIT
#
# D0A-R9-01, third measurement — two questions E left open.
#
# F: can we keep the user namespace AND get a real outside identity?
#    E forced a choice only because bwrap's OWN userns maps sandbox_uid -> parent_uid
#    (leg A: INNER 0 / SO_PEERCRED 0 — identity-transparent). But bwrap accepts an
#    EXTERNALLY PREPARED userns (`--userns FD`, and `--uid` explicitly permits it,
#    bubblewrap 0.11.1). A root parent can write a map of inner 0 -> outer <tool>, so
#    bwrap holds full caps INSIDE for its setup while an outside observer sees the tool
#    uid. If F works it DOMINATES E and no §6 trade needs making at all.
#
# P: production's socket is a PATHNAME socket under /run/delphi/<session>, reached
#    through a bind mount. E died three times on traversal (measured cause: bwrap
#    creates the jail's /tmp as mode 0700 root). The session dir is 0711 root-owned —
#    chosen when the tool was root and modes were irrelevant. P walks the PRODUCTION
#    path shape as the tool uid and reports the first component that blocks.
#
#   sudo ./scratch/d1-userns-map-probe.sh [F|P]
set -u

TOOL=${TOOL:-delphi-tool}
[ "$(id -u)" = 0 ] || { echo "REFUSING: needs root"; exit 1; }
TUID=$(id -u "$TOOL" 2>/dev/null) || { echo "REFUSING: no such account $TOOL"; exit 1; }
TGID=$(id -g "$TOOL")
ONLY=${1:-}
RAN=0
echo "tool=$TOOL uid=$TUID gid=$TGID"; echo

# ── F ────────────────────────────────────────────────────────────────────────
if [ "$ONLY" = F ] || [ -z "$ONLY" ]; then
  RAN=$((RAN + 1))
  echo "── F: bwrap in an externally-mapped userns (inner 0 -> outer $TUID)"

  # A process that unshares a userns and waits. Root then writes its map: the whole
  # point is that the map is OURS, not bwrap's parent_uid default.
  python3 -c '
import ctypes, os, sys, time
libc = ctypes.CDLL("libc.so.6", use_errno=True)
if libc.unshare(0x10000000) != 0:          # CLONE_NEWUSER
    print("  HOLDER: unshare(CLONE_NEWUSER) failed: %s" % os.strerror(ctypes.get_errno()), flush=True)
    sys.exit(2)
open("/tmp/.d1-f-holder", "w").write(str(os.getpid()))
time.sleep(30)
' & HOLDER=$!
  for _ in $(seq 1 40); do [ -s /tmp/.d1-f-holder ] && break; sleep 0.1; done
  HPID=$(cat /tmp/.d1-f-holder 2>/dev/null); rm -f /tmp/.d1-f-holder
  if [ -z "${HPID:-}" ]; then echo "  holder never came up"; kill $HOLDER 2>/dev/null; exit 1; fi

  # inner 0 -> outer TOOL. Root may write an arbitrary map; that is the mechanism.
  echo "deny" > "/proc/$HPID/setgroups" 2>/dev/null || true
  if ! echo "0 $TUID 1" > "/proc/$HPID/uid_map" 2>/dev/null; then
      echo "  FAILED writing uid_map"; kill $HOLDER 2>/dev/null; exit 1; fi
  if ! echo "0 $TGID 1" > "/proc/$HPID/gid_map" 2>/dev/null; then
      echo "  FAILED writing gid_map"; kill $HOLDER 2>/dev/null; exit 1; fi
  echo "  holder pid=$HPID  uid_map='$(cat /proc/$HPID/uid_map)'"

  python3 - "$TUID" <<'FPY' & LP=$!
import socket, struct, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind("\0delphi-d1-f"); s.listen(1); s.settimeout(20)
open("/tmp/.d1-f-ready", "w").close()
try:
    c, _ = s.accept()
    _, u, g = struct.unpack("3i", c.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    print(f"  SO_PEERCRED uid={u} gid={g}   <-- outside observer", flush=True)
except socket.timeout:
    print("  SO_PEERCRED: (no peer connected)", flush=True)
FPY
  for _ in $(seq 1 40); do [ -e /tmp/.d1-f-ready ] && break; sleep 0.1; done
  rm -f /tmp/.d1-f-ready

  # NOTE: netns is NOT unshared here, for the same reason as E2 — an abstract socket is
  # the only observation channel with no traversal, and abstract names are netns-scoped.
  # Whether the jail BUILDS with --unshare-net in this userns is the second line below.
  # `--userns FD` is an fd NUMBER, not a path — passing the path made bwrap reject the
  # ARGUMENT ("Invalid fd"), so the mapping was never exercised. Explicitly numbered bash
  # fds are inherited across exec (verified), unlike `{var}<` which bash marks CLOEXEC.
  exec 9< "/proc/$HPID/ns/user" || { echo "  cannot open the holder's userns"; kill $HOLDER; exit 1; }
  bwrap --userns 9 --uid 0 --gid 0 \
    --unshare-ipc --unshare-pid --unshare-uts --die-with-parent --new-session \
    --clearenv --proc /proc --dev /dev --ro-bind /usr /usr \
    --symlink usr/lib /lib --symlink usr/lib64 /lib64 --symlink usr/bin /bin \
    --symlink usr/sbin /sbin --chdir / -- \
    /usr/bin/python3 -c '
import os, socket, sys
print("  INNER id: %d:%d  (0 here means the MAPPED root, not host root)" % (os.getuid(), os.getgid()), flush=True)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect("\0delphi-d1-f"); s.send(b"x")
    import time; time.sleep(1)
except OSError as e:
    print("  PAYLOAD could not connect: %s" % e, flush=True); sys.exit(4)
' 2>&1 | sed 's/^/  /'
  echo "  CHAIN rc=${PIPESTATUS[0]}"
  wait $LP 2>/dev/null

  echo "  --- does the SAME userns still build a netns (the leg-C failure)? ---"
  bwrap --userns 9 --uid 0 --gid 0 --unshare-net --unshare-ipc \
    --die-with-parent --clearenv --proc /proc --ro-bind /usr /usr \
    --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
    --chdir / -- /usr/bin/true 2>&1 | sed 's/^/  /'
  echo "  NETNS rc=${PIPESTATUS[0]}   (0 = loopback came up; the E trade may be unnecessary)"
  exec 9<&-
  kill $HOLDER 2>/dev/null; wait $HOLDER 2>/dev/null
  echo
fi

# ── P ────────────────────────────────────────────────────────────────────────
if [ "$ONLY" = P ] || [ -z "$ONLY" ]; then
  RAN=$((RAN + 1))
  echo "── P: can the tool uid traverse the PRODUCTION socket path?"
  # anchor.rs: base 0755, session dir 0711, socket 0660 root:<session-gid>.
  BASE=/run/delphi-probe; SESS=$BASE/probeuser
  rm -rf "$BASE"; install -d -m 0755 "$BASE"; install -d -m 0711 "$SESS"
  python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.bind(sys.argv[1]); s.listen(1)
import time; time.sleep(300)
' "$SESS/approve.sock" & PL=$!
  for _ in $(seq 1 40); do [ -S "$SESS/approve.sock" ] && break; sleep 0.1; done
  # PRODUCTION'S GROUP IS THE **SESSION USER'S**, NOT THE TOOL'S.
  # anchor.rs: bind_approval_socket(&dir, session_gid); delphi-runtimed.rs passes
  # `user.gid` where `user` is the SESSION user. The first version of this leg chowned
  # to the TOOL's own gid — the single configuration in which 0660 admits it — and so
  # measured a fixture that differed from its subject (class 25). Use a group the tool
  # is NOT in, which is what production has.
  SESSGRP=delphi-probe-session
  getent group "$SESSGRP" >/dev/null || groupadd --system "$SESSGRP"
  SGID=$(getent group "$SESSGRP" | cut -d: -f3)
  if id -nG "$TOOL" | tr ' ' '\n' | grep -qx "$SESSGRP"; then
      echo "  REFUSING: $TOOL is in $SESSGRP — that is the misconfiguration under test, not the fixture"; exit 1
  fi
  chown root:"$SGID" "$SESS/approve.sock"
  chmod 0660 "$SESS/approve.sock"
  echo "  host modes: $(stat -c '%n %a %U:%G' "$BASE" "$SESS" "$SESS/approve.sock" | tr '\n' ' ')"

  # `--perms 0755 --dir /run` FIRST: bwrap otherwise auto-creates /run as 0700 owned by
  # the sandbox uid (measured), so a dropped payload never reaches the modes under test
  # and P's refusal would be indistinguishable from its success condition.
  run_leg() {   # label  socket-mode  expectation
    echo "  -- $1 (socket mode $2)"
    chmod "$2" "$SESS/approve.sock"
    bwrap --unshare-ipc --unshare-pid --die-with-parent --clearenv --proc /proc \
      --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib \
      --symlink usr/lib64 /lib64 --perms 0755 --dir /run --bind "$BASE" "$BASE" \
      --chdir / -- \
      setpriv --reuid="$TUID" --regid="$TGID" --clear-groups -- \
      /usr/bin/python3 -c '
import os, socket, sys
p = "/"
for part in sys.argv[1].split("/")[1:-1]:
    p = os.path.join(p, part)
    try:
        st = os.stat(p)
        print("    %-26s mode=%o uid=%d X_OK=%s" % (p, st.st_mode & 0o7777, st.st_uid, os.access(p, os.X_OK)), flush=True)
    except OSError as e:
        print("    %-26s UNREACHABLE: %s" % (p, e), flush=True); sys.exit(5)
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.connect(sys.argv[1]); print("    CONNECTED", flush=True)
except OSError as e:
    print("    REFUSED: %s" % e, flush=True)
' "$SESS/approve.sock" 2>&1 | sed 's/^/  /'
  }
  # POSITIVE CONTROL FIRST. Without it a refusal caused by traversal is indistinguishable
  # from a refusal caused by the mode — which is exactly how this leg failed before.
  run_leg "POSITIVE CONTROL: must CONNECT, or the refusal below proves nothing" 0666
  run_leg "THE REAL TEST: production shape, root:$SESSGRP 0660 — must be REFUSED" 0660
  # The CONDITIONAL. The mode excludes the tool only while the tool is outside the
  # socket's group. Re-owning to the tool's group is what the FIRST run of this leg
  # accidentally measured, and it is also what the naive R9-01 fix (drop to the SESSION
  # uid) would have produced. Documented as a real misconfiguration, not a pass.
  chown root:"$TGID" "$SESS/approve.sock"
  run_leg "MISCONFIGURATION: socket group == the TOOL's group — expected to CONNECT" 0660
  chown root:"$SGID" "$SESS/approve.sock"
  kill $PL 2>/dev/null; wait $PL 2>/dev/null; rm -rf "$BASE"
  echo
fi

[ "$RAN" -gt 0 ] || { echo "REFUSING: leg '$ONLY' matched nothing (legs are F, P)"; exit 1; }
echo "F: if SO_PEERCRED reports $TUID *and* NETNS rc=0, the userns is kept AND the"
echo "   identity is real — E's trade is unnecessary and §6 needs no change."
echo "P: a REFUSED connect is the DESIRED result — the tool must not reach the socket."
echo "   A CONNECTED one means the 0711/0660 modes do not hold against uid $TUID."
