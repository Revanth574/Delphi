#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Capture the launch context of `delphi-shell` so two shells that DISAGREE about whether the
# host survives can be diffed instead of guessed about.
#
# WHY. The GTK icon-loader abort (gtkiconhelper.c:495, via glycin) reproduces 3/3 from the
# operator's interactive terminal and 0/24 from the agent's tool shell — same box, same binary,
# same bundle, and the obvious environment variables (DBUS_SESSION_BUS_ADDRESS, XDG_DATA_DIRS,
# XDG_CURRENT_DESKTOP, GDK_BACKEND, GTK_MODULES, session bus reachability, icon-theme=Yaru) all
# MATCH. So the difference is something not yet looked at, and the way to find it is a diff of
# the full context, not another hypothesis.
#
#   bash scratch/capture-shell-context.sh > /tmp/ctx-<where>.txt
#
# Run it from EACH shell that disagrees, then diff the two files.
set -u

echo "=== identity ==="
echo "date:        $(date -Is)"
echo "whoami:      $(id)"
echo "tty:         $(tty 2>/dev/null || echo '<not a tty>')"
echo "ppid chain:  $(ps -o pid=,ppid=,comm= -p $$ 2>/dev/null); parent: $(ps -o comm= -p $PPID 2>/dev/null)"
echo "cgroup:      $(cat /proc/self/cgroup 2>/dev/null | head -3)"
echo "logind sess: $(loginctl --no-legend list-sessions 2>/dev/null | head -5)"
echo "my session:  $(cat /proc/self/cgroup 2>/dev/null | grep -o 'session-[0-9]*\.scope' | head -1)"

echo
echo "=== full environment (sorted; the diff target) ==="
env | LC_ALL=C sort

echo
echo "=== ★ PRIME SUSPECT: AppArmor confinement + unprivileged userns ★ ==="
# Ubuntu 24.04+ gates unprivileged user namespaces behind AppArmor
# (kernel.apparmor_restrict_unprivileged_userns=1). glycin runs its image loader under
# `bwrap`, which REQUIRES a userns. A shell whose AppArmor profile forbids userns creation
# therefore cannot load ANY themed icon through GTK3-on-Ubuntu-26.04 — the loader exits 1,
# and gtkiconhelper.c:495 asserts instead of degrading. This is the leading explanation for
# why the abort reproduces from one shell and not another with IDENTICAL env vars.
echo "apparmor profile:  $(cat /proc/self/attr/current 2>/dev/null || echo '<none>')"
echo "restrict_userns:   $(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo '<unset>')"
printf "unshare -r:        "; unshare -r true 2>&1 && echo "OK (userns permitted)" || echo "DENIED (userns blocked)"

echo
echo "=== ★ THE DECISIVE TEST: glycin's own bwrap invocation ★ ==="
# Verbatim from the journal's abort message, minus --seccomp/--dbus-fd which need live fds.
# Expected when userns is PERMITTED: the loader starts and complains it has no --dbus-fd
#   'FD that facilitates the D-Bus connection not specified via --dbus-fd'  (exit 2)
# Expected when userns is BLOCKED: bwrap fails to create the namespace (exit 1) — which is
# exactly the "Loader process exited early with status '1'" GTK reported.
timeout 30 bwrap --unshare-all --die-with-parent --chdir / --ro-bind /usr /usr --dev /dev \
  --ro-bind-try /etc/ld.so.cache /etc/ld.so.cache --ro-bind-try /nix/store /nix/store \
  --tmpfs /tmp-home --tmpfs /tmp-run --clearenv --setenv HOME /tmp-home \
  --setenv XDG_RUNTIME_DIR /tmp-run --setenv XDG_RUNTIME_DIR /run/user/1000 \
  --symlink /usr/lib /lib --symlink /usr/lib64 /lib64 \
  -- /usr/libexec/glycin-loaders/2+/glycin-image-rs --help 2>&1 | head -3
echo "bwrap+loader exit: ${PIPESTATUS[0]}   (2 = userns OK / 1 = the failure GTK saw)"

echo
echo "=== process limits (glycin sets a loader memory limit) ==="
cat /proc/self/limits 2>/dev/null

echo
echo "=== seccomp / no_new_privs on THIS shell (glycin's loader installs its own filter) ==="
grep -E "Seccomp|NoNewPrivs" /proc/self/status 2>/dev/null

echo
echo "=== memory at capture time ==="
free -m 2>/dev/null | head -2
grep -E "^(MemAvailable|MemFree)" /proc/meminfo 2>/dev/null

echo
echo "=== glycin loader processes currently alive ==="
pgrep -af glycin 2>/dev/null | head -5 || echo "(none)"

echo
echo "=== user bus reachable? ==="
gsettings get org.gnome.desktop.interface icon-theme 2>&1 | head -1

echo
echo "=== does a bare themed-icon load survive HERE? (the exact failing path) ==="
python3 - <<'PY' 2>&1 | tail -4
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk, Gio
Gtk.init([])
try:
    pb = Gtk.IconTheme.get_default().load_icon("image-missing", 16, 0)
    print(f"load_icon('image-missing'): OK {pb.get_width()}x{pb.get_height()}")
except Exception as e:
    print(f"load_icon('image-missing'): ERR {type(e).__name__}: {e}")
img = Gtk.Image.new_from_gicon(Gio.ThemedIcon.new("image-missing"), Gtk.IconSize.DIALOG)
win = Gtk.OffscreenWindow(); win.add(img); win.show_all()
while Gtk.events_pending():
    Gtk.main_iteration()
print("gicon render: survived")
PY
