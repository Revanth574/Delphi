#!/bin/sh
# SPDX-License-Identifier: MIT
#
# D1 go/no-go probe — answers Q2: does this lane present a DRM device with a
# MODESETTABLE CRTC, or is it a framebuffer-only virtual GPU?
#
# WHY THIS IS A GO/NO-GO AND NOT A CHECKLIST
# ------------------------------------------
# D1 (session + device acquisition) is the feasibility probe for the WHOLE display arc.
# If libseat cannot take the seat, or no DRM device with a connected, modesettable
# connector exists, then D2 (modeset) cannot prove its Tier-2 claim here and the arc
# needs a different lane — that is "the approach needs rethinking on this lane", NOT
# "D1 needs more work". Read a FAIL below as information about the lane.
#
# Run ON THE SEATED LANE (the Ubuntu 26.04 VM with seat0), as a user in the `video`
# group, from a session on the seat. Root is NOT required for the read-only parts and
# is deliberately not requested: a probe that needs root proves less about what the
# compositor (which runs priv-dropped after taking the seat) will actually be able to do.
#
# Reports FACTS, refuses to conclude. Every line is a measurement or a refusal.

say()  { printf '%s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }
miss() { printf 'ABSENT   %s\n' "$*"; }
have() { printf 'PRESENT  %s\n' "$*"; }

hdr "0. Where am I"
say "uname:   $(uname -srm)"
say "seat:    ${XDG_SEAT:-<unset>}   vtnr: ${XDG_VTNR:-<unset>}   session: ${XDG_SESSION_ID:-<unset>}"
say "groups:  $(id -nG)"
case " $(id -nG) " in
  *" video "*) have "user is in group 'video' (needed to open /dev/dri/* without root)" ;;
  *)           miss "user is NOT in group 'video' — device opens may EACCES; add and re-login" ;;
esac

hdr "1. Seat — is it graphical? (the libseat/logind precondition)"
if command -v loginctl >/dev/null 2>&1; then
    loginctl show-seat "${XDG_SEAT:-seat0}" -p Id -p CanGraphical -p ActiveSession 2>&1
    say "--- sessions on this seat ---"
    loginctl list-sessions 2>&1 | head -10
else
    miss "loginctl — cannot evaluate the seat; this lane is not systemd-logind managed"
fi

hdr "2. DRM devices — do any exist at all?"
if [ -d /dev/dri ]; then
    ls -l /dev/dri/ 2>&1
    # card* = the KMS/modeset node the compositor needs. renderD* = render-only,
    # NO modesetting — a lane with only renderD* CANNOT drive a display.
    cards=$(ls /dev/dri/card* 2>/dev/null | wc -l)
    say "modeset-capable nodes (card*): $cards"
    [ "$cards" -eq 0 ] && miss "no card* node — RENDER-ONLY or no DRM. D2 cannot modeset here."
else
    miss "/dev/dri does not exist — no DRM at all. This is a HARD no-go for D1/D2 on this lane."
fi

hdr "3. Which driver is bound (the vboxvideo question)"
for d in /sys/class/drm/card*; do
    [ -e "$d" ] || continue
    drv=$(readlink -f "$d/device/driver" 2>/dev/null | xargs -r basename)
    say "$(basename "$d"): driver=${drv:-<none>}"
done
say "--- kernel modules of interest ---"
lsmod 2>/dev/null | grep -E '^(vboxvideo|virtio_gpu|vmwgfx|qxl|i915|amdgpu|nouveau|simpledrm)' \
    || miss "none of the expected DRM drivers are loaded"
# simpledrm is the trap: it binds the EFI/VESA framebuffer and presents a card* node
# with a FIXED mode. It can scan out, but it cannot mode-SET, so a D2 claim proven
# against it would not transfer to real hardware.
lsmod 2>/dev/null | grep -q '^simpledrm' \
    && say "!! simpledrm is loaded — a FIXED-mode framebuffer shim. If the card* node above is
   simpledrm's, D2's modeset claim is NOT provable on this lane even though a display appears."

hdr "4. Connectors — is anything actually connected, with modes?"
found_mode=0
for c in /sys/class/drm/card*-*; do
    [ -e "$c/status" ] || continue
    st=$(cat "$c/status" 2>/dev/null)
    en=$(cat "$c/enabled" 2>/dev/null)
    nmodes=$(grep -c . "$c/modes" 2>/dev/null || echo 0)
    printf '%-28s status=%-12s enabled=%-8s modes=%s\n' "$(basename "$c")" "$st" "$en" "$nmodes"
    if [ "$st" = "connected" ] && [ "$nmodes" -gt 0 ]; then
        found_mode=1
        say "    first modes: $(head -3 "$c/modes" 2>/dev/null | tr '\n' ' ')"
    fi
done
[ "$found_mode" -eq 0 ] && miss "NO connected connector reporting modes — D2 has nothing to light up"

hdr "5. Build prerequisites for the smithay DRM backend"
# These are the headers the ALREADY-ENABLED workspace features need. The dev box was
# missing all five, which is why `cargo check -p compositor` fails there.
for p in libdrm libseat libinput libudev gbm egl wayland-server xkbcommon; do
    if pkg-config --exists "$p" 2>/dev/null; then
        have "$p $(pkg-config --modversion "$p" 2>/dev/null)"
    else
        miss "$p  (apt: libdrm-dev libseat-dev libinput-dev libudev-dev libgbm-dev)"
    fi
done

hdr "VERDICT INPUTS (the operator decides; this script does not)"
say "GO for D1 requires:   a graphical seat + at least one card* node."
say "GO for D2 requires:   additionally a CONNECTED connector with >0 modes, on a driver"
say "                      that is NOT simpledrm."
say "If D2's inputs fail but D1's hold, the arc can still start — D2 then needs a"
say "different lane, and that is a lane fact, not a D2 defect."
