#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""
P3a-1 — the HOST-SIDE composition proof, unprivileged and interactive.

WHAT THIS IS FOR. The daemon-driven run (P3a-2) denies at the gate within milliseconds, so
the consent dialog appears and dismisses faster than a human can see it — the preview render
would be unobservable. This probe stands in for the daemon: it speaks the real private-channel
protocol to the REAL installed host binary and then simply DOES NOT CLOSE the channel, so the
dialog persists and can actually be looked at.

It is NOT a substitute for the daemon run and proves nothing about the daemon, the gate, PAM,
or execution. It isolates exactly one question the daemon run cannot answer legibly:

    does the composed shell — real WebKit, real bundle, P2's mounted dialog — receive the
    host's injections and render the preview?

WIRE (runtime/src/service.rs:252-256, runtime/src/pam.rs:53 — SOCK_SEQPACKET, one message
per datagram):
    daemon -> shell   approval request   [digest:32][preview utf8]
    daemon -> shell   PAM prompt         [prompt utf8]              (raw, no prefix)
    shell  -> daemon  password response  [password utf8]            (raw, no prefix)
    shell  -> daemon  mint confirm       [digest:32]

TWO MACHINE-CHECKABLE OUTCOMES, either of which proves the full native->renderer->native
round trip under real rendering (not jsdom):

    Cancel  -> the host calls process::exit(0)  (shell-host/src/main.rs:144)
               => observed here as a clean child exit with status 0.
    Allow   -> the renderer posts the password over window.ipc, the host relays it as a
               datagram => observed here as N bytes arriving.

⚠ THIS PROBE RENDERS THE REAL CONSENT DIALOG — A REAL-LOOKING PASSWORD FIELD.
   A WARNING IS NOT AN ENFORCEMENT MECHANISM (docs/DEFECT_CLASSES.md class 21). This text
   did NOT stop a real password being entered the first time this probe was run, because the
   dialog is indistinguishable from the production one — which is exactly what it is proving.
   So the probe does not rely on you reading this:

     * BY DEFAULT THE PROBE DOES NOT SEND THE PAM PROMPT. The dialog's Approve button is
       `disabled={submitted || !prompt}` (shell/src/consent/pam-consent-dialog.tsx), so
       without a prompt the credential path is UNREACHABLE — not discouraged, unreachable.
       Cancel still proves the full renderer->native round trip.
     * Exercising the password leg requires an explicit opt-in:
       DELPHI_PROBE_SEND_PROMPT=1, which prints the residual before it does anything.

   RESIDUAL, stated up front rather than after the fact: if you defeat the prefill and type a
   real secret, it enters this process's memory and crosses a socket. It is never written
   anywhere — only `len(data)` is reported, never the bytes — but memory + socket is still a
   rotation-worthy event. Rotate if you do it.
"""

import os
import socket
import subprocess
import sys
import time

# The installed host by default. `DELPHI_HOST_BIN` lets a dev point at a freshly-built
# binary before installing — useful precisely when the installed one is known stale.
HOST_BIN = os.environ.get("DELPHI_HOST_BIN", "/usr/libexec/delphi-shell")
# A representative action preview. Deliberately literal so what is on screen is legible and
# obviously matches what was "requested" — the same property the real consent preview needs.
PREVIEW = "touch /tmp/delphi-p3-marker"
# Sent ONLY under DELPHI_PROBE_SEND_PROMPT=1. Names itself so the field is never mistaken
# for a production prompt — though per class 21 the LABEL is not what protects anyone; the
# default of not sending it at all is.
PROMPT = "[TEST PROBE — do NOT enter a real password] "
TIMEOUT_SECS = 300


def main() -> int:
    if not os.path.exists(HOST_BIN):
        print(f"REFUSE: {HOST_BIN} not installed — run: sudo bash installer/install.sh")
        return 1
    # The bundle the host will serve. Reported so a blank window is never a mystery about
    # WHICH bytes were on screen — the host also logs a per-asset sha256 audit line at startup.
    root = os.environ.get("DELPHI_BUNDLE_ROOT", "/usr/share/delphi/shell")
    print(f"bundle root: {root}")
    if not os.path.exists(os.path.join(root, "index.html")):
        print(f"REFUSE: {root}/index.html missing — the host will refuse to start (fail-closed).")
        return 1
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        print("REFUSE: no DISPLAY/WAYLAND_DISPLAY. This probe must run INSIDE the graphical")
        print("        session. On a bare VT the host panics at GTK init (exit 101) — that")
        print("        is the measured horn-1 result, not something this probe can work around.")
        return 1

    daemon_end, shell_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)

    # The host reads DELPHI_CHANNEL_FD to find its channel; pass the real fd number rather
    # than forcing a dup to 3.
    child_fd = shell_end.fileno()
    os.set_inheritable(child_fd, True)
    env = dict(os.environ, DELPHI_CHANNEL_FD=str(child_fd))

    print(f"launching {HOST_BIN} (channel fd {child_fd})")
    proc = subprocess.Popen([HOST_BIN], env=env, pass_fds=(child_fd,))
    shell_end.close()  # the child owns its end now

    # Give WebKit time to start and load delphi://shell/index.html (served from the host's
    # startup snapshot). A blank page would happen here — silently — if the bundle were stale
    # or its asset URLs absolute, which is why the pre-flight checks both.
    time.sleep(3)
    if proc.poll() is not None:
        print(f"FAIL: host exited early with status {proc.returncode}")
        print("      status 101 = Rust panic; check for 'Failed to initialize gtk backend!'")
        return 1

    digest = bytes(32)  # not verified by this probe — no minting happens here
    daemon_end.send(digest + PREVIEW.encode())
    print(f"sent approval request  preview={PREVIEW!r}")
    time.sleep(1)
    send_prompt = os.environ.get("DELPHI_PROBE_SEND_PROMPT") == "1"
    if send_prompt:
        print()
        print("!" * 78)
        print("DELPHI_PROBE_SEND_PROMPT=1 — enabling the password field.")
        print("Anything you type enters this process's memory and crosses a socket. It is")
        print("NEVER written anywhere (only its length is reported), but that is still")
        print("rotation-worthy. Use a throwaway value.")
        print("!" * 78)
        daemon_end.send(PROMPT.encode())
        print(f"sent PAM prompt        prompt={PROMPT!r}")
    else:
        print("PAM prompt NOT sent (default) — Approve stays disabled, so the credential")
        print("path is unreachable. Set DELPHI_PROBE_SEND_PROMPT=1 to exercise it.")

    print()
    print("=" * 78)
    print("LOOK AT THE SCREEN. The Delphi shell should be rendered, with the consent dialog")
    if send_prompt:
        print("showing the preview above and a password field labelled with the prompt.")
    else:
        print("showing the preview above. The password field is present but Approve is")
        print("disabled — no prompt was sent.")
    print()
    print("  Click CANCEL -> proves the round trip; the host exits 0.")
    if send_prompt:
        print("  Or type a THROWAWAY value and click APPROVE -> also proves it.")
        print("     (Nothing authenticates it; only its length is ever reported.)")
    else:
        print("  APPROVE is disabled by design — no prompt was sent, so no credential can")
        print("  be submitted at all. Cancel is the whole proof.")
    print("=" * 78)
    print()

    # ── CLASSIFY EXACTLY ONE OUTCOME ─────────────────────────────────────────────────
    # Cancel and Approve are DIFFERENT VALID outcomes, and an earlier version ran both
    # checks unconditionally — so a Cancel run printed "round trip OK" AND "no round trip
    # observed" in the same output. A report that states two contradictory things forces the
    # reader to adjudicate, which is exactly the job the report exists to do.
    #
    #   Approve -> the renderer posts the password; bytes arrive on the channel.
    #   Cancel  -> the host calls process::exit(0); no bytes ever arrive.
    #
    # Both prove the same underlying property (native -> renderer -> native under real
    # WebKit). Report whichever ACTUALLY happened, once.
    daemon_end.settimeout(TIMEOUT_SECS)
    received = None          # Some(n) only if bytes actually arrived
    channel_note = None      # why nothing arrived, when nothing did
    try:
        data = daemon_end.recv(4096)
        if data:
            received = len(data)          # LENGTH ONLY — never the content. See the header.
        else:
            channel_note = "channel EOF — the host closed its end"
    except socket.timeout:
        channel_note = f"no message within {TIMEOUT_SECS}s"
    except ConnectionResetError:
        channel_note = "channel reset — the host exited"

    # ── SHELL LIFETIME — "started" is NOT "survived" ─────────────────────────────────
    # Conflating the two produced a false success once already. Exit statuses that matter:
    #   0    Cancel taken (main.rs `RendererMsg::Cancel` -> process::exit(0))
    #   101  Rust panic — GTK init failed, no display
    #   -6   SIGABRT — the host DIED DURING RENDERING. Two known causes, both measured:
    #        (a) the GTK themed-icon assertion (gtkiconhelper.c:495) when glycin's bwrap
    #            loader cannot create a userns — needs /etc/apparmor.d/delphi-shell LOADED;
    #        (b) wry's IPC unwrap on a page URL that is not a valid http::Uri — only reachable
    #            if something forced a file:// URL back into DELPHI_SHELL_URL.
    #        Either way, whether anything rendered before the abort is UNKNOWN, so a -6 can
    #        never support a rendering claim.
    time.sleep(0.5)
    rc = proc.poll()

    print()
    if received is not None:
        print(f"RESULT: APPROVE path — renderer -> native round trip OK ({received} bytes).")
        print("        => window.ipc.postMessage reached the host through real WebKit.")
        verdict = 0
    elif rc == 0:
        print("RESULT: CANCEL path — the host exited 0 (RendererMsg::Cancel).")
        print("        => the renderer received the injection, rendered, and posted back.")
        verdict = 0
    elif rc == -6:
        print("RESULT: the host ABORTED (SIGABRT) — it did NOT survive rendering.")
        print("        Whether the preview ever drew is UNKNOWN: this run CANNOT support a")
        print("        rendering claim. Check, in order:")
        print("          1. is the AppArmor profile LOADED?  bash installer/p3-preflight.sh")
        print("          2. the host's own stderr for the panic/assertion text")
        print("        NOT GTK_DEBUG=icontheme — Ubuntu's GTK3 is built without G_ENABLE_DEBUG")
        print("        and ignores it (measured); it will not name the icon.")
        verdict = 1
    elif rc == 101:
        print("RESULT: the host panicked (101) — GTK init failed; no usable display.")
        verdict = 1
    elif rc is None:
        print(f"RESULT: no interaction observed ({channel_note}); the host is still running.")
        verdict = 1
    else:
        print(f"RESULT: the host exited with status {rc} ({channel_note}).")
        verdict = 1

    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    daemon_end.close()

    print()
    if verdict == 0 and rc == -6:
        # Belt and braces: a round trip observed but an aborted host is still not a clean
        # pass, and must never be summarised as one.
        verdict = 1
    if verdict == 0:
        print("── P3a-1: the host↔renderer contract HOLDS under real WebKit ──")
        print("   Proven: the bundle loads over delphi://shell/index.html (served from the")
        print("   host's startup snapshot), window.__delphiConsent registers under")
        print("   REAL rendering (not jsdom), injections reach the live handler, and the")
        print("   renderer posts back over window.ipc.")
        print("   NOT proven here: the gate, PAM, mint-confirm, execution, leader==shell.")
    else:
        print("── P3a-1: INCONCLUSIVE — no round trip observed ──")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
