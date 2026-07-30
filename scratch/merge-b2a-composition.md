merge(phase-3b): B2a composition — the real shell draws through the consent path

Merges `phase-3b/b2a-composition` (44 commits, 40 files, +7116/-114).

WHAT THIS MAKES TRUE THAT WAS NOT BEFORE
========================================
The B2a security core was merged twice already (`3e40e22` WSL2-provable half,
`71ce87d` lane-dependent core) but nothing had ever DRAWN through it. This
branch closes that: the real React bundle is installed as a directory tree,
served to the real WebKit shell over a custom scheme, the consent dialog is
actually mounted, and a human approved a prompt whose 13-byte reply came back
over `window.ipc` — after which the daemon's gate DENIED for exactly the
predicted reason with no marker written.

Five defects had to be fixed before a window could show anything at all, and
each was silent — a blank window with no error, no log line, no crash:

  1. vite `base` was absolute, so every asset 404'd against the scheme root.
  2. ES modules will not load over `file://` (opaque origin).
  3. wry's IPC path `.unwrap()`s a URL that is not a valid `http::Uri`, so a
     `file://` or authority-less URL SIGABRTs after GTK reports success.
     Reported upstream; routed around, not worked around.
  4. `PamConsentDialog` was defined but never mounted — and because the host
     guards on `&&`, late registration is a silent no-op, not an error.
  5. glycin's image loader needs an unprivileged userns, which Ubuntu's
     `kernel.apparmor_restrict_unprivileged_userns=1` denies — the SECOND
     AppArmor+userns failure in this arc, same gate, different door.

CONTENTS
========
* P1  — the project's first directory-TREE install. Two-rename replace with
        deterministic temp names, per-entry AND per-directory `fstat_trust`,
        Class-12 gating on names that come from the SOURCE (traversal,
        charset, depth, entry type), and restore-before-clear so a good
        bundle exists at every instant.
* P2  — `<PamConsentDialog />` mounted unconditionally at the app root, with
        the host↔renderer contract pinned by byte-exact `inject()` goldens
        and cross-referenced by file:line at both ends.
* P3a — the composition up to the gate, PROVEN BY OBSERVATION (render +
        human interaction + 13 bytes over real WebKit) and then
        MACHINE-CHECKABLY (gate DENIED with the predicted reason, no marker).
* the custom-protocol host — `delphi://shell/…`, startup snapshot + EXACT-KEY
        lookup. Design B: `..` is not rejected, it is simply a key that does
        not exist. Foreclosed by construction rather than by check. Fails
        closed on an empty or partial bundle; hashes every entry and logs the
        set once.
* the AppArmor profile — named-unconfined, granting only `userns`. Its header
        states at length that this is NOT confinement and the renderer remains
        unconfined, and the test suite ASSERTS those statements are present.
        A real confining profile is recorded as a follow-up increment.
* p3-preflight.sh — a pre-flight that REFUSES, never warns. It asks systemd
        for the unit environment rather than reparsing unit syntax, resolves
        the bin paths the daemon will actually execve, and probes the
        kernel-applied exec label rather than the AppArmor registry.

CODEX LEDGER — 7 ROUNDS, CLOSED BY DECISION
===========================================
R1 REVISE 2xP1+2xP2 (c2c60f4) · R2 3xP2 (33dc258) · R3 1xP1+2xP2 (02e4806) ·
R4 2xP1+1xP2 (e6ad4c5) · R5 1xP1+2xP2 (efa92f3) · R6 1xP1+2xP2 (1508b2b) ·
R7 1xP1+2xP3 (d89a72a). Every finding fixed at root cause with a regression
test verified to FAIL against the pre-fix code.

Findings never decreased — flat at 3 for five rounds — but rounds 4-7 produced
ZERO findings in shipping code, and R7 stated that as a judgement ("do not
reopen the shipping surfaces") rather than as an absence. Both R4 P1s were in
the TEST APPARATUS, not the product.

The sweep is closed BY DECISION, not by APPROVE, on this argument:

    Round 6 found a sampler defect. Round 7's fix replaced that sampler with
    ~200 new lines, which would be round 8's subject, whose fix would be
    round 9's. A verification harness generates its own next subject
    indefinitely. There is no terminus to reach, so the close must be a
    decision about the SHIPPING surface rather than an exhaustion of the
    harness.

MERGING UNPROVEN — recorded so the merge does not absorb it
==========================================================
1. `installer/tests/trace-invariant.py` is NEW, UNREVIEWED and LOAD-BEARING —
   the sole evidence for the both-absent invariant. Acceptable ONLY because it
   fails CLOSED (unknown syscall, dirfd-relative mutation, split on a mutating
   call, unreadable return -> REFUSE, never OK), which biases its failure mode
   toward false positives (loud, blocking) over false negatives (silent,
   certifying a broken installer). Reviewed when it next changes, or when a
   second invariant depends on it.
2. The class-22 weaken blind spot was ASKED OF CODEX AND NEVER ANSWERED
   against the merged B-1 / FD-01 / B-3 proofs, which are themselves defended
   by weakens over fork ordering and fd lifetime. The standing counter-argument
   (those weakens produced specific discriminating output — 8678 != 8707,
   socket inode 371938, uid 0 -> 1345 — and a flake yields noise rather than
   the exact expected disagreement) is REASONING, not a discharge.
3. P3b gate-POSITIVE via the real shell — BLOCKED, not deferred. Needs the
   TRUST_MODEL §4 R3-02a PRIMARY shape; nothing in-repo can put a display on a
   bare VT (`compositor/` is library-only, winit-only, no udev/DRM/libseat).
4. P4 long-lived-shell lifecycle — NOT STARTED. B1 still services one action
   then exits.
Known-unfixed BY DECISION: installer AppArmor ATTACHMENT verification (loaded
!= attached), and `DELPHI_AI_BIND_RW` existence. Named limitation: R1-01's
weaken (b) was unconstructable with shell tooling (both attempts FAIL/FAIL
including the control).

METHODOLOGY YIELD — `docs/DEFECT_CLASSES.md` classes 18-24
=========================================================
Most of this arc's findings were about the REVIEW APPARATUS, not the product,
and the corpus now says so: 18 the verification loop mutates its subject;
19 runs compared under different instruments; 20 a correct test in a
non-representative environment; 21 a warning banner is not enforcement;
22 THE FIX INHERITS THE CLASS IT WAS CLOSING — including the weaken protocol's
blind spot for scheduler-dependent properties and its round-7 resolution
(three defects of one class means the INSTRUMENT is wrong: derive the
invariant from a COMPLETE syscall record instead of sampling states, which
makes the weaken deterministic — 10/10, violation DERIVED rather than
observed); 23 forecasting your own code instead of interrogating it;
24 in-band sentinel drawn from the value space it describes.

VERIFICATION AT MERGE
=====================
installer  tree-install 26/26 · p3-preflight 27/27 · apparmor-profile 12/12
rust       delphi-runtime 97/97 (serial) · shell-host 10 unit + 7 integration
           clippy -D warnings clean on both (exit status captured directly)
shell      tsc -b clean · vitest 14 files / 107 tests
chain      build.sh -> install.sh (root) -> p3-preflight.sh: ALL PRECONDITIONS MET

NOT PROVEN BY THIS MERGE, stated because a green run invites the opposite
reading: the unprivileged `cargo test` run SKIPS 17 root-gated tests,
including every trust-boundary proof (B-1, FD-01, B-3, sibling-fd-theft,
PAM interposition, anchor, systemd_smoke, all of b1_integration). Those are
covered by the privileged lane run separately at this merge, not by the
unprivileged suite. `cargo test --workspace` does not build on this box at
all — `llama-cpp-sys-2` bindgen needs clang, which is absent; that is a
pre-existing environment gap unrelated to this branch, which touches no Rust
outside `runtime/shell-host`.
