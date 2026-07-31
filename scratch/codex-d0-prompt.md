# Codex adversarial review — D0, the shell readiness contract (commit `6b9e322`)

<!--
INVOCATION — THE WORKING FORM. USE THIS ONE.

    codex review - < scratch/codex-d0-prompt.md

DO NOT reconstruct the flags from memory or from CLAUDE.md §6. `--commit <SHA>` and a
PROMPT are MUTUALLY EXCLUSIVE in the installed CLI:

    error: the argument '--commit <SHA>' cannot be used with '[PROMPT]'

That mistake has cost SEVEN retries across the B2a composition sweep. The scope is
therefore carried IN THIS DOCUMENT (the "Scope" section below names the commit and the
exact diff stat), not in a flag — which is more robust anyway, because §6 requires the
reviewer to inspect the live code through the CLI rather than trust a supplied diff.

KNOWN DRIFT: CLAUDE.md §6 still documents `codex review --commit <SHA> - < prompt.md` as
a valid form. It is not. That note needs correcting; it is flagged, not yet fixed.
-->

## Scope — exactly this, and detect drift from it

**Target: commit `6b9e322`** on branch `phase-3b/d0-readiness-contract` (parent `9d65586`,
the B2a composition merge). Inspect the live tree via the CLI — `git show 6b9e322`,
then read the files themselves. Do not reason from this prompt's summary.

**Expected diff stat for the code under review** (`git show --stat 6b9e322 -- runtime/`):

```
 runtime/Cargo.toml                      |   5 +-
 runtime/shell-host/src/main.rs          |  24 ++
 runtime/src/bin/delphi-minimal-shell.rs |   6 +
 runtime/src/launcher.rs                 |  42 +++-
 runtime/src/lib.rs                      |  33 +++
 runtime/src/readiness.rs                | 391 ++++++++++++++++++++++++++++++++
 runtime/tests/leader_is_shell.rs        |  23 +-
 7 files changed, 519 insertions(+), 5 deletions(-)
```

If what you find does not match this, **say so first** — scope drift is itself a finding.

**Explicitly OUT of scope** (documentation only, no production code; §8 exempts them):
`PROGRESS.md`, `docs/TRUST_MODEL.md`, `scratch/*`. A later docs-only commit on this branch
amends `docs/DEFECT_CLASSES.md` class 18 and a PROGRESS finding; also out of scope.

**Tool grounding is required** (§6, Iron Law #12). Verify every library/API claim against
Context7, docs.rs, or the crate source in `~/.cargo/registry` — specifically `nix` 0.30's
`poll`/`PollFd`/`PollTimeout` semantics and `wry` 0.55.1's `with_on_page_load_handler` /
`PageLoadEvent`. Do not accept this document's characterisation of either.

## What D0 is

The pre-D0 launcher **could not represent "the child died after `execve`" at all**.
`launcher.rs::wait_for_child_setup` reads an `O_CLOEXEC` setup-sync pipe, so its EOF is
delivered *by* the `execve` — nothing after it is observable through that channel. Measured
consequence (PROGRESS, P3a): the WRY host printed `GTK INIT: ok`, aborted during rendering,
and the daemon went on to derive the logind verdict, accept the AI, and service an action
against a dead shell.

D0 adds a **post-`execve` readiness signal**. The shell writes
`readiness::READY_DATAGRAM` on the **existing** private `SOCK_SEQPACKET` consent channel
(`SHELL_CHANNEL_FD` = 3); `launch()` blocks in `readiness::await_shell_ready`, which polls
the channel **and** the shell's pidfd, and returns `Ok` only on the marker.

Design decision to attack: readiness rides the existing channel rather than a second pipe,
because a new inherited fd would have to be **exempted from the FD-01 sweep**, and widening
that allowlist is the precise class FD-01 (P1) closed. Is that reasoning sound, and is the
implementation consistent with it?

## §13.9 defect-class partition — where NOT to spend budget, and where to

Per `docs/DEFECT_CLASSES.md`. **(a) is pre-foreclosed — do not re-hunt it. (b) is
applicable and NOT foreclosed — this is where the budget goes.**

### (a) Pre-foreclosed by construction or by a `delphi-hardening` primitive — skip

| Class | Why it cannot bite here |
|---|---|
| **1** under-coverage hashing / non-injective encoding | No hashing or encoding is introduced. The marker comparison is a whole-slice `==` against a fixed constant, with a buffer sized `len+1` so an over-long datagram is *detected* rather than truncated into a match. `canonical_hash` is untouched. |
| **2** path-resolution races (symlink/TOCTOU) | No paths are opened, resolved, or created on this diff. `safe_open` is untouched. |
| **3** per-connection PRAGMA / transient-lock | No SQLite. `pragma_setup` is untouched. |
| **5** convention → unforgeable type | `VtName` and the existing capability types are untouched; D0 adds no new invariant-by-convention. |
| **9** normalize-then-detect offset drift | No normalisation step exists; the comparison is exact-match on raw bytes. |
| **11** error-message oracles at validation boundaries | The one new message reports a **length**, never the payload bytes — deliberately, see `classify_datagram`. |
| **13** atomic versioned migration | No on-disk schema or artifact. |
| **24** in-band sentinel drawn from its own value space | The channel is `SOCK_SEQPACKET`, so the marker is **framed**, and the constant (ASCII + embedded NUL, 21 bytes) is in none of the subsequent message spaces (32-byte digest, preview, PAM prompt, password, 32-byte mint-confirm). Argued in the module docs — **verify the argument, but the class is addressed, not ignored.** |

### (b) Applicable and NOT foreclosed — concentrate here

| Class | The specific exposure D0 creates |
|---|---|
| **6** correct fix, incorrect **composition** | The unit tests prove `await_shell_ready`. They do **not** prove `launch()` consults it — that composition is only exercised by root/PAM tests which **SKIP on the dev box**. This is the sharpest (b) item. |
| **8** same post-condition reached by multiple paths | `ShellDiedBeforeReady` is now returned from **three** places: the pidfd leg, the EOF leg (`n == 0`), and the `POLLHUP/POLLERR` leg. Are all three genuinely the same condition, and is any real case falling through none of them? |
| **10** platform test-gating that masks bugs | Four `leader_is_shell` tests SKIP without root. Their own messages say "A SKIP PROVES NOTHING." D0 **changed the fixture they depend on** and the change is unexercised here. |
| **14** guard must cover **all forms** of what it guards | Three shell binaries must now signal: `delphi-minimal-shell`, the `sleeper.c` fixture, and the real `delphi-shell` host. Is there a fourth path that execs as `shell_path` and does not signal? Is anything else calling `launch()`? |
| **17** defect propagated by copy — fix the PATTERN | The `sleeper.c` C literal is **generated** from `READY_DATAGRAM` rather than transcribed, to foreclose the duplication class that produced B2A-COMP-R3-03's false green. Check the generation is correct (octal escapes, length) and that no *other* copy of the marker was introduced. |
| **20** a correctly-biting test in a NON-REPRESENTATIVE environment | The weaken/restore was run on a box with **no display and no root**. Does that invalidate any leg of it? |
| **22** the FIX inherits the class it was closing | D0 closes "a signal that cannot observe what it claims to." Does the readiness signal itself have that shape — i.e. does `PageLoadEvent::Finished` actually mean "the shell is up", or is it another proxy that can fire for a shell about to die? |
| **23** forecasting your own code instead of interrogating it | The wry callback behaviour for a **custom scheme** is **read from the API, not measured**. See the honesty section below. |

## The weaken/restore evidence, for you to attack

Weaken = `await_shell_ready`'s body replaced with `Ok(())` (a faithful encoding of pre-D0
behaviour: nothing observed the child post-`execve`).

```
weakened: test result: FAILED. 2 passed; 4 failed
  FAIL shell_that_dies_without_signalling_is_not_ready   (keystone)
  FAIL wrong_first_datagram_is_a_protocol_error_not_a_ready
  FAIL marker_with_trailing_bytes_does_not_match
  FAIL shell_that_neither_signals_nor_dies_times_out
  ok   shell_that_signals_is_ready                       (positive leg)
  ok   marker_is_not_digest_sized                        (constant)
restored: test result: ok. 6 passed; 0 failed
```

Non-determinism: **30/30 pass, DEFAULT PARALLEL**, full 57-test lib binary. Claimed *not* to
be the §6 serial-only carve-out because these forked children do only raw syscalls — no PAM,
no allocation, no D-Bus — so the multithreaded-fork-parent hazard does not apply.
**Attack that claim**: is any of these children doing something non-async-signal-safe?

## The four focus questions

1. **Does readiness-on-the-consent-channel interact with the R‑2 keystone or with
   `HostSession::recv_approval`'s ordering?** The daemon now reads one datagram *before* it
   writes the approval request; the host writes one *before* it calls `recv_approval`. Is
   there any interleaving — a shell that signals twice, a shell that signals *after* the
   approval request arrives, a daemon restart mid-prologue — where a readiness datagram is
   consumed as an approval, a mint-confirm is consumed as readiness, or the renderer gains
   any path it did not have? The keystone is "renderer cannot forge approval"; the marker is
   written by native code, but confirm that.

2. **Is the `drop(shell_end)`-before-wait ordering sound?** `launch()` now drops the daemon's
   copy of the shell's channel end *before* `await_shell_ready`, so a dead shell produces EOF
   rather than silence. Verify: (a) no other copy of that fd survives anywhere (including
   across `fork_ai`), (b) the drop cannot close an fd the child still needs, (c) the EOF and
   pidfd legs cannot both fire in a way that mis-reports, and (d) the deliberate
   channel-before-pidfd check order — justified in-code as resolving a
   signalled-then-exited-fast race toward "it did signal" — is actually correct and not
   masking a real death.

3. **Does forking the AI only after readiness change any failure mode?** Previously both
   children were forked before `launch()` returned. Now a shell that never signals means the
   AI is **never forked**. Check the §4 failure-mode table still holds: pending approvals,
   daemon restart, socket lifetime, and whether anything assumed both pids exist by the time
   `launch()` returns.

4. **`docs/TRUST_MODEL.md` §4 R3-01d (out of code scope, in scope as a claim):** the display
   arc adopts leader == compositor, replacing **structural** teardown with **mechanized**
   teardown (daemon pidfd-pins both, kills the survivor). It is recorded as a cost accepted,
   with three named failure modes: daemon dies first, deaths race, and it is code where
   structure used to be. **Is that costing honest, or does it understate the loss?**
   Specifically: is there a fourth failure mode, and does the claim that R3-03's approver pin
   is unaffected actually hold when the shell is no longer the session leader?

## Honesty declarations — treat these as suspect, not as settled

1. **The WRY host's readiness leg is UNVERIFIED.** It is attached to
   `PageLoadEvent::Finished` rather than to `build()` returning — deliberately, because
   signalling at construction would report P3a's corpse as up, i.e. today's behaviour. That
   the callback fires for a **custom scheme** (`delphi://shell/…`) rather than only for
   http(s)/file is **read from the wry 0.55.1 API, not measured**; the dev box has no
   display. If it does not fire, every launch fails **closed** with `ShellReadyTimeout`
   (loud, bounded, never a false success) — but it fails. **Is fail-closed sufficient here,
   or does an unverified liveness signal on the production shell path warrant blocking?**

2. **The `sleeper.c` change is unexercised.** All four `leader_is_shell` tests SKIP without
   root on the dev box. The change is argued as **narrowing, not weakening** (Iron Law 15
   clause 3): no measured property — leader==shell, fd containment, privdrop — depends on the
   shell staying silent; the assertions are untouched; the `pause()` is kept. **Test that
   argument.** Does adding a `write(3, …)` before `pause()` perturb anything B-1, FD-01, or
   B-3 measures — fd state, timing, the child's pre-`execve` sequence?

3. **The class-22 weaken blind spot, ASKED AND NEVER ANSWERED in round 7 of the B2a sweep,
   now applies to D0 too.** For a scheduler-dependent property a weaken can pass while the
   defect is present. D0's keystone is defended by a weaken over **fork ordering and channel
   EOF timing** — the same exposure. The operator's standing argument is that these weakens
   produce *specific discriminating output* rather than noise, and that a flake does not
   manufacture the exact expected disagreement. **That is an argument, not a measurement.**
   Bound the blind spot against D0's six tests if you can; if you cannot, **say so
   explicitly** rather than leaving it unanswered a second time.

4. **`cargo check --workspace` has not been runnable on this box** (libudev/libseat/libinput/
   gbm/libdrm absent; `compositor` is a default member with the DRM features already
   enabled). All verification here is `-p delphi-runtime` scoped. The gate was **absent, not
   passing**. Whether CI covers it is currently unverified.

## Verdict format (required)

**APPROVE / REVISE / FAIL**, then per finding:

- **ID** (`D0-R1-NN`), **severity** (P1-high → P2-medium → P2-low → P3-informational)
- **root cause** — the mechanism, not the symptom
- **impact** — what an attacker or an operator actually gets
- **fix sketch** — and, where the finding is a *claim* rather than a defect, say what
  measurement would settle it

Prefer one finding that names a real mechanism over five that restate the honesty
declarations back to me. Items 1–4 above are **already known and already recorded**;
re-listing them is not a finding. Telling me one of them is *worse than stated*, or that a
fifth exists, is.
