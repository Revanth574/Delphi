# Lane run — scoped procedure (D0 branch `phase-3b/d0-readiness-contract`)

Discharges owed items 1–4. Item 5 (deferred temp paths) is **not** discharged here; it becomes
*verifiable* afterwards. Nothing below has been run — this is the plan, to be executed by the
operator on the seated lane.

---

## 0. GO / NO-GO — run this block FIRST, in full, before anything expensive

Build + install is minutes. Discovering a stale marker or an occupied VT *after* it costs the
whole sequence, and this session has already spent a day on failures that were preconditions
misattributed to code. **One block, all five, before the first build.**

```bash
{
  echo "P1 root:      $([ "$(id -u)" = 0 ] && echo OK || echo 'NO — re-run under sudo -E')"
  echo "P2 VT free:   $(grep -oE 'DELPHI_SHELL_VT=tty[0-9]+' installer/staging/delphi-runtimed@.service) \
                       -> $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $NF}' | grep -qx tty3 && echo 'OCCUPIED — STOP' || echo free)"
  echo "P3 display:   ${DISPLAY:-<none>} ${WAYLAND_DISPLAY:-}"
  echo "P4 space:"; scripts/check-free-space.sh || echo "  *** STOP ***"
  echo "P5 marker:    $([ -e /tmp/delphi-p3-marker ] && echo 'PRESENT — rm -f /tmp/delphi-p3-marker' || echo absent)"
  echo "P6 userns:    restrict=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null) \
                       profile=$(aa-status 2>/dev/null | grep -c delphi-shell)"
  echo "P7 stale:"; scripts/check-stale-test-sessions.sh || echo "  *** STOP ***"
}
```

**Every line must read OK / free / absent before proceeding.** P6 is informational: `restrict=1`
with `profile=0` means `real_webkit_load` will abort rather than skip — install has not run yet,
which is expected at this point but must be true again *after* step 1.

| # | Precondition | Why it stops the run |
|---|---|---|
| P1 | root | PAM, `/run` anchor, `/usr/libexec` |
| P2 | `tty3` free | an occupied VT gives `VirtualTerminalAlreadyTaken`, one layer below the gate |
| P3 | a display | `real_webkit_load` skips without one — **and the skip reports as `ok`** |
| P4 | free space on all four | `/tmp` filling surfaces as a protoc *build* error in an unrelated crate |
| P5 | no stale `/tmp/delphi-p3-marker` | a surviving marker makes a FAILED run read as success |
| P7 | **no surviving test session on ANY VT** | a session left by a previous run makes every launch fail `VirtualTerminalAlreadyTaken` — **a precondition failure that presents as a code regression.** Measured: it cost three wrong diagnoses (blamed a just-landed cleanup fix, then PAM) before the journal gave ground truth. |

---

## 1. Ordering — and the one that will silently waste the run

**`build.sh` → `sudo install.sh` → suites, with NO source edit in between.**

```bash
scripts/check-free-space.sh && installer/build.sh
```
```bash
sudo installer/install.sh
```

**THE RELEASE-MODE REQUIREMENT — verified 2026-08-02, and non-obvious.** C+F's staleness guard
compares `env!("CARGO_BIN_EXE_delphi-shell")` against `/usr/libexec/delphi-shell`.

- `build.sh` builds **`--release`** and stages `$TARGET/shell-host/release/delphi-shell`;
  `install.sh` copies that to `/usr/libexec`.
- A plain `cargo test` resolves `CARGO_BIN_EXE` to the **debug** binary.

So **`cargo test` without `--release` can never match, and all 7 tests skip — reporting `ok`.**
Measured here: `built 4f03d5620e5b…` vs `installed 7b0250295a04…`. The suite must run as:

```bash
cd runtime/shell-host && CARGO_TARGET_DIR=$HOME/delphi-target/shell-host cargo test --release
```

with the **same `CARGO_TARGET_DIR` `build.sh` used**, because that is what makes the test's
binary the very file that was installed — byte-identical by construction, not by luck. Confirmed:
`cargo test --release` resolved to `4f03d5620e5be427`, the exact file `build.sh` stages.

Any source edit between build and test invalidates the match and re-skips all seven.

---

## 2. Counting and stability are DIFFERENT measurements — keep them apart

They answer different questions and must not be merged in the report.

**Counting — serial, once.** Serial because SKIP (stderr) interleaves with `test NAME ... ok`
(stdout) under parallelism, which made the count drift 17/18/19 for one unchanged tree.

```bash
scripts/test-count.sh -p delphi-runtime
```
```bash
cd runtime/shell-host && CARGO_TARGET_DIR=$HOME/delphi-target/shell-host \
  DELPHI_MIN_MS_PER_TEST=100 ../../scripts/test-count.sh --release
```

`DELPHI_MIN_MS_PER_TEST=100` is the **physical floor**, and it is the reason a repeat of the
0.02s incident cannot pass silently: seven WebKit launches cannot average under 100ms, so a
skipped suite REFUSES on the timing even if the SKIP parse misses every marker. Two independent
signals — which matters, because the SKIP parse has already been wrong once.

Report as `EXECUTED n / SKIPPED m / reported n+m`. A bare total is not a coverage claim.

**Stability — default parallel, ≥30.** Except the fork+PAM tests, which are **serial-only** per
CLAUDE.md §6's carve-out: forking PAM from the multithreaded test runner is a harness hazard
production does not have (production's daemon is single-threaded).

```bash
for i in $(seq 1 30); do cargo test -p delphi-runtime --lib || echo "FAIL $i"; done
```
```bash
for i in $(seq 1 30); do cargo test -p delphi-runtime --test leader_is_shell -- --test-threads=1 || echo "FAIL $i"; done
```

Report the two separately, with the thread setting stated for each.

---

## 3. The transaction-boundary test — the item that matters most

`leader_is_shell::launch_kills_the_shell_when_a_later_step_fails_d0_r4_02`. It is the **only**
test of the `launch()` transaction boundary, it has **never executed**, and Codex found (D0-R5-03)
that its original form could pass without ever reaching `fork_ai`. R5-03's fix has also never run.

**So this run is not "does it pass" — it is the first evidence the test discriminates at all.**

```bash
sudo -E cargo test -p delphi-runtime --test leader_is_shell -- --nocapture --test-threads=1 \
  launch_kills_the_shell_when_a_later_step_fails
```

**A VALID PASS looks like:**
- the line reads `test launch_kills_… ... ok` with **no `SKIP` on it**; and
- no panic naming `expected a Filesystem error from fork_ai`.

A pass means the assertion `Filesystem { path == missing_ai, source == NotFound }` matched — an
error constructed at exactly one site (`spawn_pid`, via `fork_ai`) and reachable **only after
readiness has already succeeded**. That is what proves the boundary was crossed.

**A PASS THAT PROVES NOTHING looks like:**
- `test launch_kills_… ... ok` **with `SKIP` on the same line** — a skip scores as a pass, so
  without `--nocapture` this is indistinguishable from success. This is the single most likely
  way to come away believing the item is discharged when it is not; and
- a pass whose panic-free path was reached because the launch failed *earlier* (PAM, setup,
  readiness) — which the pre-R5-03 `is_err()` form accepted. If the assertion has been reverted,
  a pass is vacuous.

**RECOMMENDED, and it is what turns the test from green into evidence — the weaken.** The test
has never been RED-proven. Disarm the guard and confirm the test FAILS:

```bash
# in runtime/src/launcher.rs, ShellGuard::drop — make it return immediately:
#     fn drop(&mut self) { return; ... }
sudo -E cargo test -p delphi-runtime --test leader_is_shell -- --test-threads=1 \
  launch_kills_the_shell_when_a_later_step_fails
# EXPECT: FAILED, naming a surviving pid executing the sleeper. Then REVERT the edit.
```

If it passes under the weaken, the test is decorative and the boundary is still untested.

### 3a. MANDATORY cleanup after the weaken — check the SESSION, on ANY VT

The weaken disarms the guard, so **a surviving shell is the point of the run**: a root-spawned
process holding a **logind session**. Left there, every subsequent launch fails
`VirtualTerminalAlreadyTaken` at `pam_open_session`.

**THE FIRST VERSION OF THIS SECTION LOOKED FOR THE WRONG RESOURCE ON THE WRONG VT.** It checked
for *processes on tty3*, because it was written for the weaken's tty3 scenario. The actual
survivor was a **session on tty1** — `c523`, owned by `delphi-r402-119101` — and tty1 is the VT
the tests actually use. The check found nothing, reported clean, and three wrong diagnoses
followed. Sessions outlive their last process; the session, not the process, holds the VT.

```bash
git -C /home/revanth-aditya/Delphi diff --stat runtime/src/launcher.rs   # expect: empty — revert FIRST
```
```bash
scripts/check-stale-test-sessions.sh --vt tty1
```

`--vt tty1` because the tests run on tty1 — the weaken's survivor was on tty1 while the old
cleanup looked at tty3. The bare form (any VT, keyed on our PAM service) is the go/no-go gate;
this per-VT form is the one to use here. The script is the check: it matches **any logind session owned by a `delphi-*` or `db1*` user on
any VT**, prints the `terminate-user` command per user, and also reports leftover accounts as a
secondary signal. Run it until it prints `no stale test sessions or accounts`.

**If a session will not clear** — it is `closing` with a member that will not die:

```bash
sudo loginctl terminate-session <session-id>   # then re-check; if it persists, reboot the lane
```

Do **not** start the next suite until the script is clean. A held VT makes every launch fail at
`pam_open_session`, which looks exactly like a PAM regression and is not one.

---

## 3b. R6-03 — Codex's acceptance criterion, verbatim

`pam_interposition`'s shared consent dir was moved into a `tempfile::TempDir` (item 5) and
regressed: `tempdir()` is **0700 root-owned**, and the privilege-dropped child could no longer
create the response file. The fix (`chown` to the session uid/gid, `chmod 0770`) was reviewed
in round 7 and judged **mechanically sound by inspection, with the mechanics cited** — uid
ownership plus `0770` gives write+execute; `setgroups([])` clears only *supplementary* groups
while `setgid(gid)` sets the primary; nothing is created in the dir before the `chown`; and
`Service=` is retained through `closing`.

**That is inspection judgement, NOT behavioural evidence, and it was stated as such.** The
settling measurement is below — and it is a better acceptance criterion than "the tests pass",
because a skip also passes:

```bash
sudo -E cargo test -p delphi-runtime --test pam_interposition -- --nocapture --test-threads=1
```

**Discharged only when ALL of these hold:**

1. **both** `pam_interposition` tests **execute** — no `SKIP` on either line;
2. the **privilege-dropped child creates `response`** in the shared dir;
3. **PAM authenticates** over the private channel;
4. the **RED attacker observes the prompt** (the red-proof leg still bites);
5. the **temp dir is absent afterward** — check the parent of the path named in the output.

Any one of these missing means the fix is unproven, whatever the test result line says.

---

## 4. Discharge criteria — what each owed item needs

| # | Item | Discharged when |
|---|---|---|
| 1 | **B-1 / FD-01 / B-3 serial ≥30** | 30/30 pass under `--test-threads=1`, 0 failures, against the marker-writing sleeper. A parallel failure is a harness artifact **only if shown** to be pre-`execve` child death (read the lines; do not assume). |
| 2 | **Transaction boundary** | runs (not SKIP) **and** passes **and** fails under the weaken in §3. Two of three is not discharge. |
| 3 | **WRY host readiness path** | **CORRECTED.** `sudo -E bash scratch/p3-daemon-run.sh tty3 <session-user>`. Discharged when there is **no** `ShellDiedBeforeReady` / `ShellReadyTimeout` **and** the run reaches a gate verdict with an explicit deny reason — reaching the gate proves `launch()` returned `Ok`, i.e. the marker arrived. **NO MARKER FILE IS WRITTEN and that is correct:** tty3 is not seat0's `ActiveSession`, so the gate denies by design; a marker would be a gate-POSITIVE, which is P3b and still blocked. The earlier "confirm the marker exists" criterion was wrong. |
| 4 | **`real_webkit_load` (7)** | all 7 **run** (no `SKIP` on their lines under `--nocapture`) and pass, in `--release`. |
| 5 | **Deferred temp paths** | **NOT discharged by this run.** It becomes verifiable afterwards: with the lane green, the ~23 conversions can be made and re-verified against a suite that actually executes them. |

---

## 5. Report back

For each: the command, the literal `EXECUTED/SKIPPED/reported` or `n/30`, and — for item 2 —
both the pass line **and** the weaken's failure line. Per §13.5, quote the output rather than
summarising it, and state executed-vs-skipped rather than a total.

If anything fails, the failure is the result; do not re-run to green.
