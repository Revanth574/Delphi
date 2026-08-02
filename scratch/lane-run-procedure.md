# Lane run — scoped procedure (D0 branch `phase-3b/d0-readiness-contract`)

Discharges owed items 1–4. Item 5 (deferred temp paths) is **not** discharged here; it becomes
*verifiable* afterwards. Nothing below has been run — this is the plan, to be executed by the
operator on the seated lane.

---

## 0. Preconditions — check all five before starting

| # | Precondition | Check | Why |
|---|---|---|---|
| P1 | **root** | `id -u` = 0 for the install + the gated suites | PAM, `/run` anchor, `/usr/libexec` |
| P2 | **a free VT matching the unit** | `DELPHI_SHELL_VT` in `delphi-runtimed@.service` is `tty3`; confirm nothing holds it | a taken VT gives `VirtualTerminalAlreadyTaken` |
| P3 | **a display** | `echo $DISPLAY $WAYLAND_DISPLAY` non-empty | `real_webkit_load` skips without one, and that skip reports as `ok` |
| P4 | **free space on all four** | `scripts/check-free-space.sh` | `/tmp` filling surfaces as a protoc *build* error in an unrelated crate |
| P5 | **no stale P3 marker** | `rm -f /tmp/delphi-p3-marker` | a surviving marker makes a FAILED run read as success |

If P4 fails it names which path is short. Do not proceed on "probably enough".

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
cd runtime/shell-host && CARGO_TARGET_DIR=$HOME/delphi-target/shell-host ../../scripts/test-count.sh --release
```

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

---

## 4. Discharge criteria — what each owed item needs

| # | Item | Discharged when |
|---|---|---|
| 1 | **B-1 / FD-01 / B-3 serial ≥30** | 30/30 pass under `--test-threads=1`, 0 failures, against the marker-writing sleeper. A parallel failure is a harness artifact **only if shown** to be pre-`execve` child death (read the lines; do not assume). |
| 2 | **Transaction boundary** | runs (not SKIP) **and** passes **and** fails under the weaken in §3. Two of three is not discharge. |
| 3 | **WRY host readiness path** | the daemon launches the real shell and `launch()` returns `Ok` — i.e. `readiness::READY_DATAGRAM` arrived. Confirm the P3 marker `/tmp/delphi-p3-marker` exists after the run, and that the journal shows no `ShellDiedBeforeReady` / `ShellReadyTimeout`. |
| 4 | **`real_webkit_load` (7)** | all 7 **run** (no `SKIP` on their lines under `--nocapture`) and pass, in `--release`. |
| 5 | **Deferred temp paths** | **NOT discharged by this run.** It becomes verifiable afterwards: with the lane green, the ~23 conversions can be made and re-verified against a suite that actually executes them. |

---

## 5. Report back

For each: the command, the literal `EXECUTED/SKIPPED/reported` or `n/30`, and — for item 2 —
both the pass line **and** the weaken's failure line. Per §13.5, quote the output rather than
summarising it, and state executed-vs-skipped rather than a total.

If anything fails, the failure is the result; do not re-run to green.
