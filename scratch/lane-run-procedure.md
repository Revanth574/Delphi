# Lane run 2 — scoped procedure (branch `phase-3b/d0-readiness-contract`, HEAD `c61fc1a`)

**Run 1 discharged items 1–4.** This run exists because rounds 6 and 7 landed **behaviour
claims with no behavioural evidence** — root-gated fixes that were compile-verified only, which
is the same route by which the regression they fix arrived. Nothing below re-litigates run 1;
it settles what has changed since.

What this run settles, in priority order:

| | Claim | Why it needs a lane |
|---|---|---|
| **A** | **R6-03** — `chown`+`0770` on the `pam_interposition` temp dir | the fix for a review-found regression, returning by the same compile-only route |
| **B** | **R7-05 / R6-11** — the per-test entry assertion attributes a leak to its *causer* | the whole point is what happens at the SECOND test after a leak; unobservable off-lane |
| **C** | **R6-04 / R7-04** — `Setup::drop` polls the session away before `userdel` | run 1 leaked one account per iteration; this is the fix, unproven |
| **D** | **R7-02/03** — the checker's anchored `Service=`/`TTY=` parse against a REAL seat | off-lane it has no real session to parse; a spurious refusal here is a defect |
| **E** | **R7-07** — `ReportingTempDir` reports a removal failure | root-created, uid-owned children under a root temp dir |
| **F** | **regression** — B-1 / FD-01 / B-3 still 30/30 serial at this HEAD | item 5 rewrote 22 temp-dir sites underneath them |
| **G** | *conditional* — the workspace test-count pair | fills `.github/rust-test-count-baseline`, which is deliberately UNRECORDED |

---

## 0. GO / NO-GO — run this block FIRST, in full, before anything expensive

Build + install is minutes; discovering an occupied VT after it costs the sequence. Run 1 spent
a day on preconditions misattributed to code.

```bash
{
  VT=$(grep -oE 'DELPHI_SHELL_VT=tty[0-9]+' installer/staging/delphi-runtimed@.service | cut -d= -f2)
  TVT=${DELPHI_TEST_VT:-tty1}   # what Setup::new asserts on; leader_is_shell.rs:366
  echo "P1 root:      $([ "$(id -u)" = 0 ] && echo OK || echo 'NO — re-run under sudo -E')"
  echo "P2 VT free:   unit=$VT  tests=$TVT"
  for v in "$VT" "$TVT"; do
    loginctl list-sessions --no-legend 2>/dev/null | awk '{print $NF}' | grep -qx "$v" \
      && echo "   $v OCCUPIED — STOP" || echo "   $v free"
  done
  echo "P3 display:   ${DISPLAY:-<none>} ${WAYLAND_DISPLAY:-}"
  echo "P4 space:";  scripts/check-free-space.sh || echo "  *** STOP ***"
  echo "P5 marker:    $([ -e /tmp/delphi-p3-marker ] && echo 'PRESENT — rm -f /tmp/delphi-p3-marker' || echo absent)"
  echo "P6 userns:    restrict=$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null) \
                       profile=$(aa-status 2>/dev/null | grep -c delphi-shell)"
  echo "P7 stale:";  scripts/check-stale-test-sessions.sh || echo "  *** STOP ***"
  echo "P8 accounts: $(getent passwd | grep -cE '^(delphi-|db1|dsmoke|dpam|de2e)') leftover (record it — it is the DELTA that matters)"
}
```

**Every line must read OK / free / absent before proceeding.** Two notes:

- **P2 now checks two VTs.** The unit's VT and `tty1` are different resources and run 1's
  survivor was on the one the old block did not check.
- **P8 is a baseline, not a gate.** Run 1's finding was 1 account leaked *per iteration*; claim
  C is discharged by the **delta being 0**, so the number before matters as much as after.

P6 is informational here: `restrict=1` with `profile=0` means `real_webkit_load` **aborts**
rather than skips — expected before install, and must be non-zero after step 1.

---

## 1. Ordering — and the one thing that will silently waste the run

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
Measured: `built 4f03d5620e5b…` vs `installed 7b0250295a04…`. The suite must run as:

```bash
cd runtime/shell-host && CARGO_TARGET_DIR=$HOME/delphi-target/shell-host cargo test --release
```

with the **same `CARGO_TARGET_DIR` `build.sh` used** — that is what makes the tested binary the
installed file by construction rather than by luck. Any source edit between build and test
invalidates the match and re-skips all seven.

---

## 2. Counting and stability are DIFFERENT measurements — keep them apart

**Counting — serial, once.** Serial because SKIP (stderr) interleaves with `test NAME ... ok`
(stdout) under parallelism, which made the count drift 17/18/19 for one unchanged tree.

```bash
scripts/test-count.sh -p delphi-runtime
```
```bash
cd runtime/shell-host && CARGO_TARGET_DIR=$HOME/delphi-target/shell-host \
  DELPHI_MIN_MS_PER_TEST=100 ../../scripts/test-count.sh --release
```

`DELPHI_MIN_MS_PER_TEST=100` is the **physical floor**: seven WebKit launches cannot average
under 100ms, so an all-skipped suite REFUSES on timing even if the SKIP parse misses every
marker. Two independent signals, because that parse has already been wrong once.

Report as `EXECUTED n / SKIPPED m / reported n+m`. A bare total is not a coverage claim.

**Stability — default parallel, ≥30**, except the fork+PAM tests, which are **serial-only** per
CLAUDE.md §6's carve-out (forking PAM from the multithreaded test runner is a harness hazard
production's single-threaded daemon does not have).

---

## 3. Claim A — R6-03, in Codex's words

Item 5 replaced hand-rolled temp paths with `tempfile::TempDir`. Round 6 found the regression:
`tempdir()` is **0700 root-owned**, so `pam_interposition`'s privilege-dropped child could no
longer create the response file. The fix — `chown` to the session uid/gid, `chmod 0770` — was
reviewed in round 7 and judged **mechanically sound by inspection, with the mechanics cited**:
uid ownership plus `0770` gives write+execute; `setgroups([])` clears only *supplementary*
groups while `setgid(gid)` sets the primary; nothing is created in the dir before the `chown`;
`Service=` is retained through `closing`.

**That is inspection judgement, NOT behavioural evidence, and it was stated as such.** The
settling measurement is below, and it is a better acceptance criterion than "the tests pass",
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

Any one of these missing means the fix is unproven, whatever the result line says.

---

## 4. Claim B — the entry assertion, RED-proven on the lane

**This is the one measurement that cannot be faked off-lane, and it costs nothing extra**
because §5's weaken already produces the survivor it needs.

The claim under test is *not* "the assertion doesn't fire on a clean lane" (that is the negative
and it proves little). It is: **after a leak, the NEXT test fails by NAME at entry, attributed
to the previous test — instead of dying at `pam_open_session` with
`VirtualTerminalAlreadyTaken`, which names neither cause nor culprit.** That failure mode cost
run 1 nine consecutive red tests and three wrong diagnoses.

Sequence, in this order, and **do not clean up between the two commands**:

```bash
# 1. the weaken from §5 leaves a live shell holding a session. Run it.
# 2. THEN, with the survivor still there, run any other root test in the same crate:
sudo -E cargo test -p delphi-runtime --test leader_is_shell -- --nocapture --test-threads=1 \
  shell_child_drops_to_the_session_user_b3
```

**Discharged when** the failure message is the checker's — naming the stale session, its VT and
the `terminate-session` command — and **not** `VirtualTerminalAlreadyTaken`. Record the literal
message either way; if it is the PAM one, the assertion is not doing its job and that is the
finding.

Then clean up per §5a before anything else.

---

## 5. Claim F — the three regression tests, re-proven at this HEAD

Item 5 rewrote 22 temp-dir sites underneath these, and rounds 6–7 changed `Setup`. The ≥30
serial run is the standing evidence for the security core; re-establish it here.

```bash
for t in leader_is_shell; do
  for i in $(seq 1 30); do
    sudo -E cargo test -p delphi-runtime --test $t -- --test-threads=1 || echo "FAIL $i"
  done
done
```

Report `n/30` and the failure count, not "tests pass". A parallel failure is a harness artifact
**only if shown** to be pre-`execve` child death — read the lines, do not assume.

**The weaken (also feeding §4).** `ShellGuard::drop` in `runtime/src/launcher.rs` → make it
return immediately, then:

```bash
sudo -E cargo test -p delphi-runtime --test leader_is_shell -- --test-threads=1 \
  launch_kills_the_shell_when_a_later_step_fails
# EXPECT: FAILED, naming a surviving pid executing the sleeper.
```

Confirm the edit is present before believing the result (`git diff --stat runtime/src/launcher.rs`
must be non-empty). A weaken that silently did not apply reports on the shipped code.

### 5a. MANDATORY cleanup after the weaken — check the SESSION, on ANY VT

The weaken disarms the guard, so **a surviving shell is the point**: a root-spawned process
holding a **logind session**. Left there, every later launch fails `VirtualTerminalAlreadyTaken`.

**Run 1's version of this section looked for the wrong resource on the wrong VT** — processes on
tty3, when the survivor was a *session* on tty1. Sessions outlive their last process; the
session, not the process, holds the VT.

```bash
git -C /home/revanth-aditya/Delphi diff --stat runtime/src/launcher.rs   # expect EMPTY — revert FIRST
```
```bash
scripts/check-stale-test-sessions.sh --vt "${DELPHI_TEST_VT:-tty1}"
```

Run until it prints `no stale session on …`. If one will not clear:

```bash
sudo loginctl terminate-session <session-id>   # then re-check; if it persists, reboot the lane
```

Do **not** start the next suite until it is clean.

---

## 6. Claims C, D, E — read off the runs above, no extra commands

**C — teardown.** After §5's 30 iterations, re-run P8:

```bash
getent passwd | grep -cE '^(delphi-|db1|dsmoke|dpam|de2e)'
scripts/check-stale-test-sessions.sh
```

**Discharged when both deltas are 0** against P8's baseline. Run 1 leaked one account per
iteration, so 30 iterations is the measurement that has teeth. If `Setup::drop`'s poll times out
it now REPORTS rather than proceeding silently (R7-04) — quote any such line; a timeout is a
finding, not noise.

**D — the checker against a real seat.** It ran in P7, P8 and §5a against a lane with real
sessions on a real seat. **Discharged when it never refused spuriously** and its `Service=` /
`TTY=` parse produced a verdict every time. A `REFUSING to certify` on a healthy lane is a
defect in the checker (its parse), not a stale session — report the literal output.

**E — `ReportingTempDir`.** Root creates the dir; the dropped child creates uid-owned files in
it. **Discharged when no `TEMP DIR REMOVAL FAILED` line appears** across the runs above and §3's
criterion 5 holds. If one does appear, it has done its job and the path it names is the finding.

---

## 7. Claim G — *conditional*, and only if the workspace builds here

`.github/rust-test-count-baseline` deliberately records **no** counts: the old floor (1891)
predates the `runtime` crate and is known wrong, and `cargo test --workspace` cannot run on the
dev box because `compositor` needs graphics headers absent there. The lane may have them.

```bash
cargo test --workspace --no-run 2>&1 | tail -5    # if this fails on libudev/libseat/gbm, SKIP claim G
```
```bash
scripts/ci-test-count-gate.sh --workspace         # will FAIL and print the pair to record
```

If it builds, paste the printed `EXECUTED=` / `SKIPPED=` pair into the baseline file. If it does
not, say so — CI records it on its next run and that is the designed path, not a fallback.

---

## 8. Report back

For each claim: the command, the literal `EXECUTED/SKIPPED/reported` or `n/30`, and for §4 and
§5 the weaken's failure line as well. Per §13.5 quote the output rather than summarising, and
state executed-vs-skipped rather than a total.

**If anything fails, the failure is the result. Do not re-run to green** — and if a red looks
like a harness problem, it is one only when *shown* to be (Iron Law #15 clause 5).

---

# ROOT RUN — D0A-R12-08 and D0A-R9-01 (added 2026-08-21)

Two properties on this branch have **no live evidence** because they need euid 0, and `sudo`
in the Claude Code session has no terminal. Both are the same run.

* **R12-08** — R11-06 made execution READ a recorded credential plan and refuse when
  privileged with none. Every root execution test then died at `CredentialsNotPlanned`
  *before* the drop it exists to test. `build_action` now plans once per process. **That the
  root tests reach their subject again is REASONED, not measured.**
* **R9-01** — `an_approved_action_runs_with_the_tool_account_credentials` is the credential
  proof itself: the action's own `/proc/self/status` read from inside the jail. It SKIPs
  unprivileged, and a skip proves nothing.

## 0. Preconditions — verify, do not assume

```bash
getent passwd delphi-tool                      # expect: delphi-tool:x:997:972:…
sha256sum /usr/libexec/delphi-drop installer/staging/delphi-drop   # the two must MATCH
bwrap --version                                # expect: bubblewrap 0.11.x
md5sum /etc/pam.d/delphi-runtime > /tmp/pam-before.md5   # class 16 external check
```

Measured 2026-08-21 on this box: `997:972`, both helpers `d9ce49055ddddb85`, bwrap 0.11.1.
The helper is profile-independent — `build.rs` compiles it with `-O` in every profile — so
debug, release and installed bytes agree, and a mismatch means a stale install, not a
profile difference.

## 1. Build UNPRIVILEGED, then check the binary is the one you think

`sudo -E cargo` does not work here (sudoers drops `-E`; root has no rustup toolchain), so
build as yourself and run the produced binary under `sudo`.

```bash
cd ~/Delphi && export CARGO_TARGET_DIR=$PWD/target
cargo test -p delphi-runtime --lib --no-run 2>&1 | tail -3
BIN=$(ls -t target/debug/deps/delphi_runtime-* | grep -v '\.d$' | head -1); echo "$BIN"
stat -c '%n mtime=%y' "$BIN"; git log -1 --format='HEAD  %h %cd' --date=iso
```

**Check freshness — but NOT against the commit timestamp.** That rule mis-fires, and it did
on 2026-08-22: binary mtime `15:03:24`, `HEAD` committed `15:04:31`, so the binary read as
67 seconds STALE while in fact containing the fix. The **pre-commit hook builds and tests
before the commit object exists**, so a binary built by the hook is always older than the
commit it belongs to.

Compare against the SOURCE instead, or force the question:

```bash
sha256sum "$BIN"                                   # note it
touch runtime/src/execute.rs
cargo test -p delphi-runtime --lib --no-run >/dev/null 2>&1
sha256sum "$BIN"                                   # same hash => the run used this code
```

An unchanged hash after a forced rebuild is the proof the earlier rule was reaching for; an
unchanged hash *without* one proves nothing, which is the trap that produced three false
readings in this arc.

## 2. The run

```bash
sudo "$BIN" execute::tests:: --nocapture --test-threads=1
```

Serial deliberately: these fork and open PAM/jails, and CLAUDE.md §6's carve-out makes the
serial run the authoritative one for that shape.

## 3. What the outcomes MEAN — so the run is diagnostic, not pass/fail

| what you see | what it means |
|---|---|
| `an_approved_action_runs_with_the_tool_account_credentials … ok` with a printed `/proc/self/status` block showing `Uid: 997 997 997 997`, `Gid: 972 …`, empty `Groups:`, `CapEff: 0000000000000000` | **R9-01's mechanism is proven at root.** Observed 2026-08-22. |
| `test result: FAILED. 15 passed; 2 failed` for `execute::tests::` | **THE EXPECTED ROOT RESULT**, not a problem: the two are the intentional D0A-R9-02 REDs, by name. A prediction of "17 passed, 0 failed" was written once in this arc and was wrong — the R9-02 pair lives in this same module. Check the NAMES against the `RED=` lines in `.githooks/runtime-test-count-baseline`, never the count alone. |
| that test prints `SKIP …` | the gate did not fire — a skip proves nothing. Report the SKIP line verbatim; it names its own blocker. |
| any test fails with `no validated tool identity was recorded` | **R12-08 is NOT fixed.** The planning call is not reaching that path; the fix is wrong, not the test. |
| `the_tool_receives_its_approved_argv0 … ok` | the restored test (deleted by `f380085`) holds at root as well as unprivileged. |
| a failure mentioning `bwrap: … RTM_NEWADDR` | environment, not product — but say so rather than assuming it. |
| anything else | the failure IS the result. Do not re-run to green (Iron Law #15). |

## 4. The count, with the root baseline

The recorded pair is unprivileged (`EXECUTED=115 SKIPPED=1`). At root the credential test
EXECUTES, so the pair is **`EXECUTED=116 SKIPPED=0`** — point the gate at a different file
rather than editing the committed one for one run:

```bash
printf 'EXECUTED=116\nSKIPPED=0\nRED=execute::tests::nested_interpreter_substitution_executes_unapproved_content\nRED=execute::tests::same_inode_overwrite_executes_unapproved_content\n' > /tmp/root-baseline
DELPHI_TEST_COUNT_BASELINE=/tmp/root-baseline scripts/test-count.sh -p delphi-runtime --lib --bins
```

## 5. After — prove the run did not mutate what it does not own

```bash
md5sum -c /tmp/pam-before.md5          # the PAM stack must be UNCHANGED
scripts/check-stale-test-sessions.sh   # no leaked logind sessions
```

The PAM check is not ceremony: test fixtures deleting the operator's installed
`/etc/pam.d/delphi-runtime` is a defect this project has already paid for
(`docs/DEFECT_CLASSES.md` class 16), and it surfaced far away as unrelated tests reporting
"not installed".

## 6. Report

Paste the literal output. Per §13.5, executed-vs-skipped rather than a total, and the
`/proc/self/status` block from R9-01's test if it ran — that block IS the evidence, and
without it the pass is decorative (class 38).
