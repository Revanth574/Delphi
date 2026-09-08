# D0-A round 32 review

**Verdict: REVISE — five P2 findings.**

Reviewed `git diff 63af7f7..4a0a0b1` on `phase-3b/d0-readiness-contract`.
The checkout is `05d89c6bf482307e79110561ad1f005c2695b20f`; its only tracked change
beyond the pinned tip is the round-32 prompt. Review probes use pinned source,
or the unchanged retained round-31 extraction script. No product, test, harness,
or conformance files were edited. The files in this directory are experiments,
not installed regression tests.

## Findings

**D0A-R32-01 — P2 — A live child can disappear from the survivor scan.**
Location: `runtime/tests/b1_integration.rs:1694` (also the error handling at 1683).
Root cause: the scanner decodes the entire stat record as UTF-8 and treats every
read/decode failure as absence. Linux process names can contain non-UTF-8 bytes.
`scan-probe.py` sets such a name with PR_SET_NAME: the child stays alive in its
own group but the exact scanner returns `[]`. More decisively,
`assembly-probe.py` extracts the actual spawn/wait/scanner and assembly assertion
block. An ordinary-name counterfeit is rejected; the same counterfeit with a
non-UTF-8 child name passes every assembly assertion, `killed=false`, while the
GUARD supplies SIGKILL. This is an unprivileged oracle reproduction, not a
production/root mutation, and the currently fixed stubborn fixture has not been
shown to set such a name.
Impact: the new negative observation still admits the original false closure
for valid process records; a failed `/proc` enumeration similarly returns clean.
Fix: parse bytes through the closing comm delimiter; parse only the ASCII suffix.
Return a fallible observation, distinguish disappeared entries from observation
errors, and invalidate rather than certify an incomplete scan. Retain an actual
non-UTF-8 survivor control against the complete guard/assertion path.

**D0A-R32-02 — P2 — The real-signal guard observes the wrong process group.**
Location: `scripts/mutation-campaign.test.py:225`.
Root cause: `pgrep -g proc.pid` observes the campaign's group, while `mc.sh()`
starts each build/test command with `start_new_session=True`. Its children are
in different groups. The pre-signal `>=1` check is satisfied by the campaign
itself. The journal also precedes spawning the worker, so it is not a worker-ready
barrier.
Evidence: replacing only `_kill_active_child_group` with a no-op leaves every
check in `guard_real_signal_during_a_real_campaign` passing. Extending only its
fast shell fixture with a long-lived grandchild whose output descriptors are
closed makes the defect observable after the guard returns: it still passes,
while the probe observes live adopted descendants in different groups.
Impact: the claimed process-cleanup property does not enforce descendant cleanup.
The separate direct killer test does not establish that the signal handler invokes
that killer correctly.
Fix: have the worker publish its PID/PGID and readiness, verify the descendant
exists before signalling, then check those identities after cancellation. Keep
it alive until cancellation; a six-second natural exit inside a thirty-second
allowance is an alternative explanation for absence. Prove RED when the signal
handler's group-kill call is removed, with the rest of the fixture intact.

**D0A-R32-03 — P2 — The zombie-exclusion demonstration does not establish a zombie.**
Location: `runtime/tests/b1_integration.rs:1618`.
Root cause: `sh -c 'sleep 60 & : & sleep 60'` does not retain the short-lived
background child as a zombie; the shell can reap it before the fixed 400 ms sleep
ends. The test asserts only that returned members are non-zombies and never
asserts that a known zombie was available to exclude.
Evidence: the exact fixture had zero zombies at observation. The actual extracted
test passed 30/30 runs unchanged and 30/30 after deleting only the scanner's
`if st == 'Z' { continue; }` filter. Neither version failed.
Impact: the register and test-count baseline overclaim the demonstrated behavior;
the live-member leg works, but zombie filtering is not guarded by this test.
Fix: create an owned child that exits, use checked waitid(WNOWAIT) to establish and
retain its terminal state, and identify that PID alongside a synchronized live
child. Require the live PID present and zombie PID absent. Use cleanup guards so
an assertion failure also collects the fixture.

**D0A-R32-04 — P2 — The isolated suite still runs under an uncommitted instrument.**
Location: `scripts/mutation-campaign.py:398` (dirty refusal changed to warning).
Root cause: only the source/build cwd moves to the captured commit. The Python
interpreter continues executing the original working-tree harness, including its
mutation inventory and classifier. That harness is in INPUT_PATHS, but its dirty
state is now permitted with a message saying changes are not included.
Evidence: in a disposable repository with the pinned harness committed, an
uncommitted `MUTATIONS = []` change produced exit 0 and an empty campaign attributed
to the original commit. The warning said the changes were NOT included. The fast
suite override was recorded; the changed instrument was not.
Impact: input attribution remains false for the very tool producing the evidence.
This does not require a shared-hook/config attack.
Fix: refuse a dirty executing harness, or bootstrap/re-exec the captured harness
from the isolated checkout. If local harness changes are intentionally allowed,
retain their exact bytes/digest and identify the instrument separately from the
product commit. Document environment/toolchain inputs separately; a worktree
isolates tracked file contents, not the entire execution environment.

**D0A-R32-05 — P2 — Baseline refusal abandons the newly created worktree.**
Location: `scripts/mutation-campaign.py:409` (creation outside a lifetime finally).
Root cause: checkout removal occurs at the normal bottom of main and in the signal
handler, but not on the early baseline-refusal return or ordinary exceptions.
Evidence: the pinned harness with the documented command override `false` exits 2;
its checkout still exists and remains registered in `git worktree list`.
Impact: ordinary failed campaigns leave complete checkouts and potentially build
artifacts behind; repeated retries consume disk. The caller's source is protected,
but resource collection is not complete.
Fix: wrap the complete lifetime after checkout creation in an outer try/finally or
context manager, and check removal's return value. Test baseline failure and a
normal exception in addition to signals. Remove the temporary parent too.

## Answers to the merge-gate questions

Run 5's observation is different in kind: it samples process state BEFORE the
intervention. Our ordinary-name counterfeit is rejected by that new assertion,
which establishes real discrimination absent in run 4. R32-01 is a defect in the
observer, not a reason to deny that improvement. It recreates run 4's false green
for a valid input class.

The fixture demonstrates that the scanner can find a fork/exec child in an
inherited process group. It does not assert that the actual stubborn AI is in
the group being sampled. The cheapest additional assembly control is to publish
the fixture PID/PGID through a readiness handshake and require that exact live
PID in the scan before allowing shutdown to proceed. Pair that with the retained
counterfeit control. A full deliberately non-cleaning root daemon run is stronger,
but not the only way to verify the mapping. Process-group inheritance is a
reasonable argument for the current code; the test is not an assertion of that
assembly mapping merely because its own fixture uses the same mechanism.

Use precise wording: "no live members of the observed group remained before
harness intervention; daemon reaping was not observed." "Cleaned up" is ambiguous
because ChildOutcome::is_clean explicitly defines success to include reaping.
Also separate the two residuals: a killed-but-unreaped zombie is invisible to this
scan, but a still-live D-state child would be INCLUDED. Excluding zombies does not
make all possible Unreaped outcomes invisible. The row's three-outcome table also
cannot distinguish guard-success from guard-failure without an after-intervention
observation; the implementation records the before sample only.

For EINTR, use a deterministic syscall seam around the actual ChildGuard::reap_status
implementation: return EINTR, then a terminal status, and assert retry, preserved
result, and real child cleanup where appropriate. Include it in a required suite
and demonstrate failure when retry is removed. Keep the real-signal probe as a
separate experiment, or add a bounded stress lane with explicit observed-EINTR
and reap assertions, an execution entry point, and >=30 iterations under the
project's timing-test rule. Zero observed EINTR must be inconclusive, never a pass.
Deterministic policy coverage does not claim reproduction of the kernel signal
window; the real-signal experiment does not have to be discarded or called
permanently untestable.

Killing the child group before restoring is the right ordering. `ESRCH` cannot be
made a false success by a currently recycled, existing PID: existence would make
that assertion fail instead. It remains an instantaneous existence check, not
historical proof of which parent reaped. The three waitid terminal constants
match the terminal cases requested by WEXITED. The command seam is appropriate for
signal-lifecycle testing when it preserves the worker topology and lifetime; its
presence is not the defect in R32-02. Yes, INVALID versus a property-detecting RED
applies to weakens of the harness as well. A NameError from an accidentally deleted
global is not a RED for signal registration.

The stale-session Rust wrapper now marks both checker launch failure and nonzero
checker exit. The shell checker's REFUSE function itself still lacks the token,
so "every site emits it" is not literally true; through this Rust wrapper those
errors are nevertheless marked. I did not establish an additional misclassified
campaign through that path and do not report it as a sixth defect.

Class 51 already demands a discriminating measurement: the failure was applying
it to evidence that could certify the wrong actor. Add actor attribution and
observation-before-intervention to the examples. Merely having a measurement or
a retained PASS log is insufficient.

## Execution and retained evidence

Run each script with `python3 scratch/d0a-round32-review/<name>.py`.

- `scan-probe.py` / `.log`: exact scanner, real normal/non-UTF-8 children, and
  inspection of the exact shell zombie fixture.
- `assembly-probe.py` / `.log`: adapts the retained round-31 generator to the
  pinned guard and full assertion block. Normal-name counterfeit rejected;
  non-UTF-8 counterpart accepted. Both children were alive at counterfeit exit
  and reaped after the guard's SIGKILL. No root/PAM execution is claimed.
- `zombie-weaken-probe.py` / `.log`: exact extracted test, original and filter
  deletion, each 30 iterations using libtest's default settings (one selected
  test in this extracted binary), zero failures each. This is NOT a full-suite
  parallel stress run.
- `campaign-probe.py` / `.log`: actual real-signal guard under the no-op killer,
  longer-lived grandchild control, dirty executing instrument, and baseline
  refusal leak, all in disposable Git repositories. The fake command tests
  harness behavior and does not claim any Rust mutation result.

`scripts/check-free-space.sh` passed. `sudo -n true` reported
`sudo: interactive authentication is required`; the reported root assembly run
was not independently rerun. Full workspace builds/tests were not run; this
review used focused probes. All probe descendants were killed/reaped and created
worktrees unregistered. Final `git worktree list` contains only the original
checkout. `git status --short` shows only this untracked evidence directory.

API references checked:

- Process stat fields and states: https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html
- Process-name interface: https://man7.org/linux/man-pages/man2/PR_SET_NAME.2const.html
- Child sessions and subprocess lifecycle: https://docs.python.org/3/library/subprocess.html
