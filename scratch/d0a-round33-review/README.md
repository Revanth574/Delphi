# D0-A round 33 review

**REVISE — four P2 findings.** Reviewed `05d89c6..5fca885` on
`phase-3b/d0-readiness-contract`. Checkout HEAD was `04428d2`; its sole change beyond
the pinned tip is the round-33 prompt. All executable probes extract pinned source.
No product, regression-test, harness, or conformance files were edited.

## Findings

**D0A-R33-01 — P2 — Failed checkout deletion is still silent.**
Location: `scripts/mutation-campaign.py:222-227`.
Root cause: the lifetime finally invokes cleanup, but cleanup discards Git's return
status, uses `shutil.rmtree(..., ignore_errors=True)`, and clears its ownership record
unconditionally. Invocation is not successful collection.
Evidence: `probe.py` creates a real isolated checkout containing an owned, nonempty
mode-000 directory. The exact cleanup returns normally, with the parent and tree still
on disk, no Git registration, and `_WORKTREE == {}`. Thus this reproduces precisely
the filesystem/registration divergence R32-05 was supposed to close. The probe restores
permissions and collects its own residue afterward.
Impact: a successful campaign can still finish without reporting a cleanup failure;
the outer finally cannot retry because the identity was discarded. Repeated failures
consume disk while the registration list looks clean.
Fix: check removal results, verify both the owned filesystem path and registration
are gone, retain the identity on failure, and report a nonzero cleanup outcome with
the surviving path. Exercise a real removal failure as well as omitted cleanup.
Python explicitly documents that `ignore_errors=True` suppresses failed removals:
[shutil.rmtree](https://docs.python.org/3/library/shutil.html#shutil.rmtree).

**D0A-R33-02 — P2 — The EINTR regression test leaks its signal sender on its RED path.**
Location: `runtime/src/test_child_guard.rs:304-309`.
Root cause: stopping/joining the hammer and restoring SIGUSR1 happen only after
`guard.reap_status()` returns normally. The exact regression being tested panics there.
Unwinding drops the JoinHandle without stopping the thread and leaves the handler installed.
Evidence: the extracted restored test returns with zero additional signals over the
next 100 ms. Delete only the EINTR retry and catch the resulting panic on the same
thread: the retained run records seven additional signals after the function unwinds.
The isolated observer process is then terminated normally, collecting the sender.
Impact: the failure path contaminates the rest of the test process; once the target
test thread's lifetime ends, the sender's safety premise is no longer valid.
[pthread_kill(3)](https://man7.org/linux/man-pages/man3/pthread_kill.3.html) documents
undefined behavior for an expired thread ID.
Fix: use unwind-safe ownership for the sender and installed disposition. On every
exit, stop and join the sender before restoring the disposition and before the target
thread can exit. Verify cleanup after the deliberate retry-deletion panic.

**D0A-R33-03 — P2 — A nonempty census does not establish that the control is defective.**
Locations: `.githooks/runtime-test-count-baseline.expected:66-75` and
`runtime/tests/b1_integration.rs:2031-2037`.
Root cause: the new outcome partition treats nonempty-without-AI as proof of a
probe defect and empty as proof of an assembly defect. Neither implication follows.
Evidence: `probe.py` runs the exact scanner and polling body against a stand-in daemon
with two actual children: one remains in its inherited group, while the correctly
named `sai` child has a separate group. The result is `seen=[]` and a nonempty census
containing the other child. This is a constructed topology defect, yet the new rule
classifies it as a control defect. Only the poll horizon is shortened, from 140 s to
1 s; both children remain alive throughout. This is an unprivileged observer probe,
not evidence of such a defect in the production launcher.
Impact: the committed policy says to preserve closure and fix the control for precisely
a result that can mean the observer cannot reach the AI. Empty samples also cannot
prove the group was never populated between polls or before the probe was scheduled.
Fix: fail the run with cause unresolved in both cases. Retain observations, then check
the AI's actual identity, process group, and lifetime before assigning fault. A fixture
identity handshake checked against kernel state is legitimate independent observation;
it does not supply the daemon's cleanup.

**D0A-R33-04 — P2 — The narrowed register prose leaves its contradictory causal table intact.**
Locations: `docs/CONFORMANCE_REGISTER.md:65-73`, contradicted by the changed statement
at lines 91-93 that the narrowed sentence is the whole claim.
Root cause: the rewrite narrows the quoted sentence but leaves a table asserting that
the run distinguishes three outcomes. It still labels the empty sample “the DAEMON
cleaned up” and claims to recognize “neither” through a still-alive-after observation.
`DaemonRun` retains only the pre-intervention survivor sample; there is no corresponding
after-intervention sample. The round-32 review already called out this table.
Impact: the trusted row still makes the causal claim the new prose says it withdrew,
and advertises a discriminator the test does not implement.
Fix: replace the table with the observations actually retained: live members found,
none found, or observation incomplete. If distinguishing successful/failed harness
cleanup is needed, add a separate post-intervention observation and limit its claim
to that actor. Preserve the explicit reaping limitation.

## Decisions requested by the prompt

**The human-transcription decision does not survive as a stronger enforcement strategy.**
R23-05 justified rejecting that particular runner; it did not establish that manually
reimplementing the procedure preserves its checks. Run 20 demonstrates the contrary.
This does not invalidate completed test outcomes, nor justify reinstating the defective
runner. It does require revising the mechanism for accepting future lane evidence.

The third option is a single authoritative collection of executable steps, with the
runbook rendered from it (or executable blocks extracted without transcription), plus
a separate acceptance verifier. Existing helper checks should be invoked directly.
Each invocation retains its command, exit status and evidence under a run ID bound to
the source SHA, expectation commit, procedure revision, target list and binary hashes.
The verifier rejects missing, failed, stale or out-of-order required records. It must
recompute membership from retained lists/transcripts and require a passing space check
before allowing the build step. Exercise omission of each required step and a forced
precondition failure. This is a concrete design requirement, not a claim that an
unimplemented verifier is already trustworthy.

A manually ticked checklist is an aid, not this enforcement boundary. It still allows
“checked” without execution or after a refusal. Nor can a tool prevent a machine owner
from deliberately bypassing it; what it can enforce is that such a run does not acquire
the normal accepted-lane status. An exception must remain visibly exceptional rather
than silently rewriting the guard's result.

The two lapses share a useful parent class: **required checks are not coupled to the
action or acceptance they are supposed to govern**. Record distinct variants: omitted
execution and ignored refusal. Classes 5/21 describe the convention/enforcement theme;
39 covers an existing check not run at the necessary trigger. “It fired and we stepped
over it” needs an explicit example/variant; classes 49 and 51 do not cover it. Prefer
this bounded operational description to a class called “human error.”

**The strengthened sentence:** no additional defect is established in its literal,
run-scoped claim. A live sighting at T1 establishes a reachable positive result; a
complete scan at T2 observes membership of that group at T2. This does not prove the
AI never changed groups, universal scanner completeness, or reaping. Suggested wording:
“In lane run 20, the scanner observed the staged AI in the daemon's group while it was
running and found no live members of that group in the pre-intervention shutdown scan;
daemon reaping was not observed.” R33-04 concerns the additional claims surrounding it.

The successful probe retains **no census in the transcript**: `seen`, `census` and sample
count are local variables, and their only diagnostic use is inside the failed assertion.
Returning early is sufficient for an existential positive control; it does not preserve
a history. Print or serialize the positive witness and the shutdown sample, including
PID/start-time identity and observation times, if later rereading is required. The
corpus already treats this as class 38's transcript convention, not evidence that the
passing assertion itself is false. A passing explicit control is also not class 49's
silence: it answers a specified question, albeit a narrower one than general closure.

**R32 sufficiency:** the enumeration-failure sentinel makes the shutdown assertion fail
closed, as intended; it cannot satisfy the `sai` match. It would be clearer to return an
explicit incomplete-scan result. `entries.flatten()` still drops enumeration errors,
and malformed pgrp parsing still drops a record; these residual paths were inspected,
not demonstrated as real `/proc` failures here, so they are not extra findings.
The new zombie construction checks WNOWAIT and the actual Z state, which gives the
exclusion assertion a real subject. Ten failing weakens are useful discrimination
evidence; they do not replace the project's separate >=30 restored stability requirement.
No zombie-filter repeat run was performed in this review.

The dirty-instrument flag implements the previously offered third option for ordinary
local edits: retain and separately identify the instrument. Explicitly allowing an
identified different instrument is not the same as silently stepping over a failed
precondition. This is not complete environment reproducibility, and the retained file
must be placed in the documented repository context to replay it.

**The four claimed campaign weakens were independently reproduced.** Restored guards
passed, and C/A/D/B each failed on the exact assertion named in the prompt; see
`campaign-guards.log`. This supports those four cases, not a universal assertion about
all weakens. Retain executable patches, expected assertion IDs and restored controls,
and have a checker reject a failure at any other assertion. R33-01 demonstrates why
omission mutations alone do not cover failed deletion.

**EINTR is regression guarded, with R33-02 still owed.** A required test exists and the
retry deletion demonstrably fails at `Err(EINTR)`. Delivery count is not an observed-EINTR
counter, so a single green run does not certify kernel interruption on that run. The
reported 30 restored parallel iterations were not independently rerun here; the extracted
restored/weak pair is a focused check, not a replacement for full-suite parallel stress.

**Derivation:** the corrected grep fixed this instance; matching count partitions cannot
prove identical identities. Use compiled libtest `--list` inventories at the pinned
before/after revisions to enumerate added/removed identities, then inspect source for
their gates. Keep grep for inspection, not as the authoritative test inventory.

**227/227 membership:** the record claims it; this review cannot independently certify
it. `/tmp/root-run20.log` and `/tmp/targets.txt` no longer exist in this environment,
and the pinned range retains the conclusion rather than those inputs. Neither matching
totals nor a present-day inventory reconstructs that historical root observation.
This is the artifact-retention weakness described in the prompt, now observable to a
subsequent reviewer; it is not evidence that the claimed comparison was false.

## Validation and scope

- `python3 scratch/d0a-round33-review/probe.py`: all three focused probes reproduced;
  exact results in `probe.log`. Rust helpers link the existing local nix build.
- `python3 scratch/d0a-round33-review/campaign-guards.py`: restored guards passed;
  all four weaken failures attributed to their expected assertions. Disposable Git
  repositories and a private TMPDIR isolate mutations and cleanup observations.
- Space precondition passed. No root/PAM run, full workspace build, production mutation,
  or complete Rust-suite stability claim is made. All probe-owned worktrees were
  collected; actual repository registration remains the original checkout only.
- Review artifacts are experiments, not newly installed regression guards.
