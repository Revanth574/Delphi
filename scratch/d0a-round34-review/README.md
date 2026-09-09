# D0-A round 34 review

**REVISE — five P2 findings.** Four concern this remediation; the fifth is a
pre-existing classifier defect examined at the prompt's explicit request.

Reviewed `04428d2..d94875d` on `phase-3b/d0-readiness-contract`. Checkout HEAD
`0ba5ddb` adds only the round-34 prompt beyond the pinned tip. Probes extract
the specified revisions and operate in disposable repositories/processes. No
product, regression-test, harness or conformance files were changed.

## Findings

**D0A-R34-01 — P2 — A system-wide namesake is treated as this run's AI.**
Locations: `runtime/tests/b1_integration.rs:1634-1635`, `2093-2102`.
Root cause: `processes_named` identifies candidates only by `comm`; the verdict
treats any matching PID outside the daemon's group as the daemon's AI. There is
no connection to the launched child, session user, executable identity or run.
The staged AI's actual name is the short, fixed `sai`, not a unique run identity.
Evidence: the extracted scanner and exact verdict code diagnose TOPOLOGY when
the target daemon is a separate owned process with no AI child, and a sibling
process merely has the expected name. The probe uses a unique temporary name
to avoid interference from real processes; the matching logic is unchanged.
Impact: an unrelated process can turn an unresolved control failure into a
confident assembly diagnosis. It can also override an in-group sighting because
`elsewhere` takes precedence. The new diagnostic still assigns causes that its
evidence cannot establish.
Fix: obtain the actual launched child's identity and bind observations to it
(PID plus lifetime/start time or a held process handle, with executable/run
provenance). Treat a name lookup as candidate discovery only. Unverified
candidates must not decide TOPOLOGY. A sighting outside the group establishes
observed membership there, not that the child never inherited another group
or that historical runs were invalid.

**D0A-R34-02 — P2 — Zombies become evidence of a missed live AI.**
Location: `runtime/tests/b1_integration.rs:1642-1647`.
Root cause: the new parser returns PID/PGID without checking or retaining state.
`live_group_members` intentionally excludes zombies, but `processes_named` does
not. The diagnostic interprets the latter's records as sightings while alive.
Evidence: the probe holds a correctly named child terminal with checked
`waitid(WNOWAIT)` and confirms `Z` before either scan. `processes_named` includes
it; the live scanner correctly excludes it; the exact verdict nevertheless
returns SCAN and calls the control defective. No live observation was missed.
Impact: the new cause classifier turns expected zombie filtering into a scanner
diagnosis, repeating the ambiguity problem under a richer-looking record.
Fix: retain state and observation time alongside verified identity. Only live
sightings qualify as live evidence. Establish an overlapping observation window
before concluding that a live scanner missed a subject; two sequential snapshots
can legitimately differ. A zombie-only observation cannot decide SCAN.
The Linux process-stat documentation explicitly distinguishes `Z` from live states:
[proc_pid_stat(5)](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html).

**D0A-R34-03 — P2 — “Both resources gone” verifies only the filesystem.**
Location: `scripts/mutation-campaign.py:242-250`.
Root cause: final-state verification checks `path` and `parent`, but never checks
Git's registration. The preceding remove/prune commands can fail or retain an
entry; their results do not substitute for observing the final registration.
Evidence: create a disposable checkout, lock its registration, then invoke the
exact cleanup. It returns `True`, removes the directory, clears ownership, and
leaves the locked registration in `git worktree list --porcelain`. The probe
unlocks and prunes its own entry afterward.
Impact: cleanup can still report success and forget a resource it owns. Exit 4
cannot catch this case because the cleanup predicate itself is falsely true.
Fix: verify both filesystem absence and absence of the exact Git registration.
On an unreadable registration list or a remaining entry, retain ownership and
report failure. Retry/prune after filesystem cleanup where appropriate; do not
blindly override an external lock. Git documents that locks prevent pruning:
[git-worktree](https://git-scm.com/docs/git-worktree).

**D0A-R34-04 — P2 — Both replacement tables still infer successful harness killing.**
Locations: `docs/CONFORMANCE_REGISTER.md:81` and
`runtime/tests/b1_integration.rs:1764`.
Root cause: the rewritten nonempty row says the guard's kill ended the members,
while the immediately following explanation admits there is no post-intervention
observation. Issuing a kill is not observing death or establishing its cause.
Also, a nonempty vector may contain the scanner's unknown sentinel rather than
a demonstrated live member. Both introductions still say “three outcomes.”
Impact: R33-04 remains incompletely remediated in both copies. The table asserts
exactly the guard-success distinction the new prose says cannot be made.
Fix: describe the nonempty result as a failed/incomplete pre-intervention scan
that invalidates the daemon-cleanup inference. For verified live records, say
members were observed alive before the guard attempted intervention. Claim no
post-intervention result without a separate observation. Remove the stale
introductions. Unknown records must remain distinguishable from live members.

**D0A-R34-05 — P2 — Assertion data is classified as infrastructure evidence.**
Location: `scripts/mutation-campaign.py:456-465`.
**Pre-existing; included because the prompt explicitly asks to audit `run_suite`.**
Root cause: substring searches across all captured output treat markers inside
ordinary panic data as reports from the infrastructure or precondition mechanism.
Evidence: run a real compiled libtest assertion `assert_eq!("altered payload",
expected)` through the actual `run_suite` command seam. Changing only `expected`
from `ordinary payload` to `Killed` changes CAUGHT to INFRASTRUCTURE; changing it
to `DELPHI_PRECONDITION_FAILED` changes the verdict to PRECONDITION FAILURE.
All three executions have exit 101 and the same named failing test. No resource
or precondition failure occurs; the marker is the expected value in an assertion.
Impact: a genuine property failure can be discarded or misdiagnosed because its
data happens to contain a marker. The token solved vocabulary drift but did not
establish origin. This probe establishes a classifier defect, not that a retained
production mutation result has already been affected.
Fix: separate structured producer/precondition events from test output and bind
them to the invocation. Do not infer cause from arbitrary assertion text. When
provenance is unavailable or causes conflict, return an unresolved/unattributed
outcome rather than asserting infrastructure causality. Add marker-as-data
counterexamples to the classifier's required checks.

## Decisions requested

**The quoted run-20 sentence can stay. The entire row is still not correct.**
“No live members remained” is defensible as the scoped sample observation, not a
causal claim; the explicit run/group/time scope does real work. “The pre-intervention
scan returned no live members of that group” would state the instrument's result
more directly. Reaping need not be observed before recording this narrower evidence.
Do not stretch that evidence to a closure whose obligation explicitly includes
reaping. R34-04 is the remaining contradiction, rather than a reason to delete
sound observations. The prose/table duplication is class 48 applied to documents,
not a new defect class. Prefer one concise authoritative account over accumulated
correction narratives that retain contradictory fragments.

**Class 53 is useful if stated as unsupported causal attribution.** It is not
merely class 45: the error can occur with positive observations and no universal
absence claim. Two different causes can produce the same evidence, so a
deterministic choice between them is not identification. However, the current
title's universal assertion about what the author wanted is itself unsupported.
A wrong classifier can arise from mistaken assumptions without a preference.
Nor was every individual statement in the old diagnostic true: “this is a defect
in the control” was false in the constructed case.

Keep the symmetry question as a bias check, not a correctness test. The stronger
engineering test is: construct distinct causes compatible with the same observed
record, and require the diagnostic to remain unresolved unless it collects a
discriminator. Expected-case tests are useful too; they simply do not establish
exclusivity. R34-01/02 show that the replacement moved the unsupported inference
into identity/lifetime assumptions. R34-05 supplies the requested second example.

**The cheapest verdict coverage needs no root/PAM run.** Extract observation and
classification into functions over explicit process snapshots and typed outcomes.
Test each branch with controlled owned children, an outside-group child, an
unrelated namesake, a confirmed zombie, missing/unreadable evidence and an exit
between observations. Make the expected decision an assertion. The review's
`probe.py` already executes the exact TOPOLOGY, SCAN and UNRESOLVED blocks with
real process records, including counterexamples; these retained experiments are
not installed regression guards or a root assembly execution. Do not wait for a
root control failure merely to test pure decision logic.

**Keep the lost membership check as explicitly attributed history, not accepted
membership evidence.** The record should say inline at its headline: “operator
reported 227/227; comparison inputs were not retained; independently unauditable.”
The caveat currently appears later while the top membership line remains unqualified.
There is value in recording what was reported, but neither that report nor matching
totals fulfils a reproducible identity-set acceptance requirement. We cannot declare
the report false, and should not certify it as true solely because its author does.
A new retained comparison is new evidence, not reconstruction of run 20. This
conclusion assumes no independent copy of the lost inputs can be recovered.

**The EINTR sender fix has demonstrated impact beyond defence in depth.**
`sender-probe.py` deletes the retry in both old and fixed versions, runs the actual
test body on a thread, joins that thread, and starts a subsequent thread. In all
three retained runs each, the thread identity is reused. Before the fix the new
thread receives 51/53/54 signals over 300 ms and its unrelated `waitpid` returns
EINTR; afterward it receives zero signals and that wait returns the child's exit.
Both versions still report the intended initial test panic: aggregate PASS/FAIL
counts were observing the wrong property. These are isolated-process experiments,
not a claim about full-suite failure frequency or >=30-run stability.

Unwinding a function alone does not expire its thread ID; thread termination and
the ID's lifetime matter. In the constructed reuse case, the stale sender targets
a different live thread. `pthread_kill` is not guaranteed to turn misuse of an
expired ID into ESRCH; the documented behavior is undefined:
[pthread_kill(3)](https://man7.org/linux/man-pages/man3/pthread_kill.3.html).
The new guard stops/joins the sender and restores the disposition on the tested
panic path. That remediation discriminates on the relevant mechanism and effect.

**Cleanup exit propagation is correct for the paths tested, apart from R34-03's
predicate.** A mode-000 resource causes exit 4 after an otherwise successful body;
an ordinary exception stays the original exception with a cleanup diagnostic;
SIGTERM remains exit 143 with cleanup diagnostics and retained ownership. Preserving
an already-failing exit is reasonable; literal exit 4 everywhere is not required
to prevent false success. The comments should describe that distinction accurately.

**`eprintln!` is a suitable observer channel when retained.** This writes from the
test process, not the daemon's captured stderr. The sanctioned lane command uses
`--nocapture` and merges stderr into the log, so it will retain it. Default libtest
capture suppresses successful output; `--nocapture` or `--show-output` is therefore
part of the retention contract. Printing alone is not durable storage and cannot
retroactively add witness data to run 20.

**Deferring the acceptance verifier is reasonable only as an explicit next-increment
dependency.** No new lane ran here, so this round did not incur another transcription.
The deferral must not be described as fixing R22-01 or as making future manual runs
equivalent to verified ones. Schedule the verifier before relying on another lane
for merge acceptance; until then, required-check omissions remain possible and lane
acceptance remains a manual audit. This separates implementation scope from the
evidence requirement without restoring the rejected runner.

## Retained verification

- `probe.py` / `probe.log`: exact cleanup with locked registration; cleanup exit,
  exception and real SIGTERM propagation; extracted process scanners and all three
  verdicts; actual libtest outputs passed through the real campaign classifier.
- `sender-probe.py` / `sender-probe.log`: old/fixed retry-deletion comparison,
  three isolated runs each, including a subsequent thread's wait behavior.
- `campaign-suite.py` / `campaign-suite.log`: **77 guards held** in a disposable
  repository with a private TMPDIR. This validates existing guards, not the missing
  cases established by this review.
- Free-space guard passed; no root/PAM lane, full Rust suite, full workspace build
  or production mutation was run. Probe-owned children and worktrees were collected.
  The actual repository has only its original worktree. Only this evidence directory
  is untracked; product/test/harness/documentation sources are unchanged.
