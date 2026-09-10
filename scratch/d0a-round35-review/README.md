# D0-A round 35 — REVISE

Reviewed `git diff 0ba5ddb..06eeea7` on `phase-3b/d0-readiness-contract`.
The advertised 23-file, +2431/-274 diff matches. HEAD is `4319c83`; its only
addition after the target is the review prompt. All probe sources are extracted
from the pinned target. No product or existing test sources were changed.

## Findings

**D0A-R35-01 — P2 — Apply provenance to the successful control path too.**
Location: `runtime/tests/b1_integration.rs:1707-1708`; assembly match at 2225.
Root cause: `classify_control` returns `Reached` before applying its provenance
filter. Its caller sets the Boolean from group membership plus `comm` only.
The new unit test explicitly accepts `classify_control(DAEMON, true, &[])`.
Evidence: the extracted scanner/classifier accepts a live same-group grandchild
with the requested name, even though every candidate has the wrong parent.
Adding a verified direct child outside the group still produces `Reached`:
the namesake masks the topology observation.
Impact: the successful branch retains the identity-by-name problem while the
failure branches are repaired. Run 21's statement that `Reached` verified
parentage is unsupported by the executed predicate or its retained paste. This
does not establish that the actual run-21 PID was a namesake.
Fix sketch: carry identified process records through the group-match path, bind
the match to the expected child and its lifetime, and apply the same provenance
requirements before `Reached`. Assert namesake-plus-outside-child rejection.
Correct the baseline's successful-path claim. Also, 20 polls is not 20 sightings:
the loop returns on its first match.

**D0A-R35-02 — P2 — Two misses do not establish an overlapping lifetime.**
Location: `runtime/tests/b1_integration.rs:1724-1729`.
Root cause: `missed` counts any two qualifying iterations, without matching PID,
start time, adjacency, or a liveness observation after either scan.
Evidence: spawn a named direct child in the daemon-fixture group, collect its
live candidate record, terminate/reap it, then run the unchanged group scanner.
Repeat with a different child. Both scanners correctly return no named live
member; the exact classifier nevertheless returns `Scan`. The log retains the
two distinct PIDs and start times. No scanner was weakened.
Impact: a repeated legitimate observation race still becomes a confident control
defect. The single-miss guard proves only the threshold, not the claimed window.
Fix sketch: associate observations by process lifetime, bracket the scan with
checks of that same subject, and use controlled lifetime/group/name stability in
the discriminating fixture. Without those guarantees, return `Unresolved`.
Repeating independent sequential snapshots is insufficient.

**D0A-R35-03 — P2 — Test output can still impersonate classification events.**
Locations: `scripts/mutation-campaign.py:477-479` and `533-539`.
Root cause: printable text remains the boundary between test data and trusted
events. Any captured line beginning `running ` ends the test region; any line
beginning the precondition token is treated as a precondition event without
checking its origin.
Evidence: a real compiled libtest test prints input and then fails an unchanged
ordinary equality assertion. Printing `Killed` gives `CAUGHT`. Printing
`running user command\nKilled` gives `UNATTRIBUTED FAILURE`. Printing
`DELPHI_PRECONDITION_FAILED is the payload under test` gives `PRECONDITION FAILURE`.
All have exit 101 and the same named failing test; neither a resource failure nor
a failed precondition occurred.
Impact: R34-05 remains incomplete. A property detection can be discarded based
on the data printed before it. Conflict handling is appropriate for genuine
conflicts, but this parser manufactures the producer side of the conflict.
Fix sketch: separate invocation-bound producer/precondition events from arbitrary
test text. Keep actual stdout/stderr provenance; do not treat arbitrary lines as
framing. Tightening `running ` helps this example but cannot make printable
libtest framing unambiguous. Add real-libtest printed-marker and framing-marker
cases alongside the existing expected-value cases.

**D0A-R35-04 — P2 — Retain the freshness and producer-status evidence too.**
Location: `.githooks/runtime-test-count-baseline.root:76-86` (also line 8).
Root cause: the new retention procedure preserves membership files and the test
log while leaving other acceptance inputs in `/tmp` or on the terminal.
Evidence: run 21's five retained files contain no target enumeration, before/after
hash lists, forced-rebuild transcript/status, per-target exit-status file, or
captured before/after PAM and free-space checks. The baseline asserts enforced
freshness and 17/17 zero producer exits; `root-run.log` records test output, not
those exit codes. Its complete summaries support the counts but cannot prove a
producer did not fail after printing its summary.
Impact: these acceptance claims remain operator reports, with the same independent
audit limitation explicitly acknowledged for Part B. The absence of retained
evidence does not prove any claimed check failed.
Fix sketch: retain those inputs, outputs and statuses in the run directory and
have the acceptance verifier consume them. Attribute the existing run-21 claims
as operator-reported where original captures cannot be recovered. Re-running a
freshness or hygiene check now cannot reconstruct the historical check.

**D0A-R35-05 — P3 — Preserve multiplicities in retained identity lists.**
Location: `scratch/lane-run-7-procedure.md:259-262`.
Root cause: comparison uses Counters, but serialization iterates their keys.
Evidence: `{a:2,b:1}` and `{a:1,b:2}` have equal totals and serialize to identical
retained identity lists, despite being different multisets.
Impact: the persisted inputs do not retain the property the in-memory comparison
checks. Root multiplicity can be reconstructed from the producer log; unprivileged
multiplicity cannot, because its raw `--list` outputs are not retained. This is
a format defect, not a demonstrated mismatch in run 21: that run's retained
identities and producer log agree at 229, with no duplicates.
Fix sketch: serialize `Counter.elements()` or explicit counts and retain checked
`--list` outputs/statuses. Test a duplicate-identity case through capture and replay.

**D0A-R35-06 — P3 — Remove the motive attribution left in class 53's body.**
Location: `docs/DEFECT_CLASSES.md:2957-2958`.
Root cause: the title and introductory discussion were corrected, but the instance
still says the rule was “picking the reading its author wanted.”
Impact: the authoritative entry repeats the unsupported motive inference its own
new introduction rejects. The counterexample establishes a wrong classification,
not what its author wanted.
Fix sketch: say the rule selected the closure-preserving diagnosis in the
constructed topology case; omit the author's presumed preference. This is the
existing class-48 remediation pattern, not a new class.

## Requested decisions

**The two `Reached` results are bounded positive evidence, not proof of agreement
or of discrimination.** An expected result can be useful evidence; its agreement
with an author's expectation does not make it worthless. Conversely, two successes
cannot establish that the diagnostic distinguishes alternatives. Here the claimed
instrument improvement on the successful path is specifically overstated by
R35-01. Keep run 21 as an attributed observation of the reported group/name match,
and do not promote it to verified parentage. The probes establish classifier
counterexamples, not that the production daemon violated boundedness.

**The cheapest real non-`Reached` fixture needs no PAM or product change.**
An owned parent in its own group spawns one live named direct child using
`.process_group(0)`. The pinned observer reads actual `/proc` records and returns
`Topology`; after collecting the child, no candidates yields `Unresolved`.
This review executed that construction unprivileged. Rust documents that zero
selects the child's PID as its group ID:
[CommandExt::process_group](https://doc.rust-lang.org/std/os/unix/process/trait.CommandExt.html#method.process_group).
Run the same small fixture under root if root observer execution is the missing
evidence. It would still certify the observer fixture, not the real daemon/PAM
assembly; a misassembled daemon fixture is needed for that stronger claim.

`ppid` is a useful necessary discriminator for the current direct-spawn AI
topology in `fork_ai`; it is not a role identity for arbitrary descendants.
Reparenting/intermediary cases should remain unresolved unless separately bound.
The parser's ppid/pgrp/starttime indices agree with
[proc_pid_stat(5)](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html).
Recording starttime does nothing for lifetime association until classification
actually uses it. Also, the prompt overstates the parser consolidation:
`live_group_members` still has its own stat parser.

**Retain the labelled Part B transcription as history.** Its explicit warning
prevents silent substitution when downstream claims preserve that qualification.
Committing it does not turn it into captured, independently verifiable evidence.
R35-04 identifies the next retention boundary: freshness hashes, producer exits,
and hygiene checks. The same restriction applies to those operator summaries.

**Assert enumeration with deliberately held, identified subjects.** The current
survivor fixture asserts merely nonempty, so it does not prove both of its live
children are returned. Extend a controlled fixture to hold two distinct named
children alive, confirm their identities and group membership before scanning,
and assert both PIDs occur, with the leader and demonstrated zombie excluded.
A scanner returning at most one member must fail that assertion. For an assembly
enumeration claim, add a synchronized non-AI witness with a guaranteed lifetime.
Do not assert an incidental census length or a particular transient comm: the
forked daemon image execs into the shell, and PAM helpers are transient. The
printed census is accumulated across polls, not a simultaneous whole-group
snapshot. A two-member check establishes that fixture property, not universal
exhaustiveness over arbitrary groups.

**Continuing to defer the acceptance verifier while using another manual lane as
merge acceptance is now unreasonable.** Round 34's condition was to schedule it
before relying on another lane for merge acceptance. Run 21 incurred another
manual capture, and the new unset-variable guard does not enforce check ordering,
successful completion, or evidence retention. Build one executable procedure with
a per-run evidence manifest and a verifier rejecting missing, failed, stale or
misordered required steps. It can be small and local. Until it exists, call lane
acceptance a manual audit and keep R22-01 open. The unset-variable incident itself
does not establish that a stale file was actually accepted; that remains a
counterfactual, not an observed run-21 outcome.

## Verification and scope

- `probe.py` / `probe.log`: exact pinned scanner/classifier with owned live
  processes; false `Reached`, masked topology, false `Scan`, real `Topology` and
  `Unresolved`; real libtest output through `run_suite`; membership replay and
  multiplicity-loss demonstration. `libtest-*.log` captures the classifier inputs.
- `guards.py` / `guards.log`: all **88** pinned campaign guards passed in a
  disposable repository. All six specified weakens fail on their intended
  assertions: provenance, liveness, window threshold, whole-blob matching,
  unanchored precondition token, and omitted registration verification. The
  whole-blob weaken now yields **UNATTRIBUTED FAILURE**, not INFRASTRUCTURE,
  because the new conflict branch runs first; it still fails the intended guard.
- `count.log`: retained run-21 log re-extracted as **223 executed / 6 skipped /
  229 reported**, rc 0, expecting 17 targets. Producer-derived identities exactly
  match both retained 229-line lists. Expectation commit `d1fa4fe` precedes the
  measured-record commit `06eeea7` and changes only the expectation file; git order
  does not independently timestamp the actual measurement.
- The genuine-event and marker-as-expected-value directions are guarded and pass;
  they do not cover R35-03's framing/printed-data examples. The registration fix
  detects the locked-worktree case. No demonstrated additional owned cleanup
  resource was found in the reviewed path.
- Free-space guard passed. No root/PAM lane, full workspace build, production
  mutation campaign, or new stability claim was made. Disposable worktrees and
  probe-owned children were collected. Only this review-evidence directory was
  added; existing repository files are unchanged.
