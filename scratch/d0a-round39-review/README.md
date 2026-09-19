# D0-A round 39 review

**REVISE — three P1 findings and two P2 findings.**

Reviewed `git diff 715248a..c560cae` on `phase-3b/d0-readiness-contract`.
The advertised seven commits and `32 files changed, 2180 insertions(+), 156 deletions(-)`
match Git. HEAD was `d2622725b32e6256b66f32c910378fee5b4a5264`; its only difference from
the pinned endpoint is the round-39 prompt. Product and test files match the pin.

All three requested suites exited **0**: weaken driver **45**, lane acceptance **112**,
mutation campaign **108**. Their complete streams are retained as `*-suite.log`.
Review mutations were applied only to temporary copies / an isolated worktree of
`c560cae`. No product files were edited. The isolated worktree was removed after recording
its patch and suite output. No root or seated-lane claim is made.

The prompt's pre-foreclosed classes were not re-hunted. Findings concern classes 12, 16,
22 and 58; the authority discussion concerns 54. The documented setsid escape and other
listed open items are not presented as new findings.

## D0A-R39-01 — P1: validation can load the original's bytecode and certify an invalid mutant

**Location:** `scripts/weaken-driver.py:201-205` (`_validation_cmd`).

**Root cause:** the new import-based validation uses `spec.loader.exec_module`, which may
load a timestamp-based `.pyc` created by original validation. A same-size replacement in
the same timestamp second leaves that cache valid. The disk digest measures the mutant,
while `mutant_loads` measures the original's bytecode.

**Reproduction:** on a temporary target, change `FLAG = 1` to `FLAG = X`. The suite executes
the target directly and reports `subject-imports-clean` when that command fails. The pinned
driver returned **RED_PROVEN**, `original_loads=true`, `mutant_loads=true`, and the expected
label. Executing those exact mutant bytes directly exited **1**, with **NameError: name 'X'
is not defined**. The entire driver record and direct execution stderr are retained in
[`cached-invalid.json`](cached-invalid.json). Run `python3 scratch/d0a-round39-review/probe.py`
to reproduce; the probe aligns its short experiment near the beginning of a timestamp second.

**Impact:** R38-03's invalid-experiment-as-proof defect remains reachable through the new
validator, without a forged label or hostile report writer.

**Fix:** execute the exact current source bytes in a correctly initialized module namespace,
without accepting cached target bytecode, and bind validation to their digest. Ensure the
suite also observes the mutant. Add a same-size/same-timestamp invalid mutant guard. Merely
adding `-B` does not prevent reading an existing bytecode cache.

## D0A-R39-02 — P1: signal restoration leaves the active suite able to overwrite it

**Location:** `scripts/weaken-driver.py:323-327` (`_on_signal`).

**Root cause:** the signal handler restores and deletes the backup, then terminates the
driver without collecting the active `_run` process group. The suite's new session survives
the driver's death. `_run` never resumes to execute its cleanup.

**Reproduction:** a temporary suite signals readiness after observing the mutation, sleeps
one second, then writes the target. Send SIGTERM to the real driver only after that readiness
file exists. Driver exit is **-15**; the target immediately contains its original bytes;
after the suite wakes it contains **CLOBBERED BY ACTIVE SUITE**; the backup is absent.
The suite's PID equals its PGID: **there is no descendant setsid escape**.
See [`signal-survivor.json`](signal-survivor.json) and `probe.py`.

**Impact:** an ordinary interrupted run leaves working-tree damage after apparently
successful restoration and removes the recovery copy.

**Fix:** track active child groups across every invocation. On cancellation, terminate and
wait for the managed work before restoration; verify restored bytes before removing the
backup. Add a signal guard that attempts a delayed write and observes the target after that
deadline. The current SIGTERM guard observes only immediate bytes and backup absence.

## D0A-R39-03 — P1: the new validation subprocess is outside lifecycle management

**Location:** `scripts/weaken-driver.py:208-216` (`_loads`).

**Root cause:** validation now executes target code but uses plain `subprocess.run`, bypassing
the process-group ownership and collection implemented for suite invocations. Even a
successful import can leave ordinary children running after restoration.

**Reproduction:** a temporary, valid mutant starts a child at import, with detached stdio
but **without** `start_new_session` or `setsid`. The child waits one second and writes the
target. The suite reports the intended flag guard, then passes after restoration. The
driver returns **RED_PROVEN** with matching restoration digests. One second later the target
contains **CLOBBERED BY VALIDATION** and no backup remains. The actual record and replacement
source are in [`validation-survivor.json`](validation-survivor.json); `probe.py` reproduces it.

**Impact:** the newly introduced execution phase reintroduces the post-restoration damage
R38-02 intended to contain. This is distinct from the documented group escape: this child
was never put under a group that the driver manages.

**Fix:** put baseline and mutant validation through the same managed invocation primitive,
with group collection on success, failure, timeout, cancellation and exceptions. Add a
validation-child guard independently of the suite-child guard.

## D0A-R39-04 — P2: the new failure-section boundary has no discriminating guard

**Location:** `scripts/mutation-campaign.test.py:675-688`.

**Root cause:** the new two-binary fixture includes both `failures:` headers but no
name-shaped captured output between them. Both `find` and `rfind` therefore produce the
same names. The fixture verifies binary segmentation but cannot verify exclusion of the
captured-output section.

**Reproduction:** in an isolated pinned checkout, replace `body.rfind("failures:")` with
`body.find("failures:")`. The entire campaign suite still exits **0**, **108 guards held**.
[`campaign-weakened.log`](campaign-weakened.log) retains the full output;
[`surviving-weakens.patch`](surviving-weakens.patch) retains the exact change.

An independent real Cargo crate has a failing `genuine_guard` that prints
`failures:\n    fabricated_name`. Actual Cargo execution exits **101**. The pinned parser
correctly returns **CAUGHT**; the weakened parser returns **UNATTRIBUTED FAILURE**, having
counted the captured-output name as a second failure. Both full producer streams, parsed
records and outcomes are in [`parser-discrimination.json`](parser-discrimination.json).
Run `python3 scratch/d0a-round39-review/guard-probes.py` for the real-producer comparison.

**Impact:** the suite stays green when this range's captured-output exclusion is removed,
although a genuine detection is lost. This is a coverage defect, not a claim that the
pinned `rfind` implementation failed this input.

**Fix:** retain the real transcript (or an equivalent explicit fixture), assert only the
final name list supplies attribution, and demonstrate that this exact weaken fails that
guard. Keep enumeration expectations independent of the parser under test.

## D0A-R39-05 — P2: snapshot forwarding guards check the assignment token, not its value

**Location:** `scripts/lane-accept.test.py:572-580`.

**Root cause:** the three new assertions count command lines, check the presence of
`DELPHI_FAILURE_SNAPSHOT_DIR=`, and check the `sudo env` prefix. None observes the path
passed to the test process.

**Reproduction:** replace `$SNAPDIR` with unset `$SNAP` in all three explicit assignments
in the procedure. The entire lane suite still exits **0**, **112 guards held**; see
[`lane-weakened.log`](lane-weakened.log) and the retained patch. Execute the actual loop
command with initialized SNAPDIR, unset SNAP, an argv-preserving stand-in for sudo and a
child that prints the received variable. The original delivers the intended directory;
the weaken delivers **an empty string**, both exiting **0**. Full commands and child
observations are in [`snapshot-value.json`](snapshot-value.json).

**Impact:** the guards accept the same variable-arrangement defect described as the round's
near-miss. Rust sees an existing empty variable, so its new unset-variable diagnostic does
not trigger; its formatted output path becomes `/at-failure-...txt`.

**Fix:** exercise all three procedure invocations through a command receiver with SNAPDIR
set and unrelated variables unset, and assert the received value equals the intended
directory. An argv-preserving sudo stand-in suffices to check shell expansion; it does not
prove real root environment delivery, which remains explicitly unverified.

## Authority, records, and the three stated limits

The clarified informal authority changes the sequencing. Proof publication already has a
consumer: reviewers and commit readers granting credit to `RED-proven`. It needs a record
now, independently of future lane-acceptance integration. Keep using the tool for exploration
on disposable copies, but suspend authoritative proof credit until the defects above are
fixed and retained evidence can be reopened. Existing claims need reruns or an explicit
unverified disposition; passing these suites does not recover their missing history.

A minimal first mechanism can be an independent wrapper that retains the expected guard
before execution, instrument and suite identities, target before/mutant/restored bytes or
digests plus the patch, argv/cwd and relevant configuration, phase outcomes, reports, full
stdout/stderr, restoration evidence, and a stable record ID. The rule that credits claims
only through such records is already a consumer. A future CI gate can enforce presence,
identity and schema; none of those checks alone establishes causal validity. Producer and
consumer should land together, but that does not require waiting for full lane integration.

The range's unretained proof claims are **unverified, not demonstrated false**. The findings
above concern fresh observed behavior. They are not retroactive claims about exactly what
happened during the seven commits.

The recursion needs structural handling. An already-loaded driver can mutate a separate
on-disk copy of its own source without logically changing its executing code. That narrow
recursion is acceptable. However, suites that are independent of application behavior are
not automatically an independent oracle for driver validity, process lifetime or provenance.
Pin the executing instrument separately, retain the mutant and suite identities, and use
external observations for properties the instrument itself is claiming. These reproductions
observe actual process exits, later target bytes and real producer output independently.

`--expect` is the necessary attribution contract; the driver enforces it consistently. A
disciplined human who preregisters and compares expected and observed guard names could
catch the three refused weakens too. The assertion that *no reading rule* could catch them
is too strong. Conversely, an expected label is insufficient: R39-01 obtains that exact label
from an invalid mutant. Guard identity must be paired with validity and experiment
preconditions. The third refused weaken illustrates the need to observe timing and lifecycle
conditions as well; comparing names catches its symptom, not every possible self-invalidating
experiment.

The setsid boundary is a real limit of group signalling. It is not sufficient justification
for continued mutation of the operator's live tree. The pinned escape test is useful as an
executable limitation, but should have a retirement condition and must not be counted as
positive safety evidence. The new lifecycle findings do not depend on that escape.

The generic-argv objection to isolation is true but insufficient for this tool's known
usage. Support a constrained repository-relative suite command run from a disposable
checkout, or require the caller to provide that checkout explicitly. Setting cwd alone will
not relocate absolute script paths; rebase those paths or reject them. A declared restricted
interface is a reasonable immediate solution for `python3 scripts/*.test.py`.

`NOT_CAUGHT` is ambiguous under the current interface. The multiplicity argument is also
locally sound under the present checks: root counts come from increments starting at one,
and exact map equality rejects zero, negative and extra identities. Call it a static
redundancy argument supported by the tested case, not universal measured redundancy. The
new reason assertion measures diagnostic behavior. If an experiment needs to distinguish
redundancy from an unarranged precondition, it needs separate precondition and guard-entry
observations; prose cannot supply those observations.

## Re-running the two suite weakens

Create a disposable checkout of `c560cae`, apply `surviving-weakens.patch`, then run:

```sh
python3 scripts/lane-accept.test.py
python3 scripts/mutation-campaign.test.py
```

Observed exits were both 0, with 112 and 108 guards respectively. The patch changes distinct
inputs: the procedure for the lane suite and the parser for the campaign suite. Restore or
remove only the disposable checkout afterward. The two standalone probe scripts obtain
pinned instrument sources with `git show`; all their subjects live under temporary paths.
