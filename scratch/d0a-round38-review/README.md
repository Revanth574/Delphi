# D0-A round 38 review — REVISE

Reviewed `0e2a384..aa0d0e1` on `phase-3b/d0-readiness-contract`.
The pinned range has eight commits and exactly 24 files changed, 1215 insertions,
51 deletions. HEAD is `715248a`; its only change after the pin is the round-38
prompt. Reviewed implementation files are byte-identical to the pin.

The unmodified suites pass: weaken driver 17 guards, lane acceptance 101,
mutation campaign 101. These results do not discharge the findings below.
Implementation files were not edited. Experiments mutate temporary subjects/copies.

## Findings

### D0A-R38-01 — P1 — Separate the report channel for every suite invocation

Location: `scripts/weaken-driver.py:87`, `_run` at lines 67–76.

Root cause: one report path is allocated per `drive`, then reused for baseline,
mutant and restoration. Unlinking it does not revoke it from baseline descendants.
The narrower claim in the prompt is therefore false even without hostile subject
code or guessed paths.

Reproduction: the baseline launches a reporting child with its inherited path and
returns 0. The child waits for the mutant invocation, then writes `expected` to
that path. The mutant returns 1 and writes no report. Restoration returns 0.
The driver returns **RED_PROVEN**, attributing the prior invocation's report to
the mutant. See `late-report.json` and the complete process outputs in
`process-observations.json`.

Impact: a real but unattributed mutant failure becomes proof of the intended guard.
Fix: fresh channel/identity for each `_run`, bind events to that invocation, and
collect descendants before advancing stages. This still assumes trusted reporting
helpers; it does not establish authenticity against hostile code.

### D0A-R38-02 — P1 — Isolate mutations and own subprocess lifetime

Location: `scripts/weaken-driver.py:71`, lines 110 and 146–149.

Root cause: the driver mutates the operator's target directly, has no termination
handling, and `subprocess.run(timeout=...)` kills only its immediate child.
`finally` does not run on ordinary default SIGTERM termination and cannot run on
SIGKILL/power loss. Nor does it prevent a surviving child from rewriting the file.

Reproductions: SIGTERM after the mutant suite starts yields driver exit **-15**
and leaves `FLAG = False` in the target (`sigterm.json`). In a separate test the
mutant suite spawns a child writer and hangs: the driver returns **TIMEOUT** with
matching restore digest and the target immediately restored, then the surviving
child rewrites it to `FLAG = False` (`timeout-child.json`). Probe cleanup collects
the explicitly terminated experiment's process group.

Impact: interruption damages the working tree even when the driver reported a
successful restore. Fix: run in an isolated, identified checkout/snapshot; own
and collect the suite process group before restoration/verification, with signal
handling and recoverable cleanup records. The existing campaign already provides
the relevant isolation precedent. Signal handlers alone cannot cover SIGKILL.

### D0A-R38-03 — P1 — Syntax compilation is not mutant validity

Location: `scripts/weaken-driver.py:118–123`.

Root cause: the validity stage only calls `compile` for `.py`; it never imports
the module, and has no build/validation command for other target languages.

Reproduction: change `FLAG = True` to `FLAG = MISSING_NAME`. The real subject
process exits 1 with a top-level **NameError**, before executing successfully.
A suite that checks the subject command's success reports its intended failing
guard. Baseline and restoration exit 0, and the driver returns **RED_PROVEN**.
`nameerror.json` retains all three actual subject exits and the traceback.

Impact: the exact invalid-mutation class cited as motivation can still be credited
as RED-proof. A reported guard failure does not establish a valid experiment.
Fix: supply an explicit suite-specific build/import validity adapter and retain
its structured outcome separately from guard failure. Refuse unsupported or
unverified validity rather than asserting buildability from syntax alone.

### D0A-R38-04 — P1 — Compare failures with the corresponding binary's summary

Location: `scripts/mutation-campaign.py:548–552`.

Root cause: `re.search` selects the first summary in the whole Cargo transcript;
failure identities can come from a later test binary. The command explicitly
runs both library and integration tests.

Reproduction: a real temporary Cargo package has one passing library test and one
failing integration test. Cargo exits **101** and names `actual_failure`; `--list`
contains that test. The campaign returns **UNATTRIBUTED FAILURE**, claiming
`summary_says: 0, names_found: 1` from the library's earlier passing summary.
Full Cargo stdout/stderr are retained in `multi-binary.json`.

Impact: genuine integration-test detections following a green binary are discarded
by the R37-03 narrowing. Fix: enumerate and execute binaries separately and bind
each failure multiset to that binary's completed summary, or otherwise preserve
those boundaries explicitly. Add a real multi-binary positive control.

### D0A-R38-05 — P1 — Failed enumeration must refuse attribution

Location: `scripts/mutation-campaign.py:536–549`.

Root cause: enumeration's exit status is ignored, and membership validation runs
only `if known`. Empty output therefore waives the new requirement. Likewise,
the count validation is conditional on finding a matching summary.

Reproduction: a real Rust test writes a fictitious `fabricated_name` failure and
summary, then calls `process::exit(1)` without a guard detecting anything. A
controlled command wrapper launches real Cargo for execution and dies by SIGTERM
for the enumeration request. The campaign nevertheless returns **CAUGHT** for
`fabricated_name`. This is a deliberately failed enumeration collaborator, not
a claim that ordinary `cargo --list` always fails. Execution and classification
are real; stdout/stderr are in `failed-enumeration.json`. The listing process's
actual **-15** exit is retained in `process-observations.json`.

Impact: a missing observation restores the fabricated-detector acceptance the fix
was meant to prevent. Fix: require successful complete enumeration, a populated
known set, and the required complete summary before granting CAUGHT; retain
enumeration diagnostics and refuse when any prerequisite is missing.

### D0A-R38-06 — P2 — Restore bytes and check restoration on every exit

Location: `scripts/weaken-driver.py:84`, lines 146–157.

Root cause: `read_text` normalizes newlines; `write_text(original)` cannot restore
the original bytes. Also, returns inside `try` run `finally` and then skip the
digest predicate after it.

Reproductions: an actual CRLF target reaches **RESTORE_FAILED**, with no filesystem
mock, short write or concurrent writer (`crlf.json`). A missing-anchor request
still rewrites CRLF to LF but returns **MUTATION_NOT_APPLIED**, despite unequal
before/restored digests (`missing-anchor-crlf.json`). Deleting only the purportedly
unreachable restore-digest predicate leaves **all 17 guards passing, exit 0** and
causes that CRLF experiment to return **RED_PROVEN** with unequal digests
(`surviving-weaken.json`, `weakened-driver-suite.stdout`).

The anchor redundancy claim also fails as currently implemented: deleting just
the anchor predicate leaves all 17 guards green, but a missing anchor on CRLF
becomes **NOT_CAUGHT** because newline conversion changes the digest
(`anchor-weaken.json`).

Impact: even a no-op request alters source, restoration failures are hidden on
early exits, and the untested predicate is a reachable sole defence against a
false proof. Fix: capture/restore exact bytes, preserve encoding/newlines during
replacement, avoid rewriting on no-op paths, and verify restoration before every
terminal verdict. Keep experiment outcome and restoration outcome separately.
After byte preservation, the anchor check may indeed be only diagnostic defence
in depth; that is not true of the current transformation.

### D0A-R38-07 — P2 — Pass the snapshot directory through sudo

Location: `scratch/lane-run-7-procedure.md:108–110`; consumer at
`runtime/tests/b1_integration.rs:168–169`.

Root cause: the new snapshot variable is exported in the invoking shell, while
all three root invocations use plain `sudo "$b"`/`sudo "$B"`. The new Drop path
silently skips capture unless that variable survives sudo's environment policy.

Grounding: on this host, invoking installed sudo as the current user with the
variable present in its parent prints **None**, exit 0 (`sudo-environment.json`).
The installed sudo-rs manual documents a mandatory reset to a minimal environment.
Root invocation required interactive authentication and was not run; this review
does not claim to have reproduced a root PAM failure. The procedure specifies
neither preservation nor a required env_keep policy.

Impact: under the reset policy, R37-06's pre-cleanup snapshot is disconnected from
the documented producer; only the already-too-late outer capture remains.
Fix: explicitly set this one variable in each elevated command, e.g.
`sudo env DELPHI_FAILURE_SNAPSHOT_DIR="$SNAPDIR" "$b" ...`, and test the environment
observed by the actual elevated test process before relying on the capture.

### D0A-R38-08 — P2 — Do not overwrite duplicate membership rows

Location: `scripts/lane-accept.py:247–250`.

Root cause: the claimed multiset parser is dictionary assignment. Repeated
identities overwrite earlier multiplicities instead of adding or being rejected.

Reproduction: start with the current strict fixture, which accepts. Append its
first `1\texe::test_0` row to `unpriv-identities.txt`. Its actual count becomes
six versus five root entries, but acceptance still reports **ACCEPTED**, five
unprivileged identities, and zero difference. Full input and acceptance report
are in `duplicate-membership.json`.

Impact: duplicated/corrupt retained evidence can still certify unequal multisets.
Fix: reject duplicate keys as malformed producer output or accumulate counts;
validate positive counts and use the same strict parser on both sides.

### D0A-R38-09 — P2 — Do not encode timeout as a valid signal return code

Location: `scripts/weaken-driver.py:72–73`, lines 92 and 129.

Root cause: `_run` returns `-1` for timeout, but `subprocess` also returns `-1`
when the actual child dies from SIGHUP.

Reproduction: the suite immediately sends SIGHUP to itself. The observed process
exit is **-1**, with no timeout exception, but the driver returns **TIMEOUT**
(`sighup.json`, `process-observations.json`).

Impact: the partition misidentifies termination and destroys an observation it
actually had. Fix: return a typed execution result with distinct timeout, launch
error, exit and signal fields; derive the verdict from those fields and phase.

## Where the requirement belongs

Use **A + C with a fourth placement: a structured proof-publication gate**.

1. Define an authoritative proof record produced by the driver: claim/mutation ID,
   exact patch, source/suite/driver identities, invocation IDs, validity results,
   guard events, phase exits/signals, restoration results and retained diagnostics.
2. Make `lane-accept.py` consume that record for proofs used by lane acceptance.
   Require the corresponding manifest verification in repository CI for proofs
   used outside the lane, including binding to the reviewed inputs. Produce and
   verify it end to end; a prose step saying to retain it is insufficient.
3. State in the corpus that only a validated record earns RED-proof credit.
   Commit messages can cite its ID. Arbitrary prose has no independent authority.

That addresses the actual site where proof is *credited*, which need not be the
site where English is written. It does not claim to prevent humans from writing
unsupported sentences. A prose-only rule cannot implement acceptance; a local
hook is an optional convenience, not a repository-wide trust boundary. In
addition, `pre-commit` is the wrong Git hook for inspecting the final message;
`commit-msg` is the relevant hook, but it still need not classify English.

Do not wire the current RED_PROVEN result in as sufficient authority. Fix the
false-proof/restoration defects, then land producer, consumer and an integration
case that omits/corrupts the record together. Review before giving the result
authority is appropriate; indefinite absence of a consumer after validation is
not. The intentional current disconnection is treated as this design decision,
not a rediscovered finding.

## The verdict partition and the two exceptions

Nine labels are not nine exhaustive, independently observed states. A better
underlying record is a product of **phase, execution outcome, validity, guard
observation and restoration**. Derive concise verdicts from it while preserving
all dimensions. Restoration failure must not erase what the experiment did,
and the earlier experiment outcome must not hide restoration failure.

UNVERIFIABLE is the right conservative answer to failure without attributable
guard evidence. Keep that refusal. A unique channel per invocation is useful
against accidental/stale evidence under a trusted-helper threat model; it is
neither unforgeable nor currently implemented by allocating once per drive.

NOT_CAUGHT cannot distinguish redundancy from an unarranged condition using the
current observations. Nor does exit 0 prove the intended guard ran: an empty
filter or skipped guard can also exit 0. Naming the ambiguity is honest **given
this interface**, not the most a redesigned driver can do. Structured events
for guard entry/completion and a separately asserted precondition would distinguish
many cases. A missing guard/precondition observation must remain unverified;
even an observed surviving mutation does not prove general redundancy.

MUTATION_INVALID currently means only caught Python SyntaxError, not verified
build/import invalidity. TIMEOUT aliases a real signal. Launch/report/restore I/O
exceptions also escape the nine-return-value scheme. Record those observations
explicitly rather than inventing a causal diagnosis from absence of evidence.

Both exception arguments are contradicted by real newline conversion (R38-06).
The restore predicate is reachable today and its deletion survives the suite;
no filesystem double is required. The postscript's crash is not itself proof
that a completed Python write returned success without landing, and the findings
do not depend on making that inference. Power-loss safety belongs primarily in
isolation; exact byte restoration and all-path verification remain necessary.

## Reproduction and limits

Run `python3 scratch/d0a-round38-review/probe.py` and
`python3 scratch/d0a-round38-review/lifecycle-probe.py` from this repository.
The former records actual child exits/stdout/stderr through a transparent
subprocess spy and writes all subjects/mutants into temporary directories.
The Cargo examples use a tiny dependency-free temporary package, not the runtime
or privileged lane. The failed-enumeration wrapper intentionally supplies a real
SIGTERM outcome for that collaborator. No actual failing subject outcome was
inferred from a missing filtered line.

The separate `anchor-weaken.json` contains the complete 17-guard run after only
the anchor check was removed. `lane-guards.log` and `campaign-guards.log` retain
the unmodified 101-guard runs. No seated/root lane or production logind gate was
run. Existing explicitly open runtime issues were not re-found.
