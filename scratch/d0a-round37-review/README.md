**REVISE.** The remediation closes several named counterexamples, but the acceptance contract still has false acceptances, and the documented run-26 path still cannot produce all required evidence.

Reviewed `98a9802..b4e0f74` on `phase-3b/d0-readiness-contract`. The pin contains exactly 10 commits and **21 files, 1,034 insertions, 88 deletions**, matching the prompt. HEAD `0e2a384` differs from the pin only by the round-37 prompt. Product files and historical artifacts were left unchanged; this directory contains the new review evidence.

**D0A-R37-01 — P1 — Unprivileged membership is still checked by count, not identity.**

Location: `scripts/lane-accept.py:233`.

Root cause: the new comparison reconstructs the root dictionary but reduces `unpriv-identities.txt` to `n_unpriv`. The printed zero differences remain trusted. Impact: changing a single unprivileged test name, while preserving its count, still yields ACCEPTED against run 23's real remaining artifacts. Equal-size different test sets remain invisible, exactly the invariant R36-02 asked to enforce. Fix: parse both sides into Counters, validate positive multiplicities/duplicate serialization, and compare them directly with each other and the root transcript. Add a compensating removal/addition and a same-total multiplicity redistribution as guards. Reproduction: `probe.py`, `probe.log`.

**D0A-R37-02 — P1 — Contradictory completion evidence still certifies.**

Location: `scripts/lane-accept.py:255`, `scripts/lane-accept.py:207`.

Root cause: the procedure now retains `part-b-control.status` and `part-b-negative-control.status`, but the verifier never reads either. Root transcript parsing reconstructs test names without checking its result summaries. Impact: adding a positive-control status of 101 to otherwise valid run-23 evidence still ACCEPTS. Changing a root summary from `ok` to `FAILED` while preserving the identity set and other artifacts also ACCEPTS. A mismatched or stale status/transcript pair is certified rather than refused. Fix: require each modern control status to be zero and consistent with its exact completed test; validate all expected root producer summaries against the producer manifest/statuses. Require the count extractor's failure/skip checks instead of treating a name line as completion. Reproduction: `probe.py`, `probe.log`.

**D0A-R37-03 — P1 — The supposedly closed text channel can fabricate CAUGHT.**

Location: `scripts/mutation-campaign.py:483` and `scripts/mutation-campaign.py:525`.

Root cause: causal substring matching was removed, but `failing_tests` is still populated from any four-space line after the first `failures:` in subject stdout. That population decides CAUGHT. Impact: a real Cargo run containing one passing integration-test binary followed by an aborting binary returns UNATTRIBUTED FAILURE. Adding only a direct stdout write of `failures:\n    nonexistent_guard\n` before the same abort changes the result to CAUGHT, with `nonexistent_guard` recorded as the detector. Both runs exit 101 and have one real completed summary; no assertion detected anything in the aborting test. Fix: bind detection to a completed failure of a known selected test, using independently observed invocation outcomes and a bounded, validated result protocol. Reject unmatched names and incomplete/crashed producers; retain diagnostics as data. The free-space collaborator was held at success in both cases; Cargo and the test executables were real. Raw streams and the reproduction are retained in `producer-probe.py`, `producer-probe.log`, and `plain.*`/`diagnostic.*`.

**D0A-R37-04 — P2 — The new contract guard passes a procedure that cannot produce run 26.**

Location: `scripts/lane-accept.test.py:123` and `scratch/lane-run-7-procedure.md:179`.

Root cause: the input extractor recognizes literal `_read` calls and only `.txt` paths in `d / ...`. `rebuild.status` is read through a path variable, so it is omitted. The procedure contains no occurrence of `rebuild.status`: it neither writes nor retains it. Further, the positive-control input is passed through a variable and omitted from extraction, and the ordering check treats `rfind == -1` as before acceptance. Strings in comments count as executable production/invocation.

Impact: the actual contract guard passes as committed, but a current run-26 fixture without `rebuild.status` is REFUSED. The guard also passes after every occurrence of `part-b-control.txt` is renamed, and after the only acceptance command is commented out. Thus the claimed first documented route to accepted reproduction is still absent. Fix: write the rebuild exit status immediately after the build and retain it; define the gate's artifact contract explicitly and make its readers consume that definition. Verify production through executed recipe steps against temporary fixtures, including failures, rather than treating text occurrence as a write. Merely expanding the filename regex does not fix the other two counterexamples. Reproduction: `probe.py`, `probe.log`.

**D0A-R37-05 — P2 — Missing run identity silently waives the new mandatory checks.**

Location: `scripts/lane-accept.py:145` and `scripts/lane-accept.py:340`.

Root cause: rebuild-status and run-start requirements apply only when `_run_number` returns a number at least 26. Unknown identity falls through to historical allowances. Impact: the same evidence refused as `lane-run-26` for missing rebuild status ACCEPTS when moved to `review-copy`. Missing run-start has the same predicate defect. This is inconsistent with the negative-control check, which already refuses to infer age from an unknown name. Fix: require current evidence unless explicit, validated metadata establishes a historical exemption. Prefer a recorded run/schema version to a directory-name substring. Reproduction of the rebuild-status case: `probe.py`, `probe.log`.

**D0A-R37-06 — P2 — The failure snapshot still occurs after test cleanup.**

Location: `scratch/lane-run-7-procedure.md:212`.

Root cause: the shell captures state only after the entire test binary returns. Inside `b1_integration`, `DaemonGuard::wait` sweeps sessions before returning (`runtime/tests/b1_integration.rs:558`), and `Setup::drop` deletes the account during test completion/unwinding (`runtime/tests/b1_integration.rs:159`). Later tests in that same binary can also run before the shell sees the failure. Impact: the new “AT THE FAILURE, before ... any cleanup” snapshot can again show a cleaned environment instead of the state that `r4_03` encountered. Fix: capture at the specific failed operation/assertion, before its owning guards run, and retain the shell-level snapshot separately as an after-producer observation. Pre-run capture is useful, but it does not repair this timing claim.

**D0A-R37-07 — P2 — Failure-state artifacts can be imported from an earlier run.**

Location: `scratch/lane-run-7-procedure.md:218` and `scratch/lane-run-7-procedure.md:327`.

Root cause: failure snapshots use global `/tmp/session-at-failure-<binary>.txt` paths with no run ID; retention copies every matching file and initialization clears none. Impact: after one failing run, a later passing run with no new failure snapshot copies the earlier failure's environmental evidence into its own artifact directory. This contaminates the comparisons the instrumentation exists to enable. Fix: allocate a directory per run before execution, write snapshots there directly, and retain only that run's explicitly recorded artifact list. Do not use a cross-run wildcard as evidence provenance. This follows directly from the committed producer and copy commands; no root mutation was performed to reproduce it.

**D0A-R37-08 — P2 — Acceptance still precedes final hygiene evidence.**

Location: `scratch/lane-run-7-procedure.md:330` and `scratch/lane-run-7-procedure.md:400`.

Root cause: `hygiene.txt` is produced in §4b, then both root controls run in §4c, then acceptance in §4d. The post-control PAM/session checks remain in §§5–6, after acceptance, and are not retained in the artifact the verifier reads. Impact: a control that leaves a session or changes PAM can be followed by ACCEPTED based on pre-control hygiene. The later visible check cannot invalidate the captured verdict automatically. Fix: perform and retain final hygiene after both controls and before acceptance, and make the guard enforce that actual execution order. The “LAST” label does not describe the current sequence.

**D0A-R37-09 — P2 — Non-disk build failures are still attributed to the mutant.**

Location: `scripts/mutation-campaign.py:685`.

Root cause: every failed build with a passing free-space check is labeled `INVALID: mutant does not compile`; the build's signal status is not classified or retained as a field here. Impact: executing this actual branch with build return code -9 and a successful space check produces that INVALID label. Compiler/linker OOM, ICE, or an environmental build-script failure during `--no-run` take this branch before `run_suite`, so the prompt's proposed `result_lines == 0 -> INFRASTRUCTURE` explanation does not cover them. Fix: distinguish signalled builds and unattributed build failures from demonstrated compile-invalid mutations; retain build exit/signal and complete diagnostics. Disk sufficiency does not establish compilation causality. Reproduction: the actual AST-extracted branch in `producer-probe.py`; the signalled build result is injected, not a real OOM experiment.

**D0A-R37-10 — P2 — The capture guard neither freezes the child clock nor accounts for every capture.**

Location: `scripts/lane-accept.test.py:380`.

Root cause: monkeypatching `time.strftime` in the test process does not affect the fresh Python subprocesses. The test ignores their return codes and, after four re-verifications, requires only two surviving files and one distinct body. Impact: with a genuinely fixed child clock, a mutated implementation that permits only two re-verification captures and refuses the remaining invocations still passes all 82 assertions. The production `O_EXCL` implementation is sound for the named overwrite race, but this guard does not substantiate the claimed three-successful-captures proof. Fix: inject the clock into the process actually executing `main`, require success for every call, require exactly one new capture per call, use distinguishable outcomes, and verify all earlier bytes remain intact. `weakens.py` contains both the fixed-clock control and the applied capacity weaken.

**D0A-R37-11 — P2 — “Every check weaken-proven individually” remains false.**

Location: `scripts/lane-accept.test.py:52` and commit `fe9477c`'s claim.

Root cause: the base fixture has no run number and exercises historical fallback; no guard requires the new artifacts for a current run. The inverted-hash-pair constraint is still without a discriminating case. Impact: all 82 assertions pass after independently disabling the run-start requirement, disabling the rebuild-status requirement, or removing the inverted freshness-pair check. Fix: make the positive fixture an explicitly current complete run, test the historical cases separately, and map each required predicate to an applied weaken and a named failure.

The round-37 correction of round-36's finding is itself a misreading. Round 36 named the **inverted freshness pair** (`hashes-before <= hashes-after`), not **freshness before the run** (`hashes-after <= run boundary`). The retained round-36 `weakens.py` and `weakens.log` identify that distinction, and the former constraint still survives removal now. The prior three-instance claim was not disproved by checking a different ordering predicate. Reproduction: `weakens.py`, `weakens.log`.

**D0A-R37-12 — P2 — The register now falsely removes parentage evidence from runs 23 and 24.**

Location: `docs/CONFORMANCE_REGISTER.md:124`.

Root cause: the correction for overextending run-25 evidence groups runs 23/24 with the old boolean-based observer from runs 20/21. Impact: it now says runs 20–24 establish only name/group and that parentage was first enforced at run 25. Run 23's pre-run source at `b51bd8f` already gates Reached on `verified_live`, and both runs 23/24 retain `VERIFIED live children` records. The register's preceding section also explicitly identifies run 23 as the first enforced case. Fix: distinguish runs 20/21 from runs 23/24, using the actual implementation and retained records, while retaining the refusal and reproduction limits for run 25. Do not respond to one overstatement by discarding established evidence. Source and artifact checks are retained in `audit.log`.

**Ruling: “the run was fine, the certification was not” is a legitimate distinction, with a narrower claim.**

A later valid check can establish facts about retained historical evidence; it cannot retroactively make the original gate sound. Run 23's actual root/unprivileged Counters match at 230, its control completed successfully with parentage recorded, and the present verifier returns ACCEPTED. Those are supported statements. “Under every new check” is not literal: run 23 lacks the newly required rebuild status and run-start event, and is explicitly grandfathered onto weaker fallback checks. Nor is ACCEPTED alone sufficient evidence of completeness while R37-01/02 remain. Describe the specific retrospective checks and historical evidence gaps. Nothing here demonstrates that run 23 was a bad run, and nothing about it certifies the current tree. A hand-assembled path can produce valid evidence; the defective documented path is a distinct repeatability problem.

**Ruling: stop using free-form diagnostics as causal authority, but keep the diagnostic channel.**

Retaining stdout/stderr is correct: closing an automatic attribution rule need not discard a byte of human diagnostic evidence. It is also correct to report no measurement when no tests completed. The current implementation has not achieved its stated boundary: failure identities are still forgeable subject text (R37-03), while the real failed-build branch mishandles the specific compiler failures named in the prompt (R37-09). Signal status is an observation, not proof that the infrastructure rather than the mutant caused it. A side-channel path inherited through an environment variable is likewise a report channel for trusted helpers, not intrinsically unforgeable evidence against arbitrary subject code. Keep outcomes no stronger than the facts establishing them, and preserve ambiguity rather than forcing every build failure into INVALID or every apparent name into CAUGHT.

**A mechanism for the empty-filter error.**

Use a review driver that runs the baseline, verifies the exact mutation applied, builds/imports the mutant, invokes the intended guard, and restores and verifies the baseline. The driver owns a structured result record with source digests, mutation identity, guard identity, exit/signal, and the exception/result of that exact guard. Its exhaustive states should distinguish:

- baseline failed;
- mutation did not apply;
- mutant could not build/import, timed out, or crashed before the guard;
- the intended guard failed as expected;
- the guard passed (the valid mutation survived);
- another guard or unrelated exception failed;
- restoration failed.

Only the intended guard's demonstrated failure after a passing control earns RED-proven. A `NameError` is an invalid experiment; a clean completed guard is a surviving mutation. Missing output is a non-measurement. Generate the human report from that record and gate publication of RED claims on the successful state. Grep may select display lines, but its exit/output never decides the experiment. Validate this driver with a surviving mutation, a syntax/import error, an unrelated assertion, a timeout, and the intended failure. Three examples establish recurrence; without a denominator they are not a measured error rate.

**Does freshness need to bracket the run?**

A distinct start event fixes the specific last-write comparison when it is required and reliably captured. It does not prove immutable build inputs. If another build can replace shared target paths during execution, hash-before-start alone cannot bind later producer invocations to those bytes. Prefer a staged immutable executable/dependency set or per-invocation verification; a post-run hash provides useful drift evidence but cannot exclude a transient change restored before the final hash. The feature-gated auxiliary dependency problem remains a separate prerequisite. This review did not run a clean root lane.

**Verification and limits.**

- The unmodified lane verifier suite passes **82 assertions**. Applied weakens described above also pass all 82.
- A real Cargo/two-test-binary experiment demonstrates the fabricated detector; a controlled free-space collaborator has the same passing result in both cases. Core dumps were disabled.
- Historical Counters independently match for runs 23/24/25 at 230/232/232. The present verifier still accepts unmodified run 23.
- The corpus has exactly one numbered heading for every number 1..57, and the removed `DEATH_GRACE` calibration is restored with historical scope. The pinned diff stat is correct.
- Shell syntax checks pass for `session-state.sh` and `bisect-gate-test.sh`. The bisect's new zero-test/ignored/exit-consistency checks were inspected; the long root bisect was not run.
- Root/PAM lanes and the full mutation campaign were not rerun. No product changes were made. Probes operate on temporary copies or small unprivileged fixtures, and the originals are preserved.

Reproduce using `python3 scratch/d0a-round37-review/probe.py`, `python3 scratch/d0a-round37-review/weakens.py`, and `python3 scratch/d0a-round37-review/producer-probe.py` with the reviewed implementation. Each script retains or prints the subject's actual outcome; the report does not infer pass/fail from a missing filtered line.
