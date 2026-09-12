**REVISE — the acceptance verifier can certify failed or incomplete evidence.**

Reviewed `4319c83..e9a843a` on `phase-3b/d0-readiness-contract`: 22 commits. HEAD is `98a9802`; its only difference from the pinned endpoint is the review prompt. All reviewed implementation files therefore match the pin. No product files or historical run artifacts were changed. Review probes and their output are retained beside this report.

**D0A-R36-01 — P1: Part B can fail and still certify.**

Location: `scripts/lane-accept.py:171` and `runtime/tests/b1_integration.rs:2555`.

Root cause: `check_control` accepts any parsed positive verdict, and neither control transcript is checked for successful test completion or producer status. The positive test prints its verdict before the survivor, deadline and shutdown assertions. Impact: even `Reached` followed by an assertion failure, or `Topology` followed by a failed positive control, certifies. Both mutations of run 23's real transcript return ACCEPTED (`probe.log`). The 17 root producer statuses describe the featureless lane, not these later feature-enabled invocations. Fix: require positive `Reached`, negative `Topology`, the exact expected test identity, one completed non-skipped passing test, and successful invocation status for each control. A matching diagnostic alone cannot certify the test that emits it.

**D0A-R36-02 — P1: Membership and producer completeness are asserted, not verified.**

Location: `scripts/lane-accept.py:126` and `scripts/lane-accept.py:140`.

Root cause: membership trusts the two zeroes in `membership.txt`; identity files receive only a line-format check. Producer checking counts status lines without checking the executable identities. The root transcript is used only as a timestamp. Impact: an empty root identity file, altered unprivileged multiplicity, an empty root log, and 17 copies of one producer's successful status each remain ACCEPTED with the remaining run-23 artifacts intact. These are precisely partial or mismatched evidence sets the gate claims to refuse. Fix: parse and compare nonempty Counters, derive the root Counter from the retained transcript, join the distinct producer identities to the hash/enumeration manifest, and run the count extractor with the expected target count. Check failed summaries and the allowed executed/skip identities rather than accepting any set with two printed zeroes.

**D0A-R36-03 — P1: Failed rebuilding still proves “freshness.”**

Location: `scripts/lane-accept.py:113`.

Root cause: `rebuild.log` need only exist; there is no retained rebuild exit status or success check. Identical pre/post hashes are equally consistent with a failed rebuild that left stale binaries untouched. Impact: replacing the real rebuild log with `error: could not compile delphi-runtime` still returns ACCEPTED. Fix: retain and require the rebuild producer's successful exit, associate its artifact set with the hash manifest, and check the complete dependency set, including auxiliary executables. The manual procedure's early exit does not establish this fact for an evidence-only verifier intended to catch procedural omissions.

**D0A-R36-04 — P2: The ordering check compares freshness with the run's end.**

Location: `scripts/lane-accept.py:210`.

Root cause: `root-run.log` is appended throughout execution, so its mtime records the last write, not the start. Impact: a rebuild and hash comparison performed halfway through the lane satisfy the comparison and are described as “freshness proven before the run.” Copying with `-p` preserves this wrong boundary accurately. Fix: capture a distinct run-start event before the first producer invocation and require rebuild completion and both hashes before that event. Preserve run-end separately for membership ordering. This finding concerns what the predicate can prove; it does not assert that run 23 actually rebuilt halfway through execution.

**D0A-R36-05 — P2: Re-verification captures can still overwrite one another.**

Location: `scripts/lane-accept.py:268`.

Root cause: the fallback filename has one-second resolution and `write_text` truncates an existing file. The initial exists/write pair also has a concurrency race. Impact: two re-verifications in the same second overwrite the earlier capture. With the clock held constant, the probe replaced an ACCEPTED re-verification with REFUSED while retaining only one file. Fix: create every capture exclusively, retrying a unique suffix on collision; never open a capture for truncation. Test two same-clock invocations with distinct outcomes and a concurrent first capture.

**D0A-R36-06 — P2: stderr is still test-controlled data.**

Location: `scripts/mutation-campaign.py:499`.

Root cause: moving marker matching to stderr assumes libtest captures every way a test can write there. Direct `std::io::stderr().write_all` bypasses that capture; spawned processes can also inherit stderr. Impact: a real Rust test writing `Killed` and failing an assertion is classified UNATTRIBUTED FAILURE. Changing only that text to `ordinary payload` makes the same failure CAUGHT. The raw stdout/stderr and executable reproduction are retained. This is a narrower false-attribution outcome than INFRASTRUCTURE, but still contradicts the claimed elimination of test-text influence. Fix: separate build status from execution status, obtain diagnostics from identified producers, and avoid treating inherited stderr text as authenticated infrastructure evidence. Retain this real-libtest case as a guard.

**D0A-R36-07 — P2: The bisect accepts zero matching tests as PASS.**

Location: `scripts/bisect-gate-test.sh:105` and `scripts/bisect-gate-test.sh:130`.

Root cause: the harness requires a summary line, but not execution of the requested test. Impact: its exact `run_one` function returns PASS for a real libtest binary reporting `running 0 tests` and `test result: ok. 0 passed`. An older revision without the test can therefore appear clean. Fix: use `--exact`, require exactly one completed named test, reject ignored/skipped outcomes, require a consistent producer status, and validate N as positive before building. The reproduced case uses a harmless local Rust fixture and a sudo stand-in, not root execution.

There is also a reasoning limit: failures on both sides do not eliminate a range that might change failure probability, and failures on one side do not establish causality from a small intermittent sample. Report per-side observations and comparable conditions; reserve causal language for discriminating evidence.

**D0A-R36-08 — P2: Following the procedure cannot produce a fresh accepted run.**

Location: `scratch/lane-run-7-procedure.md:320` and `scratch/lane-run-7-procedure.md:349`.

Root cause: the only acceptance invocation precedes Part B; Part B contains only the positive-control command. There is no command producing the negative-control artifact required from run 24. Impact: an operator following the procedure in order is refused for missing controls and reaches the end without a subsequent acceptance invocation. Acceptance still requires undocumented manual additions. Fix: include both exact control invocations, retain each producer status, finish all post-run hygiene checks, and invoke acceptance once those artifacts exist. Test the procedure's artifact contract against the verifier's required-input contract.

**D0A-R36-09 — P2: The new environmental snapshot is taken after the evidence-changing work.**

Location: `scratch/lane-run-7-procedure.md:303`.

Root cause: account and session state are captured in §4b, after the entire lane. Tests create/delete users and sweep sessions before that capture. Impact: a future failure can again leave a clean post-run snapshot even if it began with, or encountered, accumulated state. Also, `loginctl` errors are discarded and can become a count of zero. Fix: capture boot identity/uptime, accounts and sessions before the lane, before the failing test, and on failure before cleanup, with command status and stderr. Preserve post-run state as a separate observation. Add the PAM error detail and relevant retained diagnostics at the failure boundary where feasible.

**D0A-R36-10 — P2: Run 25 cannot validate every earlier observer version.**

Location: `docs/CONFORMANCE_REGISTER.md:104`.

Root cause: the register extends run 25's discrimination result to prior `Reached` verdicts including runs 20 and 21, although the same section acknowledges those observers did not validate parentage on their success path. Impact: a successful test of the repaired observer appears to rehabilitate observations made by the defective observer. Fix: scope the negative-control evidence to the observed implementation, and distinguish which earlier runs used equivalent relevant logic. Runs 20/21 retain their known provenance limitation; a later negative control does not remove it.

**D0A-R36-11 — P2: “Every check weaken-proven” exceeds the executable guard coverage.**

Location: `scripts/lane-accept.test.py:211` and the review prompt's acceptance-verifier claim.

Root cause: the suite exercises selected negative inputs but leaves independent refusal predicates without discriminating guards. Impact: all 46 assertions pass after independently removing (a) the inverted freshness-pair check, (b) membership-after-run ordering, or (c) the requirement for a rebuild artifact. These applied weakens and their successful suite runs are retained in `weakens.py`/`weakens.log`. Fix: map each required invariant to a discriminating negative case and run its verified mutation against that case. State precisely whether coverage refers to six top-level functions or every enforced constraint; 46 assertions are not 46 independent refusal cases.

**D0A-R36-12 — P3: The class-26 consolidation did remove unique quantitative evidence.**

Location: `docs/DEFECT_CLASSES.md:1624`.

Root cause: “nothing unique was lost” was asserted without a content comparison. Impact: all four named defect instances and the stronger mechanism remain, but the removed entry uniquely recorded `DEATH_GRACE` calibration: 0 ms yielded 32/100 wrong acceptances; at least 2 ms yielded 0/100. That evidence no longer appears in this corpus. Fix: retain the calibration with its historical scope, or explicitly say that obsolete quantitative detail was intentionally removed. Do not preserve a literal no-loss claim. The numbering itself is now exactly unique 1..56.

**D0A-R36-13 — P3: The pinned diff stat disagrees with the review prompt.**

Location: `scratch/codex-d0a-round36-prompt.md:13`.

Root cause: the stated diff stat was not generated from the final pinned range. Impact: 74 files and 22 commits match, but the actual change is **6,328 insertions / 408 deletions**, not 6,315 / 365. Fix: regenerate the displayed stat from `git diff --stat 4319c83..e9a843a`; keep the SHA pin unchanged. This is reported as requested, without implying that the implementation was reviewed against another range.

**Ruling on the refused run: the observation is citable with its refusal and scope retained.**

The explicit rule prohibits citing a refused run *as merge acceptance*. It does not erase measurements within it. Run 25's artifact contains the named negative-control execution, the detached live-child records, and a successful one-test completion. The failed root producer and the missing-colon consumer rejection do not themselves invalidate that measured topology. Cite this as an observation from a REFUSED run, with the exact observer version and artifact, and keep accepted reproduction owed. Apply the same rule to adverse observations. Do not call the lane accepted, certify unrelated properties such as reaping, or extend the result across changed observer implementations (R36-10). Requiring the consumer to accept a format before the underlying observation may be discussed would also prevent citing evidence of consumer defects.

**Cheapest class-56 enumeration and closure.**

I ran `cargo metadata --offline --no-deps --format-version 1` and audited all discovered feature-gated binary references and their helper callers. There are three such targets in the workspace, all requiring `insecure-test-seams`:

| Binary | Test consumers in `b1_integration.rs` | Featureless behavior |
|---|---|---|
| `delphi-surface-shell` | `the_daemon_binary_runs_the_real_gate_d0a_r4_03`, through `surface_shell_or_skip` | Existence-dependent: consumes residue or skips |
| `delphi-stubborn-ai` | `b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive`; `the_control_reports_topology_when_the_daemons_child_leaves_its_group` | Both explicitly feature-guarded |
| `delphi-detached-ai` | `the_topology_fixture_leaves_the_parents_process_group`; `the_control_reports_topology_when_the_daemons_child_leaves_its_group` | Both explicitly feature-guarded |

The static inventory found no second unguarded consumer of these binaries. This inventories source dependencies; it is not a claim that a clean root lane has passed.

The cheap general construction is: derive gated binary targets from Cargo metadata; join every test/helper executable dependency to that inventory and the selected build's JSON artifact manifest; fail an undeclared or missing dependency before root execution. Trace helper callers rather than counting only direct `env!` occurrences. A small checked dependency manifest is acceptable if new/unaccounted executable references are rejected. For broader build-residue coverage, build once into a fresh target directory and compare the intended test/auxiliary artifact closure with a feature-prewarmed build. This costs a build, not repeated heavy root lanes; running only `--list` or an unprivileged suite cannot expose dependencies behind a root guard.

Make the surface-shell build an explicit prerequisite of the production-profile lane, hash it with the other consumed executables, and verify the daemon under test remains featureless. Keep Part B's artifacts separate. Merely enabling seams for the entire lane would change the real-gate test's subject. A fresh target directory also changes the locally pinned helper build; resolve the installed-helper precondition explicitly before calling a subsequent root execution a measurement.

**Ruling on instrumenting rather than reproducing.**

Instrumentation is proportionate as the next investigative step. The evidence cannot establish whether the choice was motivated by comfort, and it does not support that attribution. It also cannot close a merge-blocking failure: run 23 predates later changes, runs 24/25 failed, and this range contains no demonstrated fix for `r4_03`. Treat the failure as unresolved. Improve capture at the pre-run/failure boundaries (R36-09), specify the conditions under which the next longer-session run is informative, and retain its first outcome. Deliberately rebuilding accumulated state becomes worthwhile when another comparable failure or captured diagnostic provides a concrete axis to vary. Seventeen passes after reboot do not exclude interactions under the old conditions.

**Class 55 needs an executable join test.**

A recorded real transcript is a useful seed, but it can become stale while both suites keep passing. Use one producer formatter/emitter in the real control and an unprivileged format-emission test, feed that actual output through the verifier, and assert an accepted expected event plus successful completion. Retain the real run-25 transcript as a historical missing-colon regression; do not silently rewrite it into current format. Changing just the producer format must break this join test. Discovery likewise needs a test that executes the shim and checks discovery against the final `comm`. Class 54 is not closed throughout the tree, and R36-01..04 show it is not fully closed even for this lane.

**Verified claims and limits.**

- Run 23: independently derived 230 identities; root and unprivileged Counters match; count extractor exits 0 with 224 executed / 6 skipped.
- Runs 24/25: independently derived 232 identities each; both retained Counter pairs match exactly. The extractor exits 1 with 222/8 and 223/8 respectively. Its `reported` values are 230 and 231 because that field sums passing tests; they are not the identity cardinalities. The prompt's statement that the test-set derivations were right is supported.
- The acceptance suite passes 46 assertions. The three selected applied weakens also pass all 46, as recorded above.
- The corpus has 56 numbered headings, each number 1..56 exactly once.
- Root/PAM lanes, a clean full build, and the full mutation campaign were not rerun. Rust counterexamples were compiled and run unprivileged; acceptance mutations used temporary copies and preserved input mtimes. No conclusions here claim new root acceptance.
- `git diff --check` reports whitespace in retained producer transcripts; those captures were left intact.

Reproduce from the repository root with `python3 scratch/d0a-round36-review/probe.py`, `python3 scratch/d0a-round36-review/weakens.py`, and `python3 scratch/d0a-round36-review/producer-probe.py`. These scripts target the current implementation, which matched the pin during this review; use that pinned implementation for later reproduction.
