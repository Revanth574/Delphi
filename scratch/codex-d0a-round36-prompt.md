# Codex adversarial review — D0-A round 36 (the merge gate)

This prompt is `scratch/codex-d0a-round36-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 4319c83..e9a843a`** — 22 commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 74 files changed, 6328 insertions(+), 408 deletions(-)

(D0A-R36-13: the stat first published here was 6315/365 — generated BEFORE the last commit
in the range and then pinned to a SHA that included it. The stat exists so scope drift is
detectable, and the first drift it detected was the author's.)
```

The round-35 remediation, the lane acceptance verifier, lane runs 22-25, the negative control,
a bisect harness, three new corpus classes, and an investigation that failed.

**This range is larger than usual and spans several sessions.** If that makes the diff stat
disagree with what you find, report the mismatch as a finding — that is what the stat is for.

---

## Lead: an investigation eliminated five hypotheses, then found its own conditions were wrong

`the_daemon_binary_runs_the_real_gate_d0a_r4_03` failed **2/2** in lane runs 24 and 25 with
`shell child failed before execve: pam_open_session failed`, after passing in runs 20, 21 and
23. Five hypotheses were tested and eliminated, each by measurement rather than argument:

| hypothesis | eliminated by |
|---|---|
| a stale logind session before the run | the pre-run check reported clean before AND after run 25 |
| test ordering inside `b1_integration` | the inserted test SKIPS instantly; checked against both retained logs |
| the commit range | HEAD passes **5/5** with the test run alone |
| anything earlier in `b1_integration` | the whole binary, serial, root: **3/3** clean |
| `--nocapture`, then the lane's exact FD shape (stdin a regular file, stdout appended to a file) | **3/3** and **3/3** |

Seventeen consecutive passes outside the lane against 2/2 inside it.

**Then: the box had rebooted between the failures and the investigation.** Runs 24 and 25 were
the 4th and 5th heavy root runs of ONE uptime session. Every repro ran on a system **fifteen
minutes old**, with zero leftover test accounts.

**So every elimination is narrower than it reads.** Each shows *X alone does not cause the
failure on a freshly booted system*. None shows *X was not a contributor under the conditions
that produced it*. The failure is **unreproducible, not resolved**, and nothing in this range
fixed it.

**The uncomfortable part, and the reason this leads:** the signal was in front of me two
commits earlier. The bisect failed with `'/tmp/delphi-bisect-b51bd8f' is a missing but already
registered worktree` — **because `/tmp` had been cleaned by that reboot.** It was read as an
inconvenience, the script was fixed, and the most informative fact available about the failure
under investigation was filed as noise. That is the same shape as the stale-session check: the
environmental fact was in the output and was not read as evidence.

**What I want attacked:** the response was to **instrument rather than chase** — the lane now
records uptime, leftover test-account count, and the live logind session list, so a future
failure and a future pass become comparable on the untested axis. **Is that the right call, or
is it the comfortable one?** The alternative is deliberately rebuilding a long session to
reproduce, which is expensive and speculative. I chose the cheap option and I am aware that is
what someone would choose either way.

---

## Class 56's scope question — what ELSE has never been built clean?

`the_daemon_binary_runs_the_real_gate_d0a_r4_03` needs `delphi-surface-shell`, which carries
`required-features = ["insecure-test-seams"]`. The lane builds featureless, so that binary is
absent and the test **SKIPS** — and a skip is scored as a PASS (class 10). It ran in lane runs
20-25 **only because each run's feature-enabled Part B left the binary in the shared target
directory for the next run's lane.** Measured: the binary was stamped at run 25's Part B, and no
lane run's skip list ever contained this test.

It was findable only by putting a **clean tree beside a contaminated one** — the bisect's
worktree. The contaminated tree alone never reports anything, which is why six lane runs did not
surface it.

**So the question is not this test. It is: what else in this tree has the same dependency and
has never been built clean?** That is class 49's shape applied to **build state** rather than to
review attention — a region that produces no findings because nothing has ever looked at it in
the condition where the finding would appear.

I have not enumerated it. The obvious candidates are every test that consumes a
`required-features` binary while the lane builds featureless, but I do not know the list and
have not built a clean tree to find out. **What is the cheapest construction that enumerates
this class exhaustively rather than one instance at a time?**

---

## RULING REQUESTED: can an observation from a REFUSED run be cited?

Lane run 25's negative control produced **`Topology`**:

```
verdict Topology, from ProcRecord { pid: 32595, ppid: 32440, pgid: 32595, state: 'S' }
```

`ppid` is the daemon, `pgid` is the child itself — a verified live child outside the group,
from a real daemon whose AI calls `setpgid(0,0)` before `exec`, not a constructed record.
**The control discriminates.** Four prior `Reached` verdicts (runs 20, 21, 23, 24) were
consistent with a control that had never detected anything — class 49's silence — and are now
reports from an instrument shown to detect the defect it would otherwise pass.

**But run 25 was REFUSED by the acceptance gate**, for a producer failure in an unrelated test
and a format defect in the verifier itself. Neither touches this measurement, which is retained
in `scratch/lane-run-25/part-b-negative-control.txt`.

I have recorded it with the provenance kept separate: the RUN does not certify the lane, the
OBSERVATION stands on its artifact, and an accepted run reproducing it is owed. The register
says exactly that.

**Rule on whether that is legitimate.** Two readings, and I do not think the answer is obvious:

1. **Citable with the refusal recorded.** The gate decides whether a run certifies the LANE.
   A discrete retained measurement inside it answers a different question, and discarding it
   would be discarding evidence for a bookkeeping reason.
2. **Not citable until reproduced under acceptance.** The refusal says the run's evidence is
   incomplete; carving out the convenient part is exactly how "accepted" erodes, and the first
   time the rule is inconvenient is the first time it gets bent.

I wrote the rule (`a run it refuses may not be cited as merge acceptance`) and then
immediately faced a case where a narrower reading served me. **That is the conflict of interest
that makes this a question for you rather than for me.**

## The acceptance verifier — class 54, built after a deferral that was wrong

`scripts/lane-accept.py` refuses to certify a run whose retained evidence is missing, failed,
or out of order. 46 guards, positive control first, every check weaken-proven.

**It was specified by you, deferred by the operator, and every round after the deferral produced
another instance of the defect it prevents** — four, three of them inside remediation for the
finding that named the pattern. The deferral's reasoning was sound about the runner reverted at
D0A-R23-05 and was **generalized to all lane infrastructure**; a tool that RUNS the lane and a
tool that REFUSES an under-evidenced lane are different things. The reasoning error is recorded
inside class 54 rather than beside it.

**Its record so far: refused runs 22, 24 and 25; accepted run 23.** And it has had four defects
of its own, every one found by USING it:

| defect | how it presented |
|---|---|
| `cp` without `-p` | refused artifacts written minutes earlier — destroying the only evidence that freshness preceded the run |
| the run's own artifact directory counted as a dirty tree | would have refused EVERY future run for a condition the procedure guarantees |
| a re-verification overwrote the run's captured verdict | a capture any later run can mutate is not a capture |
| the negative control's verdict format | REFUSED a run for a check that had in fact PASSED |

**Attack the third and fourth hardest.** The third means a committed artifact was silently
rewritten by a newer tool version — caught only because `git status` showed it. The fourth is
class 55.

## Class 55 — the interface neither side's tests cover

*A producer and its consumer can agree about the property and disagree about the format, and
neither side's tests can see it.* Two instances, one run apart, both in code written to observe
something:

- run 24: the shim **detached** correctly (`ppid` = daemon, `pgid` = itself) and could not be
  **found** — `exec` replaces `comm`, so it carried the exec'd file's name while the probe
  searched for the shim's. `Unresolved` after 2640 samples.
- run 25: the control **discriminated** correctly and could not be **read** — it printed
  `verdict Topology`, the verifier's parser requires `verdict:` with a colon.

Each side's suite was correct and testing one end of a rope. **Is the foreclosing discipline
stated usefully** — build the consumer's fixture from a *recorded real* producer transcript
rather than one shaped like it — **or does it need a mechanism?**

## The bisect harness learned THREE non-measurement states, each by producing a confident answer from nothing

`scripts/bisect-gate-test.sh` alternates A/B/A/B so environmental drift hits both sides. It now
refuses when: the test SKIPPED (a skip is a PASS, so an unprivileged bisect reports zero
failures on both sides); the binary produced **no `test result:` line at all** (verified by it
printing "BOTH sides fail — the range is ELIMINATED" when `sudo` could not authenticate); and
the daemon **refused its own helper** (`build.rs` pins the digest of a helper compiled into
OUT_DIR, so an out-of-tree build can never run against an installed one — source verified
identical, so the mismatch is build-path nondeterminism).

**Three states, all found by the harness confidently reporting a result it had not measured. Is
there a fourth, and is "refuse unless the thing demonstrably ran" a stateable general rule?**

## The defect corpus had two class 26s

Found 2026-09-12 **by counting the corpus, not reading it**: 57 numbered headings for 56
classes. Two entries under 26 — the same class, one thinner and superseded. A citation of
"class 26" was ambiguous for however long that stood, in the one document whose entire function
is to be cited. Consolidated; numbering verified unique 1..56.

**The corpus's own standard is one authoritative account over accumulated narratives
(D0A-R34-04), and it carried two.** The check that found it was `grep -c`.

## Lane runs 22-25

| run | outcome |
|---|---|
| 22 | **REFUSED** — handover split across shells, so `$RUN`/`$LOG` were empty from the second step; the run step refused BY ITS OWN GUARD and every unguarded sibling produced a plausible artifact |
| 23 | **ACCEPTED** — 224/6/230 as predicted; first lane run accepted by machine rather than convention; membership re-derivable from the retained log by anyone |
| 24 | **REFUSED** — two root failures, the negative control `Unresolved` (class 55), the gate's own dirty-tree false positive |
| 25 | **REFUSED** — one root failure, the negative control `Topology` but unreadable (class 55 again) |

Predictions: 224/6/230 matched exactly at run 23. Runs 24 and 25 measured 222 and 223 against a
predicted 224 — **the derivation of the test SET was right both times** (232 identities each
side, zero in either direction, exactly 8 skips); `EXECUTED` counts passing tests, so the
difference is the failures.

## What remains open

**Reaping is NEVER independently observed** — the only evidence is the daemon's own exit status,
a self-report by the component under test; R29-05's `Unreaped` is UNCONSTRUCTED. `r4_03` is
unreproducible and uninstrumented-until-next-long-session. `Scan` and `Unresolved` have never
been produced at root. `action.timeout` enforced nowhere (R9-04); the pending store has no cap;
the mutation campaign is unprivileged-only (90 guards); the production logind gate is blocked on
a seated lane; R22-01's ordering is now machine-checked for the first time.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:** **10** (a skip reports `ok`) — though class 56 is 10 arriving through
build state rather than through a gate; **43**; **44**.

**(b) Applicable and NOT foreclosed:**

- **56** (coverage from build residue) — **new, and its scope is the open question above.**
- **55** (producer/consumer format) — new; two instances; foreclosing discipline unproven.
- **54** (a required check disconnected from acceptance) — the verifier closes it for the lane.
  **Does it close it anywhere else?** Nothing else in this tree has an acceptance gate.
- **49** (silence ≠ coverage) — five eliminations under conditions that differ from the failing
  one is 49's shape pointed at my own investigation.
- **45** (the totality claim) — this range asserts "every check weaken-proven", "nothing unique
  was lost" in the class-26 merge, "the derivation was right both times". **Audit all three.**
- **41** (wrong altitude) — `processes_named`/`read_proc_record` remain hand-rolled `/proc`.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R36-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**Most valuable returns:** (1) **the ruling on citing an observation from a refused run** — I
wrote the rule and immediately benefited from the narrow reading; (2) **the cheapest exhaustive
enumeration of class 56** rather than one instance at a time; (3) whether instrumenting for
`r4_03` instead of reproducing it is rigor or comfort; (4) a defect in `lane-accept.py`, which
now gates every lane run and has had four of its own.
