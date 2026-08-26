# Codex adversarial review — D0-A round 17 (D0A-R10-12 remediation)

This prompt is `scratch/codex-d0a-round17-prompt.md`, the round-17 prompt for the
`phase-3b/d0-readiness-contract` branch. If you are reading it detached from that branch,
say so and stop — the target below will not resolve.

## Lead with this, because it is a PATTERN and not an incident

**Round 16's D0A-R16-01 falsified a totality claim of mine. It was at least the fourth of
its kind in this arc, and the first to escape the rule written to stop it.**

`docs/TRUST_MODEL.md` §3 records three, in its own words: *"Three rounds, three sentences in
this section that measurement contradicted: v7's contract version, named limit 2, and the
static-ELF 'no handler' claim."* It then adopts a rule — **"§3 states what is BOUND. It does
not state what is UNREACHABLE"** — on the reasoning that *"a claim that some path is absent
is a claim about the entire kernel and every configuration it can be in."*

**That rule is scoped to §3. The class is not.** R16-01's claim — "the NNP-absent shape is
not constructible in-tree", written as *"NOT WEAKEN-PROVABLE IN-TREE"* — lived in a **test
doc comment** and in **`docs/CONFORMANCE_REGISTER.md`**, which the rule does not cover. It
was an absence-claim about every possible mechanism, made about a tool whose linkage takes
one `readelf` to check, and it was **load-bearing**: it downgraded a security guard's
evidence from a RED to a probe pair, and it would have shipped that downgrade.

**So the question this round should press first: where else does this tree assert an
absence?** Not "is this particular claim true" but "which claims are of the KIND that has
now failed four times". Candidates worth auditing as a class — the accepted chain gaps in §3
(`PT_INTERP`, `env`+`PATH`, `binfmt_misc`), the "closes when" clauses in the register that
assert no mechanism exists, and any remaining *"cannot"* / *"no way to"* / *"not possible"*
phrasing in `runtime/src/**` doc comments. **A finding that the rule should be widened
beyond §3, or that a specific absence-claim is false, is the most valuable thing you can
return.**

## Your target

**`git diff 9af7d16..db6393a`** — the two round-16 remediation commits, `4cfceb7` and
`db6393a`, on `phase-3b/d0-readiness-contract`. Round 16's own subject was `3e4a275`;
`9af7d16` is the last commit before the remediation and is the correct exclusive base.

Inspect through the CLI — `git show 4cfceb7`, `git show db6393a` — rather than trusting any
supplied diff. Expect exactly:

```
 docs/CONFORMANCE_REGISTER.md
 runtime/src/execute.rs
 runtime/src/sandbox.rs
 scratch/d0a-r10-12-red-proof.sh
 scratch/d0a-r10-12-window-probe.sh
 scratch/nnp-shim/nnp_suppress.c        (added)
 6 files changed, 336 insertions(+), 145 deletions(-)
```

**Report any disagreement with that as a finding.** In particular, `scratch/codex-d0a-
round16-prompt.md` is NOT in this range — it changed in `9af7d16`, which is the base. If you
see it, you are reviewing a wider range than this prompt scopes.

## Grounding

Verify capability and loader claims against source or official docs — `capabilities(7)`,
`credentials(7)`, `ld.so(8)`, the kernel's `security/commoncap.c`, the bubblewrap
repository. Do not reason from memory about `cap_bprm_creds_from_file`, `no_new_privs`,
`LD_PRELOAD` eligibility, or bounding-set inheritance. Measurements are reproducible:
`scratch/d0a-r10-12-window-probe.sh` (root, seven legs) and
`scratch/d0a-r10-12-red-proof.sh` (unprivileged; it sudo's for the test binary only).

## What round 16 found and what was done

All seven were fixed at root. Judge the fixes, not the findings:

| finding | fix to judge |
|---|---|
| R16-01 | `scratch/nnp-shim/nnp_suppress.c` + red-proof **leg A**, the real RED. RAN: *"FAILED ON THE c0 ASSERTION under NNP suppression."* |
| R16-02 | `assemble_profile(action, creds)` — production's own function; both tests routed through it. Weaken (c) verified: deleting the branch while leaving the method now fails |
| R16-03 | stability leg runs `--nocapture` and requires the guard's capability witnesses; a SKIP is rejected explicitly |
| R16-04 | leg outcomes reach the exit status |
| R16-05 | the timed helper leg now carries the capability flags |
| R16-06 | ancestors deduplicated to match production's `BTreeSet` |
| R16-07 | `cap_read` requires rc=0 **and** the expected field; the probe exits non-zero on an absent measurement |

**The headline number changed KIND, not value.** `~1.7 ms/bind` was an artifact of R16-06's
duplicate emission. Re-measured: 1 bind 11.8 ms, 4 binds 10.7 ms, 8 binds 9.9 ms — no slope.
Recorded as *"~9–13 ms of fixed bwrap setup cost, neither depth nor bind count driving it"*
rather than as a revised slope. **Check that re-framing is honest and not a second
overstatement**: is "fixed cost" supportable from three medians that drift downward, or
should the register say only that no driver was found?

## Other surfaces

**1. Does leg A prove what it claims?** It suppresses NNP via `LD_PRELOAD` on the TEST's
bwrap. Production's `run_fd_pinned` calls `env_clear()`, so the shim could never reach
production's bwrap. Is simulating "bwrap stopped setting NNP" this way a faithful RED, or
does the fixture/production divergence (class 25) undermine it?

**2. `assemble_profile` gating.** Round 16 judged the `creds.is_some()` boundary defensible.
It is unchanged — the un-dropped path still runs the tool as root with `000001ffffffffff`.
Re-examine only if you disagree with round 16's judgement.

**3. Stability's witness check.** `require_guard_executed` greps for `restricted (--cap-drop`
in the output. Is that witness actually unforgeable by a skipping or partially-failing run?

**4. The shim as committed artifact.** A `.so` that suppresses a security mechanism now lives
in the repo. It is built by the harness rather than shipped, and `installer/` does not
reference it — verify that, and say if its presence creates a hazard.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per CLAUDE.md §13.9

**(a) Pre-foreclosed — do not re-hunt:**

- **10** (a skipped test reports `ok`) — foreclosed twice over now: `scripts/test-count.sh`
  plus the exact-equality baseline, AND `require_guard_executed`, which was R16-03's fix.
- **44** (a restore whose precondition is absent) — `trap` + `cmp` verification.
- **1** (`canonical_hash` both-halves) — no `PendingAction`/`ScriptPin` field added.

**(b) Applicable and NOT foreclosed:**

- **the totality-claim class** — the lead above. It has no number in `DEFECT_CLASSES.md` and
  arguably should; a finding that proposes the entry is in scope.
- **22 / 37** (the fix inherits the class it was closing) — R16-03's fix was itself a class-10
  instance inside the harness written to catch class 10. Check the fixes did not re-inherit.
- **25** (fixture constructed differently from what it stands in for) — surface 1.
- **34** (a deferral is an untested claim) — is anything in the remediation still deferred?
- **41** (assertion at the wrong altitude) — `cap_read`'s required-field regexes.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Every finding carries an **ID** (`D0A-R17-nn`), a
**severity** (P1-high → P2-medium → P2-low → P3-informational), a **root cause**, an
**impact**, and a **fix sketch**.

Findings that the remediation *overstates its own evidence* are in scope and welcome — that
is what round 16 returned, and it was correct to.
