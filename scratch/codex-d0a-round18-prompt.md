# Codex adversarial review — D0-A round 18 (the merge gate)

This prompt is `scratch/codex-d0a-round18-prompt.md`, the round-18 prompt for
`phase-3b/d0-readiness-contract`. If you are reading it detached from that branch, say so and
stop — the target will not resolve.

## Why this round exists, stated plainly

The branch is at a natural close and the shipping surface looks settled. **That is the
argument for having this round, not against it.** The largest single item in the range is a
new *test* — and this arc's base rate is that **verification code has been wrong more often
than the code it verifies**: a probe that measured nothing, a stability leg that counted
skips as successes, a harness that committed the defect it was written to detect, a dead-code
sweep at the wrong altitude. The demonstration is verification code and no reviewer has seen
it.

## Your target

**`git diff db6393a..d7c4df0`** — nine commits. **PINNED, not `..HEAD` (D0A-R18-09):** this prompt said `..HEAD`, and committing the prompt itself then moved HEAD, so the stated stat excluded a commit the target included. A prompt that names a moving reference cannot state a diff stat the reviewer can check against. `db6393a` was round 17's review target; every
commit after it is unreviewed, **including round 17's own remediation** (`89a8b09`), which
was fixed in response to findings and then never re-reviewed.

Inspect through the CLI. Expect:

```
 14 files changed, 871 insertions(+), 42 deletions(-)
```

Report any disagreement as a finding. In scope: the preview allowlist (`53e9758`), the
cleanup pass and its conformance row (`71fd898`), the lane-run-7 procedure (`7458a25`), the
chain-gap demonstration (`d4a741e`), and the R17 remediation (`89a8b09`).

## Grounding

Verify against source or official documentation — `capabilities(7)`, `ld.so(8)`,
`execve(2)`, the coreutils/uutils sources, bubblewrap. Do not reason from memory about
`argv[0]` dispatch, `env`'s PATH fallback, or `LD_*` semantics. Reproducible instruments:
`scratch/d0a-r10-12-window-probe.sh`, `scratch/d0a-r10-12-red-proof.sh`,
`scratch/lane-run-7-procedure.md`.

## The two questions this round most needs answered

**1. Is the demonstration's CONTROL sufficient, or does it pass while the impostor was merely
unreachable?** This is the assertion shape this arc has most often found insufficient, so it
gets asked directly rather than left to inspection.

`chain_gap_approved_path_selects_the_impostor_and_the_preview_discloses_it`
(`runtime/tests/b1_integration.rs`) asserts three things: the impostor ran (marker written),
the preview discloses the deciding directory, and — the control — **the same action without
`PATH` in `env_delta` SUCCEEDS while writing no marker**. The control's success is deliberate:
a control that errored would prove the impostor UNREACHABLE rather than UNSELECTED, so the
script body is valid Python and the real `/usr/bin/python3` is expected to run it via `env`'s
confstr `/bin:/usr/bin` fallback.

**Attack that.** Is there a path where the control passes — exit 0, no marker — for a reason
other than "`python3` resolved to something else"? Consider: the real python3 failing
silently; the marker path being unwritable in the control leg for an unrelated reason; the
action being refused in a way that still yields `Ok`; `env`'s fallback resolving to something
that neither writes nor errors.

**2. What ELSE in this path was generalised from one implementation?** The demonstration's
first run found that `/usr/bin/env` here is uutils coreutils, a multi-call binary dispatching
on `argv[0]`, which refused the approved `argv[0]`. That was written up as "fails closed, a
functionality limit not a hole" — and **that framing was local and nearly shipped as
general**. Measured since, on the same box:

| `env` implementation | approved `argv[0]` = `tool` |
|---|---|
| uutils (`/usr/bin/env`) | refuses |
| **GNU (`/usr/bin/gnuenv`)** | **runs the impostor, rc=0** |

So the refusal protects *here* and nowhere claimed. The correction is in `TRUST_MODEL.md` §3
and `DEFECT_CLASSES` 46. **The question for you is whether the correction is complete** — is
anything else in the canonicalize→execute path a behaviour of *this* toolchain that has been
written down as a property of the design? `bwrap` 0.11.1's `--cap-drop` semantics and its
unconditional `no_new_privs` are the obvious candidates, both load-bearing and both
measured on one implementation.

## Other surfaces

**3. The preview allowlist.** `CODE_SELECTING_ENV` shows `PATH`, `LD_PRELOAD`,
`LD_LIBRARY_PATH`, `LD_AUDIT`, `GCONV_PATH` in full and redacts everything else because the
delta may carry secrets. Is the allowlist under-inclusive in a way that matters (it
deliberately excludes interpreter-level `PYTHONPATH`/`NODE_PATH`/`PERL5LIB`), and is showing
these values ever itself a disclosure problem?

**4. The `assemble_profile` extraction** (`89a8b09`) — production and both tests now route
through one function. Does anything still bypass it?

**5. The §7 row opened by the cleanup pass.** `RuntimeAuditEntry::record` has test-only
callers and the `audit` module has no production entry point. The row asserts §7 is unwired
end to end. Verify that claim rather than accepting it.

**6. The lane procedure's counting path.** It runs 17 targets under `sudo` into one log and
parses it with `test-count.sh`'s `DELPHI_TESTCOUNT_LOG` mode, because the counter shells out
to cargo and cannot run under sudo. Dry-run verified identical to the cargo path
unprivileged. Is a concatenated multi-binary log parsed correctly in all cases, or only the
one that was tried?

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per CLAUDE.md §13.9

**(a) Pre-foreclosed — do not re-hunt:**

- **10** (a skipped test reports `ok`) — `test-count.sh` + the exact-equality baseline +
  `require_guard_executed`.
- **44** (a restore whose precondition is absent) — `trap` + `cmp`.
- **42** (sufficiency resting on a default) — the NNP dependency is named in code and
  register, and the shim's `.gitignore` dependency was removed by building into a temp dir.

**(b) Applicable and NOT foreclosed:**

- **46** (the isolated measurement cannot reach the seam) — **newly written, and question 2
  is whether crossing one seam cleared it.** The class's own text says it did not.
- **45** (the totality claim) — the range contains fresh absence-shaped prose in §3, class 46
  and the register. Audit it as a class.
- **20** (latent until the environment arrives) — the demonstration chowns four paths
  explicitly because `chown_to_tool` is not recursive; is that enumeration complete?
- **25** (fixture constructed differently from what it stands in for) — the demonstration
  sets `argv[0] = "env"` to accommodate uutils, which production would not do.
- **41** (assertion at the wrong altitude) — including in analyses, not only assertions.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Every finding: an **ID** (`D0A-R18-nn`), a **severity**
(P1-high → P2-medium → P2-low → P3-informational), a **root cause**, an **impact**, a **fix
sketch**.

Findings that the work overstates its own evidence are in scope and welcome — rounds 16 and
17 both returned exactly that, and both were correct.
