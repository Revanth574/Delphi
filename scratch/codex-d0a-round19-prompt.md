# Codex adversarial review — D0-A round 19 (the merge gate)

This prompt is `scratch/codex-d0a-round19-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Lead: round 18 FAILED, and both questions I asked to be attacked broke

Round 18 returned **FAIL, 4×P1**. Two of its findings answered questions the round-18 prompt
had asked the reviewer to attack directly — **and in both cases the thing I was defending was
wrong**:

- **The control was satisfied by a real `python3` that FAILED.** The prompt argued the
  control was sound because it *succeeds while writing no marker*. `exec_no_path.is_ok()`
  proves only that a child was spawned and reaped; `Command::output()` returns `Ok` on a
  nonzero exit. So a control asserting "succeeded, no marker" was satisfied by the real
  interpreter dying. **The absence was doing all the work.**
- **R18-05 falsified a RATIONALE, not a mechanism.** The preview redacted environment values
  "because the delta may carry secrets and the preview reaches the untrusted requester". That
  premise was false: production sends the AI only `Pending { pending_id }`; the preview goes
  to the pinned shell over the private channel. **Redaction was hiding the code-selecting
  fields from the only party entitled to see them** — an inherited justification that had
  never been checked against the code it justified.

**So the highest-value thing this round can return is the same shape again**: not a defect in
a mechanism, but a *justification* that does not survive contact with what the code actually
does. The remediation below is full of them — every fix carries a rationale I wrote, and none
has been checked by anyone else.

## Your target

**`git diff 05d59d1..04f809c`** — three commits, pinned rather than `..HEAD` (D0A-R18-09 was
exactly that mistake: committing the prompt moved HEAD and invalidated the stated stat).

Inspect through the CLI — `git show 0d9abaa`, `3f7ffb2`, `04f809c`. Expect:

```
 10 files changed, 356 insertions(+), 220 deletions(-)
```

Report disagreement as a finding. The **deletions matter here**: 220 lines went, including
two tests that encoded a spec R18-05 retired. Whether that removal was legitimate or a
weakening is a question for you.

## Grounding

Verify against source or official docs — `environ(7)`, `execve(2)`, the protobuf spec,
Rust's `std::process::Output`, coreutils/uutils sources. Do not reason from memory about NUL
handling in protobuf strings, `escape_debug`'s escaping guarantees, or `Command::output()`'s
success semantics.

## What changed, and the rationale attached to each

| finding | fix | the rationale to attack |
|---|---|---|
| R18-01 | both legs require `Output.status.success()`; the script body writes a **distinct control marker** | "a positive witness beats an absence" — does `REAL-PYTHON-RAN` actually prove the *real* python3 ran, or only that *something* interpreted the body? |
| R18-02 | injective rendering: every field quoted via `escape_debug`, explicit indices; `preview_version` 1→2 | "quoting + indices makes it injective" — is that true for **all** inputs, including non-UTF-8 paths via `to_string_lossy`, and bidirectional Unicode? |
| R18-03 | canonicalization refuses empty names, NUL in name or value, `=` in a name | "refusing at canonicalization covers it" — is that the only place such values enter, and are the *other* string fields (`argv`, `cwd`, bind paths) subject to the same transport hazards? |
| R18-04 | parse-only derives rc from the log; `DELPHI_TESTCOUNT_EXPECT_TARGETS`; per-target producer status | "both gates passed on first use" — passing is not the same as biting. Would they catch the failure they were built for? |
| R18-05 | the allowlist is **deleted**; all env values shown | "the audience is the pinned shell, so disclosure is safe" — verify the claim about who receives the preview, and whether any *other* consumer exists now or is implied |
| R18-06 | **every** interpreter arg marked unbound, including `-` forms | is the no-arg case's *unmarked* assertion the right discriminator? |

## Specific surfaces

**1. `q()` and injectivity.** `escape_debug` escapes quotes and backslashes, and the fields
are indexed — but `cwd` and bind paths go through `to_string_lossy`, which is **not
injective** (distinct byte sequences can map to the same lossy string). Does that reintroduce
the collision R18-02 closed, on a different field?

**2. The NUL refusal's blast radius.** `env_delta` is validated. `argv` entries also reach
`execve` and cannot contain NUL; `cwd` and bind paths reach bwrap's command line. Is
validating one field and not the others a real gap or a non-issue?

**3. The deleted tests.** `preview_redacts_env_values_no_oracle` and
`preview_shows_code_selecting_env_and_redacts_the_rest` were **removed**, not repaired,
because they encoded a spec built on a false premise. The oracle argument in the first was
sound *given its premise*. Confirm the premise really is false and the deletion is not a test
weakened to green (Iron Law #15).

**4. Run 8's evidence.** `EXECUTED 170 / SKIPPED 5 / reported 175`, rc 0, all 17 producers
exited 0, superseding run 7's 168/5 which D0A-R18-07 found stale. Is the +2 accounted for,
and is the "overlapping sets, neither a superset" claim about 170 vs the unprivileged 150
correct as stated?

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:**

- **10** (a skip reports `ok`) — extractor + exact baseline + `require_guard_executed`.
- **44** (restore without precondition) — `trap` + `cmp`.
- **43** (one error string, two processes) — the demonstration prints the child's stderr and
  the lane procedure's §7 mandates it; it converted `left: ""` into a named cause on first
  use.

**(b) Applicable and NOT foreclosed:**

- **45** (the totality claim) — the remediation added fresh absence-shaped prose ("the only
  place such values enter", "no other consumer"). Audit it as a class.
- **46** (the isolated measurement cannot reach the seam) — R18-04's gates were verified
  against synthetic logs. Synthetic is isolation.
- **25** (fixture unlike what it stands in for) — the demonstration still sets
  `argv[0] = "env"` to accommodate uutils, which production would not do.
- **22 / 37** (the fix inherits the class it was closing) — five of six fixes are in
  verification code, which is where this arc's defects have concentrated.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R19-nn`), **severity**
(P1-high → P2-medium → P2-low → P3-informational), **root cause**, **impact**, **fix sketch**.

A finding that a *rationale* is unsupported — rather than a mechanism defective — is the most
valuable return this round can produce, because that is what round 18 found twice and both
were correct.
