# Codex adversarial review — D0-A round 20 (the merge gate)

This prompt is `scratch/codex-d0a-round20-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Lead: a decision was REVERSED, and both of us have a stake in the reversal being right

Round 18 removed the preview's environment redaction. **I argued for it and the operator
approved it on my rationale.** Round 19 (R19-04) then found the rationale was checked at one
boundary and generalised: the AI socket does send only `Pending { pending_id }`, but the
preview is also injected into the **WebView page realm** by `shell-host`'s `drive_consent`,
`TRUST_MODEL.md` §3 still normatively required the allowlist, and §4's flow permits the AI to
receive `{pending_id, preview}` even though today's code does not.

**The remediation restored the code rather than amending the contract** — the allowlist is
back, both deleted tests are restored, and §3 now records the removal-and-restoration.

**The question this round most needs answered is whether that was the right resolution.**
Specifically:

- Was §3 correct, so restoring the code is simply conformance — or did the contract genuinely
  need amending, and does the restoration **paper over a decision nobody made**?
- The renderer receives the preview. Is redacting non-code-selecting values the *right*
  boundary, or does a renderer that cannot be trusted with `API_TOKEN=…` also not belong
  receiving `PATH=/tmp/evil` — i.e. is the allowlist coherent, or a split-the-difference?
- `docs/TRUST_MODEL.md` §4's flow says the AI gets `{pending_id, preview}`; the code sends
  only the id. **That divergence is unresolved in either direction** and is recorded nowhere
  as a conformance row. Should it be?

**I am the wrong party to answer this and so is the operator** — I proposed the removal, the
operator approved it, and we have both now endorsed the reversal. An outside verdict is the
point of asking.

## Your target

**`git diff 2f5a545..7ec10df`** — three commits, pinned rather than `..HEAD` (D0A-R18-09 was
exactly the error of naming a moving reference and then committing into it).

Inspect via the CLI. Expect:

```
 11 files changed, 209 insertions(+), 45 deletions(-)
```

Report disagreement as a finding.

## Carry: a fail-open fix that was itself fail-open

R19-02 found that `DELPHI_TESTCOUNT_EXPECT_TARGETS` was **documented non-optional and was
optional**, with every self-test case using the fail-open form — so nothing would have
noticed the gate's deletion. The fix makes it mandatory in parse-only mode and adds three
regressions.

**The block containing those regressions landed AFTER the verdict line** — unreachable, with
`fail` already evaluated, and `ALL PASS` printed regardless. **Class 22 inside the fix for a
fail-open finding.** Caught only by checking whether the new cases appeared in the output
rather than trusting the summary.

**I have since audited every shell suite for the same shape and found none** — but the audit
itself was wrong first: a textual sweep for top-level code after `exit` returned three hits,
**all false**, each an `exit 0` inside a heredoc defining a stub script, plus a fourth that
was the string `ALL PASS` inside a grep pattern. That is class 41 in an audit, the second
time in this arc. **Check both the conclusion and the method.**

## The rest of the remediation, with the rationale to attack

| finding | fix | what to attack |
|---|---|---|
| R19-01 | RAII tempdir replacing a predictable `/tmp` path written as root | is RAII sufficient, or does the test still touch predictable paths elsewhere? |
| R19-05 | env re-validated at the execute choke point, since `PendingAction`'s fields are public | is the choke point the *only* remaining entry, and are `argv`/`cwd`/bind paths subject to the same hazard and still unvalidated? |
| R19-07 | "the string is bound; any PROGRAM it names is resolved at run time and is NOT bound" | is that true for **every** argument shape, or is there one it misdescribes? |
| R19-08 | witness records `py<major>\|<sys.executable>` and asserts the interpreter is not from the impostor dir | `sys.executable` is EMPTY under `env`'s confstr fallback — does the not-from-impostor-dir assertion mean anything when the path is empty? |
| R19-03 | named as a limit: `escape_debug` gives machine injectivity, not human distinguishability | is naming it sufficient, or does a preview a human cannot distinguish need a mechanism rather than a note? |
| R19-06 | the `+2` attribution corrected in three places | verify the `+1` for run 9 is the NUL test and not something else |

## Lane evidence

Run 9 at the round-19 remediation: `EXECUTED 171 / SKIPPED 5 / reported 176`, rc 0, 0
failures, 0 leaks, PAM intact, all 17 producers exited 0. The R19-02 gate **bit on a real
log** — omitting `EXPECT_TARGETS` refuses at rc 2. Verify the +1 accounting and the
"overlapping sets, neither a superset" claim for 171 vs the unprivileged 151.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed:**

- **10** (a skip reports `ok`) — extractor, exact baseline, `require_guard_executed`.
- **43** (one error string, two processes) — the demonstration prints the child's stderr;
  it diagnosed R19-08's own first failure.
- **44** (restore without precondition) — `trap` + `cmp`.

**(b) Applicable and NOT foreclosed:**

- **22 / 37** (the fix inherits the class it closes) — **live, with a fresh instance**: see
  the unreachable-block carry above.
- **41** (wrong altitude) — twice now in *analyses* rather than assertions.
- **45** (the totality claim) — the remediation added "the tree has NO other instance" and
  "the choke point every execution passes". Audit both as claims.
- **25** (fixture unlike its subject) — the demonstration still sets `argv[0] = "env"`.

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R20-nn`), **severity**,
**root cause**, **impact**, **fix sketch**.

**A finding that the R19-04 reversal was wrong is the single most valuable return** — it
would mean the contract needed changing and two rounds of remediation moved in the wrong
direction. Findings that a rationale is unsupported remain in scope; that is what rounds 18
and 19 both produced, and both were correct.
