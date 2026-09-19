# Weaken records — the ledger a RED-proof claim is cited from

A record is written by `scripts/weaken-driver.py` for **every** run, whatever the verdict. It
is cited from a commit message as a trailer:

```
weaken-record: 7e0137dae16c6eb8
```

`.githooks/commit-msg` **refuses** a message that claims RED-proof without one, or that cites
an id which does not resolve, does not hash to its own contents, or whose verdict is not
`RED_PROVEN`. It is a consumer, not advice — a rule that merely advised would be
`DEFECT_CLASSES` 54, the class this mechanism exists to close.

## What a record is for

**Re-openability, not truth.** The test applied to every field: *could a reader who was not
here reconstruct the experiment well enough to DISAGREE with its verdict?* A field that does
not serve that is decoration; a missing field that does is a gap. That test — not a list — is
what the next person adding a field should apply.

## Two fields that are there for reasons worth keeping

**`phases[].duration_s`.** Every other field is a *content* fact (which bytes, which label,
which exit). The sharpest refusal this tool has produced was a *timing* fact: deleting a
`killpg` made the driver hang for the suite's full timeout, so its restore landed **after** a
grandchild's write and masked the defect the weaken targeted. A record of what happened that
cannot show *when* it happened cannot surface a self-invalidating experiment — the category
this tool exists to catch, and the one that produced three refusals in a single session.

**`instrument.digest_executing` vs `subject.digest_before`, as two fields.** Rounds 38 and 39
were the driver making claims about the driver. It runs from memory while mutating its own
source on disk, so a single "instrument digest" is ambiguous in exactly the case needing most
scrutiny. `is_the_instrument_file` says when that is happening; the executing digest is taken
at import, before anything can be written. Both records in this directory have it set.

## Why records exist at all

Class 22's longest-running instance — validity established by *proxy*, three rounds running
(text, then compilation, then an import that reads `__pycache__`) — was caught by a reviewer
each time and by nobody here. **An instrument's own claims about itself are exactly what needs
to be independently re-openable.**

## What a record does NOT establish

Every record carries its own `limits` array, so a citation cannot shed them. In summary: the
weakened guard may be ill-chosen; `NOT_CAUGHT` does not separate redundancy from a condition
never arranged; the side channel is a report channel for trusted helpers; a `setsid`
descendant escapes group collection; and content-addressing prevents post-hoc **editing** of a
record, not **fabrication** of one. `--no-verify` and per-clone `core.hooksPath` mean the hook
gates the default path, not a determined author — repository-wide enforcement is CI, a later
placement.
