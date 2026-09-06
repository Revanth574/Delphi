# Codex adversarial review — D0-A round 26 (the merge gate)

This prompt is `scratch/codex-d0a-round26-prompt.md`, for `phase-3b/d0-readiness-contract`.
If you are reading it detached from that branch, say so and stop.

## Your target

**`git diff 40d7fb7..53e2b5a`** — five commits. Pinned to a SHA, not `..HEAD` (D0A-R18-09).

```
 15 files changed, 1197 insertions(+), 218 deletions(-)
```

The round-25 remediation (four product fixes, four record fixes, one corpus class), the
corrected lane procedure, and lane run 14.

---

## Lead: NOT "are we converging". **Which regions are still unexamined?**

Round 25 asked whether four quiet rounds meant convergence or scope exhaustion. **The answer
was scope exhaustion, and it was proven, not argued**: three P1 product defects in
`runtime/src/**`, in the regions a measurement had flagged as never-named. So this round
inverts the question. Convergence is not the hypothesis; **coverage is**.

### The class-49 check, RUN rather than described

`docs/DEFECT_CLASSES.md` class 49 was written from round 25 and specifies a mechanical check:
enumerate the source files in the trust boundary, grep the last N review prompts for each,
report the zeros. Here is its output for rounds 21–25, so you start from data:

```
FILE                      R21 R22 R23 R24 R25   TOTAL
readiness.rs                0   0   0   0   0     0     <- the D0 increment's OWN subject
launcher.rs                 0   0   0   0   0     0
consent_relay.rs            0   0   0   0   0     0
pam.rs                      0   0   0   0   0     0
logind.rs                   0   0   0   0   0     0
fdsec.rs                    0   0   0   0   0     0
privdrop.rs                 0   0   0   0   0     0
pidfd.rs                    0   0   0   0   0     0
audit.rs                    0   0   0   0   0     0
wire.rs                     0   0   0   0   0     0
scaffold_env.rs             0   0   0   0   0     0
lib.rs                      0   0   0   0   0     0
delphi-runtimed.rs          0   0   0   0   0     0
delphi-minimal-{ai,shell}   0   0   0   0   0     0
delphi-surface-shell.rs     0   0   0   0   0     0
--- named at least once ---
execute.rs                  0   0   0   0   3     3
anchor.rs / canonicalize.rs / channel.rs / service.rs / store.rs / token.rs / sandbox.rs   1-2 each
action.rs                   0   0   0   0   1     1
```

**Fourteen of twenty-six files have never been named in five rounds of prompts.** Seven of
those fourteen are **tier 1** by CLAUDE.md §6's own classification — the trust boundary:
`readiness.rs`, `launcher.rs`, `consent_relay.rs`, `pam.rs`, `logind.rs`, `fdsec.rs`,
`privdrop.rs`.

**The corroboration that makes this worth acting on:** round 25's findings landed in
`service.rs`, `canonicalize.rs`, `execute.rs` and `token.rs` — files the round-25 prompt had
named for the first time. Naming a region and finding defects in it correlated once. That is
one data point, not a law, but it is the only one available.

**The same qualifier as last round, and it still cuts both ways:** a prompt not naming a file
is not proof you did not read it. These prompts tell you to inspect the live tree. So the table
bounds **what I steered toward**, not what was looked at. **You are the only party who can say
which.** If some of those zeros are regions you have already covered, saying so is a useful
finding in itself — it converts a suspicion into a closed question.

**Where I would start, if the choice were mine:** `readiness.rs`, and there is a second reason
beyond the zero. It is the D0 increment's **own subject**, it has never been named in a prompt,
and CLAUDE.md §6 records it as the worked example of the comment-budget failure — "shipped at
830 lines for a ~200-line mechanism, most of the remainder being comment that taught classes
already written down elsewhere."

**It is now 1094 lines.** It has grown by 264 since the amendment that named it as over-budget
and declared trimming it owed work. So the one file the project singled out as bloated, in the
increment it belongs to, has gained a third again in size while never once being pointed at by
a reviewer. I have no evidence there is a defect in it. That is the point: **nobody has looked,
and its growth is the only signal available, which is exactly the situation class 49
describes.**

Then `pam.rs` + `logind.rs` — the two halves of the gate that every finding in this arc has
been adjacent to without ever being aimed at.

---

## Second focus: **are the four fixes SUFFICIENT, or merely present?**

**Three of the four are REFUSALS, not implementations**, and a refusal is only as good as its
enumeration of what to refuse. Attack the enumerations.

### R25-01 — refusing a tier the daemon cannot enforce

`ENFORCED_TIER = RequiredTier::Biometric`; anything above is denied before store/preview.

**The attack I most want made, because I chose the answer and I am not disinterested:** is
`Biometric` the right ceiling, or should it be `Confirm`? My justification is that this crate's
own doc comment defines `Biometric` as "live PAM authentication", and the one gate sequence is
exactly that. But the enum is *named* `Biometric`, and `docs/TRUST_MODEL.md` says the
biometric/TPM tiers "ride the same daemon-driven PAM stack" — which reads as *a biometric PAM
module is IN the stack*. The shipped stack is `pam_unix` alone. **So the same argument that
refuses `Hardware` as a password-backed false claim may refuse `Biometric` too, and I stopped
one tier short of where my own reasoning leads.** If that is right, the fix understates the
problem and the register's "CLOSED" is wrong.

Also: is refusing above the ceiling the right shape at all, versus refusing *unknown* tiers and
implementing the known ones? And the floor direction is deliberately unimplemented — an
`Autonomous` request receives the stronger gate, documented as fail-safe-by-absence-of-
branching. Is documenting that sufficient, or does an unenforced floor invite the downgrade the
finding warned about?

### R25-02 — refusing non-regular files and oversized reads

`O_NONBLOCK` open, `is_file()`, a 64 MiB ceiling, bounded `take`.

**The ceiling is the soft spot and I will name it before you do.** 64 MiB is derived from *this
box*: 1449 executables in `/usr/bin`, `/bin`, `/usr/libexec`, largest 34.5 MiB, none above 64.
That derivation is honest and **local**. It says nothing about a deployment with a large
statically-linked toolchain, a container image, or a different distribution. Is a
measured-on-one-machine constant an acceptable security bound, or does this need to be
configuration with a documented default? What does the daemon do when a *legitimate* tool
exceeds it — the refusal is loud, but it is also a denial of service against the user's own
software.

**On the type enumeration**, which is the part a refusal lives or dies by:

- `is_file()` admits regular files. **A regular file on a FUSE or network filesystem can block
  indefinitely in `read`, and `O_NONBLOCK` does not help there** — the FIFO fix does not cover
  it. Real gap or acceptable?
- procfs entries report `st_size == 0` and yield data anyway. The `take` bounds them, but the
  fstat ceiling is inert for that whole class. Does anything else depend on the size check
  being meaningful?
- Symlink-to-FIFO: `open` follows, then `fstat` on the fd sees the FIFO. I believe this is
  covered. **Verify rather than accept it.**
- Is there any deadline at all? The finding asked for "cancellation/deadlines" and the fix
  delivered type + size bounds. A slow-but-regular file is still unbounded in TIME.

### R25-03 — refusing an empty argv

Refused at canonicalization and at the execute choke point.

**A GAP I FOUND WHILE WRITING THIS PROMPT AND AM HANDING OVER RATHER THAN QUIETLY FIXING.**
`env_delta` is validated for embedded NUL, empty name and `=` in the name, at BOTH doors
(D0A-R18-03 / R19-05). **`argv` is validated for EMPTINESS ONLY.** A NUL inside an argv element
is checked nowhere.

What I know: the preview renders argv through `escape_debug`, so a NUL would be *visible* to
the human rather than hidden, and the digest covers the raw bytes — so this is not obviously
the env-smuggling shape, whose whole force was that the preview showed one entry and `execve`
saw two. What I do **not** know: what `std::process::Command` does with an interior NUL at
spawn — error, panic, or truncation — and whether any transport path truncates rather than
rejects. **I did not verify it and am not asserting it.** Determine what actually happens and
say whether the asymmetry between argv and env validation is a defect.

### R25-04 — the monotonic consent window

`granted_at: Option<Instant>` set by `PendingStore::grant`, checked at Present; `None` is
fail-closed.

Attack: the wall-clock `within_ttl` in `token.rs` is **still there** and still authoritative
inside `execute_approved`, which is reachable directly. Are there two clocks disagreeing where
one should govern? Does `Instant` survive a suspend/resume on this platform the way the fix
assumes (`CLOCK_MONOTONIC` vs `CLOCK_BOOTTIME`)? **A machine suspended for an hour between
consent and Present is the exact scenario, and I did not check which clock Rust uses.**

---

## Run 14, and the check that previously could not check

`EXECUTED 187 / SKIPPED 5 / reported 192`, rc 0, 17/17 producers exited 0. Predicted
`187/5/192` at `af6dde0`, committed alone before the run, matched exactly.

**The freshness step is the substance.** R25-05 found that the prior step claimed "an unchanged
set of hashes" while its commands hashed nothing — `| tail -3` printed artifact paths and the
forced rebuild went to `/dev/null`, with no `pipefail` to catch a failed cargo. The corrected
§2b hashes the enumerated set before and after a forced rebuild: `before=17 after=17`, `diff`
empty.

Judge: **is the new step actually sufficient?** It hashes what §2 enumerated — so a defect in
the enumeration propagates silently into the freshness claim. Both counts are printed to catch
a short list; is that the right guard, or does it need to assert against the target count
rather than display it? And does `touch runtime/src/execute.rs` force a rebuild of all 17
targets, or only those that depend on it?

Also judge whether run 14 legitimately closes D0A-R24-01, or whether closing a finding with a
run performed under a procedure corrected in the same range is circular.

## The record fixes, and class 49

R25-06 (one `RUN` variable, derived paths, freshness moved after enumeration), R25-07 (PROGRESS
rewritten as a current snapshot with chronology relocated, not deleted), R25-08 (the daemon
entrypoint no longer describes a flow ending in `audit` while §7 is unwired).

**Class 48 caught a THIRD site this round**, and it was a contradiction rather than a stale
reference: after fixing the two sites R25-05 named, running the predicate found that an earlier
section of `CONFORMANCE_REGISTER.md` still asserted the withdrawn freshness check as fact AND
still read "This closes D0A-R24-01" — so the document would have carried the reopening and a
stale closure of the same finding. Three consecutive rounds where the predicate found a site
the finding did not name.

**Attack class 49 itself.** It is new, it is a process class rather than a code class, and this
prompt is its first use. Is its check sound, or does grepping prompt text measure the wrong
thing entirely? Is "the discriminator is whether anyone looked" actually right — or can a
region be genuinely closed by construction such that not looking is correct?

## What remains open, by state

- **DEPENDENT on the native-UI increment**: R21-01's semantic-forgery half, R21-04, R21-06.
- **SCOPED ELSEWHERE by decision**: §7's audit unwired, the tool's bounding set full, the
  socket refusal fixture-measured, R9-03/04/05/07/12.
- **INHERITED BY A FUTURE INCREMENT**: R23-01..R23-10 (a lane runner worth having).
- **REOPENED**: R22-01 — ordering is convention; it has now held for two consecutive runs,
  which makes the failure non-guaranteed, **not** the convention sufficient.

A fifth state found now is a finding; the partition has failed twice.

## Defect-class partition (`docs/DEFECT_CLASSES.md`), per §13.9

**(a) Pre-foreclosed — do not re-hunt:** **10** (a skip reports `ok` — extractor, exact
baseline, and run 14's five skips each quoted); **43** (child's own stderr); **44** (restore
precondition).

**(b) Applicable and NOT foreclosed:**

- **49** (silence ≠ coverage) — **new this round, and this prompt is its first application.**
- **48** (the fix scoped to the named instance) — third consecutive catch; is the predicate
  now load-bearing enough to be a gate rather than a habit?
- **45** (the totality claim) — this range asserts "all ten execute at root", "every hygiene
  check captured with the evidence that decides it", "the enumeration of non-regular types is
  complete". **Audit all three.**
- **41** (wrong altitude) — the class-49 table above is a grep. Grep sweeps in this arc have
  returned confident false negatives three times.
- **15** (Iron Law #15 clause 2) — one test in this range PASSED under its own weaken
  (`contains("ceiling")` matched both guards' messages) and was caught only by performing the
  weaken. Are the other nine new tests free of that shape? **Check the assertions, not the
  names.**

## Verdict format

**APPROVE** / **REVISE** / **FAIL**. Each finding: **ID** (`D0A-R26-nn`), **severity**, **root
cause**, **impact**, **fix sketch**.

**The most valuable return is a defect in one of the fourteen never-named files** — that is the
hypothesis this round exists to test. Second: a demonstration that one of the three refusals
has an incomplete enumeration, since a refusal that misses a case fails silently and looks
exactly like a refusal that does not. **An APPROVE that rests on "the round-25 fixes are
correctly implemented" would be answering a narrower question than the one asked.**
