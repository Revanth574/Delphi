# Conformance register — where the tree does not satisfy `docs/TRUST_MODEL.md`

**`TRUST_MODEL.md` is normative and is NOT edited to match the code.** Marking a ratified clause
"unimplemented" inside the normative text would weaken the invariant until the mismatch
disappears — the move the weaken/restore discipline forbids for a test, applied to a document.
The document keeps asserting the standard; **this register carries the delta.**

Every row: the clause, the finding that found it, the commit at which the gap was measured, and
what closes it. A row leaves only when a test proves it closed.

---

## Opened 2026-09-06 — D0-A round 26 (verdict: **FAIL**, 5xP1 2xP2)

**Round 25's answer held up: the hypothesis was coverage, not convergence, and the round-26
prompt handed over class 49's check as data rather than a claim** — 14 of 26 `runtime/src`
files never named across five rounds, 7 of them tier 1. The findings that came back were not in
those files, though: they were in the round-25 fixes themselves, and **three of the five P1s
land on refusals whose enumerations were incomplete**. A refusal is only as good as what it
knows to refuse.

| § | ratified clause | status | finding | closes when |
|---|---|---|---|---|
| §3 consent tiers | the tier demanded is the tier enforced | **CLOSED** at this commit | R26-01 — R25-01 set the ceiling at `Biometric` reasoning that this crate defines it as "live PAM". But the shipped stack is `pam_unix` alone, so a `Biometric` action was satisfied by a PASSWORD with the stronger claim in its preview, digest and audit — **the identical false claim `Hardware` was refused for**, one rung down | `ENFORCED_TIER = Confirm`, weaken-proven by a test that fails at `Biometric` while the `Hardware` test and the positive control both still pass |
| §3 canonicalisation | the daemon cannot be wedged pre-consent | **CLOSED** at this commit | R26-02 — `O_NONBLOCK` is **ignored by Linux for regular files**, so a stalled FUSE/NFS mount still wedges the single-threaded root daemon in `read`. The prior comment noted the no-op as a *benefit* when it was the gap | the whole open-and-read runs under a 30 s deadline on a disposable thread; `under_deadline` is factored out so the timeout branch is directly testable |
| §3 token lifetime | the consent window is bounded in REAL time | **CLOSED** at this commit | R26-03 — `Instant` is `CLOCK_MONOTONIC` (measured: 51.048 ms `elapsed()` vs a 0.051 s MONOTONIC delta), which **pauses during suspend**. A machine closed for an hour between consent and Present returns with its window barely moved | `CLOCK_BOOTTIME` via `store::boot_secs`, fail-closed when unreadable |
| §3 canonicalisation | the read bound admits legitimate tools | **CLOSED** at this commit | R26-04 — the 64 MiB ceiling generalised from a `maxdepth 1` sample of three directories and was **wrong on the machine it was derived from**: `claude` (262 MiB), `codex` (246 MiB) and `claude-desktop` (207 MiB) all exceed it | root-controlled `DELPHI_MAX_EXECUTABLE_BYTES`, default 512 MiB **derived from the exhaustion budget** (peak = 2x ceiling; 1/8 of an 8 GiB workstation floor = 1 GiB; ceiling = 512 MiB), with a malformed value refused rather than defaulted |
| — (process) | a check decides, it does not display | **CLOSED** at this commit | R26-05 — the *corrected* freshness step still only PRINTED `rebuild rc` and the hash counts. A failed rebuild would compare two stale sets and print `FRESH`; two identically-short lists compare equal | every check `exit`s: enumeration asserted at 17, both hash sides asserted equal to it, rebuild failure fatal |
| — (record) | the derivation is checkable | **CLOSED** at this commit | R26-06 — the run-14 expectation described all four service tests as one fixture shape. Two use a socketpair via `serve_one_action`; two call `present_and_execute` directly, and the tier *control* reaches the gate rather than preceding it. **The number was right and the explanation was wrong** — R19-06/R20-07's shape, third occurrence | corrected in place, labelled post-hoc; the file's protected property rests on commit order (`af6dde0` precedes `53e2b5a`), not on its wording |
| — (record) | one current root record | **CLOSED** at this commit | R26-07 — the register still read `LANE RUN 13 (current)` beside run 14's closure of the finding run 13 had failed to close | run 13 marked superseded; run 14 named as the current record at the head of the section |

### R26-07 is the sharpest result, and it is about METHOD

Class 48's predicate **worked**. It surfaced the line. The output was then filtered with
`grep -viE "…|run 13 \(|…"` to separate live claims from deliberate history — and
`RUN 13 (current)` contains `run 13 (`. **The pattern written to hide historical mentions
deleted the one line asserting currency.**

That is not class 41 (wrong altitude): the sweep did not look in the wrong place, it looked in
the right place, found the thing, and a second step threw it away. Recorded as
`DEFECT_CLASSES.md` **class 50** — *a filter applied to a mechanism's output is not part of the
mechanism and can silently invert it* — with the remedy that a suppression pattern owes the
same discrimination test as an assertion: does it exclude only what it names?

### What R26-01's fixture migration exposed

Every fixture in the crate proposed `Biometric`. Moving all of them to `Confirm` cost **no
coverage**, because **nothing had ever asserted what `Biometric` meant** — the only two
tier-touching tests assert that *changing* the tier changes the digest and the preview, which
holds for any two distinct values, and `end_to_end.rs` says "one Biometric action" in a doc
comment. The label was decoration end to end. **That is a finding about the tier system, not
about the fixtures, and it is why R25-01's "descriptive only" defect could live undetected: no
test could have caught it, because no test claimed any tier meant anything.**
`biometric_is_refused_…` is the first test in this crate to assert on a tier's meaning.

### Honest residuals carried out of this round

- **The suspend divergence is reasoned, not measured.** `BOOTTIME - MONOTONIC = 0.000s` on this
  box (never suspended), so no assertion available here distinguishes the two clocks. The test
  checks clock IDENTITY and says so; a lane that has suspended would strengthen it.
- **The deadline's timeout branch is proven on a sleeping closure, not a stalled mount.** That a
  real FUSE stall reaches it is a property of the filesystem, not of this code.
- **The pending store still has no cap.** The ceiling bounds ONE proposal; a looping daemon (B2;
  B1 services one action and exits) accumulates sealed memfds across proposals. Not closed here.
- **`argv` is validated for emptiness only** while `env_delta` is NUL-checked at both doors.
  Surfaced in the round-26 prompt, unanswered by this round's findings, still open.

---

## Opened 2026-09-06 — D0-A round 25 (verdict: **FAIL**, 4xP1 4xP2)

**This round answered the convergence question, against both the operator and me.** Rounds 22-24
had returned no defect in shipping product behaviour, and `298d4db` (round 21's remediation) was
the last commit to change it. Round 25's prompt offered both readings — convergence, or scope
exhaustion — with a measurement attached: across the round-21..24 prompts, **exactly one
`runtime/src/**` file was named by filename** (`sandbox.rs`, once). The reviewer went to the
unnamed files and returned **three P1 product defects**. The silence was blindness, not quality.
Recorded as `DEFECT_CLASSES.md` class 49; the operator proposed the measurement and read it as
possible convergence, and I preferred the same reading, which is exactly why the judgement had
to be handed over.

| § | ratified clause | status | finding | closes when |
|---|---|---|---|---|
| §3 preview = approval = sandbox | consent tiers are enforced | **CLOSED** at this commit | R25-01 — `required_tier` was bound into the digest, rendered in the preview and written to the audit entry, and **never consulted**. All four tiers took the identical logind → PAM → mint sequence, so a `Hardware` action was authorised by `pam_unix`'s password | a tier above `ENFORCED_TIER` is refused before store/preview; a positive control proves the enforced tier still passes |
| §3 canonicalisation | the arbiter opens and hashes before preview | **CLOSED** at this commit | R25-02 — unbounded `read_to_end` on two AI-selected paths, with no type check. A FIFO blocks the ROOT daemon in `open(2)`; `/dev/zero` never ends; a large file exhausts memory — all **before** the pending action exists, so before any human gate | `O_NONBLOCK` open + `is_file()` + a derived 64 MiB ceiling + bounded read; FIFO leg proven by a `recv_timeout` that observes blocking |
| §3 exact approval | what is approved is what executes | **CLOSED** at this commit | R25-03 — `argv: []` is representable in the canonical action and the digest but not in `execve`, so both transport shapes invent an `argv0`: synthesised `/proc/self/fd/N` with a helper, and bwrap's own with `--argv0` dropped | refused at canonicalisation AND the execute choke point (the R19-05 two-door reason); the RED reaches the `Ok(_)` arm, i.e. it executed |
| §3 token lifetime | the consent window is bounded | **CLOSED** at this commit | R25-04 — the TTL compares Unix timestamps, so setting the system clock backwards keeps a consented token live indefinitely | a monotonic `granted_at` stamped by `PendingStore::grant` and checked at Present; the RED returns `Completed`, i.e. an expired action ran |
| — (process) | root evidence is what it says it is | **CLOSED by LANE RUN 14** (`af6dde0`, 2026-09-06) | R25-05 — run 13's "forced freshness proven" rested on commands that computed **no hashes**: `\| tail -3` printed three artifact PATHS (and masked cargo's status, no `pipefail`), and the forced rebuild went to `/dev/null` | **closed.** Run 14 under the corrected §2b: `sha256sum` over the enumerated set before and after a forced rebuild, `before=17 after=17`, `diff` EMPTY. `EXECUTED 187 / SKIPPED 5 / reported 192`, rc 0, 17/17 producers exited 0, PAM `md5sum -c` OK, no stale sessions |

**R25-05 is the finding that matters most, and it is worse than a missed check.** The operator
had specifically asked that each hygiene check's output be captured separately, *because* the
known failure mode is confirming a group. That was done. The output appeared. **And the output
was of a command that could not perform the check** — so the watch item was satisfied in form and
defeated in substance. Capturing each check separately does not help if a check's output cannot
decide the thing it is captured for.

What run 13 genuinely measured still stands: counts, 17/17 producer statuses, PAM before/after,
stale sessions, helper digest, account, bwrap, free space. What it did not measure is "these
binaries are this code".

**Also closed this round:** R25-06 (the procedure hard-coded `root-run7` while telling the reader
to substitute `N` — now one `RUN` variable with derived paths), R25-07 (PROGRESS's status block
carried accumulated `PRIOR:` chains and held an old date, two different "latest round" claims and
two count pairs at once — rewritten as a current snapshot, chronology relocated rather than
deleted), R25-08 (the daemon entrypoint still described the flow as ending in `audit` while §7 is
unwired — **and the class-48 predicate found a second site in `PROGRESS.md` that the finding had
not named**, the fifth recurrence of that class and the second caught pre-commit).

**One self-inflicted defect, recorded because the weaken caught it and nothing else would have.**
`an_oversized_executable_is_refused_on_size` first asserted only `contains("ceiling")`, and it
**PASSED under the weaken that removes the fstat guard** — because the bounded `take` catches the
same file with a message that also says "ceiling". A PASS/PASS, worthless under Iron Law #15
clause 2. The two guards are deliberately redundant in the product, so the test had to name which
one fired. This is the second time in this arc that performing a weaken, rather than reasoning
about it, was the only thing that found the flaw.

### Run 14 — the close, and what the prediction bought (2026-09-06)

`EXECUTED 187 / SKIPPED 5 / reported 192`, **exactly the pair predicted at `af6dde0`** and
committed alone before the run. The derivation was checkable in advance and is worth recording
because it held under test: run 13's 177 plus the ten round-25 tests, with root-gating verified
by grepping each test body rather than recalled — nine ungated, and the tenth gating on
`/usr/bin/coreutils` **existing** rather than on euid, so root sees the same file.

Both lanes report **192**, which was the consistency check written into the expectation: same
test set, different skip distribution. A different total would have meant the set changed,
which is a distinct defect from a count mismatch.

**The freshness step produced hashes this time** — `before=17 after=17`, `diff` empty. That is
the whole of R25-05: the prior step's commands printed artifact paths and discarded the rebuild
output, and the result was accepted. A check that emits *something* is not a check that decides
*the thing*.

**Ordering held under convention for the second consecutive run.** `af6dde0` contains the
expectation file alone; the result follows. That makes D0A-R22-01's failure non-guaranteed — it
does not make convention sufficient, and the reopening stands.

---

## Opened 2026-08-12 — D0-A round 9 (verdict: **FAIL**, 6×P1 3×P2)

Found by a scope pivot to `execute.rs` / `sandbox.rs` / `fdsec.rs` — paths last reviewed in June,
under a threat model the following eight rounds sharpened. **These defects are on `main`** (B1
merged at `f5b823d`); D0-A did not introduce them, it found them. Measured at `09dadae`.

| § | ratified clause | status | finding | closes when |
|---|---|---|---|---|
| §6 | "the tool runs under a uid that **cannot reach daemon IPC**" | **TWO SEPARATE PROOFS, cited separately (2026-08-16) rather than one test standing for both.** **(1) Credential state** — `an_approved_action_runs_with_the_tool_account_credentials` reads the action's own `/proc/self/status` at root: `Uid:` and `Gid:` all four fields (real/effective/**saved**/fs) equal `delphi-tool`\'s, `Groups:` empty, `CapEff:` zero. It previously observed `id -u` alone and was cited for six things; widened, and renamed to stop claiming the sixth. **(2) The socket refusal** — P\'s production leg, refused at `0660 root:<session-gid>`, **measured against a probe fixture, not the real daemon**. Neither proof covers the **pre-drop window** (D0A-R10-12) | D0A-R9-01 | **remaining:** the socket refusal is measured against the real daemon rather than a fixture |
| §6 | "**seccomp default-deny**" | **ABSENT** — no `--seccomp` anywhere in `sandbox.rs` | D0A-R9-05 | a policy is attached and a denied syscall is proven denied |
| §6 | "**cgroup v2 mem/pids/CPU caps**" | **ABSENT** | D0A-R9-04 | caps applied and a breach proven contained |
| §6 | "**timeout + kill-on-expiry**" | **ABSENT** — `action.timeout` is unenforced | D0A-R9-04 | an over-running action is killed, RED-proven |
| §6 | "mount exactly `fs_binds`" | **PARTIAL** — bind sources are **path-resolved at launch**, so a symlink swap substitutes scope | D0A-R9-03 | binds resolve to what was approved, TOCTOU-proven |
| §7 | audit "carries … result" | **CORRUPTIBLE** — a bwrap SETUP failure exits nonzero and is recorded as the action having run and failed, when it never ran. **Not a bypass**: `execute.rs:175` is the only production spawn (everything else is after `#[cfg(test)]`), and a missing bwrap is a hard error | D0A-R9-07 | setup failure and tool exit are distinguished in the audit entry |
| §6 | "the daemon's socket is a root-owned filesystem socket **outside the jail's mount set**" | **UNENFORCED** — `sandbox.rs:60` binds exactly what was approved with **no path denylist**, so an action may name `/run/delphi/…` and place the socket *inside* the mount set. Distinct from R9-03: that is TOCTOU on *resolution*; this is that nothing forbids naming the target at all | **D0A-R9-10** (found while verifying, not in the review) | **CLOSED 2026-08-15** — `sandbox::refuse_denied_bind` refuses every spelling (lexical fold + canonicalize), wired at the `run_fd_pinned` choke point, with a positive control. Both weakens bite: removing the call site lets execution reach bwrap (`bwrap: Can't find source path /run/delphi/alice` — it would have BOUND it where the path exists); removing traversal folding fails `/tmp/../run/delphi/alice` |

## THE ROOT LANE — WHAT IT PROVED, AND WHAT IT COST TO FIND OUT (runs 3–6, 2026-08-24/25)

**Standing after run 6: 17 targets, 0 failures, 0 skips, 0 leaks, PAM stack intact.** Sixteen
of those seventeen targets had never executed at root before run 3.

| property | standing |
|---|---|
| the approved environment reaches the tool **on the far side of the drop** (D0A-R15-01's gradient branch) | **PROVEN** at root — one artifact carrying `Uid: 997 997 997 997` **and** `DELPHI_SECRET=s3cret-value`, fd 11 carrying the sealed env |
| the drop helper the daemon runs is the one it was built against | **PROVEN** at root — built and installed agree at `aba0f0ea14b751aa…`, and the first time the digest binding refused a *legitimate* change rather than an attack |
| every `b1_integration` / `end_to_end` / `divergence` root path | **PROVEN** — 0 failures, and **0 skips**, so nothing closed by ceasing to run |

### A COUNT IS A PROPERTY OF THE COMMIT **AND THE LANE** — reviewer figures are not comparable

**Recorded 2026-09-02 so it is not discovered later as a discrepancy.** Round 24's reviewer
reported `EXECUTED 128 / SKIPPED 53 / reported 181` against this tree and three shell suites
failing at `unshare … Operation not permitted`. **That is their environment lacking user
namespaces, not a finding about the tree** — `reported 181` agrees with ours exactly; the
extra 28 skips are tests that gate on `bwrap_available` and userns.

**So their pair and ours measure different things and must never be cited as a check on each
other.** This is the same constraint `.githooks/runtime-test-count-baseline` already states
for a restricted container (D0A-R15-04: `EXECUTED=115 SKIPPED=46` against an identical tree)
— a pair is a property of the commit AND the lane, and only `reported` is portable across
them. A future round comparing 128 to 157 would be reading a lane difference as a regression.

### THE ROOT FIGURE — recorded from the tool, and RE-recorded when run 7's proved stale

**CURRENT ROOT RECORD: LANE RUN 14** — `EXECUTED 187 / SKIPPED 5 / reported 192`, freshness
MEASURED. Everything below this line is the superseded history that led to it.

**LANE RUN 13 — SUPERSEDED BY RUN 14 (D0A-R26-07). `EXECUTED 177 / SKIPPED 5 / reported 182`, rc 0, 0 failures,
17/17 producers exited 0, and EVERY HYGIENE CHECK PERFORMED WITH ITS OWN CAPTURED OUTPUT:**
helper digest installed == staged (`aba0f0ea…`), ~~forced freshness (identical executable set
after a forced rebuild)~~ **— WITHDRAWN by D0A-R25-05, the command behind it computed no
hashes** —, free space above floor on three filesystems, stale sessions none before AND after,
PAM `439c1d15…` → `md5sum -c` **OK**.

**This was recorded as closing D0A-R24-01. IT DID NOT — see the round-25 section above; the
close is LANE RUN 14.** The evidence had been split across two runs covering different
dimensions — run 11 the hygiene, run 12 the counts and machine-bound ordering — because run 11
was swapped for run 12 as "current" without recomputing which dimensions survived the swap.
Run 13 covers both of THOSE, so both are superseded, as is run 10's `173 / 5`. But run 13
carried a freshness line its own commands could not produce, so it closed R24-01 in form only
and D0A-R25-05 reopened it.

**This correction was found by the class-48 predicate, not by the finding.** R25-05 named the
procedure and the root baseline; this section — an earlier part of the same register — still
asserted the withdrawn check as fact AND still claimed the closure. Third consecutive round in
which running the predicate mechanically after the primary fix caught a site the finding had
not named.

**Its ordering is convention, not mechanism** (D0A-R22-01, reopened): predicted 177/5 at
`feabc56`, committed alone and before the run, with `git log` on the two files as the only
evidence — which holds here, and is a property to check rather than one that is enforced.

**Run 9's `171 / 5 / 176` is SUPERSEDED** (as run 8's superseded run 7's). D0A-R21-07:
run 10 was first recorded in the root baseline ONLY, leaving this row and PROGRESS still
calling run 9 current — a contradictory record on the branch that has been most careful
about exactly that.

SUPERSEDED DETAIL — `+1` against run 8 is R19-04's net (two restored redaction tests, minus the one asserting
the opposite) — **not** the NUL test, which already existed and belongs to run 7→8
(D0A-R20-07, the second consecutive attribution error).

**Run 7's `168 / 5 / 173` is SUPERSEDED, not merely older (D0A-R18-07).** It was measured
at `71fd898` — before the chain-gap demonstration existed — and was then cited as evidence
covering it. The `+2` between the runs is the chain-gap test and the D0A-R18-03 NUL-refusal test.
**CORRECTED (D0A-R19-06):** it was first recorded as "that test and its control" — the
control is an internal leg of one `#[test]`, not a second one. The figure was right and
the account of it was wrong, which is the shape worth catching: a number nobody
disputes, explained by a mechanism nobody checked. **Both D0A-R18-04 gates passed on first real use**: the per-target producer
status check, and `DELPHI_TESTCOUNT_EXPECT_TARGETS` with the extractor returning rc 0 — so
the gate that would catch a crashed target vanishing from the count is now exercised
rather than specified. Produced by `scripts/test-count.sh`'s parse-only mode
(`DELPHI_TESTCOUNT_LOG`) over the concatenated per-target log, because the counter shells out
to cargo and cannot run under `sudo` here. Written to
`.githooks/runtime-test-count-baseline.root`. All three post-run-6 changes to `runtime/src/**`
pass at root: the R10-12 capability restriction, the R16/R17 remediation, the preview allowlist.

**168 IS NOT A SUPERSET OF 148, AND THE NUMBERS INVITE THAT READING.** Three of the five root
skips exist *because* the run is privileged, and they EXECUTE unprivileged:

| skip | reason it skips AT ROOT |
|---|---|
| `an_unreadable_login_defs…` | "this uid can read a 0000 file" |
| `a_regular_login_user_is_not_refused…` | "running as root" |
| `pidfd_refuses_a_recycled_pid_barrier` | userns unavailable to root here |

The other two are euid-independent: `b1_daemon_binary…` needs `--features
insecure-test-seams`, and `live_logind_query…` is the standing DEFER.

**So the two runs are OVERLAPPING SETS, neither containing the other** — root executes tests
the unprivileged run skips, and skips three the unprivileged run executes. "168 > 148" read as
coverage would be wrong in both directions. The exact membership is readable from the two skip
LISTS; it must not be computed from the two totals, which is the subtraction this section was
written to refuse.

### Why the figure was withheld until now

`0 skips` and `169 reported` unprivileged would give `EXECUTED=169` at root by arithmetic.
**That is two measurements and a subtraction, not a measurement**, and it is the move that put
`EXECUTED=141 SKIPPED=0` in the baseline as an expectation nobody had run. The figure gets
recorded when `scripts/test-count.sh` runs at root and prints it. Until then this file records
the shape (17 targets, 0 failures, 0 skips) and not the number.

Superseded and not to be cited: run 3's `159 passed / 8 failed` (17 targets, first whole-suite
measurement) and its lib-only predecessor `112 passed / 1 failed`, which covered one target of
seventeen because the procedure said `head -1`.

### EIGHT FAILURES, FOUR CAUSES, ONE SIGNATURE — the record, because the shape recurs

`8 → 5 → 2 → 0`. Each run shed one cause and exposed the next, and **three of the four
presented identically** as `left: ""` — an empty marker, no error, no denial:

| run | cause | why it was invisible until then |
|---|---|---|
| 3 | fixtures never planned credentials | `#[cfg(test)]` helper cannot exist for an integration test, so the lib fix could not generalise |
| 4 | out dirs not chowned to the planned tuple | the action runs as `delphi-tool` and fails INSIDE the jail, so it never surfaces as a permission error |
| 5 | a second chown instance in a funnel run 4's fix did not reach | the file-granular guard asked whether the FILE chowns, not whether THIS fixture does |
| 5 | a fixture building an action production cannot (plain fd, fake digest) | `unwrap_or_default()` collapsed a correct refusal into an empty string |

**All four were latent, none regressed.** Every one had been present since its code landed and
was waiting for an environment nobody had used — the class-20 shape, four times in one arc.

**The durable fix is not any of the four.** It is that the fixtures now assert the **result
before the marker**, so a fifth cause names itself instead of costing three inferences. And
the enumerating guard, whose record is now decisive: seal check found 9 fixtures, digest check
2, credential guard 7, chown guard 5 — **reading found 0.**

## THE LANE RUNNER — BUILT TO CLOSE D0A-R22-01, REVERTED AT D0A-R23 (2026-09-02)

**Not deferred. Reverted, with the reason.**

`scripts/lane-run.sh` was built because D0A-R22-01 found the expectation protocol's ordering
claim was enforced by nothing — no hook, no runner, no CI job read the expectation before a
run, so "the prediction predates the measurement" rested on the author's habit. The runner
read the committed blob, refused a working copy that differed, refused an expectation
committed beside a result, and bound tree + blob + counts + times into an artifact.

**It worked, once, and that result is banked.** Run 12's artifact binds expectation commit
`c16c3e9` to tree `0330b46` and remains checkable by someone who was not present. Removing the
runner does not remove what it proved.

**Round 23 returned 8×P1 against it**, and one of them decided the question:

> **D0A-R23-05 — the replacement dropped five checks the procedure it superseded performed:**
> helper-digest, free-space, forced-freshness, stale-session, and PAM before/after.

That is not a new tool with gaps. It is a **regression in safety coverage sold as an
upgrade**, on the path that produces every piece of root evidence this branch has — and
class-16 PAM damage is a defect this project has already paid for once. The others: the
runner certified its own target universe (R23-01), labelled a wholly-failing lane
`DID_NOT_RUN` (R23-02), failed open when the artifact could not be written (R23-03), left no
usable evidence on a hang or failure (R23-04), and could not enforce its own
artifact-outside-the-tree property (R23-08).

### THE FAILURE MODE, NAMED: class 48, at the level of a whole procedure

**The runner replaced a procedure whose checks were load-bearing without enumerating them.**
D0A-R22-01 named an instance — unenforced ordering — and the fix was scoped to that instance
rather than to the class, which was *everything the procedure guaranteed*. Four of class 48's
five recorded instances are now in this arc, and this is the largest: the others moved a
sentence or a record, this one moved a safety boundary.

### AND THE ROUND-SEQUENCE THAT PRODUCED IT

Round 21's remediation produced round 22's findings; round 22's produced the runner; the
runner produced round 23's eight P1s.

**NARROWED TO WHAT THE HISTORY SUPPORTS (D0A-R24-07).** The claim was "the product surface had
not moved for three rounds" and that is too broad: round 21's own remediation commits
`d6fb698` and `298d4db` changed runtime behaviour. The verifiable claim, with a pinned start:
**since `298d4db`, no executable product behaviour has changed**; rounds 22–23 concentrated on
verification and documentation; and `cfb8ba3` changes one test ORACLE without changing the
test inventory. That is a narrower statement than the terminus narrative it was serving, and
it is the one that survives checking — a defensible scope decision does not need the stronger
version, and presenting it as stronger convergence than occurred is how a stopping decision
acquires more authority than its evidence.

**What is kept:** the expectation file and its protocol (enforced by convention, with the
manual procedure's checks intact), `DEFECT_CLASSES` 47 and 48, and the record corrections from
D0A-R23-06 and R23-11.

**D0A-R22-01 IS REOPENED, NOT CLOSED (D0A-R24-02).** The expectation protocol's ordering is
again enforced by nothing. It does not fit the branch's three-state partition — it is not
dependent on the native-UI increment, not scoped elsewhere, and not merely inherited: it is an
invariant that was closed and is open again. Recorded here as its own state so it is not
carried as "done". `scratch/lane-run-7-procedure.md` step −1 now carries the sequence a human
must follow meanwhile. **D0A-R23-04 and R23-05 likewise remain limitations of the EXISTING run-12
artifact** — no timeouts, no preserved evidence on failure, and the five hygiene checks absent.

**What a future increment inherits:** R23-01 through R23-10 are, between them, a written
specification for a runner that would be worth having. It needs its own design, its own
rounds and its own lane runs — not remediation folded into a branch whose product work is
done.

## SUPERSEDED CLAIMS FROM `docs/TRUST_MODEL.md` §3 (relocated here 2026-08-23, D0A-R15-02)

### THE §4 ID-ONLY RATIFICATION — why it differs from the four before it (relocated, D0A-R22-05)

Written into normative §4 by D0A-R21-02 and relocated here one round later. **The relocation
is itself the finding:** §3's history had just been moved for exactly this reason, and the
same defect was committed in §4 in the next commit — the rule was applied to the section that
had been criticised rather than to the class.

**THIS AMENDMENT RATIFIES BEHAVIOUR; IT DOES NOT CHANGE IT (D0A-R21-02).** §3 and §4 have now
been amended five times in this arc, and it matters that this one is a different kind. The
four before it changed a claim to match an argument and three were then reversed. **This one
changes the document to match what the code has always done:** `runtime_wire.proto`'s
`Pending` has only ever carried `pending_id`, and `service.rs` has only ever sent that. The
divergence was the DOCUMENT describing a flow the implementation never had — and it was not
harmless, because R18-05 cited that never-implemented flow as a reason redaction could be
removed. An unrecorded divergence became load-bearing for a security decision.

Ratifying the stricter behaviour is also the only reading compatible with §3 as amended: the
complete preview is rendered for the renderer as a trusted audience, so delivering it to the
AI — which §1 treats as the adversary — would disclose every environment value to exactly the
party the preview exists to defend against. If a sanitised AI-facing rendering is ever needed,
it is a separate function with its own stated audience.



### THE PREVIEW-REDACTION QUESTION — three positions in three rounds (relocated 2026-08-29)

Relocated from §3 the day it was written there. **The amendment recorded this table inside
the normative text, which is exactly what D0A-R15-02 ruled against** — and the rule was not
merely unobserved, it was ratified in the same document five rounds earlier. The operator
asked for the history to be recorded and I put it in §3 without flagging that a ratified rule
said otherwise. Both intents are served here: the live requirement (the actor/audience
distinction) stays normative, the reasoning that got there lives with the other superseded
claims.

| round | position | why it was wrong / different |
|---|---|---|
| R18-05 | redaction **removed** | right conclusion, unsound reasoning: "the only entitled consumer" was checked at the AI socket and generalised. The renderer was never examined |
| R19-04 | redaction **restored** | corrected the reasoning and reinstated a rule that **breaks injectivity** — measured, `DEPLOY=production` and `DEPLOY=staging` render identically while their digests differ. It also left `PYTHONPATH`/`NODE_OPTIONS`/`BASH_ENV` redacted though they select code |
| R20-01 | redaction **removed by amendment** | different because it names the actor/audience distinction and amends this document rather than inferring a boundary from one socket. The removal is now a ratified contract change, not a code change against a live guard |



**Why they live here.** A normative document's one job is to let a reader tell what is
required. Struck-through history in §3 made the reader distinguish preserved-falsified text
from active requirement, so the narratives moved and §3 keeps a pointer. The trail survives;
the requirement text does not carry it.

### NAMED LIMIT 2 — the dynamic loader as an immutable platform TCB member

**Claimed** (2026-08-22, v7): the dynamic loader and system libraries are an immutable
platform TCB member, so the chain past the first object needs no binding.

**Falsified** (2026-08-23, D0A-R14-01): an approved binary **names its own `PT_INTERP`**, so
it selects a loader the operator never placed. A controlled probe replaced that loader after
sealing and changed the code that executed.

**Struck, not softened.** A declaration the attacker can invalidate is not a weaker boundary;
it is not a boundary. It stood for one day.

### THE STATIC-ELF CLOSURE CLAIM — "no downstream hops: no `PT_INTERP`, no interpreter, no handler"

**Claimed** (2026-08-23, in the same amendment that struck limit 2): for a statically linked
native ELF, first-object binding and total binding are the same statement.

**Falsified** (2026-08-23, D0A-R15-02): `binfmt_misc` dispatch is a property of the KERNEL,
not the file. A handler can match `\x7fELF` magic and be selected before the native ELF
handler, reintroducing the unbound interpreter hop; an `F`-flagged handler holds its
interpreter open across mount changes. Static linkage removes the two hops that live in the
file and cannot remove the one that lives in the kernel.

**Narrowed, not struck** — the configuration is still the best available, stated with the
precondition it actually needs: no matching handler registered, which a deployment can enforce
and this runtime does not check.

### THE PATTERN, WHICH IS THE POINT OF LISTING THEM TOGETHER

**Three §3 amendments in three consecutive rounds, every one found by MEASUREMENT and none by
rereading.** The author's model of the mechanism is the model that produced the sentence, so
rereading cannot catch it — this is structural blindness, not inattention.

**The narrowing claims survived; the totality claims did not.** "v7 binds the first object"
has held under every probe. "Immutable platform TCB member", "no handler", "everything
downstream is pinned" each failed within a round. §3 is now written under the rule that
follows from that: **it states what is bound, never what is unreachable** — because a claim
about the absence of a path is a claim about the whole kernel, which nothing here can measure.

## STANDING — PROVEN / DECLARED / **FALSIFIED** (three states, 2026-08-23)

The distinction this file exists to keep, and it needed a **third** state the day after it
was written: D0A-R14-01 produced the first **falsification** — a property this document had
listed as *declared* and which measurement then removed. A two-state table would have
absorbed that as a quiet edit to a "declared" row. It gets its own column so the next one
cannot.

**The three states are not degrees of confidence. They are different kinds of claim:**
*proven* is a measurement, *declared* is a trust decision we are making openly, and
*falsified* is a statement that was made and is now known to be untrue.

| property | standing |
|---|---|
| the action runs as `delphi-tool` — all four uids/gids, empty `Groups:`, `CapEff` zero | **PROVEN** (root lane 2026-08-22: `Uid: 997 997 997 997`) |
| bytes written behind a pinned inode do not execute | **PROVEN** at root, through production canonicalization with a real ELF |
| the drop helper is the one this daemon was built against | **PROVEN** at root — the digest binding fires; built/installed/staged hashes matched |
| the credential plan reaches execution (R12-08) | **PROVEN** at root (18 passed / 0 failed) |
| a **literal** nested `#!` interpreter never reaches execution | **PROVEN** at canonicalization — refused before any exec |
| the snapshot is executable regardless of the source's mode (R14-04) | **DECLARED POLICY** — adopted deliberately; a 0644 source yields a runnable object, and `noexec` on the source mount does not stop an approved action |
| **the loader and system libraries are immutable** | ~~DECLARED~~ → **FALSIFIED 2026-08-23 (D0A-R14-01).** An approved binary names its own `PT_INTERP`; a probe replaced the loader after sealing and changed executed code. **Struck from §3**, not qualified — a declaration the attacker can invalidate is not a boundary |
| the execution CHAIN is bound (loader, `env`+`PATH`, `binfmt_misc`) | **ACCEPTED GAP, three hops named in §3 — and the `env`+`PATH` hop is an EXPOSURE, not merely a gap (2026-08-26).** Measured: 52 of 412 `/usr/bin` scripts carry an `env`-style shebang (41 of them `env node`), and `env -i PATH=<dir> /usr/bin/env python3` runs the impostor. The PREVIEW is fixed — code-selecting env values are shown and a non-flag interpreter arg is marked unbound — but that is a **DISCLOSURE fix, not a binding fix**: the hop is unchanged. **DEMONSTRATED END TO END 2026-08-26** — `chain_gap_approved_path_selects_the_impostor_and_the_preview_discloses_it` composes canonicalize → preview → gate → execute: the impostor `python3` runs (marker written, exit 0), the preview discloses the deciding directory, and the CONTROL without `PATH` succeeds writing nothing. All three assertions proven to bite. **AND THE COMPOSITION FOUND SOMETHING ISOLATION COULD NOT** — see the multi-call `env` note below. Original text follows — v7 binds the FIRST OBJECT only. **CORRECTED 2026-08-26 (D0A-R17-01):** this row said closure was available by construction because *"a statically linked native ELF has no downstream hops"*. That is the claim D0A-R15-02 FALSIFIED — `binfmt_misc` dispatches on magic before the native handler, so the third hop is a property of the KERNEL, not of the file. §3 was corrected then and **this row was not**. The honest form: for a static native ELF, first-object binding is total **only on a system with no matching `binfmt_misc` handler** — a precondition a deployment must enforce and verify, and which this runtime does not check. Not hypothetical: the dev box carries a live registration (`python3.14`, magic `2b0e0d0a`), which does not match ELF magic but shows the precondition is not free |
| the pre-drop window is **SHORTENED** (D0A-R10-12) | **MITIGATION IMPLEMENTED + RE-MEASURED on the shipping configuration (2026-08-26).** `--cap-drop ALL --cap-add CAP_SETUID --cap-add CAP_SETGID` on the payload; cap set proven MINIMAL (leg 7, each removal failing at a different syscall); guard **weaken-proven by a real RED** under NNP suppression, stable 30/30 with each `ok` verified to have run. Window **~9–13 ms of fixed bwrap setup cost — neither depth nor bind count drives it**; the earlier `~1.7 ms/bind` slope was an artifact of duplicate ancestor emission and does not exist. **Shortened, NOT closed** — bwrap's own setup still runs with the full set, and that phase is unmeasured |
| the pre-drop payload's BOUNDING set is narrowed | **OPEN — own row, split out of D0A-R10-12 (2026-08-25).** Measured: the R10-12 fix leaves `CapBnd = 000001ffffffffff` at both the payload and the tool. Left inside R10-12 it would let that row close with a named property still standing |
| the socket refusal (R9-01's second half) | **FIXTURE-MEASURED**, not against the real daemon |
| §4's flow: the AI receives `{pending_id, preview}` | **CLOSED 2026-08-29 (D0A-R21-02) — RATIFIED id-only.** §4 now states the AI receives `Pending {pending_id}` and nothing else, which is what `runtime_wire.proto` and `service.rs` have always done. The divergence was the DOCUMENT describing a flow the code never had — and it was load-bearing: R18-05 cited it as a reason redaction could be removed. Distinct in kind from the four amendments before it, which changed a claim to match an argument; this one changes the document to match measured behaviour |
| §7 "audit = reality" is RECORDED AT ALL | **UNWIRED END TO END — opened 2026-08-26.** `RuntimeAuditEntry::record` has callers **only in tests** (`audit.rs`'s own module, `divergence.rs`, `end_to_end.rs`), and the `audit` module has **no production CALL, consumer, or persistence path**. **CORRECTED (D0A-R18-08):** this said "no reference from `lib.rs`", which is false — `lib.rs` publicly exports the module. The conclusion is unchanged and the supporting predicate was not reproducible as written; a module can be exported and still never invoked, which is the actual state. So no approved action has ever produced an audit entry outside a test. Distinct from the R9-07 row, which is about an entry being *wrong*; this is about there being *no entry* |

**Why the gap is accepted rather than closed** (the decision, so it is not relitigated as an
oversight): computing a dependency closure adds a mechanism to the surface that has produced
findings in **seven consecutive rounds**, and a closure that misses an element fails
**silently at exec** — D0A-R9-02's own shape, reintroduced in service of a claim no
deployment has needed. Refused deliberately.

**The lane run's hygiene, since a root run that mutates what it does not own is worse than
no run:** PAM stack unchanged (`md5sum -c` OK), no stale sessions, 0 leaked daemons, and the
test binary proven current by a forced rebuild with an unchanged sha (`fb8c6c123685…`) rather
than by mtime — the rule that was systematically wrong for hook-built binaries.

**CLOSED — D0A-R9-06 (2026-08-23).** `env_delta` no longer transits argv. `--setenv K V`
published every approved value in `/proc/<pid>/cmdline` — world-readable for as long as bwrap
lived — while satisfying §6's "scrubbed to `env_delta`" in public. The environment now travels
on the `Command` (`env_clear` + `envs`), so bwrap inherits exactly the delta and passes it on;
`--clearenv` went with it, since it would wipe what we are handing over.

**Measured before it was written** (`Command::env_clear()` does not break bwrap's own PATH
lookup, and a payload under this shape sees exactly the delta). **Both halves are asserted,
because one alone passes with the defect:** the value must ARRIVE (a real bwrap run reads the
tool's environment and finds `DELPHI_SECRET=s3cret-value`, with none of the daemon's) and must
NOT be in argv. Weaken — restore the `--setenv` loop — and the second fails, printing the
command line with `s3cret-value` in it.

**Fixed rather than excepted.** This file committed to recording an "explicit dated exception
to Iron Law #2" if R9-06 were still open at the next merge to `main`. An exception is a dated
admission that a known defect ships; taking one for something fixable inside the same review
window is the worse trade, so **no exception is recorded and none is owed**.

**CLOSED — D0A-R9-02 (2026-08-22), and the row is removed per this file's own rule.**
§3's clause now holds because the contract changed to match what a mechanism can actually
deliver: **TRUST_MODEL v7** binds an **immutable content snapshot**, not a filesystem object.
`seal_executable_snapshot` copies the bytes into `memfd_create(MFD_EXEC | MFD_ALLOW_SEALING
| MFD_CLOEXEC)`, applies **and verifies** `F_SEAL_SEAL | F_SEAL_EXEC | F_SEAL_WRITE |
F_SEAL_FUTURE_WRITE | F_SEAL_SHRINK | F_SEAL_GROW`, and `execute` re-checks the seals at the
choke point every execution passes rather than trusting the constructor.

Both reviewer reproductions are green, and both were REBUILT before they were fixed
(D0A-R13-01): the same-inode case now runs through **production canonicalization** with a
real ELF, because the shebang fixture it used tested a shape `canonicalize` never
produces — it would have been an unsafe acceptance criterion. The nested case became a
**rejection** test: a nested shebang is refused at canonicalization (v7 named limit 1)
rather than substituted at exec.

**The helper is covered, which this row required before it could close.** `build.rs` hashes
the helper it just built and embeds `DELPHI_DROP_DIGEST`; the daemon refuses a
`/usr/libexec/delphi-drop` whose bytes are not that digest, then executes a sealed snapshot
of them. Weaken-proven: with the comparison neutered, a one-bit-modified helper is accepted.

**Two residuals, both named rather than implied.** A sealed **dynamic** ELF still resolves
its loader and DSOs by path. This paragraph originally called that "a DECLARED immutable
platform TCB member"; **D0A-R14-01 falsified the declaration the next day** and it is struck
from §3 — see the standing table above. What remains is an **accepted gap** with three named
hops, not a boundary. And the helper path and credential drop execute **only at euid 0**, so
everything above is the unprivileged half; the root lane is owed (class 20 — the gap that
made seven tests silently non-representative for 15 commits).

**CLOSED — D0A-R9-11 (2026-08-15).** The daemon now refuses to serve a **system account**
before the anchor: `uid == 0`, or outside the system's own `UID_MIN..=UID_MAX` from
`/etc/login.defs`. Rejected as a **class**, not an instance — `UID_MIN` alone would have admitted
`nobody` (uid 65534, above `UID_MIN` **and** above `UID_MAX`, which is the bound that excludes
it). Both weakens verified to bite: removing the guard call makes the integration test fail with
`got: Error: establishing the root-owned runtime directory` — the daemon proceeding past user
resolution, which is the breach; narrowing the guard to `uid == 0` makes the class test fail on
`daemon`/`bin`/`nobody`. Paired with a positive control so "root is refused" cannot be confused
with "everything is refused". The row is removed from the table above per this register's rule
that a row leaves only when a test proves it closed.

**OPENED 2026-08-15 — D0A-R9-12: actions have no isolation FROM EACH OTHER.** Recorded as its
own item, deliberately **not** folded into R9-01, because E does not solve it and must not be read
as having done so. Under E every action runs as the **same** `delphi-tool` uid, so two actions —
or one action and a later one — can signal each other, and anything one leaves owner-writable is
reachable by the next. This is **better than today** (they currently share *root*) and **worse
than nothing shared**. It is a different problem with a different fix (a per-action uid, which
`DynamicUser=` cannot supply here for the reason already recorded above). Not a §6 clause
violation — §6 says nothing about inter-action isolation — so it is logged here as a known gap
rather than a conformance delta. **Closes when** two concurrent actions are proven unable to
observe or signal each other.

**NOT a §6 change (checked 2026-08-15, before implementing E).** §6's only namespace clause is
**network** (`--unshare-net` / `--share-net`, line 662); nothing in it mandates a *user*
namespace. `--unshare-all` was an implementation choice in `sandbox.rs`, never ratified text. So
adopting E **closes** the line-665 clause ("the tool runs under a uid that cannot reach daemon
IPC") and **violates none** — it creates no new row here.

**THE E TRADE, RESTATED HONESTLY (2026-08-16, D0A-R10-03).** The previous two versions of this
entry were both wrong, in the same direction, and the second was written while *correcting* the
first. Superseded rather than edited, so the drift is visible.

**What was measured and still holds:** bwrap's own userns maps `sandbox_uid → parent_uid`, so at
root the jail was `INNER 0 / SO_PEERCRED 0` — **identity**-transparent. That measurement is sound.

**What was inferred and never examined:** that identity-transparency meant the namespace "contained
nothing". It did not. **Capabilities are relative to a user namespace.** A process in a child
userns holds a full capability set *in that namespace*, but the kernel checks against the userns
that **owns the resource** — so capabilities never reached initial-namespace objects, whatever the
identity map said. `--unshare-all` was supplying a **capability boundary independent of identity**,
and E removes it. bwrap under real root retains the caller's capabilities through setup, so under E
that code runs with **initial-namespace** capabilities.

**So E is a TRADE ACROSS A TIME BOUNDARY, not a dominance:**

| window | before E | after E |
|---|---|---|
| **pre-drop** (bwrap setup + `delphi-drop` up to `setresuid`) | uid 0, capabilities confined to a child userns | uid 0, **initial-namespace capabilities** — *more powerful* |
| **post-drop** (the tool — the long-lived part) | uid 0 with userns-confined caps | uid **997**, caps dropped with the uid — *less powerful* |

"Strictly better on the escape axis" and "an escape lands on root exactly as before" are **both
false**. E improves the window that lasts and worsens the window that is short. That may still be
the right call — the tool is the untrusted part and the setup is code we ship — but it is a
judgement, and the reasoning that chose it was incomplete.

**A THIRD WINDOW NEITHER R9-01 NOR §6 COVERS.** R9-01's mechanism is *the tool runs as
delphi-tool*; §6's clause is *cannot reach daemon IPC*. The **pre-drop window** is neither, and it
is now the more powerful of the two states. It has no row, no test, and no owner.

**AND R9-01's PROOF IS NARROWER THAN ITS ROW CLAIMS.** The root test observes `id -u` and nothing
else: **not gid, not supplementary groups, not saved ids, not capabilities, and not the daemon-IPC
refusal that is the actual clause.** The gap between "mechanism closed" and "clause closed" is
therefore wider than recorded, and `997` was read from a test that proves one of six things it is
cited for.

**OPENED 2026-08-16 — D0A-R10-12: the PRE-DROP window runs with initial-namespace
capabilities.** Its own row deliberately: it is neither R9-01's mechanism (*the tool runs as
`delphi-tool`*) nor §6's clause (*cannot reach daemon IPC*), and folding it into either would
hide it.

**What is true.** Under E, `bwrap`'s setup and `delphi-drop` up to `setresuid` execute as
initial-namespace root **with capabilities that are no longer confined to a child user
namespace**. Before E the same code held caps only within bwrap's userns, where
`ns_capable(init_user_ns, …)` fails for initial-namespace objects. This is a **real enlargement of
the pre-drop TCB's power**, not a bookkeeping change.

**Why it is accepted.** Both occupants are shipped, root-owned, installer-placed components —
the same trust class as `delphi-runtimed` itself. The decisive asymmetry is *whose code occupies
each window*: **pre-drop holds code we wrote; post-drop holds code the user approved**, and the
consent apparatus exists to constrain the latter. Strengthening an attacker's position inside our
own code to weaken it inside the user's is the right direction — **and it is a trade, not
dominance.**

**The mitigation is NAMED AND UNIMPLEMENTED, which is what keeps this from being a
rationalization:** restrict the helper payload to the minimal `CAP_SETUID`/`CAP_SETGID` set. A
named unimplemented mitigation is an obligation; an unexamined acceptance is a hole.

**The reviewer's alternative — retain a mapped user namespace — is NOT available**, and is
recorded as closed rather than unexplored: that is leg F, abandoned after three harness failures
(path-instead-of-fd, then `EOVERFLOW` from bwrap's newroot setup wanting an id outside a
single-entry map). It was never falsified, only unmeasured.

**Closes when** either the helper runs with the minimal capability set, or the window is measured
and the trade re-decided against that measurement.

### RESOLVED 2026-08-25 — both conditions met, and the row is narrowed rather than closed

`scratch/d0a-r10-12-window-probe.sh`, six legs, zero skips, on the privileged path.

**DURATION.** ~9–11 ms attributable (window minus the payload's own exec chain), ~17–20 ms
wall. Driven by **bind count** (~1.7 ms/bind), **not by ancestor-emission depth** — depth 1
vs 8 does not move it, across three runs. The obligation's specific worry is falsified.

**PLACEMENT, forced by measurement rather than chosen.** Daemon-side is impossible (dropping
the bounding set before bwrap → `Creating new namespace failed: Operation not permitted`;
bwrap needs `CAP_SYS_ADMIN`). The permitted/effective lever does not exist in general: a root
`execve` recomputes `P'(permitted) = F(permitted) & P(bounding)`, and with `F(permitted)`
all-ones for the root case that restores the full set. bwrap's payload-side
`--cap-drop`/`--cap-add` is the only seam that both restricts and holds.

**IT BITES, AND ON SOMEONE ELSE'S DEFAULT.** `c0` survives a further root exec under the
restriction; the control returns `000001ffffffffff` without it. It holds only because bwrap
sets `no_new_privs=1` — unconditional, ungoverned by any flag, and **theirs, not ours**. If
that changed, the profile would still emit the flags, the immediate state would still read
`c0`, and the property would be gone with nothing failing. **Class 42 with a name attached.**
So the guard asserts the state **after a further exec**, never the immediate state, and
carries the control that makes it discriminate.

**THE WINDOW'S SHAPE WAS ALSO WRONG HERE.** The census (corrected — the first version sampled
a bash subshell that, being root, showed an identical cap set and could not discriminate)
reads `CapPrm/CapEff = 0` for bwrap while its payload lives: bwrap drops its own capabilities
after setup. The privileged span is bounded by **setup**, not by the tool's lifetime — a
materially smaller exposure than this row asserted.

**THE CAP SET IS MINIMAL, MEASURED (2026-08-25, probe leg 7).** 5b established only
SUFFICIENCY — a set carrying an unneeded capability would pass it identically. Necessity is
now measured by removing each capability in turn:

| variant | outcome |
|---|---|
| only `CAP_SETUID` (no SETGID) | fails — `setgroups failed: Operation not permitted` |
| only `CAP_SETGID` (no SETUID) | fails — `setresuid failed: Operation not permitted` |
| neither | fails — `setgroups failed` |
| **both (positive control)** | **succeeds** |

**Two DISTINCT failing syscalls, not three identical refusals** — `setgroups` when SETGID
goes, `setresuid` when SETUID goes — so each variant fails for the reason its own removal
predicts, and the positive control shows the harness can succeed at all. Both capabilities
are load-bearing; the set is exactly minimal, and a future `--cap-add` has a standing check
to justify itself against.

**WHAT DID NOT CLOSE.** The tool's bounding set is still full. Split into its own row above.

### ⚠ THE SECTION BELOW IS SUPERSEDED — the limit was FALSIFIED (2026-08-26, D0A-R16-01)

**"Not weaken-provable in-tree" was wrong, and it was wrong in the direction that flattered
the work.** The round-16 reviewer was asked to attack that claim and did: bwrap is
dynamically linked, calls `prctl` through the PLT (`R_X86_64_JUMP_SLOT`,
`prctl@GLIBC_2.2.5`), is not setuid and carries no file capabilities — so `LD_PRELOAD`
reaches it even under root. `scratch/nnp-shim/nnp_suppress.c` returns success for
`PR_SET_NO_NEW_PRIVS` without performing it; measured, bwrap's payload goes from
`no-new-privs=1` to `no-new-privs=0`.

So the NNP-absent shape **is** constructible in-tree, and the guard **now has a real RED —
RUN, not designed**. Leg A of `scratch/d0a-r10-12-red-proof.sh` executes the guard under
the shim:

```
LEG A VERDICT: FAILED ON THE c0 ASSERTION under NNP suppression.
               THIS IS THE REAL RED.
```

**The grading comes off.** The guard is weaken-proven against **the regression it exists
for** — bwrap ceasing to set `no_new_privs` — and not merely against the absence of its own
flags. The flag-removal weaken is demoted to a secondary leg exercising emission only.

**Stability is also a stronger claim than the identical number it replaces.** `GUARD ok 30 /
not-ok 0` now carries "each verified to have RUN": before D0A-R16-03, the leg accepted
libtest's `ok`, which a SKIP prints too, so the earlier 30/30 was measuring a weaker
property behind the same figure.

**The lesson is about the shape of the claim, not the mechanism.** "No mechanism exists" is
a claim about every mechanism, which is the same unmeasurable totality shape §3 was
rewritten to forbid — and it was made about a tool whose linkage takes one `readelf` to
check. The narrow form ("the only weaken I found removes the flags") would have been true
and would have invited the fix instead of foreclosing it.

**THE TIMING FIGURES WERE WITHDRAWN AND RE-MEASURED, AND THE REPLACEMENT IS A DIFFERENT
CLAIM — not a corrected number.** The old probe's helper leg **omitted the capability
flags** (D0A-R16-05 — it timed the pre-mitigation path) and **emitted duplicate shared
ancestors** where production deduplicates through a `BTreeSet` (D0A-R16-06). Re-measured
with both fixed, on the shipping configuration:

| binds | window, baseline-subtracted |
|---|---|
| 1 | 7.5 – 8.3 ms (three depths) |
| 4 | 9.3 ms |
| 8 | 9.9 – 10.0 ms (two depths) |

**Third withdrawal in this section, same cause each time: a value derived and not applied.**
`BASELINE_MED` was computed by the probe and never read, so every figure reported before
2026-08-26 still had the payload's own exec chain folded in. Corrected range: **7.3–10.1 ms**
(D0A-R17-04).

**THE BIND-COUNT SLOPE IS GONE.** `~1.7 ms/bind` did not exist — it was the duplicate
ancestor emission R16-06 named, work production never does. The corrected series does not
rise with bind count at all (it drifts slightly *down*, which is noise).

**So the honest statement is that NO DRIVER WAS DETECTED across the range measured** —
1, 4 and 8 binds at depths 1–8, window ~9–13 ms. It is recorded as a replacement claim
rather than a revised slope, because a revised slope would preserve the false structure:
the original finding was "bind count is the driver", and the driver does not exist.

**"No driver detected" is deliberately weaker than "fixed cost" (D0A-R17-04), and the
reason is the INSTRUMENT, not the shape of the series.** The corrected column is not flat:
ordered by bind count it runs 7.9 → 9.3 → 9.95, monotone, about 0.3 ms/bind. Read naively
that is a driver.

**It is below this probe's resolution.** The same cell (1 bind, depth 1) measured 16.7, 17.6
and 14.6 ms across three root runs — **~3.0 ms of run-to-run spread on one cell, against a
2.1 ms difference between the extreme cells.** The noise is larger than the effect, so the
probe cannot resolve a driver of this size in either direction.

What it CAN do is exclude large ones, and that is the finding worth keeping: it excluded
1.7 ms/bind (≈12 ms across the range), which is what the pre-R16-06 probe reported as its
headline. Stating "no driver detected across the range measured" without naming the
resolution floor would let the sentence be read as "no driver exists" — the same totality
shape, wearing a measurement's clothes. **Establishing or excluding a ~0.3 ms/bind effect
needs a different instrument, and is not owed by anything currently claimed.**

This also retires the obligation's own framing. It worried that ancestor emission on a deep
path would lengthen the window materially; measured, ancestor emission does not move it in
either dimension. The capability census is unaffected — it does no timing.

### THE SUPERSEDED RECORD (2026-08-25), kept for the trail

`the_predrop_payload_cannot_recover_capabilities_across_a_further_exec` is **stable**
(30/30 under default parallel, suite-wide clean) and **not weaken-proven**, and the second
half is a property of the subject rather than a gap in the work.

**The available weaken is the wrong weaken.** Removing the flags makes the "restricted" leg
*become* the control — both are then unflagged bwrap invocations that cannot differ. The
first attempt returned `WRONG ASSERTION — both legs read alike`, which is a correct
observation and an uninformative verdict: it cannot separate *the guard is mis-aimed* from
*the weaken deleted the only thing that made the legs differ*. Reordering the assertions
makes that weaken report the table's success string, but the result would be hollow —
it demonstrates the test notices absent flags, which
`the_credential_drop_restriction_is_emitted_only_when_asked` already demonstrates with two
weakens of its own. **A green obtained that way would overstate what was proven.**

**The regression this guard exists for is bwrap dropping `no_new_privs`, and that variable
is not ours to remove** — no flag governs it (measured against `bwrap --help`, 0.11.1).

**So the discrimination is established by measurement rather than by weaken**, which is
weaker evidence and is named as such:

- **leg 4b** constructs the NNP-absent shape directly — permitted/effective lowered to
  `c0`, bounding full — and the capabilities come back **`000001ffffffffff`** across the
  exec. That is precisely the outcome the test asserts must not occur.
- **6b/6c** show the paired behaviour under bwrap: `c0` persists with the flags, full
  recovery without them.

**The assertion ORDER was also wrong and is fixed independently of all this.** The paired
`assert_ne!` fired first, so under the real regression (both legs read full) the reported
failure was "they read alike" — a message naming no cause. The control is now a
**precondition checked first**, and the property assertion carries the `no_new_privs`
suspect. With both specific assertions present the paired comparison was redundant anyway.

**Closes when** a mechanism exists to exercise NNP-absence in-tree. None is known.

**BOUNDED BY EVIDENCE, NOT ASSUMED SHORT (obligation, 2026-08-16).** "The pre-drop window is
short" is currently an **intuition**. bwrap's setup does mount work, `--dir` creation and now
ancestor emission; the helper performs two `execve`s. If that is milliseconds the trade is
comfortable; if ancestor emission on a deep path makes it materially longer, the calculus shifts.
**Measurable rather than arguable, and not yet measured.**

**AUDIT DISCONTINUITY — `sandbox_profile_digest` values are not comparable across
2026-08-15.** `audit.rs` records a digest of the derived profile args, and two changes landed
that alter those args for **every** action: ancestor emission (`--perms 0755 --dir <ancestor>`
per bind) and the namespace change (`--unshare-all` → the explicit list minus
`--unshare-user`). So every entry after that date differs from every entry before it, for all
actions, with no attack and no defect. Recorded because someone diffing audit history later
would otherwise read a universal change as an anomaly. The `action_digest` is **unaffected** —
the approved action did not change, only the enforced scope's spelling.

**TCB ENLARGED BY ONE MEMBER — `delphi-drop` (2026-08-15).** The credential-drop helper is not
covered by the action digest, not previewed, and not named by any action. That is acceptable on
a **bounded** argument, not on "it is trusted": `bwrap` is already an undigested,
installer-placed, root-owned component the action never names, and the helper joins that
existing class on the same basis rather than establishing a new kind of trust. The enlargement
is real, is small, and is recorded here rather than left implicit. What did **not** change: the
program executed is still the same pinned fd with the same `executable_digest`, and the tool's
`argv` is still exactly `action.argv` — the helper takes `argv0` explicitly so the approved name
still lands in the tool's own `argv[0]`.

**Proof-thinness (not clause violations, recorded so they are not mistaken for coverage):**
D0A-R9-08 — the "exact approved scope" test ignores unsupported grant options, env fidelity,
cwd, and removal of `--clearenv`. D0A-R9-09 — `fdsec`'s sole test proves neither high
descriptors, nor actual exec behaviour, nor the `CLOSE_RANGE_UNSHARE` race-defence leg.

**MEASURED 2026-08-20 — which greens actually bite (`scratch/d0a-mutation-audit.sh`).**
Twelve realistic defects were introduced into the shape-E guards one at a time; five passed
the entire suite. Not read off the tests — measured, and re-measured after the fixes.

| defect introduced | before | now |
|---|---|---|
| ancestor `--perms 0755` → `0700` (bwrap's own default — the value class 40 exists to override) | **NOT CAUGHT** | caught, incl. a real-jail `stat` of the created ancestor |
| `--unshare-net` dropped for `NetPolicy::None` (bwrap then SHARES the host network) | **NOT CAUGHT** | caught by two tests |
| `--clearenv` dropped (the R9-08 gap above, now measured) | **NOT CAUGHT** | caught |
| the approved `argv[0]` never reaches the tool | **NOT CAUGHT** | caught (`exec_tail` extracted so it is provable unprivileged) |
| the drop helper never interposed at all | **NOT CAUGHT** | **STILL NOT CAUGHT** — see below |
| the other seven (denylist legs, ancestor exclusion/ordering/emission, host-creating bind, full seals) | caught | caught |

**The one that remains, stated exactly.** `tool_credentials()` returns `None` unless euid is
0, so on an unprivileged box the interposition is unreachable and no test can observe the
daemon *deciding* to drop. What is now proven without root is the **assembly** (`exec_tail`
— helper, uid, gid, pinned program, approved argv0, in that order). What still needs root is
that **the drop takes**, which is
`an_approved_action_runs_with_the_tool_account_credentials` — and it SKIPs here, so on this
box that property has no live evidence at all. **Closes when** a root lane runs it.

## OPENED-AND-CLOSED 2026-08-20 — the tree-replace invariant had NO LIVE EVIDENCE for 15 commits

Recorded as its own item rather than inside D0A-R10-10's fixture repair, because "the fixture
is fixed" and "the invariant was unproven for a window" are different statements and only the
second is about the clause.

**The clause.** `installer/install.sh` replaces the shell bundle by a two-rename swap whose
invariant is *at every instant there is at least one of `shell` or `shell.old`; it is never
the case that both are absent*. CLAUDE.md §6 names `installer/tests/tree-install.test.sh` as
the **tier-1 SOLE EVIDENCE** for it — tier 1 under clause (d), *cited as the evidence that a
property holds*, despite never shipping.

**What was true.** `cdc3418` added `delphi-drop` to install.sh's staged-artifact loop and not
to that suite's fixture. From `cdc3418` until `10d4d65` — **15 further commits** (`git
rev-list --count cdc3418..9a45679`) — all 16 of the suite's install legs failed in pre-flight
with `cannot open installer/staging/delphi-drop`, before reaching a single assertion about
renames. Measured, not inferred: a worktree at `cdc3418~1` runs **26 passed / 0 failed**; at
`9a45679`, **10 passed / 16 failed**.

**So for that window the invariant was ABSENT, not passing** — the same distinction this file
already records for `runtime/shell-host` and for `cargo check --workspace`, now applied to a
clause the project cites as proven. The install code was not modified in that window, so
there is no reason to believe the invariant was violated; the point is narrower and worse:
**nothing was in a position to notice if it had been.**

**Why nothing noticed.** The suite is run by nothing — not `cargo test` (it is a shell
script), not the pre-commit hook (scoped to staged `runtime/` paths), and not CI, which had
no shell-suite step at all. A tier-1 artifact with no runner is a tier-1 artifact that
reports whatever it last reported.

**Closed** (`10d4d65`): the fixture is repaired and the suite is back to 26/0 — now 29/0 with
the R10-11 legs; `scripts/run-shell-suites.sh` discovers and runs every `*.test.sh`; CI runs
that script. The CI leg is **unverified on a runner** — green on the dev box, never yet
executed by GitHub Actions.

## OPENED-AND-CLOSED 2026-08-20 — two tests were DELETED in a commit that described neither

`f380085` ("widen R9-01's proof to every credential it CAN observe; shrink its name") removed
**135 lines** from `runtime/src/execute.rs`, and two of the things in them were whole tests:

* `the_tool_receives_its_approved_argv0` — a real bwrap run asserting the tool's `$0` is its
  approved name and not `/proc/self/fd/N`;
* `a_second_kept_fd_survives_a_second_exec_and_is_executable` — the **premise measurement**
  the drop helper's entire design rests on.

Neither removal is mentioned in that message. The consequence was measured five commits
later by `scratch/d0a-mutation-audit.sh`: *the approved `argv[0]` never reaches the tool*
survived the entire suite, because the test for it no longer existed. Round 10 had named
that test as a green it did not trust; by the time the round was answered it was gone.

**Both restored 2026-08-20**, verified passing, and kept alongside the unit-level
`the_helper_is_interposed_…` (which observes the assembled arguments — a different, lower
altitude than the running process's `$0`).

**Foreclosed mechanically, because nothing caught this either**: the pre-commit gate counted
FAILURES, which cannot see a test that is absent, and `.github/rust-test-count-baseline` is
deliberately unrecorded, so the disappearance guard built for exactly this was inert.
`.githooks/runtime-test-count-baseline` now records EXECUTED/SKIPPED for
`-p delphi-runtime --lib --bins` and the hook refuses on any change to either number, up or
down, printing the measured pair. Its RED legs are in `.githooks/tests/pre-commit.test.sh`.

## Round 11 (2026-08-21) — the instrument was wrong, and three remedies carried their own defect

**D0A-R11-01 invalidated the previous round's item-4 answer, and that answer is superseded
rather than repaired.** The first mutation harness had no baseline: "caught" meant *any* test
in four hard-coded namespaces failed, minus two known names. In a sandbox with two AMBIENT
bwrap failures that is true for every mutant including the null one — the reviewer's run
reported 12/12 caught, including `tool_credentials() -> None`, which catches nothing. So
"11 of 12" was **unsupported, not wrong**, and is withdrawn.

Rebuilt against a measured baseline (cargo status, result-line count, ran/skipped, the
fully-qualified failure set), with compilation failure scored as CAUGHT, no verdict on
unexplained state, `--lib --bins`, and an isolated git worktree so an interrupt cannot leave
the tree mutated. **It was wrong twice more before it was right** — no `--nocapture` (so a
skip counted as executed), an executed-count that drops on every catch (13 spurious
UNEXPLAINED), and a failure regex that `--nocapture` interleaving defeated (0/16 caught).
Each produced confident output.

**Re-measured, 24 mutants: CAUGHT 21 / NOT CAUGHT 4 / UNEXPLAINED 0.** The four:

| not caught | status |
|---|---|
| the denylist's equality leg | **not a gap** — `starts_with` is reflexive, so the mutation is a semantic no-op |
| `env_delta` never emitted | **FIXED** — the scope check now requires exactly the approved set, both directions |
| the host-creating-bind error VARIANT swapped | **FIXED** — R10-08 *was* a misclassification; `is_err()` was blind to it |
| `tool_credentials() -> None` | **open, root-only** — the interposition is unreachable unprivileged |

**D0A-R11-05 — the parser's METHOD, not its form list.** Three rounds found forms, so the
single-pass strip-and-parse was replaced by shadow's own two phases: store the last RAW
value, then interpret it (quote SCAN — skip any number of leading quotes, terminate at the
first subsequent one — then `strtoul` base 0). Measured: `"50"00"` → **50**, which no
strip-based reading produces. Precedence corrected: `5000` then `garbage` is shadow's
default, not 5000. And ABSENT is no longer the same answer as UNREADABLE — a permission or
UTF-8 error refused to be silently defaulted into a wider range.

**D0A-R11-06 — the validated credentials were not the used credentials.** Three independent
resolutions existed and only one was checked; the startup check also *skipped validation
entirely* on a lookup error (`if let Ok(Some(…))`). Now one resolution, validated, recorded,
and read. **Unprovable unprivileged:** restoring the re-resolution leaves the suite green,
because the path needs euid 0. The planner's decision is covered by injection; "execution
reads the plan" is root-lane evidence.

**D0A-R11-07 — twenty bytes established almost nothing.** Replaced by a full identification
header compared against `/proc/self/exe` (a trusted NATIVE reference, not the daemon —
four mutually-matching foreign binaries passed the old check), plus e_type, e_machine, and
PT_INTERP: a named loader must exist, and `delphi-drop` must name none, since it is exec'd
in a jail that binds nothing. Weaken-proven — under the old check a **dynamic helper
installs (rc=0)**. **Residual, stated in the script:** this is loadability preconditions, not
executability; a well-formed header followed by garbage still passes, and proving otherwise
means executing an unvalidated binary as root.

**D0A-R11-02/03/04 — every remedy from round 10 carried the defect it was built to prevent.**
The hook validated counts, not the identity of the expected failures (a red/green swap
passed) and exited 0 when its baseline was missing; the suite runner refused only at ZERO
discoveries, so deleting one suite while eight survived stayed green; the fixture hard-coded
"5" for a fifth artifact. All fixed — and the hook's first fix had the same bug backwards
(identity without count let a third failure through), caught by the hook's own test suite.

## Round 12 (2026-08-21) — the fix for green-by-skip arrived as green-by-skip

Ten findings. **D0A-R12-09 outranks the six parser findings** and is recorded first because
it is the arc's recurring class landing inside the fix for that class.

**D0A-R12-09 — the tier-1 suite reported GREEN by skipping, in CI, on every run.**
`installer/tests/tree-install.test.sh` exits when it cannot find a built `delphi-drop` to
stage as its static stub, and the R11-07 fixture rewrite made that an `exit 0`. The
shell-suites CI job had **no Rust toolchain**, so on a clean checkout the fixture never
existed: the suite skipped every time and the runner reported it `ok`. It is the file
CLAUDE.md §6 names as the tier-1 **SOLE EVIDENCE** for the tree-replace invariant, so in CI
that invariant had no live evidence at all while the pipeline was green.

**Worse than the 15-commit red it replaced** (recorded above): red-and-unrun is
discoverable; green-by-skip is not. Closed at three levels — the suite REFUSES; the runner
FAILS any suite that exits 0 having printed no result line (the class, for all nine); and CI
builds the fixture, which makes that step load-bearing. Both weakens bite under CI's exact
condition.

**D0A-R12-01/02/03 — absence coerced into a value, three symptoms of one cause.** A field
not in the file read as **0**; an 8-byte field with the top bit set read as **negative**
(and a negative offset passes every `<= size` bound); a `PT_INTERP` of `"\n"` read as
**absent**. For `delphi-drop`, "no PT_INTERP" is the answer that PASSES. Each helper now
returns a failure status rather than a value it invented. Two of three weakens bite; the
negative guard is **not independently isolable** — every negative value reachable is caught
downstream by the short-read check, because `od` produces nothing at a negative offset — and
that is recorded in the script rather than claimed.

**D0A-R12-04/05/06 — a discarded terminator, a wrong bound, a too-strict header.**
The `PT_INTERP` NUL was dropped unseen (weaken: a binary whose terminator is overwritten
INSTALLS, because the old code read the original path and never saw the header lie); the NUL
is now verified **numerically**, since bash cannot hold one — `$(dd …)` warns
`ignored null byte in input` and drops it. `MAX_PHNUM` is **deleted**: 257 program headers
is a valid executable ELF, so a count cap refused good binaries; the table is now one `od` +
one `awk`, bounded by construction. Full `e_ident` equality is replaced by the fields that
decide loadability — EI_OSABI 3 (GNU) is accepted, padding is not compared, and the magic is
checked first so a non-ELF refuses for being a non-ELF.

**D0A-R12-07 — the parser's third round, and the first INTERACTION.** `UID_MIN   "5000"`:
shadow 5000, Delphi 1000. Blanks and quotes were each measured and each correct in
isolation; 28 forms then 38, and not one had **both**. Enumerating a grammar feature at a
time misses the products.

**ROOT LANE RUN, 2026-08-21 — R9-01 IS PROVEN LIVE.** The operator ran the procedure. The
credential proof produced its evidence for the first time on this branch:

```
[R9-01] Uid: 997 997 997 997 / Gid: 972 972 972 972 / Groups: (empty) / CapEff: 0000000000000000
with helper: ["--", "/proc/self/fd/9", "997", "972", "/proc/self/fd/7", "approved-name", "--flag"]
```

So §6's "the tool runs under a uid that cannot reach daemon IPC" now has its **credential
half measured at root**, not reasoned: all four uids and gids are `delphi-tool`'s, the
supplementary set is empty, and `CapEff` is zero. **R12-08 is measured too** — the root path
plans credentials, the helper is interposed with `997 972`, and no
`no validated tool identity was recorded` appeared. The socket-refusal half remains measured
against a probe fixture (R9-01's open remainder), and the PAM stack was verified unchanged
before and after (`439c1d1521d86e4eb011a927aff659db`), 0 leaked daemons, class 16 clean.

**AND THE RUN FOUND SEVEN FAILURES THAT HAD BEEN THERE SINCE SHAPE E — D0A-R12-11.** All one
cause: `cannot create /tmp/delphi-exec-*/out/result: Permission denied`. The tool at uid 997
cannot write an `out/` created by the root test process. **This is the predicted behavioural
change, arriving exactly as recorded twice before E shipped** — dropping the tool off root
removes its access to root-owned paths, a test failing for that reason is CORRECT, and
widening the uid's access to turn it green would be the forbidden weaken. The fix is the
FIXTURE: `Env::new` chowns the out dir to the **planned tuple** (never a fresh lookup —
R11-06's discipline), in the one place that creates it. One test passed at root only because
it chowned by hand; that line is now the fixture's job.

**RE-RUN 2026-08-22 — THE FIXTURE FIX IS MEASURED.** `sudo … execute::tests::` at root:
**15 passed, 2 failed**, and the two are the intentional D0A-R9-02 REDs by name
(`same_inode_overwrite_…`, `nested_interpreter_substitution_…`). Every `Permission denied`
is gone, so the chown-to-the-planned-tuple in `Env::new` is confirmed at the only privilege
level that can execute that code. `an_approved_action_runs_with_the_tool_account_credentials`
printed its `/proc/self/status` block again, and `the_helper_is_interposed_…`,
`the_tool_receives_its_approved_argv0` and `a_second_kept_fd_survives_a_second_exec_…` all
pass at root as well as unprivileged.

**Two corrections to what was written before that run, both mine.** "Expected: 17 passed, 0
failed" was wrong — the R9-02 pair lives in `execute::tests::`, so 15/2 IS the clean result;
the check is the failing NAMES against the recorded `RED=` lines, never the count. And the
binary-freshness rule "mtime must be later than the commit" mis-fires: the pre-commit hook
builds before the commit object exists, so the binary read as 67 seconds stale while
containing the fix (confirmed by a forced rebuild producing the identical hash,
`a6faef1cea8d74be`). Both fixed in `scratch/lane-run-procedure.md`.

**Why nothing caught it, and this is the part worth keeping:** the drop only happens when
`tool_credentials()` returns `Some`, which needs euid 0 — so the unprivileged run of every
execution test takes the **no-helper branch**. It ran, it passed, and it exercised a
different mechanism than production does at root. Not "absent, not passing" in the earlier
sense (a suite nothing ran) but its sharper relative: a suite that runs, reports green, and
is about the other branch. Recorded as an instance under `docs/DEFECT_CLASSES.md` class 20.

**D0A-R12-08 — the root execution tests died before their subject.** R11-06's refusal is
right for production and broke the lane. `build_action` now plans once per process, and
`decide_credentials(euid, planned)` is split out so the ROOT BRANCH is a unit fact.
**MEASURED 2026-08-22** — the root lane ran it; see the RE-RUN paragraph above. (This
sentence previously said "STILL UNMEASURED", contradicting the run recorded 40 lines later —
D0A-R13-05. A register that disagrees with itself about whether something was measured is
worse than one that says nothing.)

**D0A-R12-10 — the poisoning guard compared strings**, so `target/../target`, a symlink, or
a trailing slash walked past it. Canonicalized. Demonstrated at the comparison, because the
audit refuses on a dirty tree and weakening the audit dirties it — the two guards conflict,
so a harness-level weaken cannot run.

**Two process defects of my own, both recorded in commits rather than smoothed over:**
`git checkout --` used as a restore on a file with UNCOMMITTED work discarded the fix along
with the weaken (copy-based restore is the rule while uncommitted); and a claim —
"the alias was ACCEPTED" — was printed beneath a run that had been blocked and did not show
it. The second is this session's own recurring mechanism: a sentence written next to output
that does not support it.

## Claims whose scope was believed wider than their proof

A different kind of row from the table above. Nothing here is a violated clause — each is a
**proof that stands**, carrying a **claim built on it that the proof never covered**, because a
now-violated clause was doing the extending.

| claim as believed | what was actually proven | what extended it | closes when |
|---|---|---|---|
| "a requester cannot forge approvals" (B2a **R-2**) | the **renderer** cannot forge them | §6's "the tool runs under a uid that cannot reach daemon IPC" — **violated**, so the extension to the *executed tool* was never proven | the executed tool is proven unable to reach or satisfy the approval socket |
| "the digest is the binding" (§3) — **claim narrowed 2026-08-13** | **approve-A / execute-B** is refused (the *in-band* substitution), **and the script BODY is genuinely content-pinned** by `FULL_SEALS` | the assumption that pinning an fd pins the bytes — true for the sealed script memfd, **false for `executable_fd` / `interpreter_fd`**, which are inode pins only | the **binary/interpreter** side is content-pinned, with same-inode and nested-shebang substitution as failing-then-passing tests (**both reproduced by the reviewer**) |

### The R-2 keystone — what holds it up today, and why remediation is a TRADE

**The keystone currently holds BECAUSE THE TOOL RUNS AS ROOT**, which is the defect. Traced:
the daemon is root, spawns bwrap as root, and `accept_requester` reads `SO_PEERCRED` uid **0**
against an `expected_uid` that is the **session uid** — mismatch, rejected.

**Apply the obvious R9-01 fix — drop the action to the SESSION uid — and the rejection
disappears.** `SO_PEERCRED` then reports the session uid, `expected_uid` is the session uid, the
peer is accepted; and with **no path denylist** (R9-10) an action may bind the socket into its
own jail. **The remediation removes the mechanism presently doing the protecting.**

So **"any unprivileged uid strictly beats root" is FALSE here**, and "refining which uid is cheap
later" is false with it. **The fix must be a DEDICATED SERVICE UID distinct from the session
uid** — that *is* the decision, not a detail deferred past it.

### The four measurements — RESULTS (2026-08-13, `scratch/d1-peercred-probe.sh`)

`setuid()` inside the userns was the wrong target: what the daemon observes is set by the **uid
map**, not by what the child does after `execve`.

**M1 — at the socket.** A peer inside the jail, connecting over a bound-in socket, is read by
the outside listener as **the uid that launched bwrap** (`SO_PEERCRED pid=5304 uid=1000
gid=1000` from an `OUTER uid=1000` launcher). Observed, not inferred. **Root leg outstanding.**

**M2 — the map.** `/proc/self/uid_map` inside reads `1000 0 1`, which is *not* "inner 1000 →
outer 0": `os.stat` on a file owned by outer-1000 returns **1000** inside, so the net mapping is
**identity for the launching uid**. The `0` is w.r.t. an **intermediate userns** bwrap creates
(mapping the launcher to 0 to obtain mount capability, then mapping back). So inner 0 maps to
the **launcher** — root — **not** to the session uid. **Not breached via the map.**

**M3 — `accept_requester`'s comparison.** `if cred.uid() != expected_uid` — a plain inequality,
**no `&& uid != 0` root exemption**. The rejection is real and does what it appears to.

**M4 — can `expected_uid` be 0? YES, and it is reachable.** See the R9-11 row: unvalidated
`--session %i`. This is the one measurement that found a live breach rather than confirming a
defence.

### The measurement that decides the FIX, not the current state

Leg B ran the profile with **`--uid 65534 --gid 65534`** — the obvious shape of "run under a
dedicated service uid". Inside: `INNER uid=65534`. At the listener: **`SO_PEERCRED uid=1000`**
— *the launcher, unchanged*. **bwrap's `--uid` sets the id INSIDE the namespace and does not
change the credential the kernel reports outside it.** A fix built on `--uid` would show a
non-root `id -u` inside the jail while remaining the launcher's uid to every check performed
outside — cosmetic, and it would read as correct.

**The negative was satisfiable two ways** (standard 3, applied to my own measurement): either
(a) `--uid` never changes the outside credential, or (b) an *unprivileged* launcher owns exactly
one id, so no other result was possible. The unprivileged leg could not discriminate.

**RESOLVED — root leg run 2026-08-13. Both predictions confirmed, and leg B now discriminates:**

```
LEG A (as shipped):   INNER uid=0       →  SO_PEERCRED uid=0
LEG B (--uid 65534):  INNER uid=65534   →  SO_PEERCRED uid=0
```

Root had **two ids available** and `--uid 65534` still produced `uid=0` outside, so explanation
**(a)** holds: **`--uid` is namespace-internal only.** The obvious remediation is cosmetic — it
would pass review while changing nothing an outside check can see.

**Therefore the fix is a real credential change before `execve`** — `setresuid` / `setgid` /
`setgroups`, or a systemd `User=` — **never a bwrap flag.**

**Leg A also closes D0A-R9-11's chain end to end.** The root-launched jail presents as `uid=0` to
the listener; `delphi-runtimed@root` sets `expected_uid = 0` from the unvalidated `%i`; the peer
check compares 0 to 0 and **passes**. No attacker step, no remediation applied — the keystone
falls on a **supported unit instantiation**.

## An unexplained divergence in this file — recorded, not closed

Between the 2026-08-12 and 2026-08-13 commits, this register's working-tree copy contained the
D0A-R9-11 row and an M1–M4 results section **that I did not write**, citing the probe's exact
`pid=5304`. Every claim in it was checked against the probe's own output before it was committed,
and all of them hold.

**That disposition is not the same as knowing where it came from, and this entry exists to keep
those two apart.** The scripted edit that would have overwritten it **asserted NO MATCH and wrote
nothing** — the assert-every-replacement rule is the only reason the divergence is visible at all
rather than silently destroyed. Left **unexplained**; not to be written up later as resolved.

## Scheduling — decided 2026-08-12

**Gate before B2b** (the Brain subsumes `executor.rs`; integrating onto a broken privilege
boundary means re-reviewing all of it later): **D0A-R9-01 + D0A-R9-10 TOGETHER**, and
**D0A-R9-06**.

**R9-01 and R9-10 land together — but NOT because "each is the other's only backstop", which is
what this register said until 2026-08-15 and is wrong. Corrected before the fix, not with it,
because an overstated row reads as established and gets cited.**

Measured: the approval socket is `root:<session-gid>` mode **0660** (`anchor.rs`, "group-
connectable, owner stays root"), and `/run/delphi/<session>` is **0711** root-owned. A bind mount
preserves both. So the two halves are **asymmetric**:

- **Denylist alone** (the tool still root): root **overrides DAC**, so mode bits stop nothing and
  absence-from-the-mount-namespace is the **sole** barrier. One mechanism, one failure.
- **Uid alone** (no denylist): a `delphi-tool` peer is stopped by the socket's **mode** *and* by
  the **`SO_PEERCRED`** mismatch. Two independent mechanisms, neither of them the denylist.
  **The mode half is CONDITIONAL, and the condition is load-bearing (sharpened 2026-08-15):**
  `0660 root:<session-gid>` excludes the tool **only while the tool is outside the session
  group**. Put it inside — which is exactly what the naive R9-01 fix (drop to the *session* uid)
  would do — and `0660` grants it group access. A probe run that chowned the socket to the
  **tool's own** gid measured precisely that misconfiguration and connected; that fixture did not
  model production (`bind_approval_socket(&dir, session_gid)`), so it is **not** evidence the mode
  fails, but it is a live warning about which uid is chosen.

**So the uid is the ENABLING change and the denylist is defence in depth on top of it — while
the tool is root, the mode bits provide nothing at all.** They ship together because the denylist
is a single point of failure without the uid, not because they mutually backstop. The uid must be
a **dedicated service uid**, distinct from the session uid, since `SO_PEERCRED` equality is what
makes "which uid" the whole decision.

**`DynamicUser=` is STRUCTURALLY EXCLUDED, not merely unattractive — recorded so it is not
re-proposed.** It applies to a **systemd unit**; the tool is a child the root daemon *forks*
inside bwrap and is not a unit. Making it one requires `systemd-run` per action, which this
register's own scope cap forbids. Dynamic uid **recycling** is a separate hazard against files a
prior tenant left behind. Provisioning is therefore a **static system account created by the
installer**.

**Predicted, before implementation, so it is not later misread as breakage:** dropping the tool
off root **removes its access to root-owned bound paths**. That is the point of the change. Any
test that fails because of it is **correct**, and the finding is that the test depended on the
tool being root — widening the new uid's access to turn that red green would be the weaken this
project forbids.

**Schedulable:** seccomp (R9-05) and cgroups (R9-04). **Scope cap, deliberate:** seccomp policy
for *arbitrary tools* is open-ended and must not become the next Phase 3B. D1 ships a policy for
the tools actually reachable today, with the open-endedness recorded here rather than absorbed.

**If R9-01 or R9-06 remain open past the next merge to `main`,** that is recorded as an
**explicit dated exception to Iron Law #2 with named closure conditions** — not as a
"documented gap". Otherwise "documented gap" silently becomes what the law means, which is §6's
own failure one level up.
