# Codex adversarial review — B2a COMPOSITION, round 4

You are a COLD ADVERSARIAL REVIEWER continuing a multi-round sweep.
Round 1: REVISE (2×P1, 2×P2). Round 2: REVISE (3×P2). Round 3: REVISE (1×P1, 2×P2).
Findings only — no praise, no restatement of what the code does.

## Target

- **Range:** `33dc258..HEAD` (the round-3 fix commit plus one docs commit).
- **Diff stat to expect:** ~4 files, ~371 insertions / ~36 deletions —
  `installer/p3-preflight.sh`, `installer/tests/p3-preflight.test.sh`, `PROGRESS.md`, and a
  `scratch/` prompt. **Flag scope drift if that differs.**
- No commit count is stated: round 1's prompt named one and committing the prompt changed it.
  The range is the scope.

Read the ACTUAL diff and current files with the Codex CLI. Verify shell semantics and API
claims against docs, not memory. **Everything below is a claim to check — including the
author's account of their own testing and their own audits**, which is the subject of item 5.

---

# ⚠ ITEM 1 (LEAD) — A RETROACTIVE DEBT, REQUESTED TWICE AND NOT DELIVERED

`docs/DEFECT_CLASSES.md` **class 22** ("the FIX inherits the class it was closing") prescribes
**two weakens**:

- **(a)** revert the fix — the test must fail;
- **(b)** **re-apply the finding's own question to the fix** — construct an input exhibiting
  the ORIGINAL class against the NEW code, and assert it is caught.

**B2A-COMP-R1-01 and B2A-COMP-R1-02 have had weaken (a) ONLY.** By the class's own standard
they are proven at the **instance** level, not the **class** level.

**This was asked for in the round-3 prompt and was not delivered — every round-3 finding
landed on round-2 code instead. It is now unpaid two rounds running.** It is the first thing
to do this round, ahead of anything in the round-3 diff.

### R1-01 — subdirectory trust check (`installer/install.sh`)

Original class: **class 2**, a path-resolution race where a check and a subsequent open
disagree. The fix `fstat_trust`s every directory in the staged bundle tree.

Construct the class against the fix. Starting points, none of which have been tested:
- The directory fd is opened, checked, then **closed** (`exec {dfd}<&-`) before that
  directory's children are opened by name. Does the check still bind anything at the moment
  the child is opened, or is it a check-then-open with the fd discarded?
- Can a directory that PASSES the check be **replaced** (rename/swap) before its children are
  enumerated or opened, given the enumeration comes from a single `find … -print0 | sort -z`
  taken earlier?
- Is the parent-before-child ordering that `sort -z` yields actually guaranteed for every tree
  shape, and does the fix's correctness depend on it?
- The documented bash-cannot-`openat` residual: with directories now involved, is it still
  only a DoS (wrong content installed) rather than attacker-controlled content?

### R1-02 — fail the install when the profile does not load (`installer/install.sh`)

Original class: **an install reporting success for a system it has left unable to render.**
The fix exits non-zero on a load failure and (round 3) hoists the pure preconditions into
pre-flight.

Construct the class against the fix: **is there any path where `install.sh` exits 0 while the
shell still cannot render?** Consider at least:
- `apparmor_parser -r` succeeds but the profile attaches to nothing (the pre-flight's
  exec-label probe exists precisely because loaded ≠ attached — the installer does not check
  attachment at all);
- `systemctl daemon-reload` failing after everything else succeeded;
- a profile that loads but is later flushed/unloaded by another `apparmor_parser -R` or a
  reload of the system policy;
- the tree-replace succeeding while `rm -rf "$OLD"` fails, leaving `shell.old` behind.

If either fix fails its (b) weaken, that finding carries the severity of the original (P1).

---

# ITEM 2 — WHY (b) IS OWED BY EVERY FIX, NOT SAMPLED: R4-04

Round 3's strongest evidence is a finding that only weaken (b) could produce.

**R3-03** fixed a mirror divergence: bash's `${VAR:-default}` fires on unset *and* empty, while
`env::var().unwrap_or_else()` fires only on absent, so `Environment=DELPHI_AI_BIND_RW=`
validated as `/tmp` and ran as `""` — a false green. **The fix was itself a mirror**: it
parsed the unit file with `grep -E "^Environment=KEY="`, which reimplements systemd's unit
syntax. Measured: for `Environment="DELPHI_AI_BIND_RW=/tmp/pf-elsewhere"` that grep yields
**zero matches**, so the pre-flight reads *absent*, defaults to `/tmp`, and passes a config
whose real bind is elsewhere. **A false green inside the fix for a false green.**

Weaken (a) on R3-03 passed. Only (b) found R4-04. That is the class validating itself on live
code, and it is the argument for applying (b) to **every** fix in range rather than sampling —
including the round-3 fixes below, and including R1-01/R1-02 above.

---

# ITEM 3 — THE ROUND-3 FIXES

## B2A-COMP-R4-01 — preserve the LITERAL bind path

**Claim:** `sandbox.rs` emits `--bind $p $p` verbatim, so the bind must be compared literally;
`realpath -m -s` resolves `..` without following symlinks, which mirrors that. Round 2's
`realpath -m` followed symlinks and accepted a marker under a bind-symlink's *target*, which
the sandbox would deny.

Attack it, and apply (b): does `-m -s` introduce a NEW divergence from what the kernel does
when bwrap makes the mount? Consider a bind containing `..`; a bind whose *parent* is a
symlink; a relative bind; and whether "lexical on both sides" is what the mount actually
resolves. A false RED before a root run is less dangerous than a false green but is still a
defect.

## B2A-COMP-R4-02 — `bind_rw=/` as an explicit case

**Claim:** root contains every absolute path, and the glob `//*` matched nothing.
Attack it: any other bind value where the glob still misbehaves — trailing slashes, `//`,
a bind that is a strict prefix but not an ancestor (`/tmpfoo` vs `/tmp`)?

## B2A-COMP-R4-03 — the fixture constructs its own paths

**Claim:** the containment tests now build `/tmp/pf-bind`, `/tmp/pf-outside`, `/tmp/pf-target`
+ symlink rather than assuming the rootfs supplies `/var/tmp`.
Attack it: do the new fixtures collide across parallel runs or leave state behind? Is `/tmp`
itself an assumption (it is — is that acceptable, and is it stated)?

## B2A-COMP-R4-04 — ask systemd instead of parsing the unit

**Claim:** `systemctl show <instance> -p Environment --value` is systemd's own resolution
(quoting, `EnvironmentFile=`, later-wins) and works for a not-yet-started instance. Where
`systemctl` is unavailable the pre-flight **refuses rather than falling back**, because the
fallback is the divergence being removed.

Attack it — this is the newest trusted input path in the diff:
- Is parsing `systemctl show`'s **output** a new mirror in itself? Values containing spaces,
  quotes, or `=` are the obvious cases. The pre-flight splits on whitespace.
- Does `systemctl show` on an **instance** name reflect what that instance will actually get,
  including drop-ins (`/etc/systemd/system/…d/*.conf`) and `EnvironmentFile=`?
- The pre-flight reads the unit; the DAEMON's process environment is what the AI inherits.
  Is the unit a faithful proxy — what about `systemctl set-environment`, or a manually-started
  daemon (which is exactly how P3a-2 was run)?
- Does refusing when `systemctl` is absent break any legitimate environment?

---

# ITEM 4 — KNOWN-UNFIXED, DELIBERATELY LEFT (do not report as a discovery)

**`DELPHI_AI_BIND_RW` is never checked for EXISTENCE.** `bwrap` fails on a missing bind source,
so a nonexistent bind is another *all-preconditions-met over a broken config* shape — the same
family as R2-01 and R3-03.

It was **left unfixed on purpose**: adding an unreviewed check while remediating a round is how
a round stops being reviewable. It is recorded in `02e4806`'s commit body as an observation.

**Weigh it rather than discover it:** is it the right call to defer, is the shape correctly
identified, and is existence even the right predicate (bwrap may also require it to be a
directory, or may accept a file bind)?

---

# ITEM 5 — FOUR MIRRORS REMAIN, AND ONE AUDIT IS UNVERIFIED

## The four remaining mirrors

Round 3 removed the **parse** mirror by delegation — the pre-flight now asks systemd. Four
value mirrors remain in `installer/p3-preflight.sh`, and they have **no authority to delegate
to**, which is what `--print-config` on the binaries would fix:

| duplicated value | source of truth |
|---|---|
| `/usr/share/delphi/shell` | `shell-host/src/main.rs` `DEFAULT_BUNDLE_ROOT` |
| `/usr/libexec/delphi-shell` | `delphi-runtimed.rs:86` `bin_path("DELPHI_SHELL_BIN", …)` |
| `/usr/libexec/delphi-ai` | `delphi-runtimed.rs:87` `bin_path("DELPHI_AI_BIN", …)` |
| `/tmp` (bind default) | `delphi-minimal-ai.rs:31` `unwrap_or_else(\|_\| "/tmp")` |
| the seam symbol | `delphi-runtimed.rs` `cfg(insecure-test-seams)` |

Round 3 asked this of the seven; ask it again of these: **which can diverge TODAY, and with
what input?** Three divergences have already been found in three rounds (empty-vs-unset, the
bind symlink, `bind_rw=/`), so the base rate here is not theoretical. Also say whether
`--print-config` is the right foreclosure or whether something cheaper suffices.

## The audit you should not take on trust

The author asserts: **"zero executable references to `/var`, `/opt`, `/srv`, `/mnt`, `/home`
across all three suites"** — the remaining matches being inside an explanatory comment.

**That claim is the author's and is unverified by anyone else. Check it directly.**

The reason to be sceptical is specific and quantified: **three host-dependent tests have been
found across three rounds — R1-03's sysctl, R3-01's wrong artifact, R4-03's `/var/tmp` — and
all three were found by YOU, none by the author.** The author's audits of their own fixtures
have a zero-for-three record against this exact class. A fourth is more likely than the tidy
audit result suggests.

---

# TEST QUALITY

Across three rounds: **three tests that could not fail for the reason they named**, and **two
weakens that did not weaken** (one swallowed an unrelated section; one removed nothing and
still "passed"). Round 3 added a step that verifies each weaken actually applied before its
result is believed — check that this is done for every weaken in the round-3 diff, not
asserted in the commit body.

**Treat any test that cannot fail for the reason it names as P1**, as in rounds 2 and 3.
Reason from the assertion and the code path, not from the author's report of having run it.

# `docs/DEFECT_CLASSES.md` partition

**(a) pre-foreclosed:** class 1 (no hashing), class 3 (no SQLite), class 2 for the *handler*.
**(b) applicable — concentrate here:** **class 22** (items 1 and 2); class 2 for the
**installer** (R1-01's owed (b)); class 12 and 14 (the containment gates); class 18 (verify
the artifact, not the operation); class 20 (host-dependence — item 5's audit).

# Out of scope — do not report as findings

The AppArmor profile's `flags=(unconfined)` status. The compositor gap and P3b blocked on the
PRIMARY deployment shape. The long-lived-shell lifecycle (P4). The wry IPC unwrap (upstream,
reported, routed around). **Say so if you think any is misclassified.**

---

# ON CONVERGENCE

Findings per round: 4 → 3 → 3. Severity: 2×P1 → 0×P1 → 1×P1. That is **not** obviously
converging, and it is **not the author's call** — three of the author's own tests did not bite
on first writing, and the author's fixture audits are zero-for-three against host-dependence.

State explicitly whether the sweep has converged and on what evidence. If you APPROVE, say what
remains unproven anyway: the standing scope split (P3a-1 proven **by observation**; P3a-2 proven
machine-checkably; P3b, P4 and the compositor gap **blocked** on the PRIMARY deployment shape)
must survive the close intact rather than be absorbed into it.

If the retroactive (b) weakens on R1-01/R1-02 cannot be completed this round, **say so and say
why** rather than returning APPROVE with the debt outstanding for a third time.

# Verdict format

**APPROVE** / **REVISE** / **FAIL**, then each finding as ID / severity (P1-high → P2-medium →
P2-low → P3-informational) / root cause / impact / fix sketch.

**If a round-1 fix fails its retroactive class-22 weaken, say that first** — it outranks
anything found in round-3 code.
