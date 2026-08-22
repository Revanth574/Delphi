# Codex adversarial review — D0-A round 13: R9-02, a DESIGN question with two live reproductions

<!-- Invocation: codex review - < scratch/codex-d0a-round13-prompt.md
     Every range-selection flag rejects a PROMPT positional; the scope is carried here. -->

## BEFORE ANYTHING: if you cannot read or RUN the repository, say so and stop

Round 11's most important finding came from noticing that two bwrap tests failed **ambiently**
in your sandbox and that my harness scored that as twelve catches. Environment differences are
findings here, not noise.

- If `git show` / `git diff` do not work, report that and stop.
- **If `bwrap` fails with `loopback: Failed RTM_NEWADDR: Operation not permitted`, that is your
  environment** (measured here at `rc=0`) — not a finding, but tell me, because the tests below
  run bwrap.
- If `unshare -rm` is unavailable, `installer/tests/tree-install.test.sh` cannot run and
  everything it covers is unverified on your side. Say so rather than reasoning about it.
- **Two tests in `execute::tests::` are DELIBERATELY RED.** They are your own R9-02
  reproductions. A run showing `15 passed; 2 failed` for that module is the CLEAN result;
  check the failing NAMES against the `RED=` lines in `.githooks/runtime-test-count-baseline`.

## Target

`git diff 1902fdc..7a0a8dd` — **12 commits, 13 files changed, 681 insertions(+), 70
deletions(-).** The ending SHA is **PINNED**. This prompt's own commit is deliberately outside
the range. **If your diff stat disagrees, report that as a finding before reviewing anything.**

---

## LEAD WITH THIS: D0A-R9-02 is the last load-bearing item, and it is blocked on a DESIGN
## decision rather than on measurement

Everything else on this branch is remediation. R9-02 is the one open item where **I do not
know what the right mechanism is**, and I would rather have your judgement on the design than
another list of defects in code I have already rewritten four times.

### What is proven, precisely

The **script body IS content-pinned.** `execute.rs` verifies `ScriptPin::FULL_SEALS`
(`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL`) on `script_memfd` before any exec
path, so neither its bytes nor its length can change between the digest and the exec.

### What is NOT proven, and the grep that shows it

`executable_fd` and `interpreter_fd` are plain `File::open` fds — **inode-pinned, never
sealed**. `executable_digest` is computed once in `canonicalize.rs:64` and **never re-verified
at exec**: `sha2` appears in `execute.rs` only under `#[cfg(test)]`. So the fd pins WHICH
INODE runs; nothing pins WHAT IS IN IT.

Your two reproductions, still red, from a root run on 2026-08-22:

```
same_inode_overwrite_executes_unapproved_content
  assertion `left == right` failed: D0A-R9-02: bytes written behind the pinned inode execute
  — the digest bound content that is no longer there
  left: "SUBSTITUTED"   right: "APPROVED"

nested_interpreter_substitution_executes_unapproved_content
  assertion `left == right` failed: D0A-R9-02: the pinned inode is correct AND unmodified, yet
  the code that ran was resolved by path after the pin
  left: "SUBSTITUTED-INTERP"   right: "APPROVED-INTERP"
```

### The constraint the register already imposes

**R9-02 may not close without answering the drop helper.** `execute.rs` opens
`/usr/libexec/delphi-drop` by PATH (`DROP_HELPER`), so it carries this same inode-vs-content
gap **for itself** — and it is the one component whose substitution grants **uid control**,
because it is what performs `setresuid`. Opening once per process (`preopen_drop_helper`)
shrinks the window to process start; it does not close it. A fix that content-pins the tool
and exempts the helper fixes the smaller half.

### Candidate mechanisms — what I measured about each, and what I want judged

| candidate | what I measured | the objection I cannot resolve |
|---|---|---|
| **Re-hash the pinned fd immediately before `execve`** | nothing in production hashes today; a 5MB read is ~10ms | a write through the same inode is visible via the fd, so hash-then-exec still has a TOCTOU window. Does anything close it, short of immutability? |
| **Copy into a sealed memfd and `fexecve` that** — what the script side already does | kernel 7.0.0-28; `MFD_EXEC` is present in `/usr/include/linux/memfd.h:14` | the executed object is then a COPY, not the installed path. Does that break the audit's meaning, `argv[0]`, or `/proc/self/exe` for the tool? And is `MFD_EXEC`'s behaviour what I think — **verify, do not assume** |
| **fs-verity on the installed binaries** | `/usr/libexec` is **ext4**; the `fsverity` tool is **ABSENT** here; reading the feature flags needs root | it covers installer-placed files (helper, daemon) but not an arbitrary approved binary the user names. Is a split mechanism — verity for ours, something else for theirs — coherent or a seam? |
| **`chattr +i`** | not attempted | installer-only, same split problem, and it makes the file unremovable by ordinary means |

**The questions I actually want answered:**

1. **Which of these is right**, or what is the mechanism I have not listed?
2. **Can the binding be enforced by the KERNEL rather than by our re-read?** Everything above
   except verity is us checking; verity is the kernel checking. That asymmetry feels
   load-bearing and I may be over-weighting it.
3. **Does your answer cover the helper**, and if it needs a different mechanism for the helper
   than for the tool, is that a defensible seam or the beginning of the next finding?
4. The nested-shebang case: the pinned interpreter is exec'd with the sealed script as its
   argument, and the reproduction still substitutes. **Is interpreter-pinning even the right
   frame**, or does a shebang chain need the whole chain pinned?

---

## The rest of the range: round 12's remediation, ten findings

All closed. What each does **not** establish is stated with it, because that is where you found
the last three rounds' real defects.

- **R12-09** (the largest): `installer/tests/tree-install.test.sh` — §6's named tier-1 SOLE
  EVIDENCE — reported **green by skipping** in CI on every run, because that job had no Rust
  toolchain and the fixture it needs never existed. Fixed at instance (REFUSE), class (the
  runner fails any suite exiting 0 with no result line), and cause (CI builds the fixture).
- **R12-01/02/03**: absence coerced into a value in the ELF parsers — a missing field read as
  0, an 8-byte field with the top bit set read as negative, a `PT_INTERP` of `"\n"` read as
  absent. **NOT ISOLABLE:** the negative guard — every negative value reachable is caught
  downstream by the short-read check, because `od` produces nothing at a negative offset.
- **R12-04/05/06**: the `PT_INTERP` NUL was discarded unseen (now verified **numerically**,
  because bash cannot hold a NUL — `$(dd …)` warns `ignored null byte in input`);
  `MAX_PHNUM` **deleted** on your reasoning that 257 headers is a valid executable, replaced by
  a single `od` + `awk` pass; full `e_ident` equality replaced by the fields that decide
  loadability. **NOT SHOWN:** that a genuinely valid 257-header executable is ACCEPTED — the
  fixture cannot fabricate one honestly.
- **R12-07**: the login.defs parser's third round, and the first **interaction** — blanks and
  quotes were each measured and each correct alone; no probe had generated both.
- **R12-08 + R12-11**: R11-06's refusal broke every root execution test (they died before the
  drop they test). Fixed, and **measured on a root lane**: 15 passed / 2 failed, the two being
  your REDs. R9-01's credential proof printed `Uid: 997 997 997 997`, `Gid: 972 972 972 972`,
  empty `Groups:`, `CapEff: 0`.
- **R12-11's real lesson**, recorded as a `DEFECT_CLASSES` class-20 instance: the drop only
  happens at euid 0, so the **unprivileged run of every execution test takes the no-helper
  branch**. Seven tests had been failing at root since shape E landed. The suite ran, passed,
  and was about a different mechanism — same names, same count, same result line in both
  environments. **A privileged run is not a confirmation step; it is the only run that has ever
  executed that code.**

---

## `docs/DEFECT_CLASSES.md` — the (a)/(b) partition

**(a) Pre-foreclosed — do NOT re-hunt:** classes 1, 2, 3, 10, 26, 29a, 31, and 30 (the
mutation audit now builds in an isolated, canonicalized target dir).

**(b) Applicable and NOT foreclosed:**

- **Class 20** — its new instance is above, and R9-02's own tests are root-relevant: judge
  whether the fix you propose is provable at the privilege level it runs at.
- **Class 12 (reject the invalid CLASS)** — whatever pins content must fail closed on every
  form of "I cannot verify this", not just the forms we thought of.
- **Class 22 / 37 (remediation is where a class reappears)** — R9-02's fix will be the fifth
  rewrite of this exec path.
- **Class 41 (altitude)** — the argv-level evidence for helper interposition was necessary and
  the root run made it real. Where does R9-02's evidence have to live?

---

## What I could not prove, listed so your budget goes elsewhere

- the `elf_u` negative guard (above) — kept, not isolable;
- a valid 257-header executable being accepted — not constructible as a fixture;
- **R9-01's socket-refusal half** — still measured against a probe fixture, not the real daemon;
- **D0A-R10-12** — the pre-drop window's mitigation (restrict the helper to
  `CAP_SETUID`/`CAP_SETGID`) is **named and unimplemented**, and the window's duration is
  **unmeasured**;
- **D0A-R9-12** — actions have no isolation from each other (same `delphi-tool` uid).

**Two instructions of mine that were wrong, since they affect how you read any figure I
quote.** "Expected 17 passed, 0 failed" for a module containing two deliberate REDs — the
count was the wrong check and the names are the right one, which the pre-commit hook already
enforces. And "the binary's mtime must be later than the commit" is **systematically wrong**:
the pre-commit hook builds before the commit object exists, so a hook-built binary is always
older than its commit. The check is a forced rebuild with an unchanged hash.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R13-NN`), severity, root cause, impact, fix
sketch.

**But the thing I want most is not a finding.** It is an answer to §"LEAD WITH THIS": which
mechanism content-pins an executable at exec, does it cover the drop helper, and is the
kernel-enforced option (fs-verity) worth the deployment constraint it imposes. If your answer
is "the current design cannot be fixed without changing what gets executed", say that —
it is a legitimate answer and I would rather have it now than after a fifth rewrite.

**Current state:** `clippy -p delphi-runtime --all-targets -D warnings` rc=0;
`scripts/test-count.sh -p delphi-runtime --lib --bins` → **EXECUTED 115 / SKIPPED 1 / reported
116** with the 2 intentional REDs; root lane → **15 passed / 2 failed** in `execute::tests::`;
`scripts/run-shell-suites.sh` → **ALL 9 PASS** (`tree-install` 37/0, `pre-commit` 17/0);
`scratch/d0a-mutation-audit.sh` → **CAUGHT 23 / NOT CAUGHT 2 / UNEXPLAINED 0**.
