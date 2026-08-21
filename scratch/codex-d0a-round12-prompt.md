# Codex adversarial review — D0-A round 12: ELF parsing in a root script, and round 11's remediation

<!-- Invocation: codex review - < scratch/codex-d0a-round12-prompt.md
     Every range-selection flag rejects a PROMPT positional; the scope is carried here. -->

## BEFORE ANYTHING: if you cannot read or RUN the repository, say so and stop

Round 10's first attempt returned findings from a reviewer whose sandbox could not run the
tree, and round 11's most important finding (R11-01) came from a reviewer who **could** run it
and noticed that two bwrap tests failed **ambiently** in their sandbox. Both matter here.

- If `git show` / `git diff` do not work, report that and stop.
- **If `bwrap` fails in your sandbox with `loopback: Failed RTM_NEWADDR: Operation not
  permitted`, that is your environment, not this box** (measured here at `rc=0`). Do not
  report it as a finding — but **do** tell me, because several tests below run bwrap and
  their results in your sandbox will differ from mine.
- If `unshare -rm` is unavailable, `installer/tests/tree-install.test.sh` cannot run at all
  and everything it covers is unverified on your side. Say so rather than reasoning about it.

## Target

`git diff 5b6e83a..1902fdc` — **14 commits, 18 files changed, 1414 insertions(+), 222 deletions(-).**

The ending SHA is **PINNED, not `HEAD`**. **If your diff stat disagrees with the line above,
report that as a finding before reviewing anything.**

**A scope correction worth stating, because it was nearly wrong:** the range was initially
proposed as `af47e4e..HEAD`, which is 5 commits and **excludes the rebuilt mutation harness
and the parser rewrite** — the two things round 11 flagged hardest. `5b6e83a` is round 11's
own pinned endpoint, so this range is exactly the unreviewed remediation and nothing else.

---

## LEAD WITH THIS: three ELF parsers, in bash, in a script that runs as root

`installer/install.sh` gained `elf_u`, `elf_ident`, `elf_layout_supported` and `elf_interp`.
The last one **walks a program-header table** — offsets and lengths taken from the file being
inspected — and reads a string out of it with `dd`. This is the most intricate code in the
project's only root-privileged script, it is exercised by exactly one suite, and it is where
I expect you to find something.

**What it is for.** D0A-R11-07 established that comparing 20 header bytes of the staged
binaries against *each other* proves agreement, not nativeness: four mutually-matching
foreign binaries pass. So each staged binary is now compared against `/proc/self/exe` — the
interpreter running the installer, native by construction — across the full 16-byte
identification header, plus `e_type`, `e_machine`, and `PT_INTERP`: a named loader must
exist, and `delphi-drop` must name **none**, because it is exec'd inside a jail that binds
nothing.

**What I already bounded, having looked for these myself before handing it over:**

| bound | proven? |
|---|---|
| layout declared ELF64/LE/v1, anything else REFUSES rather than misreading | reference-checked |
| program-header table must lie inside the file | **weaken-proven** — removing it accepts a truncated binary (rc=0) and leaks `od: tried to skip past end of input` |
| interpreter string length-bounded; used only as an argument to `[ -e ]`, never evaluated | by inspection |
| `e_phnum` capped at 256 | **NOT ISOLATED — see below** |

**The `MAX_PHNUM` cap is the one I could not prove, and I want you to either break it or
tell me it should go.** Two attempts to construct an input where only that bound decides
both failed: at 65535 the past-EOF bound refuses first; at 4096 the walk reaches a garbage
entry whose `p_type` is 3 and whose `p_filesz` fails its own bound. So the test leg's claim
was narrowed from "bounded, not walked" to "refused, cause not isolated". The bound governs
**work**, not the verdict — and nothing measures work. Is it dead weight, or is there an
input that makes it the deciding check?

**Questions I actually want answered about this code:**

1. **Can the parse be made to misread a file it should refuse, or refuse one it should
   accept?** `elf_u` treats an empty `od` result (offset past EOF) as **0**, and every caller
   reads 0 as "absent". Is there a file where "absent" is the dangerous answer and the bounds
   do not already cover it?
2. **`dd if=/proc/self/fd/N bs=1 skip=… count=…`** — is re-opening the magic symlink here
   consistent with the TOCTOU property the rest of the script depends on (fstat the bound fd,
   copy from the bound fd)? `copy_fd` already relies on re-open semantics; does this?
3. **Is `/proc/self/exe` the right reference?** It is bash. If the installer is run under a
   different interpreter, or on a system where `/proc` is not mounted, what happens?
4. **The stated residual**: this establishes loadability preconditions, **not** executability
   — a well-formed native header followed by garbage still passes. Is that residual stated
   accurately, or does it understate what else gets through?

---

## The second-largest thing: the mutation harness, rebuilt because you falsified it

R11-01 was correct and its consequence is recorded: **round 10's "11 of 12 caught" is
WITHDRAWN as unsupported, not corrected.** The old harness had no baseline, so "caught" meant
*any* test in four hard-coded namespaces failed — true for every mutant including the null
one in a sandbox with ambient failures.

**The rebuilt one was wrong three more times before it was right, each with confident
output**, and that is the finding I would most like you to extend:

- no `--nocapture`, so a skipped test counted as executed;
- an executed-count derived from `passed`, which **drops on every successful catch** — 13
  spurious `UNEXPLAINED`;
- a `^test <name> \.\.\. FAILED` regex that `--nocapture` interleaving defeats, reporting
  **0/16 caught**, which looked like a catastrophic coverage result and was a parse bug.

It now takes a measured baseline (cargo status, result-line count, ran/skipped, the
fully-qualified failure set), scores compile failure as CAUGHT, gives **no verdict** on
unexplained state, runs `--lib --bins`, and mutates an isolated git worktree so an interrupt
cannot leave the tree mutated.

**Re-measured, 25 mutants: CAUGHT 23 / NOT CAUGHT 2 / UNEXPLAINED 0.** The two: the denylist
equality leg (a semantic no-op — `starts_with` is reflexive) and `tool_credentials() -> None`
(root-only, recorded).

**AND IT HAD ONE MORE, FOUND WHILE PREPARING THIS PROMPT.** The harness shared the tree's
`CARGO_TARGET_DIR`, so a mutant's build landed in the cache the repo reads: afterwards
`cargo test` reported EXECUTED **112** against a recorded 114, with two `system_account_guard`
tests failing — which reads exactly like a regression and was not one. The binary still
contained the audit's LAST mutant. Class 30, injected by the instrument built to detect
defects. It is now isolated (its own target dir, and it REFUSES if that dir is the tree's).
**Two mechanisms made it visible and neither was care**: the count baseline disagreed, and
every figure in this prompt was re-derived before it was written.

**Attack the instrument, not the number.** Specifically:

- Is `caught = mutant_failures \ baseline_failures` sound in **both** directions? Where does
  it still lie?
- The mutant set is **mine plus one of yours** — I folded in the read-only-to-writable
  translation you named (it is now caught by three tests) and labelled the set accordingly.
  **I do not have your twelve verbatim; they are not in this repository.** If you restate
  them, they replace mine rather than supplement them.
- Two mutants went `NOT APPLIED` after R11-05/R11-06 moved their target text. The harness
  scored that `UNEXPLAINED` and refused a verdict, which is right — but it means a property
  went unmeasured until someone noticed. **Should a NOT APPLIED mutant be a hard failure?**

---

## The rest of the remediation, briefly — each with what it does NOT prove

**R11-05, the parser.** Replaced the method, not the form list: shadow's two phases (store
the last RAW value; then interpret — a quote SCAN, skipping any number of leading quotes and
terminating at the first subsequent one, then `strtoul` base 0). Measured against
`useradd --prefix` on shadow 1:4.17.4, 38 forms, including `"50"00"` → **50**, which no
strip-based reading produces. **Does a 39th form disagree?** Also: `ABSENT` now defaults and
`UNREADABLE` refuses — is refusing at startup on an unreadable `/etc/login.defs` right, or a
new denial-of-service on a file the system itself tolerates?

**R11-06, the credentials.** One resolution, validated, recorded, read; the old startup check
`if let Ok(Some(…))` skipped validation entirely on a lookup **error**. The decision is
provable unprivileged via an injected resolver. **NOT PROVEN:** restoring the re-resolution
inside `tool_credentials()` leaves the suite **green**, because that path needs euid 0. Is
there a seam that proves it without weakening the privilege check?

**R11-02/03/04, the remedies that carried their own defect.** The hook checked counts not
identity (a red/green swap passed) and exited 0 when its baseline was missing; the suite
runner refused only at ZERO discoveries; the fixture hard-coded "5". All fixed — and **the
hook's first fix had the bug backwards** (identity without count let a third failure
through), caught by the hook's own suite. The expected failures are now data
(`RED=` lines in `.githooks/runtime-test-count-baseline`) so a green suite is expressible.
**Does the gate now refuse something legitimate?** It is environment-specific: a root lane
executes the credential test that skips here.

---

## `docs/DEFECT_CLASSES.md` — the (a)/(b) partition

**(a) Pre-foreclosed — do NOT re-hunt:** classes 1, 2, 3, 10 (skip-as-pass — `test-count.sh`
is mandatory and now also gates disappearance), 26, 29a, 31.

**(b) Applicable and NOT foreclosed — concentrate here:**

- **Class 12 (reject the invalid CLASS, fail-closed)** — the ELF parsers are exactly this:
  the numbers come from the artifact, so every one is an input to gate as a class.
- **Class 41 (altitude)** — the ELF check reads headers; the property is "runs on this
  machine". I claim headers are the right layer for the class of mismatch that occurs and
  state the residual. Disagree if you do.
- **Class 22 / 37 (remediation is where a class reappears)** — four of this round's fixes are
  fixes TO fixes, and one of them (the hook) reintroduced its own class backwards.
- **Class 14 (all forms)** — the login.defs grammar, three rounds in.
- **Class 42 (accepted correction, R11-08)** — `--clearenv` was demoted from a second
  instance to ordinary missing coverage; the class now rests on one grounded case. If one
  case is too thin to keep the entry, say so.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R12-NN`), severity (P1-high → P2-medium →
P2-low → P3-informational), root cause, impact, fix sketch.

Three things worth more than a long list:

1. **Break the ELF parsers**, or tell me `MAX_PHNUM` should be deleted as unprovable.
2. **Where does the rebuilt mutation harness still lie?**
3. **Your twelve mutants, verbatim**, if you still have them — they are not in this repo and
   I could only fold in the one you named.

**Current state:** `clippy -p delphi-runtime --all-targets -D warnings` rc=0;
`scripts/test-count.sh -p delphi-runtime --lib --bins` → **EXECUTED 114 / SKIPPED 1 /
reported 115** with the 2 intentional D0A-R9-02 REDs; `scripts/run-shell-suites.sh` → **ALL 9
SHELL SUITES PASS** (`tree-install` 32/0, `pre-commit` 17/0);
`scratch/d0a-mutation-audit.sh` → **CAUGHT 23 / NOT CAUGHT 2 / UNEXPLAINED 0**.
