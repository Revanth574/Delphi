# Codex adversarial review — D0-A round 11: round 10's fixes, and a mutation audit of the greens

<!-- Invocation: codex review - < scratch/codex-d0a-round11-prompt.md
     Every range-selection flag rejects a PROMPT positional; the scope is carried here. -->

## BEFORE ANYTHING: if you cannot read the repository, SAY SO AND STOP

Round 10's first attempt returned findings from a reviewer whose sandbox could not run the
tree. **Partial findings that do not announce themselves as partial cost a full round.** If
`git show` / `git diff` do not work, or `cargo` / `bwrap` are unavailable, report that as your
verdict and stop. "Could not read the tree" is worth more than any number of findings derived
without it. If bwrap fails in your sandbox with `loopback: Failed RTM_NEWADDR: Operation not
permitted`, that is **your environment, not this box** — measured here at `rc=0`. Not a finding.

## Target

`git diff 4d3815f..5b6e83a` — **17 commits, 21 files changed, 1796 insertions(+), 214
deletions(-).**

The ending SHA is **PINNED, not `HEAD`** (D0A-R10-02: a moving endpoint cannot be checked
against a fixed manifest). **If your diff stat disagrees with the line above, report that as a
finding before reviewing anything.**

Read the tree through the CLI, not from a supplied diff. Verify library/API claims against
Context7 / docs.rs / `--help` rather than memory — three findings below exist *because* a tool
behaved differently from how it reads.

---

## What this round is, in one line

Round 10's remaining findings (**R10-07 login.defs, R10-10 the unchecked copy, R10-11 the
bare `rustc`**) are fixed; and the round's own question — *which greens would you not trust?* —
was answered by **mutation** rather than by reading. That audit found more than the fixes did,
including a defect class the corpus did not have and **two tests that had been silently
deleted**.

---

## LEAD WITH THIS: the verification machinery was the defective part

Four of this round's findings are in the tools that produce this project's evidence. Judge
them as one thing, because they share a shape: **an absent check reporting as a pass.**

1. **The pre-commit gate had never run.** `1867b25` fixed its `tail -1` defect and landed
   through the documented hook-edit exemption. Its first real invocation **refused a commit
   for a reason unrelated to the commit** (`scripts/test-count.sh` exits non-zero on any
   failure; `set -e` killed the hook before its own decision). It would also have **passed a
   suite that did not compile** — no `test result:` line parses as zero failures, which is
   `tail -1`'s shape reintroduced inside its own fix.
2. **`scripts/test-count.sh` under-reported a whole target.** No `--no-fail-fast`, so cargo
   stopped at the first failing target and the LIB's count was printed as the answer to
   `--lib --bins`: **reported 99 where the truth was 108**. Its own self-test could not see
   it — all eight cases feed a captured log, so the parser was covered and the invocation was
   covered by nothing.
3. **Both installer suites had been RED for 15 commits.** `cdc3418` added `delphi-drop` to
   `install.sh`'s staged-artifact loop and to `build.sh`, and updated neither fixture.
   Measured at `cdc3418~1`: 9/0 and 26/0. At `9a45679`: 3/6 and 10/16. One of the two is what
   CLAUDE.md §6 names as the **tier-1 SOLE EVIDENCE** for the tree-replace invariant. Nothing
   ran them — not cargo, not the hook, not CI, which had no shell-suite step at all.
4. **Two tests were deleted in a commit that described neither.** `f380085` removed 135 lines
   from `execute.rs`, including `the_tool_receives_its_approved_argv0` and
   `a_second_kept_fd_survives_a_second_exec_and_is_executable`. Both are restored here.

**The question for you on this group:** the remedies are a hook test, a `--no-fail-fast`, a
suite runner, and a count baseline. **Do any of them have the defect they were built to
prevent?** That is class 22, and this project has now hit it twice in three rounds.

---

## The mutation audit — the strongest claim here, so attack it first

`scratch/d0a-mutation-audit.sh` introduces twelve realistic defects into the shape-E guards
one at a time and records which tests notice. **Five passed the entire suite:**

| defect introduced | why it matters |
|---|---|
| ancestor `--perms 0755` → `0700` | bwrap's own default — the exact value class 40 exists to override. The test named `every_ancestor_of_every_bind_is_created_traversable` asserted emission, order, and position, and never the MODE its name promises |
| `--unshare-net` dropped for `NetPolicy::None` | **bwrap's default SHARES the host network.** An approved no-network action gets the network |
| `--clearenv` dropped | §6's "env is scrubbed to `env_delta`" was asserted by nothing |
| the approved `argv[0]` never reaches the tool | its test had been deleted five commits earlier |
| the drop helper never interposed at all | the path is unreachable unprivileged |

Eleven of twelve are caught now. **What I want attacked:**

- **Is the harness sound?** It asserts each replacement matched exactly once, restores both
  files, and diffs them. Can a mutation apply, the suite pass for an unrelated reason, and
  "NOT CAUGHT" be wrong in either direction?
- **Is the twelve a good set?** Which realistic defect is *missing* from it? The value of this
  tool is bounded by the mutations someone thought to write.
- **The one still uncaught** — `tool_credentials()` returning `None` — is claimed to be
  unobservable unprivileged. Is that true, or is there a seam I did not look for that does not
  weaken the privilege check?

## Class 42, the new corpus entry — is it a real class or a rename of an old one?

`net_policy_maps_faithfully…` asserted `--share-net` **absent** for `NetPolicy::None`. That was
a complete proof while the profile opened with `--unshare-all`, which implies the unshare.
Shape E replaced that with an explicit list, so isolation became an opt-in of its own — and the
old assertion stayed true while the property died. **The test did not change; what it was
sufficient to prove did.**

I claim this is distinct from class 22 (a *fix* inheriting the class it closed), class 26 (a
*captured value* read as current) and class 41 (the wrong *layer*). **If it is one of those
wearing a new name, say so** — a corpus that grows by renaming is worse than one that does not
grow.

---

## `docs/DEFECT_CLASSES.md` — the (a)/(b) partition

**(a) Pre-foreclosed — do NOT spend budget re-hunting:**
Class 1 (`canonical_hash`), 2 (`safe_open`), 3 (`pragma_setup`), 29a (shared holder-check),
26 (stale observation), 31 (teardown reports its failure), 10 (skip-as-pass — `test-count.sh`
is mandatory and now also gates disappearance).

**(b) Applicable and NOT foreclosed — concentrate here:**

- **Class 17 (breadth)** — this round is *made of* enumerations: the login.defs grammar
  (28 measured forms), the ELF check's three binaries, the artifact lists in two fixtures, the
  twelve mutations. Class 17 scored six-for-six in round 8.
- **Class 14 (all forms)** — `login_defs_line` claims to match shadow's grammar. **Is there a
  29th form?**
- **Class 22 / 37 (remediation is where a class reappears)** — see the four-tool group above.
- **Class 41 (altitude)** — the ELF check reads headers, not behaviour; the `exec_tail` tests
  read arguments, not a running process. Both are argued to be the right layer. **Are they?**
- **Class 25 (fixture ≠ subject)** — `tree-install.test.sh` now stages 20-byte fabricated ELF
  headers instead of text stubs. Faithful enough for a header check, or a divergence that will
  matter later?
- **Class 42 (new, above).**

---

## Named attack surfaces, in priority order

1. **`login_defs_line` / `parse_c_ulong`** (`runtime/src/bin/delphi-runtimed.rs`). The grammar
   was measured against `useradd --prefix` on shadow 1:4.17.4 — the quote/blank ORDERING, the
   `\r` rejection, last-wins precedence, base-0 with no sign after the radix prefix. **Find a
   form where we disagree with shadow.** The consumers are `refuse_system_account` and
   `refuse_unsafe_tool_account`, so a disagreement is an account misclassified. Also: is
   refusing an inverted range (`UID_MIN > UID_MAX`) at startup right, or a new DoS on a
   config file shadow itself rejects?
2. **The ELF-identity check** (`installer/install.sh`, ROOT). Reads 20 bytes from the
   already-bound fds via `od` and compares class/data/machine against the daemon's. `read -r
   -a b < <(…) || true` swallows read's status deliberately (`tr` leaves no trailing newline);
   the array length is what decides. **Can it be fooled, or made to refuse a legitimate
   install?** Does re-opening `/proc/self/fd/N` for `od` preserve the TOCTOU property the rest
   of the script relies on?
3. **`exec_tail`** (`runtime/src/execute.rs`) — a behaviour-preserving extraction from the
   trust-boundary exec path. **Is it faithful?** The old inline code and the new function must
   produce identical argv for every combination of (helper, creds, script, argv). A silent
   change here alters what the approved action executes.
4. **`runtime/build.rs`** — `--target $TARGET`, and a checked copy+rename. The rename is
   claimed to fix a half-written-staging race and an ETXTBSY failure mode. Is the temp name
   (`delphi-drop.tmp<pid>`) safe against a concurrent build in the same profile dir?
5. **The hook + baseline** (`.githooks/`). A gate that refuses too much is as bad as one that
   refuses too little: the count baseline is environment-specific (root vs not). Is the
   override path adequate, or does this block a legitimate root-lane commit?

---

## What I already know is wrong or unproven — do not spend the round rediscovering it

- **The CI shell-suite job is UNVERIFIED on a runner.** Green here (9/9); never executed by
  GitHub Actions. It apt-installs `apparmor` and `strace`.
- **The drop TAKING is root-only.** `an_approved_action_runs_with_the_tool_account_credentials`
  SKIPs here, so on this box that property has no live evidence. The assembly is now proven
  unprivileged; the effect is not.
- **R9-02's two REDs are intentional** and still red (`same_inode_overwrite_…`,
  `nested_interpreter_substitution_…`). The suite is deliberately 112 executed / 2 failed.
- **A successful cross-build was NOT demonstrated.** Measured: pre-fix silently produces an
  x86-64 helper in the aarch64 profile dir (rc=0); shipped fails rc=101 with no artifact. A
  *runnable* aarch64 helper needs a cross linker + glibc that is not installed.
- **`a_bind_whose_path_does_not_exist_is_refused` asserts only `is_err()`** — a probe showed
  swapping the error VARIANT (`BindWouldCreateOnHost` → `DeniedBind`) is NOT CAUGHT, which is
  R10-08's own defect. Known, unfixed, and it is fair game for a finding about severity.
- **The pre-drop window (D0A-R10-12)** is open with a named unimplemented mitigation and an
  unmeasured duration.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R11-NN`), severity (P1-high → P2-medium →
P2-low → P3-informational), root cause, impact, fix sketch.

Two things beyond a list of findings would be worth more:

1. **Is the mutation audit's "NOT CAUGHT" trustworthy**, and what twelve defects would you have
   chosen instead?
2. **Do the four new verification tools carry the defect they were built to prevent?**

**Current state:** `clippy -p delphi-runtime --all-targets -D warnings` rc=0;
`scripts/test-count.sh -p delphi-runtime --lib --bins` → **EXECUTED 112 / SKIPPED 1 / reported
113** with 2 intentional REDs; `runtime/shell-host` → EXECUTED 12 / SKIPPED 7 / reported 19,
clippy rc=0; `scripts/run-shell-suites.sh` → **ALL 9 SHELL SUITES PASS**.
