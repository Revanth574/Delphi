# Codex adversarial review — D0-A round 14: the sealed-snapshot implementation, and R9-02 closed

<!-- Invocation: codex review - < scratch/codex-d0a-round14-prompt.md
     Every range-selection flag rejects a PROMPT positional; the scope is carried here. -->

## BEFORE ANYTHING: if you cannot RUN the repository, say so and stop

Round 13's verification boundary was explicit and useful: `bwrap` and `unshare -rm` failed
ambiently in your sandbox, so the two REDs skipped and 3 of 9 shell suites could not run.
**Say the same again if it holds** — several claims below are root- or bwrap-dependent, and a
finding derived without them should announce itself.

- **THERE ARE NO DELIBERATE REDs ANY MORE.** The suite is `108 passed / 0 failed`
  unprivileged and `18 passed / 0 failed` in `execute::tests::` at root. Every failure you
  see is a real one — the "two intentional R9-02 REDs" caveat from rounds 9–13 is gone, and
  `.githooks/runtime-test-count-baseline` now carries **no `RED=` lines**.

## Target

`git diff 7a0a8dd..b4e38e2` — **7 commits, 13 files changed, 802 insertions(+), 105
deletions(-).** PINNED. **If your diff stat disagrees, report that before reviewing.**

---

## LEAD WITH THIS: your design was adopted — judge the IMPLEMENTATION against §3 v7

You answered round 13's design question: sealed executable memfd, not rehashing, not
fs-verity as the universal mechanism. That was adopted, `docs/TRUST_MODEL.md` §3 was
**versioned to v7** first, and the code was written to the amended text.

**What to check, in order:**

1. **Does the implementation match the contract?** `action::seal_executable_snapshot` →
   `memfd_create(MFD_EXEC | MFD_ALLOW_SEALING | MFD_CLOEXEC)`, `F_ADD_SEALS` with
   `F_SEAL_SEAL | F_SEAL_EXEC | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE | F_SEAL_SHRINK |
   F_SEAL_GROW`, then **`F_GET_SEALS` verification** — a successful `F_ADD_SEALS` is not
   evidence the seals are present. `MFD_EXEC` is defined locally (this `libc` does not export
   it) from `/usr/include/linux/memfd.h:14`. **Is that value right, and is the set complete?**
2. **`execute::require_exec_sealed` re-checks at the choke point** rather than trusting the
   constructor. Is the choke point actually every path? Is there a way to reach `run_fd_pinned`
   with an unsealed fd?
3. **The helper (your step 6).** `build.rs` hashes the helper it just built and emits
   `DELPHI_DROP_DIGEST`; the daemon refuses `/usr/libexec/delphi-drop` unless the bytes match,
   then seals a snapshot of them. **Is a build-time constant the right binding, or does it
   break a legitimate workflow** (a rebuilt daemon against an older installed helper now
   refuses to start — deliberate, but say if it is wrong)?
4. **Nested shebangs are REFUSED at canonicalization** (v7 named limit 1), which was your
   preference over recursive snapshotting. The reproduction became a rejection test with a
   positive control. **Is the refusal at the right point, and is it complete** — can a chain
   be built that canonicalize accepts and the kernel still resolves recursively?

**Root evidence, so you know what is measured rather than argued:**

```
[R9-01] Uid: 997 997 997 997 / Gid: 972 972 972 972 / Groups: (empty) / CapEff: 0000…0000
same_inode_overwrite_executes_unapproved_content ... ok
the_drop_helper_is_bound_to_the_digest_this_daemon_was_built_with ... ok
a_nested_shebang_interpreter_is_refused_at_canonicalization ... ok
test result: ok. 18 passed; 0 failed.
```

---

## The finding that mattered most in round 13, and what it produced

**R13-01 was right and its consequence was larger than the two tests it named.** Both R9-02
reproductions were built by a fixture that hand-constructs a `PendingAction` with
`script: None` — a shape `canonicalize` never produces. They were rebuilt through production
canonicalization **before** being fixed, with a real ELF for the same-inode case
(gnutrue/gnufalse, differing in exit status).

**Then the choke-point check found nine more.** Adding `require_exec_sealed` immediately
failed nine fixtures that build actions production cannot — three test `ScriptPin`s, two
audit fixtures, `build_action` itself. R13-01 named two; the mechanism enumerated nine.
`build_action` now takes **bytes, not a path**, because the action binds content.

**Attack that claim.** Are there fixtures still constructing actions production cannot? The
mechanism only catches ones that reach `run_fd_pinned`.

---

## What I could not prove, and one correction I owe you

- **§3 named limit 2 is a DECLARATION, not a mechanism.** A sealed dynamic ELF still resolves
  `PT_INTERP` and its DSOs by path; nothing verifies them. The register's new
  proven-vs-declared table says so in the same place it lists what root measured. **Is
  declaring the loader an immutable platform TCB member defensible, or is it the beginning of
  the next finding?**
- **D0A-R10-12** — the pre-drop window's mitigation (`CAP_SETUID`/`CAP_SETGID` restriction) is
  named and unimplemented; its duration is unmeasured.
- **R9-01's socket half** is still fixture-measured, not against the real daemon.
- **R9-06 is open** — `env_delta` transits bwrap's argv, world-readable via
  `/proc/<pid>/cmdline`. The register commits to recording an **explicit dated exception to
  Iron Law #2** if it is still open at the next merge to `main`. **Is fixing it (drop
  `--clearenv`/`--setenv`, set the child env on the `Command` instead) as small as it looks,
  or does bwrap's env handling make that unsound?**
- **The correction:** round 13's prompt claimed only fs-verity gets kernel enforcement. You
  showed memfd seals are equally kernel-enforced, and that asymmetry was the whole reason
  verity looked necessary. It is corrected in §3 and recorded in the commit.

## `docs/DEFECT_CLASSES.md` — the (a)/(b) partition

**(a) Pre-foreclosed:** 1, 2, 3, 10, 26, 29a, 30, 31.
**(b) Concentrate here:** **class 12** (the seal verification must fail closed on every form
of "I cannot verify"), **class 20** (the helper and drop paths execute only at euid 0 — the
root lane ran, but judge whether the unprivileged suite still over-claims), **class 22/37**
(this is the fifth rewrite of the exec path), **class 43** (new — one error string, two
processes; it cost a false RED and a wrong hypothesis in this increment alone).

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R14-NN`), severity, root cause, impact,
fix sketch.

**The branch is otherwise ready to merge**, so the question I actually need answered is:
**does the sealed-snapshot implementation deliver what §3 v7 claims, or does it look like it
does?** Six consecutive rounds have found something in this exec path.

**Current state:** clippy `-D warnings` rc=0; `EXECUTED 118 / SKIPPED 1 / reported 119`, no
`RED=` lines; root lane `18 passed / 0 failed`; `ALL 9 SHELL SUITES PASS` (tree-install 38/0,
pre-commit 17/0); mutation audit `CAUGHT 23 / NOT CAUGHT 2 / UNEXPLAINED 0`.
