# Codex adversarial review — D0-A round 10: shape E, adopted as one decision

<!-- Invocation: codex review - < scratch/codex-d0a-round10-prompt.md
     All three range-selection flags reject a PROMPT positional; scope is carried here. -->

## BEFORE ANYTHING: if you cannot read the repository, SAY SO AND STOP

Round 10's first attempt returned findings from a reviewer whose sandbox could not run the
tree — it did not check the diff stat, could not evaluate the four named test defects, and did
not judge the trade. **Partial findings that do not announce themselves as partial cost a full
round**, which is the same failure this project treats as a false green: a result that looks
complete and is not.

So, explicitly: **if `git show`/`git diff` do not work, or `cargo`/`bwrap` are unavailable,
report that as your verdict and stop.** A verdict of "could not read the tree" is worth more than
any number of findings derived without it. If bwrap fails in your sandbox with
`loopback: Failed RTM_NEWADDR: Operation not permitted`, that is **your environment, not this
box** — measured here at `rc=0`, with `apparmor_restrict_unprivileged_userns=1` and no
`/etc/apparmor.d/bwrap`. Do not report it as a finding.

## Target

`git diff 09dadae..4d3815f` — **31 commits, 20 files changed, 2492 insertions(+), 27 deletions(-).**

**The ending SHA is PINNED, not `HEAD` (D0A-R10-02).** The first version said `..HEAD`
with a manifest captured when it was written; by the time it ran, HEAD had moved and the
manifest described a range four commits short — including the fix for the round's own
first finding. A moving endpoint cannot be checked against a fixed manifest, which is the
drift this instruction exists to catch. **If your diff stat disagrees with the line above,
report it as a finding before reviewing anything.**

**Read the tree through the CLI (`git show`, `git diff`), not from a supplied diff.** Verify
library/API claims against Context7 / docs.rs / `--help` rather than memory — several findings
below exist *because* an API behaved differently from how it reads.

---

## Already found and FIXED since this prompt was first written — do not re-report

**D0A-R10-01 (accepted, fixed, and it was correct).** `ancestor_dirs` excluded ancestors lying
inside another bind and the comment claimed that prevented a host write. **It did not.** Filtering
stops *Delphi* emitting `--dir`; bwrap creates that ancestor itself while installing the inner
bind, through the enclosing mount. Measured: `--bind OUTER OUTER --bind SRC OUTER/x/y` leaves
`x/y` **on the host**.

**The substantive result is what actually protects.** The profile emits `source == dest`, so a
destination's ancestors necessarily exist and bwrap creates nothing — measured, host tree
unchanged. Nothing was ever broken. But the protection was **accidental**: undocumented,
unenforced, and credited to the wrong mechanism. A future remapping bind would have removed a
guarantee nobody knew was load-bearing, **and the tests could not have caught it because they
observe args**. `refuse_host_creating_bind` now enforces it at the `run_fd_pinned` choke point —
reject, not filter. Attack that check, not the one already fixed.

## LEAD WITH THIS: shape E is ONE decision, not three fixes

The largest change here is a **single architectural adoption** that a file-by-file read will
present as three unrelated edits. Judge it as one thing:

1. **`sandbox.rs` drops `--unshare-user`** — the profile now names every namespace *except*
   user. The jail loses a user namespace it previously had.
2. **`execute.rs` interposes `delphi-drop`** — a new statically linked binary, passed to bwrap
   **by fd**, which does `setgroups([]) → setresgid → setresuid` and then execs the pinned
   program fd. **The TCB gains a member.**
3. **The helper is opened by PATH** — so it carries the same inode-vs-content gap that
   D0A-R9-02 names for the tool, for itself.

**Why (1) was done, since it looks like a straight weakening and is the thing most worth
attacking:** bwrap's own userns maps `sandbox_uid → parent_uid`. Measured at root, the jail was
`INNER uid=0 / SO_PEERCRED uid=0` — **identity-transparent**. It supplied isolation, never
identity, and an escape landed on **real root**. It also maps exactly *one* uid, so nothing
inside could drop to another (`setresuid` → `EINVAL`, measured). The route was narrowed by
measurement, not preference:

| leg | result |
|---|---|
| B | bwrap's `--uid` is namespace-internal — `INNER 65534` while the listener still read the launcher |
| C | dropping *before* bwrap drops **bwrap**, which then cannot build its own sandbox (`loopback: Failed RTM_NEWADDR`) |
| D | dropping *inside* bwrap's userns is impossible — `setresuid EINVAL`, one uid mapped |
| E1/E2 | no userns: the jail builds, the payload holds a real host uid, and an outside listener reads **997** |
| F | an externally-mapped userns — **abandoned unmeasured** after three harness failures |

**The question for you on this:** is the trade stated correctly? The claim recorded is that E
exchanges *a namespace that supplied isolation but not identity* for *a real identity* — and
that on the escape axis it is **strictly better** (997 rather than 0). If that reasoning is
wrong, everything built on it is.

---

## `docs/DEFECT_CLASSES.md` — the (a)/(b) partition

**(a) Pre-foreclosed — do NOT spend budget re-hunting these:**
Class 1 (`canonical_hash`), 2 (`safe_open`), 3 (`pragma_setup`), 25 (fixture uses the production
constructor — `mark_cloexec_except` is now called by the helper test for exactly this reason),
29a (shared holder-check), 26 (stale observation), 31 (teardown reports its failure).

**(b) Applicable and NOT foreclosed — concentrate here:**

- **Class 40 (new, this round)** — bwrap auto-creates a bind's missing parents as **`0700` owned
  by the sandbox uid**. Now production logic: `ancestor_dirs` emits `--perms 0755 --dir` per
  ancestor. It excludes (i) the bind itself and (ii) any ancestor inside another bind — **but see
  R10-01 above: that second exclusion does NOT prevent the host write it was credited with.**
  What prevents it is `source == dest`, now enforced by `refuse_host_creating_bind`. Attack the
  *enumeration* (traversal, ordering, dedupe) and the *new check*, not the falsified claim.
- **Class 17 (breadth)** — the ancestor emitter, the denylist's spellings, and the helper's
  argument validation are all enumerations. Class 17 scored six-for-six in round 8.
- **Class 14 (all forms)** — `refuse_denied_bind` checks a lexical fold *and* a canonicalized
  form. Is there a third spelling?
- **Class 33 / 38** — a diagnostic naming one side of a comparison; and a sound check whose
  report carries none of what it verified. Both bit this round (below).
- **Class 22 / 37** — remediation is where a class reappears. Several fixes here are fixes *to
  fixes*.

---

## What I already know is wrong or unproven — do not spend the round rediscovering it

Stated so your budget goes to what I have **not** seen:

- **`delphi-drop` is opened by PATH.** Opening once per process shrinks the window to process
  start; it does not close it. Recorded as an obligation on R9-02, which **may not close without
  answering the helper**. The helper is the one component whose substitution grants **uid
  control**.
- **All actions share one uid** (`D0A-R9-12`, open). No isolation between actions.
- **§6's clause is not closed.** R9-01 closes on the **mechanism** (the action runs as
  `delphi-tool`, proven at root). The clause is *cannot reach daemon IPC*, which rests on a
  socket refusal measured against a **probe fixture**, not the real daemon.
- **Two tests are deliberately RED** — `same_inode_overwrite_...` and
  `nested_interpreter_substitution_...`, the reviewer's own R9-02 reproductions, landed before
  any fix design. The suite is *intentionally* 97 passed / 2 failed.

---

## THE QUESTION — sharper than "find defects"

**Three of this round's defects were found by weakening, and two were defects in the TESTS, not
the code. Which of the assertions added here would survive their own weaken?**

Grounded, because each of these actually happened in this diff:

- `an_ancestor_inside_another_bind_is_never_created` **passed against an empty implementation** —
  nothing was emitted, so "does not contain `/opt/vendor`" was vacuously true. It acquired
  discriminating power only once emission existed.
- The drop-helper's first RED was **false**: it failed with `execvp: No such file or directory`,
  which is the signature of a missing loader **and** of a missing fd — it was the second
  (`File::open` sets `O_CLOEXEC`). It would have failed identically with a perfectly static
  helper.
- The `argv0` test's first version was **wrong about the kernel**, not about the code: for a
  shebang script the kernel builds the interpreter's argv from the script path, so `$0` cannot
  observe `--argv0` at all.
- R9-01's root test **proved its property and printed nothing** — a correct pass emitted exactly
  what a vacuous one would.

All three of those, plus R10-01, are now recorded as **class 41 — the assertion at the wrong
ALTITUDE**: it drifts to where observation is *cheap* (a `Vec<String>` of args) rather than where
the property lives (the kernel's exec handling, the filesystem, a process's errno). The
discriminating question is **"does the assertion observe the layer where the property would
actually be violated?"**

So: **assume the tests here are the weakest part of the change**, and say which greens you would
not trust.

**One piece of counter-evidence, offered so the question is fair rather than leading.** The
positive controls are load-bearing, not ceremonial — **twice now one has fired on its own fixture
rather than on the subject**. P's socket leg would have read a traversal failure as the desired
refusal until its control caught it; and the new host-tree test refused to conclude anything when
its jail failed to build, catching a missing loader path in its own setup. A control that only
ever confirms is not doing work; these interrupted two conclusions.

---

## Named attack surfaces, in priority order

1. **The credential drop itself** (`helper/delphi-drop.rs`) — order of `setgroups`/`setresgid`/
   `setresuid`; the post-drop verification; the refusal to drop to 0; argv reconstruction. It is
   a static binary with **no crate dependencies** (bare `rustc`, so not even `libc`) — the four
   entry points are hand-declared `unsafe extern "C"`. Are the signatures right?
2. **`ancestor_dirs`** — traversal, ordering, dedupe, and the inside-a-bind exclusion.
3. **The wiring in `run_fd_pinned`** — the helper fd joins the `keep` list; `--argv0` is emitted
   only on the no-helper path; the script path's argument order becomes
   `PROG argv0 [interp_arg] SCRIPT [rest]`.
4. **`build.rs` compiling a binary with a bare `rustc`** — `-C link-arg=-static` was measured to
   produce a segfaulting false-static, so `crt-static` is load-bearing. The helper is also copied
   out of `OUT_DIR` to the profile dir so `installer/build.sh` can name it.
5. **The installer** — `delphi-drop` staged, fstat-trusted, installed `0755` root-owned.

---

## Verdict

**APPROVE / REVISE / FAIL**; per finding: ID (`D0A-R10-NN`), severity, root cause, impact, fix
sketch.

Two things beyond findings would be worth more than a long list:

1. **Is shape E's trade stated correctly?** It is the load-bearing argument, and if it is wrong
   the rest follows it down.
2. **Which greens here would you not trust?** Given four test defects in one round — two of them
   tests that were wrong rather than code that was wrong — the honest answer may be that the
   verification is the weak half of this change.

**Current state:** `sandbox::` 12 passed; lib+bins **97 passed / 2 failed** (the two intentional R9-02 REDs); clippy
`-p delphi-runtime --all-targets -D warnings` rc=0; `install.sh` and `build.sh` parse; the staged
helper is confirmed `static-pie linked` and runs in a jail binding **nothing**.
