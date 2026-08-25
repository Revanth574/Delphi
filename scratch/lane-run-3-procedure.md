# Lane run 3 — procedure (branch `phase-3b/d0-readiness-contract`)

**Why this run exists.** Round 15 changed the execute path's environment transport at the
privilege boundary, and **the branch it changed has never executed.** Unprivileged there is no
gradient, so the delta goes through bwrap's `--setenv`; the branch this arc actually built —
a sealed memfd the helper reads and applies with `execve` **after `setresuid`** — is reachable
only at euid 0. It is unit-proven and nothing more.

Secondary: the helper's ABI changed, so `DELPHI_DROP_DIGEST` moved and **the installed helper
is now refused**. That refusal is R9-02 working, and this run is the first time the digest
binding has had a consequence on a legitimate change rather than an attack — which is the case
that shows whether the control is livable.

| | What the run settles | Why it needs the lane |
|---|---|---|
| **A** | `the_approved_env_reaches_the_tool_through_the_helper_after_the_drop` | the gradient branch; skips everywhere else |
| **B** | the reinstall closes the digest refusal | built-vs-installed can only disagree on an installed box |
| **C** | R9-01 / R9-02's root proofs still hold after the ABI change | the helper they exercise was rebuilt |
| **D** | the **actual** root `EXECUTED / SKIPPED` pair | see §5 — the recorded one is unverified |

---

## 0. Preconditions — cheap, run first

```bash
scripts/check-free-space.sh || exit 1
git -C . status --porcelain            # MUST be empty
git -C . log --oneline -1
```

## 1. PAM baseline BEFORE — not optional

Fixtures have deleted the operator's installed `/etc/pam.d/delphi-runtime` mid-run before, and
the symptom surfaced far away as unrelated tests reporting "not installed"
(`docs/DEFECT_CLASSES.md` class 16). The checksum is the external check; care is not.

```bash
md5sum /etc/pam.d/delphi-runtime | tee /tmp/pam-before.md5
```

If the file is absent, record that — "absent before" and "absent after" are a valid pair;
"present before, absent after" is a fixture defect and stops the run.

## 2. Build unprivileged

`sudo -E cargo` does not work on this box — sudoers strips `-E` and root has no rustup
toolchain. Build as yourself, run the binary under sudo.

```bash
export CARGO_TARGET_DIR=$PWD/target
cargo test -p delphi-runtime --tests --no-run 2>&1 | tee /tmp/build.log
```

**Freshness is checked by rebuild, never by mtime.** The pre-commit hook builds before the
commit object exists, so an mtime-vs-HEAD comparison is wrong by construction:

```bash
BIN=$(grep -oE 'target/debug/deps/delphi_runtime-[a-f0-9]+' /tmp/build.log | head -1)
sha256sum "$BIN" | tee /tmp/bin-before.sha
touch runtime/src/execute.rs && cargo test -p delphi-runtime --tests --no-run >/dev/null 2>&1
sha256sum "$BIN"          # MUST equal /tmp/bin-before.sha — a forced rebuild changed nothing
```

## 3. Install — before the run, not after

The helper's argv gained the env fd, so the compiled-in digest no longer matches whatever is
at `/usr/libexec/delphi-drop`.

```bash
sudo installer/install.sh
sha256sum /usr/libexec/delphi-drop
```

Then confirm built and installed agree — this is item **B**, and it is a one-line check
because the daemon does it by construction:

```bash
grep -oE 'DELPHI_DROP_DIGEST=[a-f0-9]+' /tmp/build.log | tail -1
```

If they disagree, **stop**: the run would measure a refusal, not the property.

## 4. The run

```bash
sudo "$BIN" --test-threads=1 --nocapture 2>&1 | tee /tmp/lane3.log
```

`--test-threads=1` is required, not a preference: every `fork`+PAM test on this branch is
serial-only (CLAUDE.md §6 carve-out — forking PAM from the multithreaded test runner is a
harness hazard production never has, since `delphi-runtimed` is single-threaded).

**What must appear** — quote these lines, do not summarise them:

```bash
grep -E '^\[R15-01\]|^\[R9-01\]' /tmp/lane3.log     # the two artifacts
grep -E 'test result:' /tmp/lane3.log
```

Item **A** passes only if the single artifact carries **both** facts: `Uid:` four fields all
`997`, **and** `DELPHI_SECRET=s3cret-value`. Either alone is satisfiable with the defect
present — the pre-fix code also delivered the value, just to root first.

## 5. Record the pair — do not predict it

The unprivileged pair is measured: **`EXECUTED 142 / SKIPPED 24 / reported 166`**, of which 20
skips say *requires root*, 2 need PAM auth, 1 needs `--features`, and 1 is a DEFER
(`live_logind_query_path_works_or_documents_deferral`).

**The root pair recorded in `.githooks/runtime-test-count-baseline` is UNVERIFIED and cannot
be right.** It claims `EXECUTED=141 SKIPPED=0`, but the PAM, features and DEFER skips do not
depend on euid, so `SKIPPED=0` is unreachable. It was written as an expectation and never
measured.

I am deliberately not replacing it with another prediction. Some of the 20 root-gated tests
carry *further* gates — a real seat, systemd, a same-uid sibling — that this box may not
satisfy, so the arithmetic `142 + 20` is exactly the one-step-past-what-was-measured move this
arc keeps paying for. **Run it, quote it, and the number goes in a separate root baseline
file** rather than overwriting the unprivileged pair:

```bash
DELPHI_TEST_COUNT_BASELINE=.githooks/runtime-test-count-baseline.root
```

## 6. PAM baseline AFTER

```bash
md5sum /etc/pam.d/delphi-runtime | tee /tmp/pam-after.md5
diff /tmp/pam-before.md5 /tmp/pam-after.md5 && echo "PAM STACK INTACT" || echo "FIXTURE DAMAGED THE INSTALLED STACK — this is the finding, not the tests"
```

## 7. What a failure means here

Two failure shapes, and they are not the same:

- **A test asserting a property fails** → the product is wrong until shown otherwise
  (Iron Law #15). Report the assertion text.
- **A test dies before its measurement** — `execvp: No such file or directory`, a child dying
  pre-`execve` — → suspect the harness, but only as far as the evidence goes. That error means
  a missing fd **or** a missing loader (class 43), and it was misdiagnosed twice by assuming
  the first. Print the subprocess's stderr before concluding anything.
