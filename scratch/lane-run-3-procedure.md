# Lane runs 3–4 — procedure (branch `phase-3b/d0-readiness-contract`)

> **RUN 4 is the re-run.** Sections 0–6 below are unchanged and still apply. What run 4 adds
> is §7, which exists because **run 3's fixes are unproven in exactly the way this arc keeps
> getting caught by.**

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

## 3. BUILD the staging tree, then install

**Corrected after run 3, where this step was wrong twice.**

`install.sh` installs whatever is in `installer/staging/` and does not build it. On run 3 the
staging helper was the PRE-ABI binary, unchanged since that morning, while the daemon had been
compiled against the new one — so the install produced a digest mismatch that the run then had
to diagnose. Build first:

```bash
installer/build.sh
sudo installer/install.sh
sha256sum /usr/libexec/delphi-drop
```

**And the digest check named in run 3's procedure does not work.** `DELPHI_DROP_DIGEST` is a
`cargo:rustc-env` emitted by `runtime/build.rs`; it is compiled INTO the daemon and never
appears in build output, so `grep DELPHI_DROP_DIGEST /tmp/build.log` returns nothing — silently,
which is worse than failing. Read it out of the binary instead:

```bash
INSTALLED=$(sha256sum /usr/libexec/delphi-drop | cut -c1-64)
strings "$BIN" | grep -q "$INSTALLED" && echo "BUILT == INSTALLED ($INSTALLED)" \
    || echo "MISMATCH — the run would measure a refusal, not the property"
```

If they disagree, **stop**.

## 4. The run

**RUN EVERY TARGET, NOT ONE.** Run 3 executed a single binary and reported `112 passed / 1
failed / 2 skips` — that is the LIB target alone (113 tests), and the other sixteen targets,
including every `b1_integration` root test, never ran. The procedure said `head -1`. This is
D0A-R14-03's shape — a scope narrower than the claim drawn from it — reintroduced by me in the
document written to avoid it, one increment after fixing it in the gate.

```bash
mapfile -t BINS < <(cargo test -p delphi-runtime --tests --no-run --message-format=json 2>/dev/null \
    | python3 -c 'import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except ValueError: continue
    if m.get("profile",{}).get("test") and m.get("executable"): print(m["executable"])')
printf '%s targets to run:\n' "${#BINS[@]}"; printf '  %s\n' "${BINS[@]}"
for b in "${BINS[@]}"; do
    echo "=== $b ==="
    sudo "$b" --test-threads=1 --nocapture
done 2>&1 | tee /tmp/lane3.log
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

### The rustc-under-sudo skip is closed by mechanism, not by a PATH reminder

Run 3 skipped `the_approved_env_never_reaches_bwrap_itself_via_ld_preload` — R15-01's own RED
leg, in the run that existed to prove R15-01 — because it compiles its `LD_PRELOAD` fixture with
`rustc`, and `sudo` does not carry rustup's `PATH`. `runtime/build.rs` now bakes cargo's own
absolute rustc into `DELPHI_RUSTC`, and a test asserts it is absolute, so the leg no longer
depends on the invoking environment. **`sudo env "PATH=$PATH"` would also have worked and is
the wrong fix** — it is a rule the operator must remember, on a run whose failure mode is a
silent skip inside a green summary.

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
arc keeps paying for. Run 3's `112 / 1 / 2` is **not** that number: it is the lib target alone. The whole-suite root
pair is still unmeasured. Run it across every target, quote it, and put it in a separate root
baseline file rather than overwriting the unprivileged pair:

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

---

## 7. RUN 4 — what it must settle, and what it must NOT be allowed to conclude

### 7.1 The guard proves they PLAN, not that they PASS

`every_fixture_that_executes_an_action_plans_its_credentials` asserts that seven fixtures now
call the credential API. **It cannot assert that the actions then execute.** Planning was the
necessary condition for the eight root failures; it is not obviously the sufficient one, and
treating "the guard is green" as "the failures are fixed" would be the same substitution —
evidence about a mechanism standing in for evidence about the property — that this run exists
to correct.

So the eight are OPEN until this run closes them by name:

```bash
grep -E 'test result:|^test .+ \.\.\. (FAILED|SKIP|DEFER)' /tmp/lane4.log
```

Each of the eight must appear as `ok`, or as a SKIP whose **measured blocker names something
other than credentials**. A SKIP is not a pass, and `r4_03_daemon_real_gate` will legitimately
skip without `--features insecure-test-seams` — which is a different statement from the
`NotFound` crash it produced before, and must be read as such.

### 7.2 The leaks were never leaks — confirm the warning is gone

The errno was `ENOENT`: both directories were already removed, and the guard reported its own
success path as a failure. `leak_report` now returns `None` for `NotFound`. **Confirm no
warning fires**, and that the mechanism has not been disabled wholesale:

```bash
grep -c 'has LEAKED' /tmp/lane4.log      # expect 0
ls -d /run/delphi-* 2>/dev/null || echo "no /run/delphi-* remains"
```

Both lines are needed. `0` warnings with directories still present would mean the fix silenced
a real leak rather than a false one — the failure mode of every "make the warning go away"
change, and the reason the fix was made in `leak_report` with both directions asserted rather
than by dropping the report.

### 7.3 Two numbers to record, neither to predict

- **the whole-suite root pair.** Run 3's first measurement was `159 passed / 8 failed` across
  17 targets. Run 4's is the one that says whether the eight closed.
- **the skip set at root.** Not the count — the NAMES. A test that stops failing by starting
  to skip has not been fixed, and a bare count cannot tell those apart (`DEFECT_CLASSES` 10).

```bash
grep -oE '^test [a-z_0-9:]+ \.\.\. SKIP' /tmp/lane4.log | sort
```

### 7.4 Unchanged from run 3, and still the point

Build every target (§4), `installer/build.sh` before `install.sh` (§3), PAM checksum both
sides (§1, §6). Run 3 found three procedure defects and one of them — running one target of
seventeen — hid sixteen targets' worth of failures behind a green summary.
