# Codex adversarial review — B2a round 2 (the round-1 fixes)

You are a COLD adversarial reviewer. Round 1 (REVISE, 4 findings) is fixed in ONE commit.
Attack the FIXES: verify each closes its finding at root, and — more important — find any NEW
defect the fixes introduced. A fix that trades one bug for another is not an APPROVE.

## Target

- **Fix commit:** `c42caaf` (the only commit since your round-1 review of `d57442e..HEAD`).
- **Expected diff stat:** 6 files, **311 insertions / 16 deletions**. Flag scope drift if different.
- Inspect the LIVE code via the Codex CLI. Verify API claims against docs/source — in
  particular `nix` 0.30 `pipe2`/`fork`/`waitpid`, `libc::read`/`write`/`_exit`, and
  `close_range` CLOEXEC semantics — do NOT reason from memory.

## The fixes to attack

### B2A-C-R1-01 [was P1] — the setup-sync pipe (`runtime/src/launcher.rs`)
The manual fork now creates `pipe2(O_CLOEXEC)`; the child publishes the write end in a
`static AtomicI32 CHILD_SYNC_FD`; `child_diag` writes one byte on failure; the parent
`wait_for_child_setup` reads EOF (success) vs byte (failure). Attack SPECIFICALLY:
- **Does the write end reliably close on a SUCCESSFUL execve?** It relies on CLOEXEC. The
  FD-01 sweep runs before execve and marks fds ≥3 CLOEXEC — confirm the sync fd is not in the
  allowlist (so it stays CLOEXEC) and is never accidentally cleared. If it stayed open, the
  parent would BLOCK FOREVER on a healthy launch.
- **The `static` + `std::mem::forget(sync_w)`**: is the raw fd sound across the fork? Any
  double-close (the OwnedFd is forgotten in the child — is it also dropped in the parent
  correctly)? Any path where `CHILD_SYNC_FD` is read as a stale/wrong fd and `write`s to an
  unrelated descriptor (e.g. if `sync_w` collided with `SHELL_CHANNEL_FD`)?
- **The weaken twin** `fork_grandchild_then_exec` now closes the holder's sync fd. Is that
  the ONLY change needed to keep the B-1 weaken from hanging? Could the holder's close race
  the grandchild's execve such that the parent misreads success vs failure?
- **Zombie/leak**: the failure path reaps the child; the success path does NOT (production
  pins by pidfd). Is there any launch failure mode that now leaks a child or an fd?
- **Behavioural change**: `launch()` now BLOCKS until the child execve's. Any deadlock risk
  (e.g. the child blocks before execve waiting on something the parent must do first)?

### B2A-C-R1-02 [was P2] — the VT existence check (`delphi-runtimed.rs`)
`anyhow::ensure!(tty.exists_on_system())`. The author has RECORDED that on a full-devtmpfs
host all `/dev/tty1..63` exist, so this is inert here and load-bearing only on minimal deploys.
Attack: is `exists_on_system` (a `metadata`/`is_char_device` check) even the right predicate —
could a VT node exist but not be usable for a seated session, so the check gives false
confidence? Is TOCTOU relevant (the node is checked, then PAM uses it later)?

### B2A-C-R1-03 [was P2] — install.sh staging trust (`installer/`)
`install.sh` now runs `trust_source` (refuse owner ∉ {root, SUDO_UID}, or group/other-write)
on the staging dir + every staged file, BEFORE any copy; `build.sh` stages the unit + PAM into
the tight staging dir too. Attack: is the `stat`-based check bypassable — symlinks in staging
(the check `stat`s the target, then `install` copies… which)? A TOCTOU between `trust_source`
and `install`? Does `$(( 0$mode & 022 ))` mis-handle any mode string (e.g. setuid bits making
`stat -c %a` return 4 digits)? Is `SUDO_UID` trustworthy (could an attacker set it)?

### B2A-C-R1-04 [was P3] — fail-closed install ordering (`install.sh`)
All pre-flight checks now precede any mutation. Attack: is there STILL any `install`/`systemctl`
that can leave a partial system if it fails midway (e.g. the 3rd binary copy fails after the
first two)? Is `daemon-reload` failure handled?

## Apply Class 17 to your own findings (mandatory)
For any defect you find, GREP the shape across the fix commit and report ALL instances — e.g.
the three `unsafe { nix::libc::write/close }` raw-fd sites, the `install -o root` copies, the
`trust_source` call sites. A finding that names one instance of a repeated shape reproduces the
class it describes.

## Required verdict
APPROVE / REVISE / FAIL. Each finding: ID, severity (P1→P3), one-line root cause, impact, fix
sketch, and its cross-scope grep result. If a named surface is clean, say so explicitly.
