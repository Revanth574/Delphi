# Codex adversarial review — B2a lane-dependent BUILD (runtime fork/PAM/exec + C2 install)

You are a COLD adversarial reviewer. Attack this code; do not certify it. When something
looks correct, your job is to find the input, ordering, or concurrency under which it is not.

## Target (exact — flag any scope drift)

- **Commit range:** `d57442e..HEAD` on branch `runtime/increment-b2a-lane` (HEAD = `d493b9b`).
- **Expected diff stat:** 32 commits, 24 files, **2813 insertions / 52 deletions**. If your
  checkout shows materially different, STOP and report scope drift before reviewing.
- Inspect the LIVE code via the Codex CLI (read the files), not from memory. Verify every
  library/API claim (`pam-client2` 0.5.5, `nix` 0.30 `close_range`/`fork`/`waitpid`, sd-login
  `sd_pid_get_session`/`sd_session_*`, systemd unit `Environment=`/`RuntimeDirectory=`
  semantics) against docs.rs / Context7 / the man pages — do NOT reason from memory.

## Review boundary — where to spend adversarial attention

**IN SCOPE (the attack target — 944 of the 2813 insertions):**
- `runtime/src/launcher.rs` — the fork / PAM / exec path (`fork_shell`, `shell_child_become`,
  `open_own_session`, the FD-01 sweep, the priv-drop, the R3-01c seam).
- `runtime/src/logind.rs` — `session_id_for_pid` / the active-local-seated gate.
- `runtime/build.rs` — the `libsystemd` link line.
- `runtime/systemd/delphi-runtimed@.service` + `installer/` (`build.sh`, `install.sh`,
  `pam/delphi-runtime`) — the C2 install surface.

**CONTEXT, NOT THE TARGET (do not spend rounds auditing these as product):**
- `runtime/tests/**`, `scratch/**` — the test harness and iteration tooling. These are
  reviewed only insofar as a test's CLAIM is wrong (see "the three tests" below). Their
  internal engineering (Defect Classes 15/16/17, `reap_children`, the flakiness scripts) is
  context that explains how the product claims were established — not surface to attack.
- `docs/**`, `CLAUDE.md`, `PROGRESS.md` — record.

## Named areas (attack these specifically)

1. **`open_own_session` raw-pointer lifecycle — the ONE unsafe surface, in a forked child on
   the security path.** `Context` is `Box::into_raw`'d and hand-freed. Verify: is it freed
   exactly once on every path (the `child_fail` unwind vs the `leak()` success path)? Is there
   a double-free with `pam_end` (the crate's `Context::Drop` calls `pam_end` + frees its conv
   box)? On the PAM-02 pre-`execve` failure paths, is `pam_close_session` + `pam_end` run while
   the handle is live? Is the "abandon on success (execve replaces the address space)" reasoning
   actually sound, or does it leak something that outlives the call? Attack the ordering of
   the FD-01 sweep vs the fds `open_own_session` opens (PAM D-Bus + `sd_pid_get_session`) — the
   sweep MUST run after them; a reorder is documented as compiling and passing unit tests.

2. **The fork+PAM and concurrent-PAM-on-shared-VT SERIAL-ONLY constraint.** The whole
   shell-child correctness rests on the daemon being SINGLE-THREADED at `fork` (PAM is not
   async-signal-safe; forking it from a multithreaded parent can deadlock on an inherited
   allocator lock — documented in `launcher.rs`'s standing constraint). This session produced
   LIVE EVIDENCE it is real, not theoretical: the parallel stability runs failed ~20/30 with
   every failure a pre-`execve` child death, 0/30 serial. Attack: is `delphi-runtimed`'s `main`
   actually single-threaded on the `fork` path (no tokio, no `thread::spawn`, no library that
   spawns a thread before the fork)? If any dependency starts a background thread before
   `launch()`, the constraint is violated in production, not just the test harness. Verify.

3. **The C2 install surface.**
   - `delphi-runtimed@.service`: `Environment=DELPHI_SHELL_VT=tty3` (deployment-config, labelled
     not-VT-policy), `Environment=DELPHI_AI_BIN=/usr/libexec/delphi-minimal-ai` (scaffold under
     its own name), `SyslogIdentifier`. Attack: does the unit run the daemon as root with the
     right `RuntimeDirectory` ownership? Any way the `Environment=` values are attacker-
     influenced? Is `tty3` hard-coding a security-relevant default that should fail-closed
     elsewhere?
   - The **empty-Brain-address discipline**: `/usr/libexec/delphi-ai` is left EMPTY on purpose
     so a missing `DELPHI_AI_BIN` override fails LOUD at ENOENT. `install.sh` REFUSES if a
     binary exists there. Attack: is the refusal correct? Can the scaffold end up at the real
     address anyway (a copy, a symlink, a prior install)?
   - `install.sh` / `build.sh` **root/unprivileged split**: build runs as the developer,
     install as root. Attack: does `install.sh` trust anything writable by non-root (the
     `installer/staging/` artifacts it copies as root)? A non-root-writable staging dir copied
     to `/usr/libexec` as root is a privilege-escalation path — check ownership assumptions.

4. **§4's partial discharge (do NOT let it read as closed).** The PAM session-only deviation
   (no `pam_setcred`; `pam_close_session` omitted on the success path, sound only post-`execve`)
   is validated against the real `/etc/pam.d/delphi-runtime` on the SUCCESS path only (B-1/B-3/
   FD-01 pass). The **PAM-02 pre-`execve` unwind paths are exercised by NO test** against the
   real stack. Attack those unwind paths by reading (a pre-`execve` failure after
   `open_session`: is the session actually closed and the handle ended before `_exit`?).

## The three regression tests — CLAIMS TO ATTACK, not evidence to trust

`runtime/tests/leader_is_shell.rs` carries three security regression tests, each with a
weaken/restore proof. **Do NOT accept them as settled.** Two of the three PASSED under their
FIRST weaken and had to be re-aimed — B-1's first draft asserted a two-legged property true
under both topologies (wrong pid); FD-01's first draft's weaken (move the sweep) could not bite
because libsystemd self-CLOEXECs its fds. **The third mistake is the one nobody has caught yet.**
For each, verify the discrimination is REAL — that the assertion fails for the reason it names
and could not pass under the weakened product:

- **B-1 `session_leader_is_the_shell_itself_r3_01c`** — weaken (seam →
  `fork_grandchild_then_exec`) FAILED: `pinned_pid=8678 leader=8678 executing_shell=[8707]`
  (the discriminator is leg 3, the pid actually running the shell binary). Restore PASSED:
  `pinned_pid=leader=executing_shell=17287` (and again 20498). Attack: is leg 3 (`/proc/exe`)
  truly independent of legs 1/2? Could a different topology pass it?
- **FD-01 `shell_inherits_only_the_allowlisted_fds_fd_01`** — weaken (sweep no-op'd) FAILED:
  injected non-CLOEXEC socket `fd 4` survived → child fds `[0,1,2,3,4]` vs allowlist `[0,1,2,3]`.
  Restore PASSED: `injected_in_child=false`, fds `[0,1,2,3]`. Attack: is the injection provably
  inherited (the parent-side non-CLOEXEC assertion), and is "absent under weaken" correctly
  treated as VOID not pass?
- **B-3 `shell_child_drops_to_the_session_user_b3`** — weaken (`drop_privileges` no-op'd)
  FAILED: `Uid [0,0,0,0] Gid [0,0,0,0] Groups [0]` (shell exec'd as root). Restore PASSED:
  `Uid/Gid [1171,1171,1171,1171] Groups []`. Attack: does the assertion require ALL FOUR uid
  fields (real/eff/saved/fs), and does it catch a partial drop?

## `docs/DEFECT_CLASSES.md` partition (do not re-hunt the foreclosed)

- **Pre-foreclosed / idiom (do not spend budget re-deriving):** Class 5 capability-type —
  `VtName` (sole constructor validates; `compile_fail` + scoped source audit prove it
  unforgeable). Class 12 reject-the-invalid-class — `VtName` rejects the pty/tty0 class.
- **Applicable, give explicit coverage:** Class 2 path-safety/TOCTOU — the installer's writes
  to `/usr/libexec` and `/etc/pam.d`, and the `access(F_OK)` PAM-03 guard (documented TOCTOU-
  racy — verify the argument that root-owned dir makes it acceptable). Class 11 error-message
  oracles — the PAM/gate failure messages (`child_bail` diagnostics via `write(2)`): do any
  leak a secret or an exploitable distinction? Class 16 — the installer writes system state by
  design; verify idempotence + that it cannot be tricked into deleting/overwriting unowned
  files.

## Apply Class 17 to your OWN findings (mandatory)

`docs/DEFECT_CLASSES.md` Class 17: *a defect propagated by copy is not fixed by patching the
instance you found — the copies you did not open still carry the shape.* This binds YOU as the
reviewer: **for every defect you find on the security surface, GREP the shape across the whole
in-scope range and report ALL instances, not the one you first saw.** A finding that names a
single instance of a copied defect reproduces exactly the failure the class describes. Concrete
risk areas where a shape repeats in this increment: the **weaken-banner / seam pattern** (three
tests), the **`child_bail` / `child_fail` diverging-exit** discipline (multiple call sites), the
**`install -o root -g root`** copies (three binaries), the **`Environment=`** lines (three). If
you flag one, state whether the sibling instances share or escape the defect.

## Required verdict

Structured: **APPROVE / REVISE / FAIL**. Every finding carries: an ID; a severity (P1-high →
P2-medium → P2-low → P3-informational); a one-line root-cause; an impact statement; a fix
sketch; AND (per the Class-17 directive above) the result of grepping its shape across scope.
Ground each finding in a file:line you inspected. If you cannot find a real defect on a named
surface, say so explicitly for that surface rather than inventing one.
