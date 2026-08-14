// SPDX-License-Identifier: MIT

//! Execute the approved action in the sandbox — the gate + the swap-proof fd-exec
//! (Increment 1d, R3-04 + `docs/TRUST_MODEL.md` §4 step 5).
//!
//! Four bindings make "execute = approval" hold:
//!
//! 1. **The gate.** [`execute_approved`] verifies the 1c capability token against
//!    `canonical_action_digest(action)` **before any exec path**. The digest covers
//!    `executable_digest` (the hashed executable content, piece 1), so a token that
//!    verifies means the human approved *this exact action including this exact
//!    executable* — unapproved or substituted actions never reach the exec.
//! 2. **One-shot (§4).** The approval is **consumed** via the [`ConsumptionLedger`]
//!    on first use; a second execution of the same action is denied
//!    ([`RuntimeError::AlreadyConsumed`]). One human approval authorizes one
//!    execution — the digest-binding closes approve-A/execute-B; the ledger closes
//!    approve-once/execute-many.
//! 3. **The fd-pin (anti-TOCTOU).** The program is exec'd as `/proc/self/fd/N`
//!    **inside the bwrap jail** — `execve` resolves the magic symlink to the
//!    **pinned inode** (the one whose bytes were hashed), not a re-resolvable path
//!    (verified: binding the path re-resolves and is NOT swap-proof; exec'ing the fd
//!    is). For a **script** (R4-02) the **pinned interpreter** fd is exec'd with the
//!    script memfd as its argument — never the script fd, whose shebang would
//!    re-resolve the interpreter by PATH. The script memfd's **full immutability
//!    seal set is verified** (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW |
//!    F_SEAL_SEAL` via `F_GET_SEALS`) before any exec path, so neither its content
//!    (write) nor its length (`ftruncate` shrink/grow) can mutate between the digest
//!    and the exec — interpreter-pinning defeats interpreter-PATH-swap, full sealing
//!    defeats script-CONTENT/LENGTH-mutation, and the two together are the full R4-02
//!    mechanism. `--proc /proc` in the [`SandboxProfile`] makes `/proc/self/fd/N`
//!    resolve.
//! 4. **fd-discipline (§6).** The 1b `fdsec` close-range runs in the child before
//!    bwrap's exec, so no daemon fd (the approval channel, the anchor socket) leaks
//!    into bwrap or the jailed tool; only the pinned program fd(s) survive.

use std::collections::HashSet;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

use nix::errno::Errno;

use crate::action::{canonical_action_digest, PendingAction, ScriptPin};
use crate::sandbox::SandboxProfile;
use crate::token::{self, ApprovalToken, MintingKey};
use crate::RuntimeError;

/// The daemon's one-shot consumption ledger (`docs/TRUST_MODEL.md` §4 — "the
/// arbiter consumes it one-shot").
///
/// Each approved action (keyed by its single-use `pending_id`) executes **at most
/// once**: one human approval authorizes one execution, not repeated execution of
/// the same destructive action within the token TTL. The digest-binding closes
/// approve-A/execute-B; this ledger closes approve-once/execute-many.
#[derive(Debug, Default)]
pub struct ConsumptionLedger {
    consumed: HashSet<String>,
}

impl ConsumptionLedger {
    /// A fresh, empty ledger (the daemon holds one in memory).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume `pending_id`. Returns `true` if newly consumed, `false` if it was
    /// already consumed (a replay).
    fn consume(&mut self, pending_id: &str) -> bool {
        self.consumed.insert(pending_id.to_string())
    }
}

/// Execute `action` in its derived sandbox **iff** `token` verifies against the
/// action's canonical digest at `now` AND the action has not already been consumed.
///
/// # Errors
///
/// [`RuntimeError::Unapproved`] if the token does not verify (the gate);
/// [`RuntimeError::AlreadyConsumed`] if this action was already executed (one-shot);
/// [`RuntimeError::Filesystem`] if the bwrap spawn fails.
pub fn execute_approved(
    action: &PendingAction,
    token: &ApprovalToken,
    key: &MintingKey,
    now: u64,
    ledger: &mut ConsumptionLedger,
) -> Result<Output, RuntimeError> {
    // THE GATE — before any exec path.
    let digest = canonical_action_digest(action);
    if !token::verify(key, token, &digest, now) {
        return Err(RuntimeError::Unapproved);
    }
    // ONE-SHOT (§4) — consume the approval; a second execution is denied.
    if !ledger.consume(&action.pending_id) {
        return Err(RuntimeError::AlreadyConsumed);
    }
    run_fd_pinned(action)
}

/// R4-02: a pinned script's content fd MUST carry the FULL immutability seal set
/// ([`ScriptPin::FULL_SEALS`] — `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW |
/// F_SEAL_SEAL`) so neither its content (write) nor its length (`ftruncate`
/// shrink/grow) can mutate between the digest and the exec. A write-seal ALONE is
/// insufficient: it does not stop shrink/grow. Refuse a script memfd missing any of
/// the four seals.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if `F_GET_SEALS` fails; [`RuntimeError::UnsealedScript`]
/// if the memfd lacks any required seal.
fn require_fully_sealed(script_fd: RawFd) -> Result<(), RuntimeError> {
    // SAFETY: F_GET_SEALS reads the memfd's seal bitmask; it touches no caller memory
    // and returns the seals (>= 0) or -1 with errno set.
    let seals = unsafe { nix::libc::fcntl(script_fd, nix::libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(RuntimeError::Syscall { op: "fcntl F_GET_SEALS", source: Errno::last() });
    }
    if seals & ScriptPin::FULL_SEALS != ScriptPin::FULL_SEALS {
        return Err(RuntimeError::UnsealedScript);
    }
    Ok(())
}

/// Build the bwrap invocation and execute the **fd-pinned** program inside it
/// (`/proc/self/fd/N` — the swap-proof inode).
///
/// * **Binary** (`script: None`): exec `/proc/self/fd/<executable_fd>`.
/// * **Script** (`script: Some`, R4-02): exec the **pinned interpreter** fd with
///   the **sealed script memfd** as its argument — never the script fd, whose
///   shebang would re-resolve the interpreter by PATH.
fn run_fd_pinned(action: &PendingAction) -> Result<Output, RuntimeError> {
    // R4-02 (the OTHER half of script-pinning): a pinned script's content memfd must
    // be FULLY sealed, so neither its bytes nor its length can change after the digest
    // was taken. Interpreter-pinning alone defeats interpreter-PATH-swap; the full
    // seal set defeats script-CONTENT/LENGTH-mutation. Refuse before any exec path.
    if let Some(sp) = &action.script {
        require_fully_sealed(sp.script_memfd.as_raw_fd())?;
    }
    // Which fd(s) the jailed tool must keep (the rest are closed before its exec).
    let (program_fd, script_arg_fd, keep): (RawFd, Option<RawFd>, Vec<RawFd>) =
        match &action.script {
            Some(sp) => {
                let interp = sp.interpreter_fd.as_raw_fd();
                let script = sp.script_memfd.as_raw_fd();
                (interp, Some(script), vec![interp, script])
            }
            None => {
                let exe = action.executable_fd.as_raw_fd();
                (exe, None, vec![exe])
            }
        };

    let mut args = SandboxProfile::derive(action).args().to_vec();
    if let Some(argv0) = action.argv.first() {
        args.push("--argv0".to_string());
        args.push(argv0.clone());
    }
    args.push("--".to_string());
    args.push(format!("/proc/self/fd/{program_fd}"));
    if let Some(script) = script_arg_fd {
        // The shebang's optional interpreter arg (e.g. `-I`), passed BEFORE the
        // script exactly as the kernel would — it is part of what executes, bound by
        // the digest + previewed, so execute == approved (B1-02).
        if let Some(arg) = action.script.as_ref().and_then(|sp| sp.interpreter_arg.as_deref()) {
            args.push(arg.to_string());
        }
        // The sealed script, passed to the pinned interpreter (not exec'd directly).
        args.push(format!("/proc/self/fd/{script}"));
    }
    for arg in action.argv.iter().skip(1) {
        args.push(arg.clone());
    }

    let mut cmd = Command::new("bwrap");
    cmd.args(&args);
    // 1D-03 / §6: extend the 1b fd-discipline to execute. In the child, before
    // bwrap's exec, mark every inherited fd >= 3 close-on-exec and un-mark only the
    // program fd(s). No daemon fd (the approval channel, the anchor socket, ...)
    // leaks into bwrap or the jailed tool; only the pinned program survives so
    // `/proc/self/fd/N` resolves.
    // SAFETY: pre_exec runs in the forked child between fork and execve, so it must
    // be async-signal-safe and MUST NOT allocate (a malloc could deadlock on the
    // allocator lock if a non-surviving thread held it). `mark_cloexec_except_raw`
    // performs only `close_range`/`fcntl` + an errno read (no allocation), and
    // `io::Error::from_raw_os_error` wraps the errno integer inline — never
    // `io::Error::other`, which would `Box` (allocate).
    unsafe {
        cmd.pre_exec(move || {
            crate::fdsec::mark_cloexec_except_raw(&keep)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        });
    }
    cmd.output().map_err(|source| RuntimeError::Filesystem {
        op: "spawn bwrap",
        path: std::path::PathBuf::from("bwrap"),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use sha2::{Digest, Sha256};

    use crate::action::{BindMode, NetPolicy, RequiredTier};
    use crate::token::mint;

    const KEY: [u8; 32] = [1u8; 32];
    const NOW: u64 = 1_000;

    fn bwrap_available() -> bool {
        Command::new("bwrap")
            .args([
                "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64",
                "/lib64", "--unshare-all", "--die-with-parent", "--", "/usr/bin/true",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    /// Write a `#!/bin/sh` script that echoes `marker` to `out`; return its bytes.
    fn write_script(path: &Path, marker: &str, out: &Path) -> Vec<u8> {
        let content = format!("#!/bin/sh\necho {marker} > {}\n", out.display());
        fs::write(path, &content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        content.into_bytes()
    }

    /// Rewrite `path`'s CONTENT in place — **same inode, no rename**. `fs::write`
    /// opens the existing file `O_TRUNC`, so an fd already open on it observes the
    /// new bytes. Returns (inode before, inode after) so a caller can PROVE the pin
    /// was intact and simply did not apply (D0A-R9-02).
    fn overwrite_in_place(path: &Path, marker: &str, out: &Path) -> (u64, u64) {
        use std::os::unix::fs::MetadataExt;
        let before = fs::metadata(path).unwrap().ino();
        let content = format!("#!/bin/sh\necho {marker} > {}\n", out.display());
        fs::write(path, &content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        (before, fs::metadata(path).unwrap().ino())
    }

    /// A script whose shebang names `interp` — the interpreter the KERNEL resolves
    /// by path *after* the fd-pin has already fixed this file's inode.
    fn write_script_with_interp(path: &Path, interp: &Path) -> Vec<u8> {
        let content = format!("#!{}\n", interp.display());
        fs::write(path, &content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        content.into_bytes()
    }

    /// Replace the script at `path` with a NEW inode (rename-over), so a fd opened
    /// on the old inode keeps the original content — the swap the fd-pin must defeat.
    fn swap_script(path: &Path, marker: &str, out: &Path) {
        let tmp = path.with_extension("swap");
        write_script(&tmp, marker, out);
        fs::rename(&tmp, path).unwrap();
    }

    fn build_action(exe: &Path, exe_bytes: &[u8], out_dir: &Path) -> PendingAction {
        PendingAction {
            pending_id: "act-exec".into(),
            preview_version: 1,
            executable_fd: fs::File::open(exe).unwrap().into(),
            executable_digest: sha256(exe_bytes),
            argv: vec!["tool".into()],
            cwd: PathBuf::from("/"),
            env_delta: vec![],
            fs_binds: vec![
                (PathBuf::from("/usr"), BindMode::ReadOnly),
                (PathBuf::from("/bin"), BindMode::ReadOnly),
                (PathBuf::from("/lib"), BindMode::ReadOnly),
                (PathBuf::from("/lib64"), BindMode::ReadOnly),
                (out_dir.to_path_buf(), BindMode::ReadWrite),
            ],
            net_policy: NetPolicy::None,
            timeout: Duration::from_secs(30),
            required_tier: RequiredTier::Biometric,
            script: None,
        }
    }

    /// The RED exec variant: bind the executable PATH and exec it (re-resolvable),
    /// instead of the pinned fd.
    fn execute_via_path(action: &PendingAction, exe_path: &Path) -> Output {
        let mut args = SandboxProfile::derive(action).args().to_vec();
        args.push("--ro-bind".into());
        args.push(exe_path.display().to_string());
        args.push("/exe".into());
        args.push("--".into());
        args.push("/exe".into());
        Command::new("bwrap").args(&args).output().unwrap()
    }

    struct Env {
        dir: PathBuf,
        exe: PathBuf,
        out_dir: PathBuf,
        result: PathBuf,
    }
    impl Env {
        fn new(tag: &str) -> Self {
            let dir = PathBuf::from(format!("/tmp/delphi-exec-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let out_dir = dir.join("out");
            fs::create_dir_all(&out_dir).unwrap();
            Self { exe: dir.join("tool.sh"), result: out_dir.join("result"), out_dir, dir }
        }
    }
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// CORRECT: the fd-pinned, gated exec runs the digest-bound (pinned) inode — a
    /// path swap after approval does not take effect.
    #[test]
    fn fd_pinned_gated_exec_runs_the_approved_content() {
        if !bwrap_available() {
            eprintln!("SKIP fd_pinned_gated_exec_runs_the_approved_content: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("ok");
        let bytes = write_script(&env.exe, "APPROVED", &env.result);
        let action = build_action(&env.exe, &bytes, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);
        // Swap the PATH (new inode) after approval; the fd keeps the original.
        swap_script(&env.exe, "SWAPPED", &env.result);

        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("approved exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "APPROVED",
            "fd-pinned exec runs the digest-bound (pinned) inode, not the swapped path"
        );
    }

    /// RED-proof (fd-pin): a path-re-resolving exec runs the SWAPPED content — the
    /// swap window the fd-pin closes and path-exec reopens.
    #[test]
    fn red_proof_path_exec_runs_the_swapped_content() {
        if !bwrap_available() {
            eprintln!("SKIP red_proof_path_exec_runs_the_swapped_content: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("swap");
        let bytes = write_script(&env.exe, "APPROVED", &env.result);
        let action = build_action(&env.exe, &bytes, &env.out_dir);
        swap_script(&env.exe, "SWAPPED", &env.result);

        let out = execute_via_path(&action, &env.exe);
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "SWAPPED",
            "RED: path-exec re-resolves the path → the swapped binary runs → executed != approved"
        );
    }

    /// D0A-R9-02, reviewer reproduction 1 — **SAME-INODE substitution**.
    ///
    /// `red_proof_path_exec_runs_the_swapped_content` above attacks the property the
    /// pin HAS: rename-over creates a new inode, and the pin catches it. This attacks
    /// the property it does NOT have — **the pin fixes an inode, not bytes.** Here the
    /// pin is intact and simply does not apply.
    #[test]
    fn same_inode_overwrite_executes_unapproved_content() {
        if !bwrap_available() {
            eprintln!("SKIP same_inode_overwrite_executes_unapproved_content: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("same-inode");
        let bytes = write_script(&env.exe, "APPROVED", &env.result);
        let action = build_action(&env.exe, &bytes, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let (ino_before, ino_after) = overwrite_in_place(&env.exe, "SUBSTITUTED", &env.result);
        assert_eq!(
            ino_before, ino_after,
            "harness: the overwrite must keep the SAME inode, else this silently \
             reproduces the rename case the pin already catches"
        );

        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("approved exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "APPROVED",
            "D0A-R9-02: bytes written behind the pinned inode execute — the digest bound \
             content that is no longer there"
        );
    }

    /// D0A-R9-02, reviewer reproduction 2 — **NESTED-INTERPRETER substitution**.
    ///
    /// The pinned file is never modified: it still hashes to `executable_digest`, and
    /// the test asserts that. What runs is the interpreter its shebang names, which the
    /// kernel resolves **by path, after the pin**, and which nothing pins or seals.
    /// (Nested shebang honoured through `/proc/self/fd/N` — measured on this kernel.)
    #[test]
    fn nested_interpreter_substitution_executes_unapproved_content() {
        if !bwrap_available() {
            eprintln!("SKIP nested_interpreter_substitution_executes_unapproved_content: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("nested");
        let interp = env.out_dir.join("interp");
        write_script(&interp, "APPROVED-INTERP", &env.result);
        let bytes = write_script_with_interp(&env.exe, &interp);
        let action = build_action(&env.exe, &bytes, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let (ino_before, ino_after) = overwrite_in_place(&interp, "SUBSTITUTED-INTERP", &env.result);
        assert_eq!(ino_before, ino_after, "harness: the interpreter swap must be in place");
        assert_eq!(
            fs::read(&env.exe).unwrap(),
            bytes,
            "harness: the PINNED file must stay byte-identical, or this proves the wrong thing"
        );

        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("approved exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "APPROVED-INTERP",
            "D0A-R9-02: the pinned inode is correct AND unmodified, yet the code that ran \
             was resolved by path after the pin"
        );
    }

    /// The gate: an invalid token is rejected (no execution); the ungated path runs
    /// the unapproved action (RED — the gate is what blocks unapproved execution).
    #[test]
    fn gate_blocks_unapproved_but_ungated_would_run() {
        if !bwrap_available() {
            eprintln!("SKIP gate_blocks_unapproved_but_ungated_would_run: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("gate");
        let bytes = write_script(&env.exe, "UNAPPROVED", &env.result);
        let action = build_action(&env.exe, &bytes, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        // A token minted for a DIFFERENT digest — does not verify against this action.
        let wrong = mint(&key, &[0xFF; 32], NOW);

        let gated = execute_approved(&action, &wrong, &key, NOW, &mut ConsumptionLedger::new());
        assert!(matches!(gated, Err(RuntimeError::Unapproved)), "gate must reject an invalid token");
        assert!(!env.result.exists(), "gated rejection → no execution → no output");

        // RED: bypass the gate → the unapproved action executes.
        let out = run_fd_pinned(&action).expect("ungated exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert!(
            env.result.exists(),
            "RED: skipping the gate executes the UNAPPROVED action — the token gate is what \
             stands between an unapproved action and the exec"
        );
    }

    /// RUNTIME-1D-02 — ONE-SHOT: the same approval executes once; a second
    /// execution of the same action is denied (approve-once/execute-many closed).
    #[test]
    fn token_is_one_shot_second_execution_denied() {
        if !bwrap_available() {
            eprintln!("SKIP token_is_one_shot_second_execution_denied: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("oneshot");
        let bytes = write_script(&env.exe, "ONCE", &env.result);
        let action = build_action(&env.exe, &bytes, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);
        let mut ledger = ConsumptionLedger::new();

        let first = execute_approved(&action, &token, &key, NOW, &mut ledger);
        assert!(first.is_ok(), "first execution of the approved action runs");
        assert_eq!(fs::read_to_string(&env.result).unwrap().trim(), "ONCE");

        // RED: same token, same action, SECOND execution → DENIED.
        let second = execute_approved(&action, &token, &key, NOW, &mut ledger);
        assert!(
            matches!(second, Err(RuntimeError::AlreadyConsumed)),
            "RED: a second execution with the same approval must be DENIED — one PAM approval \
             authorizes ONE execution, not repeated execution within the token TTL"
        );
    }

    /// A memfd holding `content` with ONLY `F_SEAL_WRITE` (NOT shrink/grow/seal) —
    /// the PARTIAL-seal case: write-sealed but still `ftruncate`-able, so its content
    /// length is mutable after the digest. The negative case that proves the exec
    /// check requires the FULL seal set, not a subset.
    fn write_sealed_only_memfd(content: &[u8]) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        // SAFETY: fresh memfd; write content, apply ONLY F_SEAL_WRITE, wrap once.
        unsafe {
            let fd = nix::libc::memfd_create(
                c"delphi-script-partial".as_ptr(),
                (nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING) as nix::libc::c_uint,
            );
            assert!(fd >= 0, "memfd_create");
            let n = nix::libc::write(fd, content.as_ptr().cast(), content.len());
            assert_eq!(n, content.len() as isize, "write memfd");
            assert_eq!(
                nix::libc::fcntl(fd, nix::libc::F_ADD_SEALS, nix::libc::F_SEAL_WRITE),
                0,
                "seal write-only"
            );
            std::os::fd::OwnedFd::from_raw_fd(fd)
        }
    }

    /// An UNSEALED memfd holding `content` (`MFD_ALLOW_SEALING` but NO seals applied,
    /// so its bytes can still be mutated) — the negative case for R4-02 sealing.
    fn unsealed_memfd(content: &[u8]) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        // SAFETY: memfd_create returns a fresh fd; we write it and wrap once, applying
        // NO seals — its content remains mutable.
        unsafe {
            let fd = nix::libc::memfd_create(
                c"delphi-script-unsealed".as_ptr(),
                (nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING) as nix::libc::c_uint,
            );
            assert!(fd >= 0, "memfd_create");
            let n = nix::libc::write(fd, content.as_ptr().cast(), content.len());
            assert_eq!(n, content.len() as isize, "write memfd");
            std::os::fd::OwnedFd::from_raw_fd(fd)
        }
    }

    /// RUNTIME-1D-01 (SEALING half) — the ratified R4-02 mechanism is interpreter-
    /// pinned AND script-FULLY-SEALED. A FULLY-UNSEALED script memfd (its content
    /// could be swapped after the digest) is REFUSED before any exec path — so the
    /// guarantee bites the script-CONTENT-mutation threat, not only interpreter-PATH-
    /// swap. No bwrap: the seal check precedes the spawn, so this runs in plain CI.
    #[test]
    fn unsealed_script_memfd_is_refused() {
        let env = Env::new("unsealed");
        let script_src = b"#!/bin/sh\n:\n";
        let mut action =
            build_action(&env.exe, &write_script(&env.exe, "UNUSED", &env.result), &env.out_dir);
        action.script = Some(crate::action::ScriptPin {
            interpreter_fd: fs::File::open("/bin/sh").unwrap().into(),
            interpreter_digest: sha256(b"interp"),
            interpreter_arg: None,
            script_memfd: unsealed_memfd(script_src), // NOT sealed
            script_digest: sha256(script_src),
        });
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        // The token verifies (the digest binds the script_digest, not the seal state),
        // the ledger consumes — then the seal check refuses before any exec.
        let res = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new());
        assert!(
            matches!(res, Err(RuntimeError::UnsealedScript)),
            "RED: a FULLY-UNSEALED script memfd must be REFUSED before exec — its content could \
             be mutated after the digest was taken; only a fully-sealed script may run (R4-02). \
             got {res:?}"
        );
        assert!(!env.result.exists(), "refused before any exec → no output");
    }

    /// RUNTIME-1D-01 (SEAL SET, round-3) — the ratified §3 immutability is the FULL
    /// seal set (`WRITE|SHRINK|GROW|SEAL`). `F_SEAL_WRITE` alone does NOT stop
    /// `ftruncate` shrink/grow, so a WRITE-only-sealed memfd's content/length is still
    /// mutable after the digest. A PARTIAL (write-only) seal is REFUSED, proving the
    /// exec check requires ALL FOUR — distinct from the fully-unsealed RED above. No
    /// bwrap (the seal check precedes the spawn).
    #[test]
    fn partial_seal_write_only_is_refused() {
        let env = Env::new("partialseal");
        let script_src = b"#!/bin/sh\n:\n";
        let mut action =
            build_action(&env.exe, &write_script(&env.exe, "UNUSED", &env.result), &env.out_dir);
        action.script = Some(crate::action::ScriptPin {
            interpreter_fd: fs::File::open("/bin/sh").unwrap().into(),
            interpreter_digest: sha256(b"interp"),
            interpreter_arg: None,
            script_memfd: write_sealed_only_memfd(script_src), // ONLY F_SEAL_WRITE
            script_digest: sha256(script_src),
        });
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let res = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new());
        assert!(
            matches!(res, Err(RuntimeError::UnsealedScript)),
            "RED: a WRITE-only-sealed script memfd must be REFUSED — F_SEAL_WRITE does not stop \
             ftruncate shrink/grow, so its content/length is still mutable after the digest; the \
             exec path must require the FULL seal set (WRITE|SHRINK|GROW|SEAL). got {res:?}"
        );
        assert!(!env.result.exists(), "refused before any exec → no output");
    }

    /// RUNTIME-1D-01 — SCRIPT PINNING (R4-02): the pinned INTERPRETER fd runs even
    /// when the interpreter PATH is swapped; the RED (exec the script fd, whose
    /// shebang re-resolves the interpreter by PATH) runs the SWAPPED interpreter.
    #[test]
    fn script_interpreter_is_pinned_against_path_swap() {
        if !bwrap_available() {
            eprintln!("SKIP script_interpreter_is_pinned_against_path_swap: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("scriptpin");
        let interp = env.dir.join("interp");
        let write_interp = |marker: &str| {
            let tmp = env.dir.join("interp.tmp");
            fs::write(&tmp, format!("#!/bin/sh\necho {marker} > {}\n", env.result.display())).unwrap();
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
            fs::rename(&tmp, &interp).unwrap(); // new inode each time (so the fd pins v1)
        };
        write_interp("INTERP-V1");
        let interp_fd: std::os::fd::OwnedFd = fs::File::open(&interp).unwrap().into();
        // The script: shebang points at the interpreter PATH (the RED re-resolves it).
        let script_src = format!("#!{}\n:\n", interp.display());

        let mut action = build_action(&env.exe, &write_script(&env.exe, "UNUSED", &env.result), &env.out_dir);
        // Bind the dir holding the interpreter (so the RED's shebang path resolves).
        action.fs_binds.push((env.dir.clone(), BindMode::ReadWrite));
        // The sanctioned constructor: a FULLY-sealed script memfd (so the exec-time
        // require_fully_sealed check passes on the legitimate path).
        action.script = Some(
            ScriptPin::sealed(interp_fd, sha256(b"INTERP-V1"), None, script_src.as_bytes())
                .expect("seal script memfd"),
        );
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        // Swap the interpreter PATH to v2 AFTER opening the pinned fd.
        write_interp("INTERP-V2");

        // CORRECT (R4-02): exec the PINNED interpreter fd → v1 still runs.
        let _ = fs::remove_file(&env.result);
        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("script exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "INTERP-V1",
            "the PINNED interpreter fd runs despite the path swap (R4-02)"
        );

        // RED: exec the SCRIPT fd → shebang re-resolves the interpreter by PATH → v2.
        let _ = fs::remove_file(&env.result);
        let script_fd = action.script.as_ref().unwrap().script_memfd.as_raw_fd();
        crate::fdsec::clear_cloexec(script_fd).unwrap();
        let mut red = SandboxProfile::derive(&action).args().to_vec();
        red.push("--".into());
        red.push(format!("/proc/self/fd/{script_fd}"));
        let rout = Command::new("bwrap").args(&red).output().unwrap();
        assert!(rout.status.success(), "bwrap: {}", String::from_utf8_lossy(&rout.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "INTERP-V2",
            "RED: exec'ing the SCRIPT fd re-resolves the interpreter by PATH → the swapped \
             interpreter runs. Pinning the interpreter fd (the CORRECT path) defeats this."
        );
    }

    /// RUNTIME-1D-03 — fd-DISCIPLINE: `mark_cloexec_except_raw` run in `pre_exec`
    /// (exactly as `run_fd_pinned` wires it) marks every inherited fd `>= 3` CLOEXEC
    /// except the keep-list, so a non-CLOEXEC daemon fd is CLOSED at the child's
    /// `execve`.
    ///
    /// Tested by a DIRECT fork+exec of `/bin/sh`, exercising `mark_cloexec_except_raw`
    /// in `pre_exec` exactly as `run_fd_pinned` wires it — rather than through bwrap, a
    /// confound-prone proxy for the fd-close discipline. Testing the runtime's OWN
    /// primitive directly is the right design independent of bwrap's fd behaviour, and
    /// is what makes the discipline load-bearing: bwrap does NOT sanitise inherited fds
    /// (a non-CLOEXEC fd reaches the jailed command — verified via `/proc/self/fd`), so
    /// `close_range` in `pre_exec` is the PRIMARY defence, closing daemon fds at
    /// `execve(bwrap)` before bwrap's process or the jail can see them. The child
    /// probes its own fd table via `/proc/self/fd/N` (no shell `>&N` redirect quirks)
    /// and reports to a FILE: deterministic and parallelism-robust. No bwrap/root → it
    /// runs everywhere.
    #[test]
    fn fd_discipline_closes_a_daemon_fd_at_exec() {
        // Fork+exec /bin/sh with a non-CLOEXEC "daemon" fd open; the child tries to
        // write "LEAKED" to it. `close_range` selects whether the 1D-03 pre_exec
        // discipline runs. Returns the file's contents after the child exits.
        fn probe(close_range: bool) -> String {
            let dir = PathBuf::from(format!(
                "/tmp/delphi-fdleak-{}-{}",
                std::process::id(),
                u8::from(close_range)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let ran_path = dir.join("ran");
            let leaked_path = dir.join("leaked");
            // The "daemon" fd: a non-CLOEXEC fd the child must NOT see after the
            // discipline runs. The child probes its OWN fd table via /proc/self/fd/N
            // (robust — no shell `>&N` redirect quirks) and reports to a FILE.
            let f = fs::File::open("/dev/null").unwrap();
            let leak = f.as_raw_fd();
            crate::fdsec::clear_cloexec(leak).unwrap();

            let mut cmd = Command::new("/bin/sh");
            // `echo RAN` proves the child exec'd; the `test -e /proc/self/fd/N` is true
            // iff the daemon fd is still OPEN in the exec'd child.
            cmd.arg("-c").arg(format!(
                "echo RAN > {}; if test -e /proc/self/fd/{leak}; then echo LEAKED > {}; fi",
                ran_path.display(),
                leaked_path.display()
            ));
            if close_range {
                let keep: Vec<RawFd> = Vec::new(); // exec by PATH → keep no fd
                // SAFETY: pre_exec runs post-fork/pre-execve; mark_cloexec_except_raw
                // is allocation-free + async-signal-safe, and from_raw_os_error wraps
                // the errno int inline (no Box) — the exact wiring run_fd_pinned uses.
                unsafe {
                    cmd.pre_exec(move || {
                        crate::fdsec::mark_cloexec_except_raw(&keep)
                            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                    });
                }
            }
            let out = cmd.output().unwrap();
            assert!(out.status.success(), "/bin/sh: {}", String::from_utf8_lossy(&out.stderr));
            drop(f);
            // The child RAN regardless of the fd's state — so an absent LEAKED means
            // "fd closed", not "the child never ran".
            assert_eq!(
                fs::read_to_string(&ran_path).unwrap_or_default().trim(),
                "RAN",
                "the child exec'd"
            );
            let s = fs::read_to_string(&leaked_path).unwrap_or_default();
            let _ = fs::remove_dir_all(&dir);
            s
        }

        // RED: WITHOUT the fd-discipline, the non-CLOEXEC daemon fd survives execve →
        // the child writes to it.
        assert!(
            probe(false).contains("LEAKED"),
            "RED: without the close_range fd-discipline a non-CLOEXEC daemon fd survives execve \
             into the child — it wrote to it"
        );
        // CORRECT: the discipline marks it CLOEXEC → closed at execve → child can't write.
        assert!(
            !probe(true).contains("LEAKED"),
            "the fd-discipline (mark_cloexec_except_raw in pre_exec) closes the daemon fd at execve"
        );
    }
}
