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
//!    **sealed script memfd** as its argument — never the script fd, whose shebang
//!    would re-resolve the interpreter by PATH. `--proc /proc` in the
//!    [`SandboxProfile`] makes `/proc/self/fd/N` resolve.
//! 4. **fd-discipline (§6).** The 1b `fdsec` close-range runs in the child before
//!    bwrap's exec, so no daemon fd (the approval channel, the anchor socket) leaks
//!    into bwrap or the jailed tool; only the pinned program fd(s) survive.

use std::collections::HashSet;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

use crate::action::{canonical_action_digest, PendingAction};
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

/// Build the bwrap invocation and execute the **fd-pinned** program inside it
/// (`/proc/self/fd/N` — the swap-proof inode).
///
/// * **Binary** (`script: None`): exec `/proc/self/fd/<executable_fd>`.
/// * **Script** (`script: Some`, R4-02): exec the **pinned interpreter** fd with
///   the **sealed script memfd** as its argument — never the script fd, whose
///   shebang would re-resolve the interpreter by PATH.
fn run_fd_pinned(action: &PendingAction) -> Result<Output, RuntimeError> {
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
    // SAFETY: pre_exec runs in the forked child before execve; `mark_cloexec_except`
    // performs only `close_range`/`fcntl` syscalls.
    unsafe {
        cmd.pre_exec(move || crate::fdsec::mark_cloexec_except(&keep).map_err(std::io::Error::other));
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

    /// Build a sealed (`F_SEAL_WRITE`) memfd holding `content`.
    fn sealed_memfd(content: &[u8]) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        // SAFETY: memfd_create returns a fresh fd; we write + seal it, then wrap once.
        unsafe {
            let fd = nix::libc::memfd_create(
                c"delphi-script".as_ptr(),
                (nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING) as nix::libc::c_uint,
            );
            assert!(fd >= 0, "memfd_create");
            let n = nix::libc::write(fd, content.as_ptr().cast(), content.len());
            assert_eq!(n, content.len() as isize, "write memfd");
            let seals = nix::libc::F_SEAL_WRITE
                | nix::libc::F_SEAL_SHRINK
                | nix::libc::F_SEAL_GROW
                | nix::libc::F_SEAL_SEAL;
            assert_eq!(nix::libc::fcntl(fd, nix::libc::F_ADD_SEALS, seals), 0, "seal memfd");
            std::os::fd::OwnedFd::from_raw_fd(fd)
        }
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
        let script_memfd = sealed_memfd(script_src.as_bytes());

        let mut action = build_action(&env.exe, &write_script(&env.exe, "UNUSED", &env.result), &env.out_dir);
        // Bind the dir holding the interpreter (so the RED's shebang path resolves).
        action.fs_binds.push((env.dir.clone(), BindMode::ReadWrite));
        action.script = Some(crate::action::ScriptPin {
            interpreter_fd: interp_fd,
            interpreter_digest: sha256(b"INTERP-V1"),
            script_memfd,
            script_digest: sha256(script_src.as_bytes()),
        });
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

    /// RUNTIME-1D-03 — fd-DISCIPLINE: a deliberately non-CLOEXEC daemon fd is CLOSED
    /// before the jailed tool runs (close_range in pre_exec); the RED (no close_range)
    /// leaks it into the tool.
    #[test]
    fn daemon_fd_does_not_leak_into_the_jailed_tool() {
        if !bwrap_available() {
            eprintln!("SKIP daemon_fd_does_not_leak_into_the_jailed_tool: requires bwrap + unprivileged userns");
            return;
        }
        // Build an action whose script tries to write "LEAKED" to `leak_fd`.
        fn leak_action(env: &Env, leak_fd: RawFd) -> PendingAction {
            let src = format!(
                "#!/bin/sh\necho LEAKED >&{leak_fd} 2>/dev/null\necho done > {}\n",
                env.result.display()
            );
            fs::write(&env.exe, &src).unwrap();
            fs::set_permissions(&env.exe, fs::Permissions::from_mode(0o755)).unwrap();
            build_action(&env.exe, src.as_bytes(), &env.out_dir)
        }
        fn drain(read_fd: std::os::fd::OwnedFd) -> String {
            use std::io::Read;
            let mut s = String::new();
            let _ = std::fs::File::from(read_fd).read_to_string(&mut s);
            s
        }

        // CORRECT: close_range in execute_approved closes the leak fd before the tool.
        {
            let env = Env::new("fdleak-ok");
            let (r, w) = nix::unistd::pipe().unwrap();
            crate::fdsec::clear_cloexec(w.as_raw_fd()).unwrap(); // non-CLOEXEC → would leak without close_range
            let action = leak_action(&env, w.as_raw_fd());
            let key = MintingKey::from_bytes(KEY);
            let token = mint(&key, &canonical_action_digest(&action), NOW);
            let _ = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new());
            drop(w);
            assert!(
                !drain(r).contains("LEAKED"),
                "the daemon fd must be CLOSED in the jailed tool (close_range in pre_exec)"
            );
        }
        // RED: without close_range, the non-CLOEXEC fd leaks into the tool.
        {
            let env = Env::new("fdleak-red");
            let (r, w) = nix::unistd::pipe().unwrap();
            crate::fdsec::clear_cloexec(w.as_raw_fd()).unwrap();
            let action = leak_action(&env, w.as_raw_fd());
            let exe_fd = action.executable_fd.as_raw_fd();
            crate::fdsec::clear_cloexec(exe_fd).unwrap();
            let mut a = SandboxProfile::derive(&action).args().to_vec();
            a.push("--".into());
            a.push(format!("/proc/self/fd/{exe_fd}"));
            let _ = Command::new("bwrap").args(&a).output().unwrap(); // NO pre_exec close_range
            drop(w);
            assert!(
                drain(r).contains("LEAKED"),
                "RED: without the close_range fd-discipline, a non-CLOEXEC daemon fd LEAKS into \
                 the jailed tool — it wrote to it"
            );
        }
    }
}
