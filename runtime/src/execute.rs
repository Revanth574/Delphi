// SPDX-License-Identifier: MIT

//! Execute the approved action in the sandbox — the gate + the swap-proof fd-exec
//! (Increment 1d, R3-04 + `docs/TRUST_MODEL.md` §4 step 5).
//!
//! Two bindings make "execute = approval" hold:
//!
//! 1. **The gate.** [`execute_approved`] verifies the 1c capability token against
//!    `canonical_action_digest(action)` **before any exec path**. The digest covers
//!    `executable_digest` (the hashed executable content, piece 1), so a token that
//!    verifies means the human approved *this exact action including this exact
//!    executable* — unapproved or substituted actions never reach the exec.
//! 2. **The fd-pin (anti-TOCTOU).** The executable is exec'd as
//!    `/proc/self/fd/N` **inside the bwrap jail** — `execve` resolves the magic
//!    symlink to the **pinned inode** (the one whose bytes were hashed), not a
//!    re-resolvable path. A binary swap between hash and exec cannot take effect
//!    (verified: binding the path re-resolves and is NOT swap-proof; exec'ing the
//!    fd is). The fd's `CLOEXEC` is cleared so it survives into bwrap and the
//!    jail's exec; `--proc /proc` in the [`SandboxProfile`] makes `/proc/self/fd/N`
//!    resolve there.

use std::os::fd::AsRawFd;
use std::process::{Command, Output};

use crate::action::{canonical_action_digest, PendingAction};
use crate::fdsec::clear_cloexec;
use crate::sandbox::SandboxProfile;
use crate::token::{self, ApprovalToken, MintingKey};
use crate::RuntimeError;

/// Execute `action` in its derived sandbox **iff** `token` verifies against the
/// action's canonical digest at `now`.
///
/// # Errors
///
/// [`RuntimeError::Unapproved`] if the token does not verify (the gate);
/// [`RuntimeError::Syscall`]/[`RuntimeError::Filesystem`] if the fd or bwrap spawn
/// fails.
pub fn execute_approved(
    action: &PendingAction,
    token: &ApprovalToken,
    key: &MintingKey,
    now: u64,
) -> Result<Output, RuntimeError> {
    // THE GATE — before any exec path.
    let digest = canonical_action_digest(action);
    if !token::verify(key, token, &digest, now) {
        return Err(RuntimeError::Unapproved);
    }
    run_fd_pinned(action)
}

/// Build the bwrap invocation and execute the **fd-pinned** executable inside it
/// (`/proc/self/fd/N` — the swap-proof inode). Shared by [`execute_approved`].
fn run_fd_pinned(action: &PendingAction) -> Result<Output, RuntimeError> {
    let exe_fd = action.executable_fd.as_raw_fd();
    // The pinned fd must survive into bwrap and the jail's exec.
    clear_cloexec(exe_fd)?;

    let mut args = SandboxProfile::derive(action).args().to_vec();
    if let Some(argv0) = action.argv.first() {
        args.push("--argv0".to_string());
        args.push(argv0.clone());
    }
    args.push("--".to_string());
    args.push(format!("/proc/self/fd/{exe_fd}"));
    for arg in action.argv.iter().skip(1) {
        args.push(arg.clone());
    }

    Command::new("bwrap")
        .args(&args)
        .output()
        .map_err(|source| RuntimeError::Filesystem {
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

        let out = execute_approved(&action, &token, &key, NOW).expect("approved exec");
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

        let gated = execute_approved(&action, &wrong, &key, NOW);
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
}
