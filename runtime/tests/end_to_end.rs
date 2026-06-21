// SPDX-License-Identifier: MIT

//! End-to-end — one Biometric action through 1a→1d composed (Increment 1d capstone).
//!
//! The bounded, complete thing the single implementation review verifies: a single
//! action flows through every layer's real property and they COMPOSE —
//!
//! * **1a** — the root daemon establishes the root-owned anchor directory + socket.
//! * **1b** — the private `SOCK_SEQPACKET` approval channel (daemon end + shell end).
//! * **1c** — LIVE PAM consent driven over that private channel, then the daemon
//!   mints the digest-bound capability token with its root-held key.
//! * **1d** — the canonical `PendingAction`, its sandbox profile, the token-gated
//!   swap-proof execute, and the audit recording the real outcome.
//!
//! The human (scripted) authenticates over the channel; the daemon mints only after
//! PAM succeeds; the sandbox executes only after the token verifies the digest; the
//! audit records what actually ran. Privileged (1a's `/run` dir + 1c's `/etc/shadow`
//! PAM) and bwrap-gated. Run the WSL2-root lane, single-threaded:
//!
//! ```text
//! wsl -u root -- env -C /mnt/c/dev/Delphi PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH \
//!   /home/raven/.cargo/bin/cargo test -p delphi-runtime --test end_to_end \
//!   -- --test-threads=1 --nocapture
//! ```

use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use nix::sys::wait::waitpid;
use nix::unistd::{fork, geteuid, ForkResult, Gid, Uid, User};

use delphi_runtime::action::{canonical_action_digest, preview, BindMode, NetPolicy, PendingAction, RequiredTier};
use delphi_runtime::audit::{ExecOutcome, RuntimeAuditEntry};
use delphi_runtime::execute::execute_approved;
use delphi_runtime::sandbox::SandboxProfile;
use delphi_runtime::token::{mint, MintingKey};
use delphi_runtime::{approval_socketpair, bind_approval_socket, drop_privileges, ensure_runtime_dir, RealPrivDropOps};

const SERVICE: &str = "delphi-runtime";
const UNIT_PAM: &str = "/etc/pam.d/delphi-runtime";
const PASSWORD: &str = "Delphi1dCapstone!";
const NOW: u64 = 1_000;

fn bwrap_available() -> bool {
    Command::new("bwrap")
        .args(["--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64", "--unshare-all", "--die-with-parent", "--", "/usr/bin/true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// PAM service + a throwaway user with a known password; torn down on drop.
struct Setup {
    user: String,
}
impl Setup {
    fn new() -> Self {
        let user = format!("de2e{}", std::process::id() % 100_000);
        let _ = Command::new("userdel").arg(&user).status();
        assert!(Command::new("useradd").args(["-M", "-s", "/usr/sbin/nologin", &user]).status().unwrap().success());
        let mut ch = Command::new("chpasswd").stdin(Stdio::piped()).spawn().unwrap();
        ch.stdin.take().unwrap().write_all(format!("{user}:{PASSWORD}").as_bytes()).unwrap();
        assert!(ch.wait().unwrap().success());
        std::fs::write(UNIT_PAM, "auth required pam_unix.so\naccount required pam_unix.so\n").unwrap();
        Self { user }
    }
    fn ids(&self) -> (Uid, Gid) {
        let u = User::from_name(&self.user).unwrap().unwrap();
        (u.uid, u.gid)
    }
}
impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(UNIT_PAM);
        let _ = Command::new("userdel").arg(&self.user).status();
    }
}

/// The scripted human on the channel's shell end: read the PAM prompt, write the
/// password.
fn be_human(shell_end: RawFd, uid: Uid, gid: Gid) -> ! {
    drop_privileges(&RealPrivDropOps, uid, gid).unwrap();
    // SAFETY: read the prompt datagram, write the password datagram on the channel.
    unsafe {
        let mut buf = [0u8; 4096];
        let _ = nix::libc::read(shell_end, buf.as_mut_ptr().cast(), buf.len());
        let _ = nix::libc::write(shell_end, PASSWORD.as_ptr().cast(), PASSWORD.len());
        nix::libc::_exit(0)
    }
}

#[test]
fn one_biometric_action_through_1a_to_1d() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP one_biometric_action_through_1a_to_1d: requires root (1a /run dir + 1c PAM)");
        return;
    }
    if !bwrap_available() {
        eprintln!("SKIP one_biometric_action_through_1a_to_1d: requires bwrap + unprivileged userns");
        return;
    }
    let setup = Setup::new();
    let (uid, gid) = setup.ids();

    // ---- 1a: the root daemon establishes the root-owned anchor. ----
    let base = PathBuf::from(format!("/run/delphi-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let anchor_dir = ensure_runtime_dir(&base, &setup.user).expect("1a: anchor dir");
    let (_anchor, _listener) = bind_approval_socket(&anchor_dir, gid.as_raw()).expect("1a: anchor socket");

    // ---- 1b: the private approval channel. ----
    let (daemon_end, shell_end) = approval_socketpair().expect("1b: channel");
    let shell_raw = shell_end.as_raw_fd();

    // ---- 1d: the canonical action (a Biometric action that writes a marker). ----
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let exe = work.join("echo.sh");
    let result = work.join("result");
    std::fs::write(&exe, format!("#!/bin/sh\necho \"$1\" > {}\n", result.display())).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    let action = PendingAction {
        pending_id: "act-e2e".into(),
        preview_version: 1,
        executable_fd: std::fs::File::open(&exe).unwrap().into(),
        executable_digest: [0x33; 32],
        argv: vec!["tool".into(), "DONE-E2E".into()],
        cwd: PathBuf::from("/"),
        env_delta: vec![],
        fs_binds: vec![
            (PathBuf::from("/usr"), BindMode::ReadOnly),
            (PathBuf::from("/bin"), BindMode::ReadOnly),
            (PathBuf::from("/lib"), BindMode::ReadOnly),
            (PathBuf::from("/lib64"), BindMode::ReadOnly),
            (work.clone(), BindMode::ReadWrite),
        ],
        net_policy: NetPolicy::None,
        timeout: Duration::from_secs(30),
        required_tier: RequiredTier::Biometric,
        script: None,
    };
    let digest = canonical_action_digest(&action);
    // The preview the human approves renders the exact action.
    assert!(preview(&action).contains("DONE-E2E"), "preview renders the action");

    // ---- 1c: live PAM consent over the private channel, then mint. ----
    // SAFETY: test-only fork; the child scripts the human side and `_exit`s.
    let human = match unsafe { fork() } {
        Ok(ForkResult::Child) => be_human(shell_raw, uid, gid),
        Ok(ForkResult::Parent { child }) => child,
        Err(e) => panic!("fork: {e}"),
    };
    let pam = delphi_runtime::pam::authenticate_over_channel(SERVICE, &setup.user, daemon_end.as_raw_fd());
    let _ = waitpid(human, None);
    assert!(pam.is_ok(), "1c: live PAM consent over the private channel must succeed: {pam:?}");

    // The daemon mints the digest-bound token ONLY after consent (root-held key).
    let key = MintingKey::from_bytes([0x5A; 32]);
    let token = mint(&key, &digest, NOW);

    // ---- 1d: token-gated execute in the sandbox + audit the real outcome. ----
    let real = execute_approved(&action, &token, &key, NOW);
    let observed = std::fs::read_to_string(&result).unwrap_or_default().trim().to_string();
    let entry = RuntimeAuditEntry::record(&action, &SandboxProfile::derive(&action), &real, NOW);

    let _ = std::fs::remove_dir_all(&base);

    // The chain composed: consent happened, the executed action IS the approved
    // action, and the audit records what actually ran.
    assert_eq!(observed, action.argv[1], "executed == approved (preview = execution, end to end)");
    assert_eq!(entry.action_digest, digest, "audit binds the approved action");
    assert!(matches!(entry.outcome, ExecOutcome::Completed), "audit records the real outcome");
}
