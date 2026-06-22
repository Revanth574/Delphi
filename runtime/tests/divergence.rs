// SPDX-License-Identifier: MIT

//! The divergence test — the capstone property (Increment 1d).
//!
//! 1a–1c each proved an attacker is denied. 1d's core is a **divergence** test: the
//! canonical [`PendingAction`] is the ONE object from which the **preview**, the
//! **approval digest**, the **sandbox profile**, and the **audit entry** all
//! derive — with no divergence path. The human approves the true action; the
//! executed action IS the approved one; the audit records what ran. This forecloses
//! approve-A/execute-B and preview-X/run-Y (the prompt-injection threat).
//!
//! Observable: a **bound output file**. The fixed executable echoes its `argv[1]`
//! (the object's argv) into a bound path; the test reads it back. Same experiment,
//! the **source of the executed argv** the only variable — CORRECT (from the
//! object → preview == execution) vs RED (decoupled → preview shows X, execution
//! runs Y).
//!
//! No root (bwrap unprivileged); gated on bwrap + userns.

use std::fs;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use nix::fcntl::{fcntl, FcntlArg, FdFlag};

use delphi_runtime::action::{
    canonical_action_digest, preview, BindMode, NetPolicy, PendingAction, RequiredTier,
};
use delphi_runtime::audit::RuntimeAuditEntry;
use delphi_runtime::execute::{execute_approved, ConsumptionLedger};
use delphi_runtime::sandbox::SandboxProfile;
use delphi_runtime::token::{mint, MintingKey};

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

struct Env {
    dir: PathBuf,
    exe: PathBuf,
    out_dir: PathBuf,
    result: PathBuf,
}
impl Env {
    fn new(tag: &str) -> Self {
        let dir = PathBuf::from(format!("/tmp/delphi-div-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let out_dir = dir.join("out");
        fs::create_dir_all(&out_dir).unwrap();
        Self { exe: dir.join("echo.sh"), result: out_dir.join("result"), out_dir, dir }
    }
    /// Write the fixed executable: echo `$1` into the bound result path.
    fn write_echo_exe(&self) {
        fs::write(&self.exe, format!("#!/bin/sh\necho \"$1\" > {}\n", self.result.display())).unwrap();
        fs::set_permissions(&self.exe, fs::Permissions::from_mode(0o755)).unwrap();
    }
}
impl Drop for Env {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn action_with_marker(env: &Env, marker: &str) -> PendingAction {
    PendingAction {
        pending_id: "act-div".into(),
        preview_version: 1,
        executable_fd: fs::File::open(&env.exe).unwrap().into(),
        executable_digest: [0x22; 32],
        argv: vec!["tool".into(), marker.into()],
        cwd: PathBuf::from("/"),
        env_delta: vec![],
        fs_binds: vec![
            (PathBuf::from("/usr"), BindMode::ReadOnly),
            (PathBuf::from("/bin"), BindMode::ReadOnly),
            (PathBuf::from("/lib"), BindMode::ReadOnly),
            (PathBuf::from("/lib64"), BindMode::ReadOnly),
            (env.out_dir.clone(), BindMode::ReadWrite),
        ],
        net_policy: NetPolicy::None,
        timeout: Duration::from_secs(30),
        required_tier: RequiredTier::Biometric,
        script: None,
    }
}

/// RED helper: exec the action's executable with an argv sourced INDEPENDENTLY of
/// the canonical object (the decoupling).
fn exec_with_independent_argv(action: &PendingAction, args_after: &[&str]) -> Output {
    let fd = action.executable_fd.as_raw_fd();
    // Clear CLOEXEC so the fd survives into bwrap + the jail's exec.
    let bf = unsafe { BorrowedFd::borrow_raw(fd) };
    let bits = fcntl(bf, FcntlArg::F_GETFD).unwrap();
    let mut flags = FdFlag::from_bits_truncate(bits);
    flags.remove(FdFlag::FD_CLOEXEC);
    fcntl(bf, FcntlArg::F_SETFD(flags)).unwrap();

    let mut a = SandboxProfile::derive(action).args().to_vec();
    a.push("--argv0".into());
    a.push("tool".into());
    a.push("--".into());
    a.push(format!("/proc/self/fd/{fd}"));
    for x in args_after {
        a.push((*x).to_string());
    }
    Command::new("bwrap").args(&a).output().unwrap()
}

fn read_result(p: &Path) -> String {
    fs::read_to_string(p).unwrap_or_default().trim().to_string()
}

/// CORRECT: all four derivations reflect the ONE object — the bound-file marker the
/// execution produced == the object's argv == what the preview shows == the digest
/// the audit binds.
#[test]
fn the_four_derivations_cannot_diverge() {
    if !bwrap_available() {
        eprintln!("SKIP the_four_derivations_cannot_diverge: requires bwrap + unprivileged userns");
        return;
    }
    let env = Env::new("ok");
    env.write_echo_exe();
    let action = action_with_marker(&env, "APPROVED-X");

    // The four derivations, ALL from the one object.
    let prev = preview(&action);
    let digest = canonical_action_digest(&action);
    let profile = SandboxProfile::derive(&action);
    let key = MintingKey::from_bytes([1u8; 32]);
    let token = mint(&key, &digest, NOW);

    let real = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new());
    let observed = read_result(&env.result);
    let entry = RuntimeAuditEntry::record(&action, &profile, &real, NOW);

    assert_eq!(observed, action.argv[1], "execution ran the object's argv → preview = execution");
    assert!(prev.contains(&action.argv[1]), "the preview renders the object's argv");
    assert_eq!(entry.action_digest, digest, "the audit binds the object's digest");
    // (the sandbox profile was derived from the same object; piece 2 proves the
    // enforced scope == the approved scope.)
}

/// RED-proof: decouple ONE derivation (the executed argv) from the canonical
/// object → the execution runs Y while the preview/digest still show X. Single-
/// object-derivation is what closes this divergence.
#[test]
fn red_proof_decoupling_execution_from_the_object_diverges() {
    if !bwrap_available() {
        eprintln!("SKIP red_proof_decoupling_execution_from_the_object_diverges: requires bwrap + unprivileged userns");
        return;
    }
    let env = Env::new("red");
    env.write_echo_exe();
    let action = action_with_marker(&env, "APPROVED-X");
    let prev = preview(&action);

    // Execution sourced from a DIFFERENT argv (not the object).
    let out = exec_with_independent_argv(&action, &["APPROVED-Y"]);
    assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
    let observed = read_result(&env.result);

    assert!(prev.contains("APPROVED-X") && !prev.contains("APPROVED-Y"), "the preview still shows X");
    assert_ne!(
        observed, action.argv[1],
        "RED: execution decoupled from the canonical object ran Y while the preview/digest \
         show X → preview != execution. Deriving every derivation from the one object is what \
         forecloses preview-X/run-Y."
    );
    assert_eq!(observed, "APPROVED-Y", "the decoupled execution ran the independent argv");
}
