// SPDX-License-Identifier: MIT

//! Reentry containment — the jailed tool cannot reach the daemon socket (1d, F5/R3-02).
//!
//! The approval authorizes THIS action in THIS sandbox; the sandbox must not be an
//! escape hatch back to the approval mechanism. The default-deny [`SandboxProfile`]
//! binds **only** the approved scope, so the daemon's approval socket (outside that
//! scope) is not in the jail's mount namespace and the tool cannot connect back to
//! self-approve.
//!
//! This is an **attack-test**: the jailed tool IS the attacker, actively attempting
//! a connection to the daemon socket. Same experiment, the **socket bind** the only
//! variable — CORRECT (default-deny, socket not bound → connect denied) vs RED
//! (socket bound into the jail → connect succeeds → reentry).
//!
//! Runs unprivileged via bwrap + a python3 `AF_UNIX` probe (no root); gated on
//! bwrap + unprivileged user namespaces being available (skips elsewhere, e.g. a
//! CI runner without userns).

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use delphi_runtime::action::{NetPolicy, PendingAction, RequiredTier};
use delphi_runtime::sandbox::SandboxProfile;

/// A python3 probe: connect to `argv[1]` (an `AF_UNIX` path); exit 0 if connected,
/// 1 if not reachable.
const PROBE: &str = "import socket,sys\ns=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\ntry:\n s.connect(sys.argv[1])\n sys.exit(0)\nexcept Exception:\n sys.exit(1)\n";

/// Minimal read-only toolset bound so python3 can run inside the jail (test
/// scaffolding — NOT part of the production scope; the socket dir is never here).
const SCAFFOLD: &[&str] = &[
    "--ro-bind", "/usr", "/usr",
    "--ro-bind", "/lib", "/lib",
    "--ro-bind", "/lib64", "/lib64",
    "--ro-bind", "/bin", "/bin",
    // --proc/--dev now come from the production SandboxProfile (jail infrastructure).
];

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

fn default_deny_action() -> PendingAction {
    PendingAction {
        pending_id: "act-reentry".into(),
        preview_version: 1,
        executable_fd: std::fs::File::open("/dev/null").unwrap().into(),
        executable_digest: [0xAB; 32],
        argv: vec!["tool".into()],
        cwd: PathBuf::from("/"), // exists in the jail
        env_delta: vec![],
        fs_binds: vec![], // default-deny: no scope binds
        net_policy: NetPolicy::None,
        timeout: std::time::Duration::from_secs(30),
        required_tier: RequiredTier::Confirm,
        script: None,
    }
}

/// Run the python3 probe inside the jail; return `true` if it CONNECTED (reached
/// the daemon socket). `bind_socket` is the single variable: when true the socket
/// directory is bound into the jail.
fn probe_reaches_socket(
    profile: &SandboxProfile,
    socket_dir: &Path,
    socket_path: &Path,
    bind_socket: bool,
) -> bool {
    let mut args: Vec<String> = profile.args().to_vec();
    args.extend(SCAFFOLD.iter().map(|s| (*s).to_string()));
    if bind_socket {
        let d = socket_dir.display().to_string();
        args.push("--bind".into());
        args.push(d.clone());
        args.push(d);
    }
    args.push("--".into());
    args.push("/usr/bin/python3".into());
    args.push("-c".into());
    args.push(PROBE.into());
    args.push(socket_path.display().to_string());

    Command::new("bwrap")
        .args(&args)
        .output()
        .expect("spawn bwrap")
        .status
        .success()
}

/// Set up a real "daemon" listener socket under a per-test-unique dir; return
/// (dir, socket_path, listener).
fn daemon_socket(tag: &str) -> (tempfile::TempDir, PathBuf, UnixListener) {
    // The TempDir is RETURNED, not dropped here: the caller binds it, so the directory
    // lives exactly as long as the test and is removed even if the test panics.
    let dir = tempfile::Builder::new()
        .prefix(&format!("delphi-reentry-{tag}-"))
        .tempdir()
        .expect("tempdir");
    let sock = dir.path().join("approve.sock");
    let listener = UnixListener::bind(&sock).expect("bind daemon socket");
    (dir, sock, listener)
}

/// CORRECT: the default-deny profile does not bind the daemon socket → the jailed
/// tool cannot reach it.
#[test]
fn jailed_tool_cannot_reach_the_daemon_socket() {
    if !bwrap_available() {
        eprintln!("SKIP jailed_tool_cannot_reach_the_daemon_socket: requires bwrap + unprivileged user namespaces");
        return;
    }
    let (dir, sock, _listener) = daemon_socket("correct");
    let profile = SandboxProfile::derive(&default_deny_action());
    let reached = probe_reaches_socket(&profile, dir.path(), &sock, false);
    assert!(
        !reached,
        "reentry containment: the jailed tool must NOT reach the daemon approval socket — it is \
         outside the approved scope, so not in the jail's mount namespace"
    );
}

/// RED-proof (same experiment, socket-bind the only variable): binding the daemon
/// socket into the jail lets the tool connect back → reentry. Proves the
/// containment is the socket-exclusion, and that the probe genuinely connects.
#[test]
fn red_proof_binding_the_daemon_socket_lets_the_tool_reenter() {
    if !bwrap_available() {
        eprintln!("SKIP red_proof_binding_the_daemon_socket_lets_the_tool_reenter: requires bwrap + unprivileged user namespaces");
        return;
    }
    let (dir, sock, _listener) = daemon_socket("red");
    let profile = SandboxProfile::derive(&default_deny_action());
    let reached = probe_reaches_socket(&profile, dir.path(), &sock, true);
    assert!(
        reached,
        "RED-proof: binding the daemon socket into the jail lets the jailed tool CONNECT back to \
         the approval mechanism (reentry). The default-deny profile must never bind it."
    );
}
