// SPDX-License-Identifier: MIT

//! Increment 1a anchor proof — the running-code analogue of the trust model's
//! root-anchor finding (`docs/TRUST_MODEL.md` §4, R3-01 / R4-01).
//!
//! These tests are **privileged**: they need root (to create the root-owned
//! `/run` directory and to spawn a same-uid attacker) and a real Linux kernel.
//! They are **EUID-gated, not `#[ignore]`d** — when not root they print the exact
//! invocation and skip; when root they run. Run the privileged lane (single
//! threaded, because the attacker is spawned with `fork`):
//!
//! ```text
//! wsl -u root -- env -C /mnt/c/dev/Delphi \
//!   /home/raven/.cargo/bin/cargo test -p delphi-runtime --test anchor \
//!   -- --test-threads=1 --nocapture
//! ```
//!
//! The both-halves test proves "unsubstitutable YET connectable"; the RED-proof
//! positive control proves that denial is the *root-ownership* property and not a
//! vacuous pass (with a user-owned directory the same-uid attacker CAN unlink).

use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chown, fork, geteuid, ForkResult, Gid, Uid};

use delphi_runtime::{bind_approval_socket, drop_privileges, ensure_runtime_dir, RealPrivDropOps};

/// A high, unprivileged uid/gid for the same-uid attacker — no passwd entry is
/// needed to `setuid`/`setgid` to a numeric id.
const TEST_UID: u32 = 60000;
const TEST_GID: u32 = 60000;

/// Skip (printing the invocation) when not root, so the test self-documents its
/// requirement instead of silently passing as a no-op.
fn skip_if_not_root(name: &str) -> bool {
    if geteuid().as_raw() != 0 {
        eprintln!(
            "SKIP {name}: requires root + systemd-style /run. Run the privileged lane:\n  \
             wsl -u root -- env -C /mnt/c/dev/Delphi \\\n    \
             /home/raven/.cargo/bin/cargo test -p delphi-runtime --test anchor \\\n    \
             -- --test-threads=1 --nocapture"
        );
        return true;
    }
    false
}

fn unique_base(tag: &str) -> PathBuf {
    PathBuf::from(format!("/run/delphi-anchor-test-{tag}-{}", std::process::id()))
}

fn cleanup(base: &Path) {
    let _ = std::fs::remove_dir_all(base);
}

/// Fork, drop to the test user in the child, run `attack`, and return the child's
/// exit code. The parent keeps the listener alive across the wait.
fn run_as_test_user<F>(attack: F) -> i32
where
    F: FnOnce() -> i32,
{
    // SAFETY: fork in a test harness. The child only drops privileges and performs
    // a few syscalls before `_exit`; the privileged lane runs `--test-threads=1`,
    // so no sibling thread holds an allocator lock at the fork point.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let code = match drop_privileges(
                &RealPrivDropOps,
                Uid::from_raw(TEST_UID),
                Gid::from_raw(TEST_GID),
            ) {
                Ok(()) => attack(),
                Err(_) => 100,
            };
            // SAFETY: `_exit` terminates the forked child immediately without running
            // atexit handlers or flushing inherited stdio — the correct post-fork exit.
            unsafe { nix::libc::_exit(code) }
        }
        Ok(ForkResult::Parent { child }) => match waitpid(child, None) {
            Ok(WaitStatus::Exited(_, code)) => code,
            other => panic!("attacker child did not exit normally: {other:?}"),
        },
        Err(e) => panic!("fork failed: {e}"),
    }
}

fn assert_dir_root_owned_0711(dir: &Path) {
    let m = std::fs::metadata(dir).expect("stat dir");
    assert_eq!(m.uid(), 0, "anchor dir must be root-owned");
    assert_eq!(m.mode() & 0o777, 0o711, "anchor dir mode must be 0711");
}

fn assert_socket_group_0660(socket: &Path, gid: u32) {
    let m = std::fs::metadata(socket).expect("stat socket");
    assert_eq!(m.uid(), 0, "socket owner must be root");
    assert_eq!(m.gid(), gid, "socket group must be the session gid");
    assert_eq!(m.mode() & 0o777, 0o660, "socket mode must be 0660");
}

/// THE BOTH-HALVES ANCHOR TEST: a same-uid process CANNOT unlink/replace the
/// socket (anchor — the directory is root-owned) AND CAN `connect()` to it
/// (connectable — the socket is `0660` group-owned by the session).
#[test]
fn anchor_is_unsubstitutable_yet_connectable() {
    if skip_if_not_root("anchor_is_unsubstitutable_yet_connectable") {
        return;
    }

    let base = unique_base("both");
    cleanup(&base);
    let dir = ensure_runtime_dir(&base, "session").expect("establish root-owned dir");
    let (paths, _listener) = bind_approval_socket(&dir, TEST_GID).expect("bind approval socket");

    assert_dir_root_owned_0711(&paths.dir);
    assert_socket_group_0660(&paths.socket, TEST_GID);

    let socket = paths.socket.clone();
    let code = run_as_test_user(move || {
        // (i) ANCHOR HALF: unlink must be DENIED (no write on the root-owned dir).
        let unlink_denied = std::fs::remove_file(&socket).is_err();
        // (ii) CONNECTABLE HALF: connect must SUCCEED (0660 socket, session group).
        let connected = UnixStream::connect(&socket).is_ok();

        let mut code = 0;
        if !unlink_denied {
            code |= 1; // breach: the attacker substituted the socket
        }
        if !connected {
            code |= 2; // regression: the legitimate client cannot connect
        }
        code
    });

    cleanup(&base);
    assert_eq!(
        code, 0,
        "both halves must hold (bit0=unlink-breach, bit1=connect-failed); \
         unsubstitutable YET connectable"
    );
}

/// THE RED-PROOF (positive control): with a deliberately USER-OWNED directory,
/// the same-uid attacker CAN unlink the socket. This proves the both-halves
/// test's denial is the *root-ownership* property — not a vacuous pass where the
/// attacker errors for an unrelated reason. If denial were vacuous, this test
/// would see the unlink fail and FAIL.
#[test]
fn red_proof_user_owned_dir_lets_attacker_unlink() {
    if skip_if_not_root("red_proof_user_owned_dir_lets_attacker_unlink") {
        return;
    }

    let base = unique_base("red");
    cleanup(&base);
    let dir = ensure_runtime_dir(&base, "session").expect("establish dir");
    let (paths, _listener) = bind_approval_socket(&dir, TEST_GID).expect("bind approval socket");

    // WEAKEN the anchor: give the per-session directory to the attacker uid, so it
    // now has write on the directory and can unlink inodes within it.
    chown(
        paths.dir.as_path(),
        Some(Uid::from_raw(TEST_UID)),
        Some(Gid::from_raw(TEST_GID)),
    )
    .expect("weaken: chown dir to the attacker");

    let socket = paths.socket.clone();
    let code = run_as_test_user(move || {
        // With a user-owned dir the unlink MUST succeed (anchor broken on purpose).
        if std::fs::remove_file(&socket).is_ok() {
            0
        } else {
            1
        }
    });

    cleanup(&base);
    assert_eq!(
        code, 0,
        "RED-proof: with a user-owned directory the same-uid attacker MUST be able to \
         unlink the socket — confirming the anchor test bites root-ownership, not a vacuous pass"
    );
}
