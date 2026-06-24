// SPDX-License-Identifier: MIT

//! F1 in running code (Increment 1b) — the trust model's strongest result.
//!
//! A same-uid **sibling** AI cannot steal the shell's approval fd via
//! `pidfd_getfd` under Yama `ptrace_scope=1` (`docs/TRUST_MODEL.md` §4, F1 closure
//! and R3-03). `pidfd_getfd` needs `PTRACE_MODE_ATTACH_REALCREDS`, and Yama
//! `scope=1` permits attach only to a **descendant** — the AI is the shell's
//! *sibling* (the daemon parents both), not its ancestor, so it is denied.
//!
//! This test proves the denial holds **by topology alone**: the shell is run at
//! `PR_SET_DUMPABLE=1`, so the kernel's credential check would otherwise permit a
//! same-uid tracer — the denial is therefore Yama ancestry (load-bearing), and
//! `PR_SET_DUMPABLE=0` is belt-and-suspenders (the round-3 distinction in code).
//!
//! The RED-proof inverts the topology: when the AI is the shell's **ancestor**
//! (the AI forks the shell), Yama *permits* the theft and it SUCCEEDS — proving
//! the sibling denial bites the not-ancestor property, not something incidental.
//! (Using "AI is a child of the shell" would also be denied — as an ancestor of
//! the AI — and stay green for the wrong reason; the bite requires attacker-as-
//! ancestor.)
//!
//! Privileged + Yama-conditional: EUID-gated AND requires `ptrace_scope=1` (a
//! deploy requirement the trust model already names). Run the WSL2-root lane,
//! single-threaded (the topologies use `fork`):
//!
//! ```text
//! wsl -u root -- env -C /mnt/c/dev/Delphi /home/raven/.cargo/bin/cargo test \
//!   -p delphi-runtime --test sibling_fd_theft -- --test-threads=1 --nocapture
//! ```

use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, geteuid, pipe, ForkResult, Gid, Pid, Uid};

use delphi_runtime::{approval_socketpair, drop_privileges, RealPrivDropOps};

const TEST_UID: u32 = 60000;
const TEST_GID: u32 = 60000;
/// The fd number at which the shell holds the approval channel (the AI's target).
const APPROVAL_FD: RawFd = 3;

fn yama_scope() -> i32 {
    std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(-1)
}

/// Skip (printing why) unless root AND Yama `ptrace_scope=1` — the defense's
/// precondition. Not a `#[ignore]`: it self-documents and runs when able.
fn skip_unless_root_and_yama(name: &str) -> bool {
    if geteuid().as_raw() != 0 {
        eprintln!(
            "SKIP {name}: requires root + a same-uid sibling. Run the privileged lane:\n  \
             wsl -u root -- env -C /mnt/c/dev/Delphi \\\n    \
             /home/raven/.cargo/bin/cargo test -p delphi-runtime --test sibling_fd_theft \\\n    \
             -- --test-threads=1 --nocapture"
        );
        return true;
    }
    let scope = yama_scope();
    if scope != 1 {
        eprintln!(
            "SKIP {name}: Yama ptrace_scope is {scope}; the sibling F1 defense REQUIRES 1. \
             This is a DEPLOY REQUIREMENT (set kernel.yama.ptrace_scope=1 via sysctl)."
        );
        return true;
    }
    false
}

fn drop_to_test_user() {
    drop_privileges(&RealPrivDropOps, Uid::from_raw(TEST_UID), Gid::from_raw(TEST_GID))
        .expect("privilege drop to the test user");
}

/// The AI's fd-theft attempt: pin the target by pidfd, then `pidfd_getfd` its fd.
/// `Ok` = the descriptor was duplicated out of the target (theft succeeded);
/// `Err` = denied.
fn attack_steal_fd(target: Pid, target_fd: RawFd) -> Result<RawFd, Errno> {
    // SAFETY: raw pidfd syscalls. On success `pidfd` is a valid fd we close here;
    // a stolen fd (if any) is returned for the caller to drop.
    unsafe {
        let pidfd = nix::libc::syscall(nix::libc::SYS_pidfd_open, target.as_raw(), 0);
        if pidfd < 0 {
            return Err(Errno::last());
        }
        let stolen = nix::libc::syscall(nix::libc::SYS_pidfd_getfd, pidfd, target_fd as i64, 0);
        nix::libc::close(pidfd as nix::libc::c_int);
        if stolen < 0 {
            Err(Errno::last())
        } else {
            Ok(stolen as RawFd)
        }
    }
}

/// The shell child: hold the approval fd at [`APPROVAL_FD`], set dumpable, signal
/// ready, then park. Never returns.
fn be_the_shell(approval_raw: RawFd, dumpable: bool, ready_w: RawFd) -> ! {
    drop_to_test_user();
    // SAFETY: raw syscalls in a forked child that only arranges its fd + dumpable
    // state and then blocks; nothing here allocates or takes a shared lock.
    unsafe {
        nix::libc::dup2(approval_raw, APPROVAL_FD);
        nix::libc::prctl(nix::libc::PR_SET_DUMPABLE, i32::from(dumpable), 0, 0, 0);
        let byte = [1u8];
        nix::libc::write(ready_w, byte.as_ptr().cast(), 1);
        loop {
            nix::libc::pause();
        }
    }
}

fn wait_code(pid: Pid) -> i32 {
    match waitpid(pid, None) {
        Ok(WaitStatus::Exited(_, code)) => code,
        other => panic!("child {pid} did not exit normally: {other:?}"),
    }
}

fn read_ready(ready_r: OwnedFd) {
    let mut f = std::fs::File::from(ready_r);
    let mut b = [0u8; 1];
    let _ = f.read_exact(&mut b);
}

/// THE F1 TEST: a same-uid SIBLING AI is denied `pidfd_getfd` of the shell's
/// approval fd — by topology (Yama ancestry), proven at dumpable=1.
#[test]
fn f1_sibling_cannot_steal_shell_fd() {
    if skip_unless_root_and_yama("f1_sibling_cannot_steal_shell_fd") {
        return;
    }

    let (_daemon_end, shell_end) = approval_socketpair().expect("approval channel");
    let shell_raw = shell_end.as_raw_fd();
    let (ready_r, ready_w) = pipe().expect("ready pipe");
    let ready_w_raw = ready_w.as_raw_fd();

    // This process (the daemon) parents BOTH children → they are siblings.
    // SAFETY: test-only fork; the child diverges into `be_the_shell`.
    let shell_pid = match unsafe { fork() } {
        Ok(ForkResult::Child) => be_the_shell(shell_raw, /* dumpable = */ true, ready_w_raw),
        Ok(ForkResult::Parent { child }) => child,
        Err(e) => panic!("fork shell: {e}"),
    };
    read_ready(ready_r);

    // SAFETY: test-only fork; the child drops privileges, attacks, and `_exit`s.
    let ai_pid = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            drop_to_test_user();
            // The AI holds NO approval fd: close every inherited fd >= 3.
            // SAFETY: best-effort close of inherited descriptors in the child.
            let _ = unsafe { nix::libc::close_range(3, u32::MAX, 0) };
            let code = match attack_steal_fd(shell_pid, APPROVAL_FD) {
                Err(_) => 0, // DENIED, as F1 requires
                Ok(_) => 1,  // BREACH: a sibling stole the fd
            };
            // SAFETY: immediate post-fork child exit.
            unsafe { nix::libc::_exit(code) }
        }
        Ok(ForkResult::Parent { child }) => child,
        Err(e) => panic!("fork ai: {e}"),
    };

    let code = wait_code(ai_pid);
    let _ = kill(shell_pid, Signal::SIGKILL);
    let _ = waitpid(shell_pid, None);

    assert_eq!(
        code, 0,
        "F1: a same-uid SIBLING must be DENIED pidfd_getfd of the shell's approval fd under \
         Yama scope=1 — and at dumpable=1, proving the denial is the sibling TOPOLOGY \
         (load-bearing), not PR_SET_DUMPABLE=0 (belt)"
    );
}

/// THE RED-PROOF (positive control): when the AI is the shell's ANCESTOR (AI forks
/// the shell), Yama permits the theft and it SUCCEEDS — proving the sibling denial
/// bites the not-ancestor property. The AI drops to the shell's uid first, so the
/// success is ANCESTRY, not root privilege.
#[test]
fn red_proof_ancestor_can_steal_shell_fd() {
    if skip_unless_root_and_yama("red_proof_ancestor_can_steal_shell_fd") {
        return;
    }

    let (_daemon_end, shell_end) = approval_socketpair().expect("approval channel");
    let shell_raw = shell_end.as_raw_fd();

    // SAFETY: test-only fork; the AI child forks the shell, attacks, and `_exit`s.
    let ai_pid = match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            let (ready_r, ready_w) = pipe().expect("ready pipe");
            let ready_w_raw = ready_w.as_raw_fd();
            // The AI (still root) forks the shell so the shell can drop from root;
            // the shell is then the AI's DESCENDANT.
            // SAFETY: nested test-only fork; the grandchild diverges into the shell.
            let shell_pid = match unsafe { fork() } {
                Ok(ForkResult::Child) => be_the_shell(shell_raw, true, ready_w_raw),
                Ok(ForkResult::Parent { child }) => child,
                // SAFETY: immediate child exit on fork failure.
                Err(_) => unsafe { nix::libc::_exit(101) },
            };
            read_ready(ready_r);
            // Drop to the shell's uid: success must be ancestry, not root.
            drop_to_test_user();
            let code = match attack_steal_fd(shell_pid, APPROVAL_FD) {
                Ok(_) => 0,  // theft SUCCEEDED, as the ancestor topology permits
                Err(_) => 1, // unexpectedly denied
            };
            let _ = kill(shell_pid, Signal::SIGKILL);
            let _ = waitpid(shell_pid, None);
            // SAFETY: immediate post-fork child exit.
            unsafe { nix::libc::_exit(code) }
        }
        Ok(ForkResult::Parent { child }) => child,
        Err(e) => panic!("fork ai: {e}"),
    };

    let code = wait_code(ai_pid);
    assert_eq!(
        code, 0,
        "RED-proof: an ANCESTOR (AI forks the shell) MUST be able to pidfd_getfd the shell's \
         fd (Yama permits tracing descendants) — proving the sibling denial bites the \
         not-ancestor property, not something incidental"
    );
}
