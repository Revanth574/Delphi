// SPDX-License-Identifier: MIT

//! PAM consent routing — the interposition surface (Increment 1c).
//!
//! ONE experiment, ONE variable: the **routing**. Same throwaway-user attacker,
//! same shared surface, same assertion; only where the consent conversation flows
//! differs.
//!
//! * CORRECT — the daemon routes the conversation over the **private channel**
//!   (`pam::authenticate_over_channel`); a same-uid attacker attached to the
//!   shared surface OBSERVES NOTHING (the prompt went to the channel it cannot
//!   reach).
//! * RED — the SAME attacker, SAME surface, but the conversation is routed over
//!   the **shared surface**; the attacker now OBSERVES the consent prompt. The
//!   "observed nothing" assertion flips.
//!
//! The two cases validate each other: CORRECT shows the routing protects; RED
//! shows the attacker was genuinely capable (so CORRECT's green is not vacuous).
//!
//! # Scope of the claim (carried to the 1d review)
//!
//! This proves the **routing** half only. That the private channel is unreachable
//! to a same-uid attacker is **1b's** proof (`sibling_fd_theft`), *reused*.
//! PAM-interposition-resistance = `(1c routing) + (1b channel-privacy)`, composed.
//!
//! Liveness is honest: `pam_authenticate` is LIVE against `/etc/shadow`
//! (`rc=0`/`rc=7`); the human response is SCRIPTED over the shell-end. Green means
//! "routes over the private channel + PAM authenticates", NOT "a human approved".
//!
//! Privileged: EUID-gated (PAM auth needs root for `/etc/shadow`). Run the
//! WSL2-root lane, single-threaded (the experiment forks):
//!
//! ```text
//! wsl -u root -- env -C /mnt/c/dev/Delphi PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH \
//!   /home/raven/.cargo/bin/cargo test -p delphi-runtime --test pam_interposition \
//!   -- --test-threads=1 --nocapture
//! ```

use std::ffi::{CStr, CString};
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, geteuid, ForkResult, Gid, Pid, Uid, User};
use pam_client2::{Context, ConversationHandler, ErrorCode, Flag};

use delphi_runtime::pam::authenticate_over_channel;
use delphi_runtime::{approval_socketpair, drop_privileges, RealPrivDropOps};

const SERVICE: &str = "delphi-runtime";
const UNIT_PAM: &str = "/etc/pam.d/delphi-runtime";
const PASSWORD: &str = "Delphi1cConsent!";

fn skip_if_not_root(name: &str) -> bool {
    if geteuid().as_raw() != 0 {
        eprintln!(
            "SKIP {name}: PAM auth needs root (/etc/shadow). Run the privileged lane:\n  \
             wsl -u root -- env -C /mnt/c/dev/Delphi PATH=/usr/sbin:/usr/bin:/sbin:/bin:$PATH \\\n    \
             /home/raven/.cargo/bin/cargo test -p delphi-runtime --test pam_interposition \\\n    \
             -- --test-threads=1 --nocapture"
        );
        return true;
    }
    false
}

/// Installs the PAM service + a throwaway user with a known password; tears them
/// down on drop.
struct Setup {
    user: String,
    /// True only if THIS test created the PAM file; gates removal on drop (Class 16).
    provisioned: bool,
}

impl Setup {
    fn new() -> Self {
        let user = format!("dpam{}", std::process::id() % 100_000);
        let _ = Command::new("userdel").arg(&user).status();
        assert!(
            Command::new("useradd")
                .args(["-M", "-s", "/usr/sbin/nologin", &user])
                .status()
                .expect("useradd")
                .success(),
            "useradd {user}"
        );
        let mut ch = Command::new("chpasswd")
            .stdin(Stdio::piped())
            .spawn()
            .expect("chpasswd spawn");
        ch.stdin
            .take()
            .unwrap()
            .write_all(format!("{user}:{PASSWORD}").as_bytes())
            .expect("write chpasswd");
        assert!(ch.wait().expect("chpasswd wait").success(), "chpasswd");
        // ADOPT an operator-installed stack; only PROVISION one if absent (Class 16).
        // This file was the THIRD copy of the write-and-delete pattern; the first fix missed
        // it, so it kept deleting the operator's real /etc/pam.d/delphi-runtime.
        let provisioned = if std::path::Path::new(UNIT_PAM).exists() {
            false
        } else {
            std::fs::write(UNIT_PAM, "auth required pam_unix.so\naccount required pam_unix.so\n")
                .expect("install pam service");
            true
        };
        Self { user, provisioned }
    }

    fn ids(&self) -> (Uid, Gid) {
        let u = User::from_name(&self.user).expect("getpwnam").expect("user exists");
        (u.uid, u.gid)
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        // Remove ONLY a file this test created; an operator-installed stack is left alone.
        if self.provisioned {
            let _ = std::fs::remove_file(UNIT_PAM);
        }
        let _ = Command::new("userdel").arg(&self.user).status();
    }
}

#[derive(Clone, Copy)]
enum Routing {
    PrivateChannel,
    SharedSurface,
}

impl Routing {
    fn tag(self) -> &'static str {
        match self {
            Routing::PrivateChannel => "chan",
            Routing::SharedSurface => "shared",
        }
    }
}

/// The deliberately-WEAKENED (test-only) conversation: routes the prompt/response
/// over a same-uid-readable shared file instead of the private channel.
struct SharedSurfaceConversation {
    prompt_path: PathBuf,
    response_path: PathBuf,
}

impl SharedSurfaceConversation {
    fn exchange(&self, prompt: &CStr) -> Result<CString, ErrorCode> {
        // Expose the prompt on the shared surface (world-readable in /tmp).
        std::fs::write(&self.prompt_path, prompt.to_bytes()).map_err(|_| ErrorCode::CONV_ERR)?;
        for _ in 0..100 {
            if let Ok(r) = std::fs::read(&self.response_path)
                && !r.is_empty()
            {
                return CString::new(trim_nl(&r)).map_err(|_| ErrorCode::CONV_ERR);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(ErrorCode::CONV_ERR)
    }
}

impl ConversationHandler for SharedSurfaceConversation {
    fn prompt_echo_on(&mut self, p: &CStr) -> Result<CString, ErrorCode> {
        self.exchange(p)
    }
    fn prompt_echo_off(&mut self, p: &CStr) -> Result<CString, ErrorCode> {
        self.exchange(p)
    }
    fn text_info(&mut self, _m: &CStr) {}
    fn error_msg(&mut self, _m: &CStr) {}
}

fn trim_nl(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && (b[end - 1] == b'\n' || b[end - 1] == b'\r') {
        end -= 1;
    }
    &b[..end]
}

fn fork_child<F: FnOnce()>(f: F) -> Pid {
    // SAFETY: test-only fork; the child runs `f` (which drops privileges and
    // `_exit`s) and never returns to the harness.
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
            f();
            unreachable!("the child body must _exit and never return")
        }
        Ok(ForkResult::Parent { child }) => child,
        Err(e) => panic!("fork: {e}"),
    }
}

fn drop_to(uid: Uid, gid: Gid) {
    drop_privileges(&RealPrivDropOps, uid, gid).expect("drop to throwaway user");
}

/// The attacker: a same-uid process attached to the shared surface. Exits 1 if it
/// OBSERVES a (non-empty) prompt there, else 0 after the poll window.
fn be_attacker(prompt_path: &Path, uid: Uid, gid: Gid) -> ! {
    drop_to(uid, gid);
    for _ in 0..40 {
        if let Ok(c) = std::fs::read(prompt_path)
            && !c.is_empty()
        {
            // SAFETY: immediate child exit — observed the prompt.
            unsafe { nix::libc::_exit(1) }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // SAFETY: immediate child exit — observed nothing.
    unsafe { nix::libc::_exit(0) }
}

/// The scripted human on the private channel's shell-end: read the prompt, write
/// the password.
fn be_human_channel(shell_end: RawFd, uid: Uid, gid: Gid) -> ! {
    drop_to(uid, gid);
    // SAFETY: read the prompt datagram, write the password datagram on the
    // inherited channel fd; buffer is stack-local.
    unsafe {
        let mut buf = [0u8; 4096];
        let _ = nix::libc::read(shell_end, buf.as_mut_ptr().cast(), buf.len());
        let _ = nix::libc::write(shell_end, PASSWORD.as_ptr().cast(), PASSWORD.len());
        nix::libc::_exit(0)
    }
}

/// The scripted human on the shared surface: wait for the prompt file, write the
/// password to the response file.
fn be_human_shared(prompt_path: &Path, response_path: &Path, uid: Uid, gid: Gid) -> ! {
    drop_to(uid, gid);
    for _ in 0..60 {
        if prompt_path.exists() {
            let _ = std::fs::write(response_path, PASSWORD);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // SAFETY: immediate child exit.
    unsafe { nix::libc::_exit(0) }
}

fn run_pam_shared(user: &str, conv: SharedSurfaceConversation) -> bool {
    let Ok(mut ctx) = Context::new(SERVICE, Some(user), conv) else {
        return false;
    };
    if ctx.authenticate(Flag::NONE).is_err() {
        return false;
    }
    ctx.acct_mgmt(Flag::NONE).is_ok()
}

/// Run the experiment for one routing. Returns `(auth_ok, attacker_observed)`.
fn run_experiment(routing: Routing, setup: &Setup) -> (bool, bool) {
    let pid = std::process::id();
    let prompt_path = PathBuf::from(format!("/tmp/delphi-consent-prompt-{pid}-{}", routing.tag()));
    let response_path =
        PathBuf::from(format!("/tmp/delphi-consent-response-{pid}-{}", routing.tag()));
    let _ = std::fs::remove_file(&prompt_path);
    let _ = std::fs::remove_file(&response_path);
    let (uid, gid) = setup.ids();

    let chan = matches!(routing, Routing::PrivateChannel).then(|| approval_socketpair().unwrap());

    // The attacker is attached to the shared surface in BOTH cases.
    let pp = prompt_path.clone();
    let attacker = fork_child(move || be_attacker(&pp, uid, gid));

    // The scripted human services the conversation over the routing in use.
    let human = match &chan {
        Some((_d, shell)) => {
            let s = shell.as_raw_fd();
            fork_child(move || be_human_channel(s, uid, gid))
        }
        None => {
            let (pp, rp) = (prompt_path.clone(), response_path.clone());
            fork_child(move || be_human_shared(&pp, &rp, uid, gid))
        }
    };

    // The daemon (root) drives live PAM over the routing in use.
    let auth_ok = match &chan {
        Some((d, _shell)) => {
            authenticate_over_channel(SERVICE, &setup.user, d.as_raw_fd()).is_ok()
        }
        None => run_pam_shared(
            &setup.user,
            SharedSurfaceConversation {
                prompt_path: prompt_path.clone(),
                response_path: response_path.clone(),
            },
        ),
    };

    let _ = waitpid(human, None);
    let observed = matches!(waitpid(attacker, None), Ok(WaitStatus::Exited(_, 1)));

    let _ = std::fs::remove_file(&prompt_path);
    let _ = std::fs::remove_file(&response_path);
    (auth_ok, observed)
}

/// CORRECT: routing over the private channel denies the same-uid attacker any
/// observation (composes with 1b's channel-privacy).
#[test]
fn interposition_denied_when_routed_over_private_channel() {
    if skip_if_not_root("interposition_denied_when_routed_over_private_channel") {
        return;
    }
    let setup = Setup::new();
    let (auth_ok, observed) = run_experiment(Routing::PrivateChannel, &setup);
    assert!(auth_ok, "live pam_authenticate must succeed with the correct scripted password");
    assert!(
        !observed,
        "ROUTING over the private channel: the same-uid attacker attached to the shared \
         surface OBSERVED NOTHING (the prompt went to the channel, unreachable per 1b). \
         PAM-interposition-resistance = 1c routing + 1b channel-privacy, composed."
    );
}

/// RED-proof (durable positive control): the SAME attacker on the SAME surface,
/// routing flipped to the shared surface → it OBSERVES the prompt. Proves the
/// routing is load-bearing AND that the correct-case attacker was genuinely
/// capable.
#[test]
fn red_proof_shared_surface_routing_lets_attacker_observe_prompt() {
    if skip_if_not_root("red_proof_shared_surface_routing_lets_attacker_observe_prompt") {
        return;
    }
    let setup = Setup::new();
    let (auth_ok, observed) = run_experiment(Routing::SharedSurface, &setup);
    assert!(auth_ok, "live pam_authenticate succeeds (correct password) regardless of routing");
    assert!(
        observed,
        "RED-proof: SAME attacker, SAME surface, routing flipped to the shared surface — the \
         attacker OBSERVED the consent prompt (confidentiality break). The routing is what \
         protects; the correct-case attacker was genuinely positioned."
    );
}
