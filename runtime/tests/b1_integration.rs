// SPDX-License-Identifier: MIT

//! B1 — the assembled boundary, both halves (Increment B1).
//!
//! Half (i) HAPPY PATH: the daemon's launcher forks the minimal shell + AI as
//! same-uid siblings; the AI proposes one action over the real protobuf wire; the
//! (scripted) human approves over the private channel via live PAM; the daemon mints
//! the digest-bound token, the AI presents it, and the STORED canonical object
//! executes — one action, end to end, as one real process tree. The first
//! integrated breath.
//!
//! Half (ii) THE ATTACK TESTS BITE THE ASSEMBLED LOOP:
//!  * **approve-A/execute-B** (foremost): a token legitimately obtained for A is
//!    REJECTED when presented for a different stored action B — and A's token still
//!    runs A, and a replay is denied. The half-(ii) invariant on the real
//!    `present_and_execute`.
//!  * **launcher fd-discipline** (sibling-fd-theft at the launcher): the forked AI
//!    holds NO channel fd — verified via `/proc/<ai>/fd`.
//!  * **logind-deny**: a non-active session denies the assembled service loop.
//!
//! Privileged + bwrap-gated; run the WSL2-root lane single-threaded:
//! `wsl -u root -- … cargo test -p delphi-runtime --test b1_integration -- --test-threads=1`

use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::sys::wait::waitpid;
use nix::unistd::{geteuid, Gid, Uid, User};

use delphi_runtime::action::{
    canonical_action_digest, NetPolicy, PendingAction, RequiredTier, ScriptPin,
};
use delphi_runtime::canonicalize::canonicalize;
use delphi_runtime::execute::ConsumptionLedger;
use delphi_runtime::launcher::{launch, LaunchSpec, VtName};
use delphi_runtime::service::{
    accept_requester, present_and_execute, propose_msg, serve_one_action, Clock, Outcome,
    ServiceCtx,
};
use delphi_runtime::store::{PendingState, PendingStore};
use delphi_runtime::token::{mint, MintingKey, TOKEN_TTL_SECS};
use delphi_runtime::wire::{pb, write_frame};
use delphi_runtime::{approval_socketpair, bind_approval_socket, ensure_runtime_dir};

#[path = "common/shell_fixtures.rs"]
mod shell_fixtures;

/// The VT these B1 specs hand PAM as `PAM_TTY`. B1's assertions are about the fd discipline,
/// the wire, and the token — not about seating — but `LaunchSpec` now requires a validated
/// [`VtName`], so they supply a well-formed one. Whether `/dev/tty1` is actually the seat's
/// foreground is the *lane's* concern (§4 R3-02a), not these tests'.
fn test_vt() -> &'static VtName {
    static VT: std::sync::OnceLock<VtName> = std::sync::OnceLock::new();
    VT.get_or_init(|| VtName::new("tty1").expect("tty1 is a well-formed VT name"))
}

const SERVICE: &str = "delphi-runtime";
const PAM_FILE: &str = "/etc/pam.d/delphi-runtime";
/// The REAL production stack (`installer/pam/delphi-runtime`), not a stand-in.
///
/// The former two-line fixture had `auth` + `account` but **no `session` group**, so
/// `pam_open_session` registered no logind session — under which B-1's leader==shell
/// assertion fails for BOTH topologies (FAIL/FAIL), exactly as non-discriminating as the
/// PASS/PASS a skipped test gives. A populated `session` group is a B-1 PRECONDITION.
const PAM_STACK: &str = include_str!("../../installer/pam/delphi-runtime");
const PASSWORD: &str = "Delphi-B1-Spine!";
const NOW: u64 = 1_000;
const KEY: [u8; 32] = [0x5B; 32];

/// The verdict the gate reads, injected as a SOURCE (WSL2 sessions are ephemeral, so a real
/// `for_pid` query is unreliable — the `logind_gate` test proves the real logind query).
/// `SessionSnapshot` is both the triple and a source of it, so these sites need no adapter.
type Verdict = delphi_runtime::logind::SessionSnapshot;

const PASS: Verdict = Verdict { active: true, remote: false, seated: true };

/// A fixed-time clock (every read returns the same second).
struct FixedClock(u64);
impl Clock for FixedClock {
    fn now_unix(&self) -> u64 {
        self.0
    }
}

/// A clock that returns a pre-programmed SEQUENCE of times (clamped to the last) —
/// so the daemon's mint read and its Present-verify read differ deterministically,
/// without sleeping. The token-expiry RED uses `[mint, mint + TTL + 1]`.
struct SeqClock {
    times: Vec<u64>,
    idx: std::sync::atomic::AtomicUsize,
}
impl Clock for SeqClock {
    fn now_unix(&self) -> u64 {
        let i = self.idx.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.times[i.min(self.times.len() - 1)]
    }
}

fn bwrap_available() -> bool {
    Command::new("bwrap")
        .args(["--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64", "/lib64", "--unshare-all", "--die-with-parent", "--", "/usr/bin/true"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// A throwaway PAM user with a known password + the PAM service file; torn down on drop.
struct Setup {
    user: String,
    /// True only if THIS test created the PAM file; gates removal on drop (Class 16).
    provisioned: bool,
}
impl Setup {
    fn new(tag: &str) -> Self {
        // D0-R7-05: the per-test entry assertion belongs HERE, not at N call sites. This
        // binary has four `launch()` consumers plus the daemon case, all on tty1, and its
        // teardown is itself one of the unproven fixes — so it is the binary most likely to
        // leak and was the one without entry attribution. Centralising is also what keeps a
        // future test from silently omitting it: every test goes through `Setup::new`.
        delphi_runtime::test_child_guard::assert_no_stale_session_on(test_vt().as_pam_tty());
        let user = format!("db1{tag}{}", std::process::id() % 10_000);
        let _ = Command::new("userdel").arg(&user).status();
        assert!(Command::new("useradd").args(["-M", "-s", "/usr/sbin/nologin", &user]).status().unwrap().success());
        let mut ch = Command::new("chpasswd").stdin(Stdio::piped()).spawn().unwrap();
        ch.stdin.take().unwrap().write_all(format!("{user}:{PASSWORD}").as_bytes()).unwrap();
        assert!(ch.wait().unwrap().success());
        // ADOPT an operator-installed stack; only PROVISION one if absent (defect Class 16).
        // These fixtures used to write this path unconditionally and remove_file it on drop —
        // harmless while it was scaffolding, DESTRUCTIVE once production installed the same
        // path. A test must never delete a system file it did not create.
        let provisioned = if std::path::Path::new(PAM_FILE).exists() {
            false
        } else {
            std::fs::write(PAM_FILE, PAM_STACK).unwrap();
            true
        };
        Self { user, provisioned }
    }
    fn ids(&self) -> (Uid, Gid) {
        let u = User::from_name(&self.user).unwrap().unwrap();
        (u.uid, u.gid)
    }
}
impl Drop for Setup {
    fn drop(&mut self) {
        // Remove ONLY a file this test created; an operator-installed stack is left alone.
        if self.provisioned {
            let _ = std::fs::remove_file(PAM_FILE);
        }
        // Same three layers as leader_is_shell's Setup::drop, which was fixed after
        // measuring 1 leaked account per passing iteration on the lane. This one was the
        // NAIVE version — no session teardown, no wait, and a DISCARDED status, so a failure
        // here was invisible. It leaks the same way for the same reason.
        let _ = Command::new("loginctl").args(["terminate-user", &self.user]).status();
        // D0A-R4-08: `terminate-user` alone does not take the USER MANAGER down promptly.
        // `pam_systemd` starts a `systemd --user` (plus dbus, pipewire, portals) that OUTLIVES
        // the daemon and HOLDS THE SESSION until it times out — measured at roughly a minute.
        // The session-scoped and `delphi-runtimed`-scoped kills cannot reach it: its cmdline is
        // `/lib/systemd/systemd --user`. So the manager is stopped explicitly, by unit.
        //
        // This is what blocked FIVE root attempts: the guard is SERVICE-keyed (D0-R6-01, and
        // rightly so — it must catch a leak on any VT), so one lingering `delphi-runtime`
        // session anywhere fails the next test's precondition, and `--vt` only ADDS a match
        // rather than narrowing it. Test 1 left a closing session; test 2 never started.
        if let Ok(out) = Command::new("id").args(["-u", &self.user]).output()
            && let Ok(uid) = String::from_utf8_lossy(&out.stdout).trim().parse::<u32>()
        {
            let _ = Command::new("systemctl")
                .args(["stop", &format!("user@{uid}.service")])
                .status();
            let _ = Command::new("systemctl")
                .args(["stop", &format!("user-runtime-dir@{uid}.service")])
                .status();
        }
        // D0-R6-04: `terminate-user` RETURNS BEFORE the sessions are gone. Deleting straight
        // after it meant `userdel` raced the teardown and the `-f` escalation covered for it —
        // which is an escalation masking a problem it should have reported.
        // 40x50ms = 2s was tuned for a session close; the MANAGER takes far longer, so the
        // budget now covers it (600x50ms = 30s) rather than timing out and reporting a leak
        // that would have cleared on its own.
        for _ in 0..600 {
            // D0-R7-04: `.unwrap_or(false)` mapped a FAILED loginctl to "no session", so a
            // spawn failure or a dead bus read as clean and userdel proceeded immediately.
            // An unknown answer is treated as BUSY — the poll then times out and the
            // userdel path reports, which is the loud outcome rather than the quiet one.
            //
            // The match is on the WHOLE user field, not a substring: `db1f16` is a substring
            // of `db1f1605`, so `contains` could report a different test's session as ours.
            let busy = match Command::new("loginctl")
                .args(["list-sessions", "--no-legend"])
                .output()
            {
                Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.split_whitespace().nth(2) == Some(self.user.as_str())),
                _ => true, // unknown => assume busy, never "clean"
            };
            if !busy {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        match Command::new("userdel").arg(&self.user).output() {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                let why = String::from_utf8_lossy(&o.stderr).trim().to_owned();
                let forced = Command::new("userdel").args(["-f", &self.user]).output();
                match forced {
                    Ok(f) if f.status.success() => {
                        eprintln!("WARN: `userdel {}` failed ({why}); -f succeeded.", self.user)
                    }
                    _ => eprintln!(
                        "WARN: `userdel {}` failed ({why}) and -f did not recover — ACCOUNT \
                         LEAKED. Remove by hand: `sudo userdel -f {}`.",
                        self.user, self.user
                    ),
                }
            }
            Err(e) => eprintln!("WARN: could not run userdel for {}: {e}", self.user),
        }
    }
}

/// A `#!/bin/sh` action that echoes its `argv[1]` into `result`, with the toolset +
/// the writable output dir bound. Returns the executable path.
fn write_marker_exe(dir: &Path, result: &Path) -> PathBuf {
    let exe = dir.join("echo.sh");
    std::fs::write(&exe, format!("#!/bin/sh\necho \"$1\" > {}\n", result.display())).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    exe
}

/// An UNSEALED memfd holding `content` (`MFD_ALLOW_SEALING` but NO seals) — so the
/// execute-time `require_fully_sealed` check refuses it AFTER the token verified +
/// the ledger consumed (the verified-then-execution-failed window).
fn unsealed_memfd(content: &[u8]) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd;
    // SAFETY: fresh memfd; write content, apply NO seals, wrap once.
    unsafe {
        let fd = nix::libc::memfd_create(
            c"b1-unsealed".as_ptr(),
            (nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING) as nix::libc::c_uint,
        );
        assert!(fd >= 0, "memfd_create");
        let n = nix::libc::write(fd, content.as_ptr().cast(), content.len());
        assert_eq!(n, content.len() as isize, "write memfd");
        std::os::fd::OwnedFd::from_raw_fd(fd)
    }
}

/// Copy a built bin into `dir` (mode 0755) so the dropped session user can exec it
/// — the build target lives under `/home/raven`, which other uids cannot traverse.
fn stage_bin(src: &str, dir: &Path, name: &str) -> PathBuf {
    let dst = dir.join(name);
    std::fs::copy(src, &dst).expect("copy minimal-side bin");
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
    dst
}

fn marker_proposal(exe: &Path, marker: &str, out_dir: &Path) -> pb::Propose {
    let ro = |p: &str| pb::Bind { path: p.into(), mode: pb::BindMode::BindReadOnly as i32 };
    pb::Propose {
        argv: vec!["tool".into(), marker.into()],
        cwd: "/".into(),
        env_delta: vec![],
        fs_binds: vec![
            ro("/usr"),
            ro("/bin"),
            ro("/lib"),
            ro("/lib64"),
            pb::Bind { path: out_dir.display().to_string(), mode: pb::BindMode::BindReadWrite as i32 },
        ],
        exe_path: exe.display().to_string(),
        net_policy: pb::NetPolicy::NetNone as i32,
        timeout_secs: 30,
        required_tier: pb::RequiredTier::TierBiometric as i32,
    }
}

// ── Half (i): the happy path — one action through the assembled loop ─────────

#[test]
fn b1_happy_path_one_action_through_the_assembled_loop() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP b1_happy_path: requires root (anchor /run dir + PAM)");
        return;
    }
    if !bwrap_available() {
        eprintln!("SKIP b1_happy_path: requires bwrap + unprivileged userns");
        return;
    }
    let setup = Setup::new("h");
    let (uid, gid) = setup.ids();

    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = delphi_runtime::test_child_guard::ReportingTempDir::new(
        tempfile::Builder::new().prefix("delphi-b1-")
        .tempdir_in("/run").expect("tempdir"));
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");

    // The work dir (root-created, user-writable) holds the exe + the marker output.
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let result = work.join("result");
    let exe = write_marker_exe(&work, &result);

    // The children's env (scaffolding): the scripted password + the AI's fixed action.
    let exe_str = exe.display().to_string();
    let work_str = work.display().to_string();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &work, "mshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");
    let spec = LaunchSpec {
        // Sleeper/minimal fixtures signal at ENTRY — the weaker claim (D0-A A1).
        ready: delphi_runtime::readiness::ReadySemantics::ScaffoldEntry,
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: test_vt(),
        shell_env: &[(delphi_runtime::scaffold_env::PASSWORD, PASSWORD)],
        ai_env: &[
            (delphi_runtime::scaffold_env::AI_EXE, &exe_str),
            (delphi_runtime::scaffold_env::AI_ARG, "B1-LIVES"),
            (delphi_runtime::scaffold_env::AI_BIND_RW, &work_str),
        ],
    };
    let children = launch(&spec).expect("launch shell + AI");

    // The daemon (this test) services the one action.
    let mut ai = accept_requester(&listener, uid.as_raw()).expect("accept AI");
    let mut store = PendingStore::new();
    let mut ledger = ConsumptionLedger::new();
    let key = MintingKey::from_bytes(KEY);
    let mut ctx = ServiceCtx {
        channel_fd: children.daemon_channel.as_raw_fd(),
        session: &PASS,
        key: &key,
        pam_service: SERVICE,
        session_user: &setup.user,
        store: &mut store,
        ledger: &mut ledger,
        clock: &FixedClock(NOW),
    };
    let outcome = serve_one_action(&mut ai, &mut ctx).expect("serve one action");

    let _ = waitpid(nix::unistd::Pid::from_raw(children.shell_pid), None);
    let _ = waitpid(nix::unistd::Pid::from_raw(children.ai_pid), None);
    let marker = std::fs::read_to_string(&result).unwrap_or_default().trim().to_string();
    let _ = std::fs::remove_dir_all(&base);

    assert!(matches!(outcome, Outcome::Completed { .. }), "the action must complete: {outcome:?}");
    assert_eq!(marker, "B1-LIVES", "the STORED canonical action executed end-to-end");
}

/// A spawned `delphi-runtimed` that CANNOT outlive the test, on any exit path.
///
/// # Why RAII and not straight-line teardown (D0A-R4-07, second attempt)
///
/// The first fix waited-and-killed with ordinary statements after `spawn()`. That reaps on the
/// happy path and on a deadline — and **skips entirely on a panic**, which is the path these
/// tests actually take: an assertion fails, the stack unwinds past the teardown, and the daemon
/// is orphaned AS ROOT holding a VT. `Setup` was already RAII; the daemon was not, so a failing
/// test leaked a privileged process while a passing one did not.
///
/// It is the same argument made for `ReportingTempDir` in D0-R7-07 — explicit cleanup runs only
/// where it is called, a `Drop` runs everywhere — applied here only after it cost four orphans.
struct DaemonGuard {
    child: Option<std::process::Child>,
    session_user: String,
}

impl DaemonGuard {
    fn spawn(mut cmd: Command, session_user: &str) -> Self {
        use std::os::unix::process::CommandExt as _;
        let child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // D0A-R5-04: its OWN process group, so teardown can reach the DESCENDANTS. The
            // daemon forks a shell and an AI which INHERIT the pipes; killing only the daemon
            // leaves them holding the write ends, so `wait_with_output()` waits for an EOF
            // that never comes. That is the mechanism under four runs of hang-chasing.
            .process_group(0)
            .spawn()
            .expect("spawn the daemon binary");
        Self { child: Some(child), session_user: session_user.to_owned() }
    }

    /// Wait to a deadline, then take the output. A kill is reported by the caller's assertion;
    /// the REAPING has already happened either way.
    fn wait(mut self) -> (std::process::Output, bool) {
        let mut child = self.child.take().expect("child present");
        // D0A-R4-11: LONGER than the daemon's own 120 s accept bound, deliberately. At 45 s the
        // test always killed first, so the daemon's bounded exit was NEVER the thing observed —
        // one of the two deadlines was entirely unexercised, and a kill was reported where the
        // daemon's own error would have been more informative. Now the daemon gets to fail its
        // own way first, and this bound is the backstop for a hang it does not cover.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(150);
        let mut killed = false;
        loop {
            match child.try_wait().expect("try_wait") {
                Some(_) => break,
                None if std::time::Instant::now() >= deadline => {
                    Self::kill_group(child.id());
                    killed = true;
                    break;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(100)),
            }
        }
        // D0A-R5-04: the daemon has exited, but its shell and AI may not have — and they hold
        // the pipe write ends. Kill the GROUP before reading, or `wait_with_output()` blocks
        // for an EOF no living descendant will send.
        Self::kill_group(child.id());
        let out = child.wait_with_output().expect("collect daemon output");
        Self::sweep(&self.session_user);
        (out, killed)
    }

    /// Kill anything still running under this test's own session user. Scoped by user, so it
    /// can never touch a daemon another test owns.
    fn sweep(session_user: &str) {
        let _ = Command::new("pkill")
            .args(["-9", "-f", &format!("delphi-runtimed --session {session_user}")])
            .status();
    }

    /// Kill the whole process GROUP, so no descendant is left holding the pipes (D0A-R5-04).
    fn kill_group(pid: u32) {
        #[allow(clippy::cast_possible_wrap)]
        let pgid = pid as i32;
        // A NEGATIVE pid signals the group — legitimate here and the whole point, but only
        // ever computed from a positive child pid. D0A-R5-01's guard, restated where the sign
        // is deliberate rather than accidental.
        if pgid > 0 {
            // SAFETY: signalling the group led by a child this test spawned.
            unsafe { nix::libc::kill(-pgid, nix::libc::SIGKILL) };
        }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            // Reached only when the test panicked before `wait()` — the path that leaked.
            Self::kill_group(child.id());
            let _ = child.wait();
            eprintln!(
                "DaemonGuard: the test unwound before wait(); killed the daemon for {}",
                self.session_user
            );
        }
        Self::sweep(&self.session_user);
    }
}

// ── D0A-R4-03: the PRODUCTION wiring, which had never executed ──────────────

/// `LogindSource` + a real `shell_pidfd` + a real logind session, together.
///
/// # Why this test exists (D0A-R4-03, merge-blocking)
///
/// `LogindSource::for_pidfd` is constructed at exactly ONE site — `delphi-runtimed.rs:188` —
/// and the only test that ran the daemon binary enabled `insecure-test-seams`, whose seam
/// returns a `SessionSnapshot` and **never reaches `LogindSource` at all**. Every other test
/// injects a source. So each piece was proven and the ASSEMBLY was not. That is the same shape
/// as D0-A's own three findings, and it survived three review rounds for the same reason.
///
/// # Why the assertion is on the CAUSE and not on "it denied"
///
/// A denial is worthless as evidence here: a **broken** assembly denies too, fail-closed, and
/// looks identical. The discriminating claim is `Resolved` — the session was reached THROUGH
/// the real pidfd and described — with `active == false` as the axis that refused it.
/// `LookupNoData` would mean the wiring never got to logind, which is exactly what a
/// denial-only assertion hides. Same discrimination problem as the barrier's `rc != 0`, one
/// layer up.
#[test]
fn the_real_logind_source_resolves_the_shells_session_d0a_r4_03() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP r4_03_real_wiring: requires root (PAM session for the spawned shell)");
        return;
    }
    let setup = Setup::new("r403");
    let (uid, gid) = setup.ids();
    let _base_tmp = delphi_runtime::test_child_guard::ReportingTempDir::new(
        tempfile::Builder::new().prefix("delphi-r403-").tempdir_in("/run").expect("tempdir"),
    );
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");

    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &work, "mshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");
    // D0A-R4-09: the AI child `expect()`s these three. Omitting them made it panic BEFORE
    // connect, which is the hang both R4-03 legs were dying of — one defect, two symptoms.
    let result = work.join("result");
    let exe_str = write_marker_exe(&work, &result).display().to_string();
    let work_str = work.display().to_string();

    // A VT that is NOT the seat's foreground, so a RESOLVED session is denied on `active`
    // specifically — the one axis whose falsity proves the query reached logind and got an
    // answer, rather than failing closed on the way.
    let vt = VtName::new("tty3").expect("tty3");
    let spec = LaunchSpec {
        ready: delphi_runtime::readiness::ReadySemantics::ScaffoldEntry,
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: &vt,
        shell_env: &[(delphi_runtime::scaffold_env::PASSWORD, PASSWORD)],
        ai_env: &[
            (delphi_runtime::scaffold_env::AI_EXE, &exe_str),
            (delphi_runtime::scaffold_env::AI_ARG, "R4-03"),
            (delphi_runtime::scaffold_env::AI_BIND_RW, &work_str),
        ],
    };
    let children = launch(&spec).expect("launch");

    // THE PRODUCTION CONSTRUCTION, verbatim from delphi-runtimed.rs:188.
    use delphi_runtime::logind::SessionSource as _;
    use std::os::fd::AsFd as _;
    let source = delphi_runtime::logind::LogindSource::for_pidfd(children.shell_pidfd.as_fd());
    let cause = source.current();

    // D0A-R4-10: KILL BEFORE REAP. `waitpid(shell_pid, None)` is UNBOUNDED, and the minimal
    // shell blocks in `recv_approval_request` forever because this test deliberately never
    // drives the flow — it only wants the gate verdict. So the reap waited on a process that
    // had no reason to exit: seven attempts, zero output, no deadline anywhere on the path.
    // The 45 s bound lives in `DaemonGuard`, which this leg does not use.
    for pid in [children.shell_pid, children.ai_pid] {
        // SAFETY: signalling children this test created.
        unsafe { nix::libc::kill(pid, nix::libc::SIGKILL) };
        let _ = waitpid(nix::unistd::Pid::from_raw(pid), None);
    }

    match cause {
        delphi_runtime::logind::SessionResolution::Resolved(snap) => {
            assert!(
                !snap.active,
                "a session on a NON-foreground VT must not be active; got {snap:?}"
            );
            assert!(
                snap.seated,
                "the shell's session was opened with PAM_TTY on a seat, so it must be seated; \
                 got {snap:?} — if this is false the launcher's seat provisioning changed"
            );
            assert!(!snap.remote, "a VT session is local; got {snap:?}");
        }
        other => panic!(
            "THE ASSEMBLY DID NOT RESOLVE. LogindSource + the real shell_pidfd + a real PAM \
             session must reach logind and be DESCRIBED; {other:?} means the wiring never got \
             an answer. A denial-only assertion would have passed here, which is why this test \
             asserts the cause."
        ),
    }
    // And the composed gate refuses it — the same call the service makes.
    // D0A-R5-08: evaluate the gate on the CAPTURED snapshot, not with a fresh query. This
    // assertion used to call `gate_allows(&source)` AFTER the kill+reap above — a new query on
    // a reaped pidfd, which returns ESRCH -> ProcessGone -> denied. It therefore passed
    // because the process was GONE, not because the session failed the gate, and would have
    // passed with `session_passes_gate` inverted.
    //
    // The `Resolved` assertion above is unaffected: `current()` runs BEFORE teardown, so it
    // asserts a value captured while the shell was alive.
    let snapshot = cause.snapshot_or_denied();
    assert!(
        !delphi_runtime::logind::session_passes_gate(snapshot),
        "the resolved-but-inactive session must fail the gate ON ITS OWN AXES: {snapshot:?}"
    );
}

/// The daemon BINARY runs its real gate — the seam absent, not merely unlogged.
///
/// D0A-R4-03: asserting "no seam line appeared" is satisfied by a run that logged NOTHING —
/// a crash, a wrong binary, an unbuilt feature. So this asserts the run produced its EXPECTED
/// startup output and that the seam line is not among it. Absence is only evidence once
/// presence is established.
#[test]
fn the_daemon_binary_runs_the_real_gate_d0a_r4_03() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP r4_03_daemon_real_gate: requires root");
        return;
    }
    let setup = Setup::new("r403d");
    let (_uid, gid) = setup.ids();
    let _base_tmp = delphi_runtime::test_child_guard::ReportingTempDir::new(
        tempfile::Builder::new().prefix("delphi-r403d-").tempdir_in("/run").expect("tempdir"),
    );
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (_paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &work, "mshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");
    let result = work.join("result");
    let exe_str = write_marker_exe(&work, &result).display().to_string();
    let work_str = work.display().to_string();

    // D0A-R4-07: SPAWN + BOUNDED WAIT + KILL, never `.output()`. `.output()` waits forever,
    // and when the operator interrupted the hang the daemon ORPHANED AS ROOT holding its VT —
    // four times, each run making the next one's precondition fail. A test that leaks a
    // privileged process is worse than a test that fails.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_delphi-runtimed"));
    cmd
        .args(["--session", &setup.user])
        .env("DELPHI_SHELL_BIN", &shell_bin)
        .env("DELPHI_AI_BIN", &ai_bin)
        .env(delphi_runtime::scaffold_env::PASSWORD, PASSWORD)
        .env(delphi_runtime::scaffold_env::AI_EXE, &exe_str)
        .env(delphi_runtime::scaffold_env::AI_ARG, "R4-03D")
        .env(delphi_runtime::scaffold_env::AI_BIND_RW, &work_str)
        .env("DELPHI_SHELL_VT", "tty3")
        // NOTE: the daemon anchors at the hardcoded DEFAULT_RUNTIME_BASE — it takes no base
        // override. An earlier draft of this test passed `DELPHI_RUNTIME_BASE`, a name that
        // exists NOWHERE in the binary; it was a silent no-op, which is D0A-R2-01's class
        // reappearing in the very test written to close a wiring gap. Caught by checking the
        // assumption against the source rather than by a reviewer.
        // DELPHI_INSECURE_ASSUME_ACTIVE_SESSION is DELIBERATELY UNSET: the real gate runs.
        .env_remove("DELPHI_INSECURE_ASSUME_ACTIVE_SESSION")
    ;
    let (out, killed) = DaemonGuard::spawn(cmd, &setup.user).wait();
    assert!(!killed, "the daemon had to be KILLED at the deadline — the orphan condition");
    // D0A-R4-10: BOTH STREAMS. `tracing_subscriber::fmt()` writes to STDOUT by default, so the
    // daemon's own startup line never appeared in the stderr this assertion was reading — the
    // "presence" leg failed while the evidence sat in the stream next to it. The AI's and the
    // shell's output WAS in stderr, which is why the capture looked populated.
    let stderr = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // PRESENCE FIRST — otherwise the absence below proves only that nothing ran.
    // D0A-R5-05: "anchor + launcher up" is logged BEFORE the gate runs, so accepting it made
    // this leg satisfiable by output that proves only that the daemon started — which is
    // exactly what the eight attempts were spent NOT settling. The evidence must come from
    // AFTER the gate: on a non-foreground VT the startup check logs this line, and it is
    // emitted only once `gate_allows` has evaluated a real verdict.
    assert!(
        stderr.contains("shell session is NOT active-local-seated"),
        "the daemon must have REACHED AND EVALUATED the real gate — a startup line proves only \
         that it launched. Without gate-side evidence the seam's absence below says nothing \
         about whether the bypass was used. stderr:\n{stderr}"
    );
    // THEN absence, by name.
    assert!(
        !stderr.contains("INSECURE TEST SEAM ACTIVE"),
        "the gate-bypass seam must NOT have engaged in this run. stderr:\n{stderr}"
    );
}

// ── D0A-R1-02: the gate is re-read ADJACENT TO THE MINT ─────────────────────

/// A source that ALLOWS the first read and DENIES every one after — the session going
/// true → false while PAM waits on a human.
struct FlipsAfterFirstRead {
    reads: std::sync::atomic::AtomicUsize,
}
impl delphi_runtime::logind::SessionSource for FlipsAfterFirstRead {
    fn current(&self) -> delphi_runtime::logind::SessionResolution {
        use delphi_runtime::logind::{SessionResolution, SessionSnapshot};
        let n = self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if n == 0 {
            SessionResolution::Resolved(SessionSnapshot {
                active: true,
                remote: false,
                seated: true,
            })
        } else {
            // D0A-R4-12: the REAL transition, not `DENIED`. A session that stops being the
            // seat's foreground KEEPS ITS SEAT — all-false modelled a session that
            // simultaneously lost its seat, which is a different event and took a different
            // wording branch. This is the shape R1-02 exists to prove.
            SessionResolution::Resolved(SessionSnapshot {
                active: false,
                remote: false,
                seated: true,
            })
        }
    }
}

/// A3 made the READ fresh and left the DECISION stale: the gate passed, then PAM blocked on a
/// human — unboundedly — and the mint never re-checked. A session that stopped being the
/// seat's foreground during authentication still minted, which is the case A3's own docs name
/// as the security property.
///
/// This test needs to get PAST PAM to reach the second read, so it is root-gated. A skip
/// proves nothing.
#[test]
fn b1_session_lost_during_pam_blocks_the_mint_d0a_r1_02() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP b1_session_lost_during_pam: requires root (anchor + PAM)");
        return;
    }
    if !bwrap_available() {
        eprintln!("SKIP b1_session_lost_during_pam: requires bwrap + unprivileged userns");
        return;
    }
    let setup = Setup::new("r102");
    let (uid, gid) = setup.ids();
    let _base_tmp = delphi_runtime::test_child_guard::ReportingTempDir::new(
        tempfile::Builder::new().prefix("delphi-r102-")
            .tempdir_in("/run").expect("tempdir"));
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");

    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let result = work.join("result");
    let exe = write_marker_exe(&work, &result);

    let exe_str = exe.display().to_string();
    let work_str = work.display().to_string();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &work, "mshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");
    let spec = LaunchSpec {
        ready: delphi_runtime::readiness::ReadySemantics::ScaffoldEntry,
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: test_vt(),
        shell_env: &[(delphi_runtime::scaffold_env::PASSWORD, PASSWORD)],
        ai_env: &[(delphi_runtime::scaffold_env::AI_EXE, &exe_str),
            (delphi_runtime::scaffold_env::AI_ARG, "B1-LIVES"),
            (delphi_runtime::scaffold_env::AI_BIND_RW, &work_str),],
    };
    let children = launch(&spec).expect("launch");
    // D0A-R2-01: a deadline, so a broken fixture FAILS FAST and names the AI rather than
    // hanging the run with no output.
    let mut ai = delphi_runtime::service::accept_requester_within(
        &listener,
        uid.as_raw(),
        std::time::Duration::from_secs(20),
    )
    .expect("the AI must connect");
    let mut store = PendingStore::new();
    let mut ledger = ConsumptionLedger::new();
    let key = MintingKey::from_bytes(KEY);
    let flipping = FlipsAfterFirstRead { reads: std::sync::atomic::AtomicUsize::new(0) };
    let mut ctx = ServiceCtx {
        channel_fd: children.daemon_channel.as_raw_fd(),
        session: &flipping,
        key: &key,
        pam_service: SERVICE,
        session_user: &setup.user,
        store: &mut store,
        ledger: &mut ledger,
        clock: &FixedClock(NOW),
    };
    let outcome = serve_one_action(&mut ai, &mut ctx).expect("serve one action");
    let _ = waitpid(nix::unistd::Pid::from_raw(children.shell_pid), None);
    let _ = waitpid(nix::unistd::Pid::from_raw(children.ai_pid), None);
    let marker = std::fs::read_to_string(&result).unwrap_or_default();

    // The FIRST read allowed, so PAM ran and the prompt was shown — that is deliberate: the
    // pre-PAM check exists so we never prompt at a surface that is not the foreground.
    assert!(
        flipping.reads.load(std::sync::atomic::Ordering::SeqCst) >= 2,
        "the gate must be read AGAIN after PAM — one read means the mint is still \
         authorized by a verdict taken before an unbounded human wait"
    );
    match outcome {
        Outcome::Denied { reason, .. } => {
            // D0A-R3-03: the expected wording is named HERE, independently. Comparing the
            // message to the constant it came from forecloses DRIFT between two sites but
            // cannot verify EITHER is correct — which is exactly how R2-05's garbled
            // `DURING<14 spaces>authentication` passed: the message was malformed, the test
            // compared it to itself, and neither noticed.
            // D0A-R4-12: assert the PROPERTIES the message must carry, not a literal. R4-04
            // rewrote the wording to derive from the failing axes and this assertion — pinned
            // to the old sentence — broke, which is Class 27: a fix invalidating an earlier
            // round's proof. Swapping in the new literal would reproduce the fragility one
            // round later, so the check is on what the message must SAY:
            //   * it names the axis that failed (the foreground), and
            //   * it places the change DURING authentication, which is what distinguishes this
            //     denial from a first-gate refusal.
            assert!(
                reason.contains("foreground"),
                "the denial must name the failing axis; got {reason:?}"
            );
            assert!(
                reason.to_lowercase().contains("during authentication"),
                "the denial must say the change happened DURING authentication — that is what \
                 distinguishes it from a first-gate refusal; got {reason:?}"
            );
            assert!(
                !reason.contains("NO seat") && !reason.contains("REMOTE"),
                "the session kept its seat and stayed local, so the message must not claim \
                 otherwise; got {reason:?}"
            );
            assert!(
                !reason.contains("  "),
                "no doubled spaces — a malformed literal is how R2-05 shipped: {reason:?}"
            );
            // AND it must still be the shared constant, so the two sites cannot drift apart.
            assert_eq!(reason, delphi_runtime::service::REASON_SESSION_LOST_DURING_AUTH);
        }
        other => panic!("a session lost during PAM must NOT mint: {other:?}"),
    }
    assert!(marker.is_empty(), "nothing may execute: the action was never granted");
}

// ── B1-R2-01: token TTL is a REAL control in the assembled loop ──────────────

#[test]
fn b1_token_expiry_blocks_the_assembled_loop() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP b1_token_expiry: requires root");
        return;
    }
    if !bwrap_available() {
        eprintln!("SKIP b1_token_expiry: requires bwrap + unprivileged userns");
        return;
    }
    let setup = Setup::new("e");
    let (uid, gid) = setup.ids();
    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = delphi_runtime::test_child_guard::ReportingTempDir::new(
        tempfile::Builder::new().prefix("delphi-b1exp-")
        .tempdir_in("/run").expect("tempdir"));
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let result = work.join("result");
    let exe = write_marker_exe(&work, &result);
    let exe_str = exe.display().to_string();
    let work_str = work.display().to_string();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &work, "mshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");
    let spec = LaunchSpec {
        // Sleeper/minimal fixtures signal at ENTRY — the weaker claim (D0-A A1).
        ready: delphi_runtime::readiness::ReadySemantics::ScaffoldEntry,
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: test_vt(),
        shell_env: &[(delphi_runtime::scaffold_env::PASSWORD, PASSWORD)],
        ai_env: &[
            (delphi_runtime::scaffold_env::AI_EXE, &exe_str),
            (delphi_runtime::scaffold_env::AI_ARG, "SHOULD-NOT-RUN"),
            (delphi_runtime::scaffold_env::AI_BIND_RW, &work_str),
        ],
    };
    let children = launch(&spec).expect("launch");
    let mut ai = accept_requester(&listener, uid.as_raw()).expect("accept");
    let mut store = PendingStore::new();
    let mut ledger = ConsumptionLedger::new();
    let key = MintingKey::from_bytes(KEY);
    // The daemon reads the clock at mint (→ NOW) then FRESH at Present-verify (→ past
    // TTL): the AI sat on the token too long → the verify rejects it. The isolated
    // expiry RED, now biting the assembled loop.
    let clock = SeqClock {
        times: vec![NOW, NOW + TOKEN_TTL_SECS + 1],
        idx: std::sync::atomic::AtomicUsize::new(0),
    };
    let mut ctx = ServiceCtx {
        channel_fd: children.daemon_channel.as_raw_fd(),
        session: &PASS,
        key: &key,
        pam_service: SERVICE,
        session_user: &setup.user,
        store: &mut store,
        ledger: &mut ledger,
        clock: &clock,
    };
    let outcome = serve_one_action(&mut ai, &mut ctx).expect("serve");
    let _ = waitpid(nix::unistd::Pid::from_raw(children.shell_pid), None);
    let _ = waitpid(nix::unistd::Pid::from_raw(children.ai_pid), None);
    let ran = std::fs::read_to_string(&result).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&base);

    assert!(
        matches!(outcome, Outcome::Denied { .. }),
        "RED: an expired token (mint→verify delta > TTL) must be DENIED by the assembled loop: {outcome:?}"
    );
    assert!(ran.trim().is_empty(), "expired → nothing executed");
}

// ── Half (ii): approve-A/execute-B against the assembled present_and_execute ──

#[test]
fn b1_approve_a_execute_b_is_rejected() {
    if !bwrap_available() {
        eprintln!("SKIP b1_approve_a_execute_b: requires bwrap + unprivileged userns");
        return;
    }
    // RAII: removed on drop, INCLUDING the panic path. `dir` stays a PathBuf, so
    // nothing downstream changes.
    let _dir_tmp = tempfile::Builder::new().prefix("delphi-b1-aeb-")
        .tempdir_in(std::env::temp_dir()).expect("tempdir");
    let dir = _dir_tmp.path().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let result_a = dir.join("res_a");
    let result_b = dir.join("res_b");
    let exe_a = write_marker_exe(&dir, &result_a);
    let exe_b = {
        let e = dir.join("echo_b.sh");
        std::fs::write(&e, format!("#!/bin/sh\necho \"$1\" > {}\n", result_b.display())).unwrap();
        std::fs::set_permissions(&e, std::fs::Permissions::from_mode(0o755)).unwrap();
        e
    };

    let key = MintingKey::from_bytes(KEY);
    let mut store = PendingStore::new();

    // Register A + B, both Granted; mint a token ONLY for A (legitimately obtained).
    let id_a = store.next_id();
    let action_a: PendingAction = canonicalize(&marker_proposal(&exe_a, "MARKER-A", &dir), id_a.clone()).unwrap();
    let digest_a = canonical_action_digest(&action_a);
    store.insert(action_a);
    store.get_mut(&id_a).unwrap().state = PendingState::Granted;

    let id_b = store.next_id();
    let action_b: PendingAction = canonicalize(&marker_proposal(&exe_b, "MARKER-B", &dir), id_b.clone()).unwrap();
    store.insert(action_b);
    store.get_mut(&id_b).unwrap().state = PendingState::Granted;

    let token_a = mint(&key, &digest_a, NOW).to_wire();
    let mut ledger = ConsumptionLedger::new();

    // THE ATTACK: present A's token for B → the daemon executes the STORED B and
    // re-verifies token_A against B's digest → mismatch → DENIED, B never runs.
    let attack = present_and_execute(&mut store, &mut ledger, &key, &id_b, &token_a, NOW);
    assert!(matches!(attack, Outcome::Denied { .. }), "approve-A/execute-B must be DENIED: {attack:?}");
    assert!(!result_b.exists(), "RED: action B must NOT have executed under A's token");

    // POSITIVE CONTROL: A's token runs A (the binding is real, not a blanket reject).
    let honest = present_and_execute(&mut store, &mut ledger, &key, &id_a, &token_a, NOW);
    assert!(matches!(honest, Outcome::Completed { .. }), "A's token must run A: {honest:?}");
    assert_eq!(std::fs::read_to_string(&result_a).unwrap().trim(), "MARKER-A");

    // REPLAY: presenting A's token a second time is one-shot-denied.
    let replay = present_and_execute(&mut store, &mut ledger, &key, &id_a, &token_a, NOW);
    assert!(matches!(replay, Outcome::Denied { .. }), "one-shot: a replay must be DENIED: {replay:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ── Half (ii): 1d swap-proof composes through canonicalize → execute ─────────

#[test]
fn b1_swap_after_canonicalize_runs_the_pinned_content() {
    if !bwrap_available() {
        eprintln!("SKIP b1_swap_proof: requires bwrap + unprivileged userns");
        return;
    }
    // RAII: removed on drop, INCLUDING the panic path. `dir` stays a PathBuf, so
    // nothing downstream changes.
    let _dir_tmp = tempfile::Builder::new().prefix("delphi-b1-swap-")
        .tempdir_in(std::env::temp_dir()).expect("tempdir");
    let dir = _dir_tmp.path().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let result = dir.join("res");
    let exe = write_marker_exe(&dir, &result); // #!/bin/sh echo "$1" > result

    let key = MintingKey::from_bytes(KEY);
    let mut store = PendingStore::new();
    let id = store.next_id();
    // Canonicalize PINS the original: hash-through-the-held-fd + a SEALED memfd of
    // the script content. argv[1] = PINNED.
    let action = canonicalize(&marker_proposal(&exe, "PINNED", &dir), id.clone()).unwrap();
    let digest = canonical_action_digest(&action);
    store.insert(action);
    store.get_mut(&id).unwrap().state = PendingState::Granted;
    let token = mint(&key, &digest, NOW).to_wire();

    // SWAP the script PATH to a new inode that ignores argv and echoes SWAPPED.
    let tmp = dir.join("swap.sh");
    std::fs::write(&tmp, format!("#!/bin/sh\necho SWAPPED > {}\n", result.display())).unwrap();
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&tmp, &exe).unwrap(); // new inode at the exe path

    // Present → the daemon execs the STORED action via the SEALED memfd (original
    // content), NOT the swapped path. The composition (canonicalize fd-pin/seal +
    // execute fd-exec) defeats the swap.
    let mut ledger = ConsumptionLedger::new();
    let outcome = present_and_execute(&mut store, &mut ledger, &key, &id, &token, NOW);
    let ran = std::fs::read_to_string(&result).unwrap_or_default().trim().to_string();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(matches!(outcome, Outcome::Completed { .. }), "the pinned action runs: {outcome:?}");
    assert_eq!(ran, "PINNED", "the SEALED/pinned content ran, not the swapped path (swap-proof composes)");
}

// ── B1-04 / B1-R2-03: store and ledger AGREE — a wrong token doesn't burn it ──

#[test]
fn b1_wrong_token_does_not_burn_the_approval() {
    if !bwrap_available() {
        eprintln!("SKIP b1_wrong_token: requires bwrap + unprivileged userns");
        return;
    }
    // RAII: removed on drop, INCLUDING the panic path. `dir` stays a PathBuf, so
    // nothing downstream changes.
    let _dir_tmp = tempfile::Builder::new().prefix("delphi-b1-burn-")
        .tempdir_in(std::env::temp_dir()).expect("tempdir");
    let dir = _dir_tmp.path().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let result = dir.join("res");
    let exe = write_marker_exe(&dir, &result);

    let key = MintingKey::from_bytes(KEY);
    let mut store = PendingStore::new();
    let id = store.next_id();
    let action = canonicalize(&marker_proposal(&exe, "RIGHT", &dir), id.clone()).unwrap();
    let digest = canonical_action_digest(&action);
    store.insert(action);
    store.get_mut(&id).unwrap().state = PendingState::Granted;
    let good = mint(&key, &digest, NOW).to_wire();
    let wrong = mint(&key, &[0xFF; 32], NOW).to_wire(); // a token bound to a different digest
    let mut ledger = ConsumptionLedger::new();

    // A WRONG token is denied AND does NOT burn the approval (ledger untouched →
    // store stays Granted, agreeing with the ledger; the 1c precedent).
    let d = present_and_execute(&mut store, &mut ledger, &key, &id, &wrong, NOW);
    assert!(matches!(d, Outcome::Denied { .. }), "wrong token denied: {d:?}");
    assert_eq!(store.get(&id).unwrap().state, PendingState::Granted, "wrong token must NOT burn the approval");
    assert!(!result.exists(), "denied → nothing executed");

    // The RIGHT token still works (the approval wasn't burned) → store Consumed,
    // agreeing with the ledger that just consumed.
    let c = present_and_execute(&mut store, &mut ledger, &key, &id, &good, NOW);
    assert!(matches!(c, Outcome::Completed { .. }), "the legit token still runs: {c:?}");
    assert_eq!(store.get(&id).unwrap().state, PendingState::Consumed, "success → store Consumed (agrees with ledger)");
    assert_eq!(std::fs::read_to_string(&result).unwrap().trim(), "RIGHT");
    let _ = std::fs::remove_dir_all(&dir);
}

/// B1-R2-03 (the ACTUAL failure mode): a token that VERIFIES but whose execution
/// FAILS AFTER the ledger consumes. An UNSEALED ScriptPin reaches `require_fully_sealed`
/// inside `run_fd_pinned` — AFTER `execute_approved` verified the token + consumed the
/// ledger — and is refused (UnsealedScript). The store must advance to Consumed,
/// agreeing with the consumed ledger (1d one-shot: "a spawn failure still consumes").
/// The wrong-token test covers failed-verify (never the bug); THIS covers verified-
/// then-failed (the path the R2-03 bug lived on). No bwrap: the seal check precedes the
/// spawn.
#[test]
fn b1_verified_then_execution_failed_consumes_the_approval() {
    let key = MintingKey::from_bytes(KEY);
    let mut store = PendingStore::new();
    let id = store.next_id();
    let action = PendingAction {
        pending_id: id.clone(),
        preview_version: 1,
        executable_fd: std::fs::File::open("/dev/null").unwrap().into(),
        executable_digest: [0xAB; 32],
        argv: vec!["tool".into()],
        cwd: PathBuf::from("/"),
        env_delta: vec![],
        fs_binds: vec![],
        net_policy: NetPolicy::None,
        timeout: std::time::Duration::from_secs(30),
        required_tier: RequiredTier::Biometric,
        script: Some(ScriptPin {
            interpreter_fd: std::fs::File::open("/bin/sh").unwrap().into(),
            interpreter_digest: [0x01; 32],
            interpreter_arg: None,
            script_memfd: unsealed_memfd(b"#!/bin/sh\n:\n"), // NOT sealed → run fails AFTER consume
            script_digest: [0x02; 32],
        }),
    };
    let digest = canonical_action_digest(&action);
    store.insert(action);
    store.get_mut(&id).unwrap().state = PendingState::Granted;
    let token = mint(&key, &digest, NOW).to_wire(); // a VALID token for this exact action
    let mut ledger = ConsumptionLedger::new();

    let outcome = present_and_execute(&mut store, &mut ledger, &key, &id, &token, NOW);
    // The token verified + the ledger consumed, then run_fd_pinned refused the unsealed
    // script → Denied. The store must AGREE with the consumed ledger: Consumed.
    assert!(matches!(outcome, Outcome::Denied { .. }), "verified-then-failed → Denied: {outcome:?}");
    assert_eq!(
        store.get(&id).unwrap().state,
        PendingState::Consumed,
        "R2-03: verified-then-execution-failed must advance the store to Consumed (agrees with the ledger)"
    );
}

// ── B1-02: the shebang interpreter arg REACHES exec (not dropped) ────────────

#[test]
fn b1_shebang_interpreter_arg_reaches_exec() {
    if !bwrap_available() {
        eprintln!("SKIP b1_shebang_arg: requires bwrap + unprivileged userns");
        return;
    }
    // RAII: removed on drop, INCLUDING the panic path. `dir` stays a PathBuf, so
    // nothing downstream changes.
    let _dir_tmp = tempfile::Builder::new().prefix("delphi-b1-arg-")
        .tempdir_in(std::env::temp_dir()).expect("tempdir");
    let dir = _dir_tmp.path().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let result = dir.join("res");
    // The "interpreter" records its FIRST arg — so if our exec passes the shebang arg,
    // its $1 is the arg; if dropped, its $1 would be the script fd-path instead.
    let recorder = dir.join("recorder.sh");
    std::fs::write(&recorder, format!("#!/bin/sh\necho \"$1\" > {}\n", result.display())).unwrap();
    std::fs::set_permissions(&recorder, std::fs::Permissions::from_mode(0o755)).unwrap();
    // The action's script: shebang names the recorder + the arg ARGPROOF.
    let exe = dir.join("act.sh");
    std::fs::write(&exe, format!("#!{} ARGPROOF\n:\n", recorder.display())).unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

    let key = MintingKey::from_bytes(KEY);
    let mut store = PendingStore::new();
    let id = store.next_id();
    let action = canonicalize(&marker_proposal(&exe, "ignored-argv", &dir), id.clone()).unwrap();
    let digest = canonical_action_digest(&action);
    store.insert(action);
    store.get_mut(&id).unwrap().state = PendingState::Granted;
    let token = mint(&key, &digest, NOW).to_wire();

    let mut ledger = ConsumptionLedger::new();
    let outcome = present_and_execute(&mut store, &mut ledger, &key, &id, &token, NOW);
    let ran = std::fs::read_to_string(&result).unwrap_or_default().trim().to_string();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(matches!(outcome, Outcome::Completed { .. }), "runs: {outcome:?}");
    assert_eq!(ran, "ARGPROOF", "the shebang interpreter arg reached exec (B1-02), not dropped");
}

// ── B1-01: the DAEMON BINARY's main runs the assembled flow (not parks) ───────

#[test]
fn b1_daemon_binary_runs_the_assembled_flow() {
    // FEATURE PRECONDITION — this test runs the REAL daemon BINARY, whose production logind gate
    // the `insecure-test-seams` seam (`DELPHI_INSECURE_ASSUME_ACTIVE_SESSION`) bypasses. Without
    // that feature COMPILED INTO the binary, the seam is inert, the real gate runs, and the
    // test's `tty1` session (NOT the seat's foreground here) is correctly DENIED — a fail-closed
    // gate doing its job, NOT a defect. The direct-serve tests (`b1_happy_path` etc.) don't need
    // this: they inject a mock `&PASS` verdict into `serve_one_action`. Declare the requirement
    // as a skip (like the root/bwrap guards) so an omitted `--features` is a legible SKIP, not a
    // confusing FAIL. `cfg!` reflects the same cargo build that produced the daemon binary.
    if !cfg!(feature = "insecure-test-seams") {
        eprintln!(
            "SKIP b1_daemon_binary: requires `--features insecure-test-seams` (the gate-bypass \
             seam the real daemon binary needs in the test env). Run: `cargo test -p \
             delphi-runtime --features insecure-test-seams --test b1_integration`. Without it the \
             real gate correctly DENIES the non-foreground tty1 session — not a defect."
        );
        return;
    }
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP b1_daemon_binary: requires root");
        return;
    }
    if !bwrap_available() {
        eprintln!("SKIP b1_daemon_binary: requires bwrap + unprivileged userns");
        return;
    }
    let setup = Setup::new("b");
    // World-accessible staging: the dropped user execs the side bins; the daemon (root)
    // opens the exe + binds the work dir.
    // RAII: removed on drop, INCLUDING the panic path. `stage` stays a PathBuf, so
    // nothing downstream changes.
    let _stage_tmp = tempfile::Builder::new().prefix("delphi-b1bin-")
        .tempdir_in(std::env::temp_dir()).expect("tempdir");
    let stage = _stage_tmp.path().to_path_buf();
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o777)).unwrap();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &stage, "mshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &stage, "mai");
    let result = stage.join("result");
    let exe = write_marker_exe(&stage, &result);

    // Run the actual delphi-runtimed BINARY — it does anchor + launch + serve itself.
    //
    // D0A-R4-07, SECOND INSTANCE. This site kept `.output()` while the sibling at :465 was
    // fixed — Class 17 inside the leak fix itself: I repaired the spawn site I had just
    // written and left the pre-existing one, which is the same unbounded wait that orphaned
    // four root daemons. Whether or not it produced THIS leak, it can produce the next one.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_delphi-runtimed"));
    cmd
        .args(["--session", &setup.user])
        .env("DELPHI_SHELL_BIN", &shell_bin)
        .env("DELPHI_AI_BIN", &ai_bin)
        .env(delphi_runtime::scaffold_env::PASSWORD, PASSWORD)
        .env(delphi_runtime::scaffold_env::AI_EXE, &exe)
        .env(delphi_runtime::scaffold_env::AI_ARG, "BINARY-FLOW")
        .env(delphi_runtime::scaffold_env::AI_BIND_RW, &stage)
        // `DELPHI_SHELL_VT` has no default (§4 R3-02a — guessing a VT is either a collision
        // or a silently SEATLESS session), so the daemon requires it.
        .env("DELPHI_SHELL_VT", "tty1")
        // The compile-time test seam (the binary is built with --features
        // insecure-test-seams in the lane); WSL has no real logind session.
        .env("DELPHI_INSECURE_ASSUME_ACTIVE_SESSION", "1")
    ;
    let (out, killed) = DaemonGuard::spawn(cmd, &setup.user).wait();
    assert!(!killed, "the daemon had to be KILLED at the deadline — the orphan condition");

    let marker = std::fs::read_to_string(&result).unwrap_or_default().trim().to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let _ = std::fs::remove_dir_all(&stage);
    let _ = std::fs::remove_dir_all(format!("/run/delphi/{}", setup.user));

    assert!(out.status.success(), "daemon main exited ok; stderr:\n{stderr}");
    assert!(
        stdout.contains("DELPHI_RUNTIMED_OUTCOME Completed"),
        "the BINARY's main RAN the assembled loop to completion (not thread::park); stdout:\n{stdout}"
    );
    assert_eq!(marker, "BINARY-FLOW", "the action executed via delphi-runtimed's main");
}

// ── Half (ii): the launcher's fd-discipline — the AI holds NO channel fd ──────

#[test]
fn b1_launcher_keeps_the_channel_out_of_the_ai() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP b1_launcher_fd_discipline: requires root (fork + privilege drop)");
        return;
    }
    let setup = Setup::new("f");
    let (uid, gid) = setup.ids();
    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = delphi_runtime::test_child_guard::ReportingTempDir::new(
        tempfile::Builder::new().prefix("delphi-b1fd-")
        .tempdir_in("/run").expect("tempdir"));
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");

    // Both children are a 2s sleeper script so /proc/<pid>/fd is readable mid-life.
    //
    // Signals readiness then sleeps — see tests/common/shell_fixtures.rs for why this is
    // shared rather than written per-file (D0-R1-03).
    let sleeper = shell_fixtures::signalling_sh_sleeper(&base, 2);
    let spec = LaunchSpec {
        // Sleeper/minimal fixtures signal at ENTRY — the weaker claim (D0-A A1).
        ready: delphi_runtime::readiness::ReadySemantics::ScaffoldEntry,
        shell_path: &sleeper,
        ai_path: &sleeper,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: test_vt(),
        shell_env: &[],
        ai_env: &[],
    };
    let children = launch(&spec).expect("launch sleepers");

    std::thread::sleep(std::time::Duration::from_millis(250));
    // The shell got the channel fork-passed at fd SHELL_CHANNEL_FD (3) — a socket
    // (its end of the socketpair). The AI got NOTHING beyond stdio (close_range([])).
    let shell_sockets = proc_socket_fds(children.shell_pid);
    let ai_sockets = proc_socket_fds(children.ai_pid);

    let _ = waitpid(nix::unistd::Pid::from_raw(children.shell_pid), None);
    let _ = waitpid(nix::unistd::Pid::from_raw(children.ai_pid), None);
    let _ = std::fs::remove_dir_all(&base);

    assert!(
        ai_sockets.is_empty(),
        "RED: the AI must hold NO socket fd (never the channel) — found {ai_sockets:?}"
    );
    assert!(
        shell_sockets.iter().any(|(fd, _)| *fd == delphi_runtime::launcher::SHELL_CHANNEL_FD),
        "the shell DOES hold the fork-passed channel at fd 3 (positive control) — found {shell_sockets:?}"
    );
}

/// fds `>= 3` of `pid` that point at a socket (`socket:[…]`), as `(fd, link)`.
fn proc_socket_fds(pid: i32) -> Vec<(i32, String)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(format!("/proc/{pid}/fd")) else { return out };
    for e in rd.flatten() {
        let Ok(fd) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        if fd < 3 {
            continue;
        }
        if let Ok(link) = std::fs::read_link(e.path()) {
            let link = link.to_string_lossy().into_owned();
            if link.starts_with("socket:") {
                out.push((fd, link));
            }
        }
    }
    out
}

// ── Half (ii): logind-deny composes into the assembled loop ──────────────────

#[test]
fn b1_logind_deny_blocks_the_assembled_loop() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP b1_logind_deny: requires root (anchor + PAM)");
        return;
    }
    let setup = Setup::new("l");
    let (uid, gid) = setup.ids();
    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = delphi_runtime::test_child_guard::ReportingTempDir::new(
        tempfile::Builder::new().prefix("delphi-b1l-")
        .tempdir_in("/run").expect("tempdir"));
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");

    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::set_permissions(&work, std::fs::Permissions::from_mode(0o777)).unwrap();
    let result = work.join("result");
    let exe = write_marker_exe(&work, &result);
    let exe_str = exe.display().to_string();
    let work_str = work.display().to_string();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &work, "mshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");
    let spec = LaunchSpec {
        // Sleeper/minimal fixtures signal at ENTRY — the weaker claim (D0-A A1).
        ready: delphi_runtime::readiness::ReadySemantics::ScaffoldEntry,
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: test_vt(),
        shell_env: &[(delphi_runtime::scaffold_env::PASSWORD, PASSWORD)],
        ai_env: &[
            (delphi_runtime::scaffold_env::AI_EXE, &exe_str),
            (delphi_runtime::scaffold_env::AI_ARG, "SHOULD-NOT-RUN"),
            (delphi_runtime::scaffold_env::AI_BIND_RW, &work_str),
        ],
    };
    let children = launch(&spec).expect("launch");
    let mut ai = accept_requester(&listener, uid.as_raw()).expect("accept AI");
    let mut store = PendingStore::new();
    let mut ledger = ConsumptionLedger::new();
    let key = MintingKey::from_bytes(KEY);
    // A NON-active session: the logind gate must DENY before PAM/execute.
    let deny_verdict = Verdict { active: false, remote: false, seated: false };
    let mut ctx = ServiceCtx {
        channel_fd: children.daemon_channel.as_raw_fd(),
        session: &deny_verdict,
        key: &key,
        pam_service: SERVICE,
        session_user: &setup.user,
        store: &mut store,
        ledger: &mut ledger,
        clock: &FixedClock(NOW),
    };
    let outcome = serve_one_action(&mut ai, &mut ctx).expect("serve");

    // The AI/shell may still be blocked; reap loosely.
    let _ = waitpid(nix::unistd::Pid::from_raw(children.ai_pid), Some(nix::sys::wait::WaitPidFlag::WNOHANG));
    let _ = std::fs::remove_dir_all(&base);

    assert!(matches!(outcome, Outcome::Denied { .. }), "logind-inactive must DENY: {outcome:?}");
    assert!(!result.exists(), "denied at the gate → nothing executed");
}

/// A non-blocking channel-read outcome (scaffolding for the terminal-contract test).
#[derive(Debug)]
enum Rd {
    Data,
    WouldBlock,
    Eof,
}

fn nb_read(fd: RawFd) -> Rd {
    let mut buf = [0u8; 8192];
    // SAFETY: a non-blocking recv on the borrowed fd — >0 data, 0 = EOF (peer closed), or
    // -1 with EAGAIN when nothing is queued (so the test never blocks).
    let n = unsafe { nix::libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), nix::libc::MSG_DONTWAIT) };
    if n > 0 {
        Rd::Data
    } else if n == 0 {
        Rd::Eof
    } else {
        // On Linux EWOULDBLOCK == EAGAIN, so EAGAIN alone covers "nothing queued".
        let e = nix::errno::Errno::last();
        assert!(e == nix::errno::Errno::EAGAIN, "unexpected recv errno: {e}");
        Rd::WouldBlock
    }
}

/// B2A-R2-02 (terminal contract, NON-root — the gate-deny path reaches no PAM/anchor):
/// once serve_one_action reaches a terminal DENIAL, the caller (delphi-runtimed) releasing
/// the daemon channel produces the EOF a wedged shell dismisses on. PRE-release the shell's
/// next read WOULD BLOCK (the wedge B2A-R2-02 identified — a prompt + EOF that never come);
/// POST-release it is EOF → the host's recv_prompt yields None → dismiss (proven in
/// consent_relay's deny_on_eof test). The pre/post contrast IS the bite: without the
/// release there is no EOF (the shell wedges); with it, clean dismissal.
#[test]
fn terminal_contract_release_produces_eof_no_wedge() {
    // The private channel (daemon end + shell end) + the AI connection.
    let (daemon_ch, shell_ch) = approval_socketpair().expect("channel");
    let (mut ai_client, mut daemon_ai) = UnixStream::pair().expect("ai pair");

    // The AI proposes a benign action; canonicalize opens /bin/true (readable, non-root).
    let propose = pb::Propose {
        argv: vec!["true".into()],
        cwd: "/".into(),
        env_delta: vec![],
        fs_binds: vec![pb::Bind { path: "/usr".into(), mode: pb::BindMode::BindReadOnly as i32 }],
        exe_path: "/bin/true".into(),
        net_policy: pb::NetPolicy::NetNone as i32,
        timeout_secs: 30,
        required_tier: pb::RequiredTier::TierBiometric as i32,
    };
    write_frame(&mut ai_client, &propose_msg(propose)).expect("send propose");

    let mut store = PendingStore::new();
    let mut ledger = ConsumptionLedger::new();
    let key = MintingKey::from_bytes(KEY);
    // A NON-active session → the gate denies BEFORE PAM (so no root/PAM is needed).
    let deny = Verdict { active: false, remote: false, seated: false };
    let mut ctx = ServiceCtx {
        channel_fd: daemon_ch.as_raw_fd(),
        session: &deny,
        key: &key,
        pam_service: SERVICE,
        session_user: "nobody",
        store: &mut store,
        ledger: &mut ledger,
        clock: &FixedClock(NOW),
    };
    let outcome = serve_one_action(&mut daemon_ai, &mut ctx).expect("serve");
    assert!(matches!(outcome, Outcome::Denied { .. }), "gate must DENY: {outcome:?}");

    let sfd = shell_ch.as_raw_fd();
    // The preview reached the shell (the approval-request datagram).
    assert!(matches!(nb_read(sfd), Rd::Data), "shell received the approval request");
    // PRE-RELEASE: the daemon has NOT closed → the next read WOULD BLOCK (the wedge).
    assert!(matches!(nb_read(sfd), Rd::WouldBlock), "pre-release: no EOF → the shell would wedge");
    // THE TERMINAL CONTRACT: delphi-runtimed releases the daemon channel after serve.
    drop(daemon_ch);
    // POST-RELEASE: EOF → the host's recv_prompt → None → dismiss (no wedge).
    assert!(matches!(nb_read(sfd), Rd::Eof), "post-release: EOF → the host dismisses cleanly");
}
