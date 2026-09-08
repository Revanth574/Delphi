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

#[path = "common/credentials.rs"]
mod credentials;

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
    // Every marker fixture goes through here, so this is where the result's directory becomes
    // writable by the dropped tool. Without it the action runs and writes NOTHING, which the
    // assertions read as `left: ""` or as NotFound on the result file — never as a permission
    // error, because the failure is inside the jail (lane run 4, five tests).
    if let Some(parent) = result.parent() {
        credentials::chown_to_tool(parent);
    }
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

/// The `insecure-test-seams` gate, in ONE place (D0A lane run 3, whole-suite).
///
/// `delphi-surface-shell` carries `required-features = ["insecure-test-seams"]`, so
/// `CARGO_BIN_EXE_delphi-surface-shell` names a path that does not exist in a plain build.
/// `b1_daemon_binary` checked the feature and skipped; `the_daemon_binary_runs_the_real_gate`
/// did not, and failed with `copy minimal-side bin: NotFound` — the same gate written twice
/// with two behaviours, which is how `bwrap --version` produced four unattributable failures
/// one increment ago.
fn surface_shell_or_skip(test: &str) -> Option<&'static str> {
    let p = env!("CARGO_BIN_EXE_delphi-surface-shell");
    if std::path::Path::new(p).exists() {
        return Some(p);
    }
    eprintln!(
        "SKIP {test}: measured blocker: {p} does not exist — delphi-surface-shell carries \
         required-features = [\"insecure-test-seams\"]. Re-run with `cargo test -p \
         delphi-runtime --features insecure-test-seams --test b1_integration`."
    );
    None
}

/// Copy a built bin into `dir` (mode 0755) so the dropped session user can exec it
/// — the build target lives under the developer's home, which other uids cannot traverse.
/// (It said `/home/raven` until lane run 3: a machine-specific path left over from the
/// `build.target-dir` pin CLAUDE.md reversed on 2026-08-15 for being exactly that.)
fn stage_bin(src: &str, dir: &Path, name: &str) -> PathBuf {
    let dst = dir.join(name);
    std::fs::copy(src, &dst)
        .unwrap_or_else(|e| panic!("copy staged bin {src} -> {}: {e}", dst.display()));
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
    dst
}

fn marker_proposal(exe: &Path, marker: &str, out_dir: &Path) -> pb::Propose {
    credentials::plan_credentials_once();
    // The rw bind is where the action writes, so it is chowned HERE and not only in
    // `write_marker_exe` — `b1_shebang_interpreter_arg_reaches_exec` writes its own executable
    // and reaches production through `canonicalize`, so it never passed through that helper
    // and stayed red on lane run 5 with the same empty-marker signature (run 4's cause fixed,
    // a second instance of it left standing).
    credentials::chown_to_tool(out_dir);
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
        required_tier: pb::RequiredTier::TierConfirm as i32,
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
/// What `wait_for_line` observed.
struct Witness {
    /// The matched line, if the prefix ever appeared.
    matched: Option<String>,
    /// Everything the daemon wrote, for diagnosis.
    seen: String,
    /// Whether the daemon was still running when the wait ended — the flag that makes an
    /// ABSENT witness mean "never reached the gate" rather than "exited or timed out first".
    alive_at_conclusion: bool,
    /// D0A-R8-03: the identity was lost during the wait, so the group was never signalled and
    /// descendants were ABANDONED. A witness recovered from the sink afterwards is not wrong,
    /// but the RUN is not clean — and a test that reports success while having leaked is the
    /// same false reassurance this arc keeps closing. Success requires both.
    identity_lost: bool,
}

/// Whether the child's identity is still provably ours (D0A-R8-02, Codex's judgement).
///
/// "Do the irreversible thing last" is not sufficient on its own — it orders operations but
/// says nothing about whether we still hold what we are about to act on. An EXPLICIT OWNERSHIP
/// STATE does: every signal is gated on `Held`, so a path that loses the identity cannot signal
/// by omission. The bool this replaced was consulted at ONE of the three `kill_group` sites.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum Identity {
    /// Reserved: the child is alive, or exited-but-unreaped. Signalling the group is sound.
    Held,
    /// A `waitid` error, an external reap, or anything else that released the number. The pid
    /// may now belong to someone else, so NOTHING may be signalled with it — ever again.
    Lost,
}

struct DaemonGuard {
    child: Option<std::process::Child>,
    session_user: String,
    identity: Identity,
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
        Self { child: Some(child), session_user: session_user.to_owned(), identity: Identity::Held }
    }

    /// The daemon's pid, and therefore its pgid — it leads its own group (`.process_group(0)`).
    ///
    /// Needed because [`Self::wait`] blocks and CONSUMES the guard, so the only way to observe
    /// the running assembly is a probe started before it (D0A-R32-01, the positive control).
    fn pid(&self) -> i32 {
        #[allow(clippy::cast_possible_wrap)]
        {
            self.child.as_ref().expect("child present").id() as i32
        }
    }

    /// Wait to a deadline, then take the output. A kill is reported by the caller's assertion;
    /// the REAPING has already happened either way.
    fn wait(mut self) -> DaemonRun {
        let child = self.child.take().expect("child present");
        let child_pid = child.id();
        // D0A-R4-11: LONGER than the daemon's own 120 s accept bound, deliberately. At 45 s the
        // test always killed first, so the daemon's bounded exit was NEVER the thing observed —
        // one of the two deadlines was entirely unexercised, and a kill was reported where the
        // daemon's own error would have been more informative. Now the daemon gets to fail its
        // own way first, and this bound is the backstop for a hang it does not cover.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(150);
        let mut killed = false;
        // D0A-R6-05: `try_wait()` REAPS on success (documented), and a reaped pid is not a pid
        // we own — the group id can already belong to someone else by the time `kill_group`
        // runs, as ROOT. Same class as R6-02, one language over. `waitid` with WNOWAIT observes
        // the exit and LEAVES THE CHILD WAITABLE, so its identity stays reserved until we reap
        // it deliberately, after the group kill.
        #[allow(clippy::cast_possible_wrap)]
        let pid = nix::unistd::Pid::from_raw(child_pid as i32);
        loop {
            let observed = nix::sys::wait::waitid(
                nix::sys::wait::Id::Pid(pid),
                nix::sys::wait::WaitPidFlag::WEXITED
                    | nix::sys::wait::WaitPidFlag::WNOHANG
                    | nix::sys::wait::WaitPidFlag::WNOWAIT,
            );
            match observed {
                // Exited, NOT reaped: the pid is still ours to signal.
                Ok(nix::sys::wait::WaitStatus::StillAlive) | Err(_)
                    if std::time::Instant::now() >= deadline =>
                {
                    killed = true;
                    break;
                }
                Ok(nix::sys::wait::WaitStatus::StillAlive) => {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                Ok(_) => break,
                Err(_) => break,
            }
        }
        // D0A-R5-04: the daemon may have exited while its shell and AI have not — they hold the
        // pipe write ends, so `wait_with_output()` would wait for an EOF no living descendant
        // sends. Killing the GROUP is safe here and only here: the leader is exited-but-unreaped
        // (or still alive), so the identity has not been released.
        // D0A-R31-02: SAMPLE BEFORE INTERVENING. Past this line the guard supplies whatever
        // cleanup the daemon did not, and no later observation can tell the two apart.
        #[allow(clippy::cast_possible_wrap)]
        let survivors_before_guard = live_group_members(child.id() as i32, child.id() as i32);
        Self::kill_group(child.id());
        // D0A-R8-04: `wait_with_output` is unbounded — a surviving descendant holding the pipe
        // wedges it, which is R5-04's mechanism. Only `wait_for_line` got the bound; this
        // sibling kept it, which is Class 17 inside the bounding fix.
        let (tx, rx) = std::sync::mpsc::channel();
        let collector = std::thread::spawn(move || {
            let _ = tx.send(child.wait_with_output());
        });
        let out = match rx.recv_timeout(std::time::Duration::from_secs(30)) {
            Ok(Ok(o)) => o,
            _ => {
                eprintln!("DaemonGuard: output collection did not finish in 30s — proceeding \
                           without it rather than wedging (D0A-R8-04)");
                std::process::Output {
                    status: std::process::ExitStatus::default(),
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }
            }
        };
        drop(collector);
        Self::sweep(&self.session_user);
        DaemonRun { output: out, killed, survivors_before_guard }
    }

    /// Kill anything still running under this test's own session user. Scoped by user, so it
    /// can never touch a daemon another test owns.
    fn sweep(session_user: &str) {
        let _ = Command::new("pkill")
            .args(["-9", "-f", &format!("delphi-runtimed --session {session_user}")])
            .status();
    }

    /// Wait for a line beginning with `prefix`, then tear the group down (D0A-R6-01).
    ///
    /// Returns the matched line, everything seen, and — critically — **whether the daemon was
    /// still alive when the wait concluded**. Without that last flag ABSENCE IS SATISFIABLE TWO
    /// WAYS: the gate was never reached, or the daemon exited before emitting / emitted after
    /// the deadline. The same shape as the barrier's `rc != 0`, so the second way is excluded
    /// explicitly rather than assumed away.
    fn wait_for_line(mut self, prefix: &str, timeout: std::time::Duration) -> Witness {
        use std::io::BufRead as _;
        let child_pid = self.child.as_ref().expect("child present").id();
        let child = self.child.as_mut().expect("child present");
        let stdout = child.stdout.take().expect("stdout piped");
        // D0A-R7-06: stderr was piped and NEVER READ. A full pipe blocks the writer, so the
        // daemon could wedge on its own logging — and every startup diagnostic was discarded
        // exactly when a failure most needed it. Drained on its own thread into the same sink.
        let stderr = child.stderr.take().expect("stderr piped");
        #[allow(clippy::cast_possible_wrap)]
        let pid = nix::unistd::Pid::from_raw(child.id() as i32);

        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = std::sync::Arc::clone(&lines);
        let reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
                sink.lock().expect("line sink").push(line);
            }
        });
        let err_sink = std::sync::Arc::clone(&lines);
        let err_reader = std::thread::spawn(move || {
            for line in std::io::BufReader::new(stderr).lines().map_while(Result::ok) {
                err_sink.lock().expect("line sink").push(line);
            }
        });

        let deadline = std::time::Instant::now() + timeout;
        let mut matched = None;
        let mut alive_at_conclusion = true;
        // Do we still provably hold the leader's identity? Only then may the group be signalled.
        loop {
            if let Some(l) = lines
                .lock()
                .expect("line sink")
                .iter()
                .find(|l| l.starts_with(prefix))
            {
                matched = Some(l.clone());
                break;
            }
            // Liveness WITHOUT reaping (D0A-R6-05): a reaped pid is not a pid we own, and the
            // group teardown below needs the identity still reserved.
            // D0A-R7-02: WNOWAIT pins the identity ONLY while the child is still waitable. If
            // `waitid` ERRORS — ECHILD because something else reaped it, or anything else — we
            // no longer know we hold that pid, and killing the group would target whoever owns
            // the number now. An error is therefore NOT "it exited": it is "identity unknown",
            // and the teardown below must not signal.
            let observed = nix::sys::wait::waitid(
                nix::sys::wait::Id::Pid(pid),
                nix::sys::wait::WaitPidFlag::WEXITED
                    | nix::sys::wait::WaitPidFlag::WNOHANG
                    | nix::sys::wait::WaitPidFlag::WNOWAIT,
            );
            if let Err(e) = observed {
                self.identity = Identity::Lost;
                alive_at_conclusion = false;
                eprintln!(
                    "DaemonGuard: waitid failed ({e}); the child's identity is UNKNOWN, so the \
                     group will NOT be signalled (D0A-R7-02)"
                );
                break;
            }
            let alive = matches!(observed, Ok(nix::sys::wait::WaitStatus::StillAlive));
            if !alive {
                alive_at_conclusion = false;
                // Drain briefly: the line may already be in the pipe.
                std::thread::sleep(std::time::Duration::from_millis(200));
                matched = lines
                    .lock()
                    .expect("line sink")
                    .iter()
                    .find(|l| l.starts_with(prefix))
                    .cloned();
                break;
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        self.kill_group_if_held(child_pid);
        // D0A-R7-03: THE DEADLINE ENDED AT THE POLL, and everything after it was unbounded —
        // `join()` blocks until the pipe closes, which a surviving descendant prevents, and
        // `wait()` blocks on a child that may not die. A guard whose own cleanup can wedge is
        // the failure it exists to prevent, one level in.
        //
        // The reader is DETACHED rather than joined: it owns only the read end and the lines it
        // has already delivered are in the mutex, so abandoning it costs nothing and cannot
        // hang. `reap_within` bounds the reap, leaking an unreaped child rather than wedging —
        // the trade the launcher already documents.
        let drain_until = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while (!reader.is_finished() || !err_reader.is_finished())
            && std::time::Instant::now() < drain_until
        {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        let seen = lines.lock().expect("line sink").join("\n");
        // D0A-R7-05: RECOMPUTE after draining. The poll's last look happened before the pipe
        // finished delivering, so a witness written just before exit could be present in the
        // sink and absent from `matched` — a load-dependent FALSE ABSENCE, which is the one
        // verdict this test must never produce for a timing reason.
        if matched.is_none() {
            matched = lines
                .lock()
                .expect("line sink")
                .iter()
                .find(|l| l.starts_with(prefix))
                .cloned();
        }
        // D0A-R6-06: reap THROUGH the guard rather than taking the child out first. `.take()`
        // before fallible work leaves `Drop` with `None` if that work unwinds — the same
        // "release the handle, then do something that can fail" shape as R5-01's fork guard and
        // R6-05's `try_wait`, written here while fixing the finding that reports it.
        #[allow(clippy::cast_possible_wrap)]
        let raw = child_pid as i32;
        if !delphi_runtime::reap_within(raw, std::time::Duration::from_secs(5)) {
            eprintln!("DaemonGuard: child {raw} did not reap within 5s — leaked UNREAPED rather \
                       than wedging the test (D0A-R7-03)");
        }
        self.child = None;
        Self::sweep(&self.session_user);
        Witness { matched, seen, alive_at_conclusion, identity_lost: self.identity == Identity::Lost }
    }

    /// Kill the whole process GROUP, so no descendant is left holding the pipes (D0A-R5-04).
    /// Signal the group, and ONLY while the identity is `Held` (D0A-R8-02).
    fn kill_group_if_held(&self, pid: u32) {
        match self.identity {
            Identity::Held => Self::kill_group(pid),
            Identity::Lost => eprintln!(
                "DaemonGuard: identity LOST — refusing to signal process group {pid}, which may \
                 now belong to someone else (D0A-R8-02)"
            ),
        }
    }

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
        // D0A-R6-06: the daemon's own anchor is this guard's business — it was cleaned by a
        // statement in the test body, which a panic skips.
        clean_daemon_anchor(&self.session_user);
        if let Some(child) = self.child.take() {
            // Reached only when the test panicked before `wait()` — the path that leaked.
            let pid = child.id();
            self.kill_group_if_held(pid);
            // D0A-R8-04: bounded here too. An unwinding test must not be able to hang the whole
            // suite in a destructor.
            #[allow(clippy::cast_possible_wrap)]
            let raw = pid as i32;
            if !delphi_runtime::reap_within(raw, std::time::Duration::from_secs(5)) {
                eprintln!("DaemonGuard::drop: child {raw} unreaped after 5s — leaked rather \
                           than wedging");
            }
            eprintln!(
                "DaemonGuard: the test unwound before wait(); killed the daemon for {}",
                self.session_user
            );
        }
        Self::sweep(&self.session_user);
    }
}

/// A VT that is VERIFIED free and non-foreground, or a named skip (D0A-R5-07).
///
/// Both R4-03 legs hardcoded `tty3` and ASSUMED it was free and not the seat's foreground. On
/// a machine where it is neither, the test either collides with a live session or — worse —
/// resolves an ACTIVE session and the leg-2 assertion (`active: false`) fails for an
/// environmental reason that reads as a wiring defect. Assumption, not measurement, in the
/// test whose whole purpose was to measure.
fn verified_spare_vt() -> Option<String> {
    let want = std::env::var("DELPHI_TEST_DAEMON_VT").unwrap_or_else(|_| "tty3".to_owned());
    // The seat's CURRENT foreground, from the kernel rather than from an assumption.
    // D0A-R6-07: `unwrap_or_default()` turned an unreadable probe into "", which matches no
    // VT — so an UNKNOWN foreground read as "not the foreground" and the test proceeded. A
    // probe that cannot answer is not evidence of safety.
    let Ok(foreground) = std::fs::read_to_string("/sys/class/tty/tty0/active") else {
        eprintln!("SKIP: cannot read /sys/class/tty/tty0/active, so the seat's FOREGROUND VT is \
                   UNKNOWN. Refusing to guess that {want} is free.");
        return None;
    };
    let foreground = foreground.trim().to_owned();
    if want == foreground {
        eprintln!("SKIP: {want} is the seat's FOREGROUND VT; this test needs a non-foreground \
                   one so the gate denies on `active`. Set DELPHI_TEST_DAEMON_VT.");
        return None;
    }
    // `Command::output()` returning Ok only means the command SPAWNED. A non-zero exit with
    // empty stdout would otherwise read as "no sessions" (D0A-R6-07).
    let busy = match Command::new("loginctl").args(["list-sessions", "--no-legend"]).output() {
        Ok(o) if o.status.success() => {
            String::from_utf8_lossy(&o.stdout).contains(&format!(" {want} "))
        }
        // Spawned but failed, or did not spawn: UNKNOWN, which is not free.
        _ => true,
    };
    if busy {
        eprintln!("SKIP: {want} already carries a logind session (or loginctl could not say). \
                   Refusing to collide with it.");
        return None;
    }
    Some(want)
}

/// Remove the anchor the DAEMON created for this session user (D0A-R5-09).
///
/// The daemon anchors at the hardcoded `DEFAULT_RUNTIME_BASE`, not at the test's temp dir, so
/// `/run/delphi/<session>` outlives the test. Scoped to this test's own user and never to the
/// base itself.
fn clean_daemon_anchor(session_user: &str) {
    let path = std::path::Path::new(delphi_runtime::anchor::DEFAULT_RUNTIME_BASE)
        .join(session_user);
    if path.is_dir() {
        let _ = std::fs::remove_dir_all(&path);
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
    let Some(vt_name) = verified_spare_vt() else { return };
    let vt = VtName::new(&vt_name).expect("a valid ttyN");
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
    // D0A-R5-10: the SURFACE-marker shell, a distinct binary. The daemon requires
    // SurfaceLive, so a scaffold-marker shell makes `launch()` refuse BEFORE the gate is ever
    // consulted — which is what leg 1 was doing for two rounds while its old assertion
    // accepted the pre-gate startup line.
    let Some(surface) = surface_shell_or_skip("r4_03_daemon_real_gate") else { return };
    let shell_bin = stage_bin(surface, &work, "sshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");
    let result = work.join("result");
    let exe_str = write_marker_exe(&work, &result).display().to_string();
    let work_str = work.display().to_string();
    let Some(daemon_vt) = verified_spare_vt() else { return };

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
        .env("DELPHI_SHELL_VT", &daemon_vt)
        // NOTE: the daemon anchors at the hardcoded DEFAULT_RUNTIME_BASE — it takes no base
        // override. An earlier draft of this test passed `DELPHI_RUNTIME_BASE`, a name that
        // exists NOWHERE in the binary; it was a silent no-op, which is D0A-R2-01's class
        // reappearing in the very test written to close a wiring gap. Caught by checking the
        // assumption against the source rather than by a reviewer.
        // DELPHI_INSECURE_ASSUME_ACTIVE_SESSION is DELIBERATELY UNSET: the real gate runs.
        .env_remove("DELPHI_INSECURE_ASSUME_ACTIVE_SESSION")
    ;
    // D0A-R6-01 + Codex's lead judgement: wait for a STRUCTURED WITNESS, not for the flow to
    // complete.
    //
    // D0A-R7-08 CORRECTS WHAT THAT CLAIMED. "No AI exchange, no terminal EOF" was false as
    // written: `launch()` forks the AI — that is part of what leg 1 exercises — and the daemon
    // keeps running after the witness, so it may well enter accept/serve before the teardown
    // lands. Observing stdout is not a barrier; it is a place to stop WATCHING.
    //
    // What is actually true, and is the property that matters: leg 1 no longer DEPENDS on any
    // of it. The witness is printed before the daemon reaches accept, and the group is torn
    // down as soon as it appears, so whether the AI connects and whether the shell dismisses on
    // EOF are both irrelevant to the verdict. That is what removes R5-11's coupling — the
    // surface shell's EXIT behaviour stopped mattering, not the flow stopped happening.
    let witness = DaemonGuard::spawn(cmd, &setup.user)
        .wait_for_line("DELPHI_GATE_WITNESS ", std::time::Duration::from_secs(60));
    // (the anchor is cleaned by DaemonGuard::drop — D0A-R6-06 — on every path, not just this one)

    // THREE DISTINCT FAILURES, NAMED SEPARATELY. Conflating them is what made the old
    // assertion cause-blind: it accepted a PRE-GATE startup line for two rounds.
    // D0A-R8-03: a recovered witness is not enough. If the identity was lost mid-wait, the
    // group was never signalled and descendants were ABANDONED — the run leaked, whatever the
    // witness says. A test that reports success while having leaked is the false reassurance
    // this arc keeps closing, so success requires BOTH.
    assert!(
        !witness.identity_lost,
        "the daemon's identity was LOST during the wait, so its process group was never torn \
         down and descendants were abandoned. The witness may be valid, but this run is not \
         clean and must not report success. Output:\n{}",
        witness.seen
    );
    let Some(line) = witness.matched.clone() else {
        assert!(
            witness.alive_at_conclusion,
            "the daemon EXITED before emitting the gate witness, so its absence says nothing \
             about the gate — this is a timing/startup failure, not a gate failure. Output:\n{}",
            witness.seen
        );
        panic!(
            "NO gate witness: the daemon ran, stayed alive, and never reached the gate. The \
             witness is printed from the resolution the decision consumes, so it cannot be \
             missing if the gate was evaluated. Output:\n{}",
            witness.seen
        );
    };

    // D0A-R7-09: PRINT THE WITNESS ON SUCCESS. Leg 1 pipes the daemon's stdout into its own
    // sink, so the line never reached the test's output and a passing run showed only `ok` —
    // the evidence existed but was invisible, which is the shape this whole arc keeps finding.
    // A pass now carries what it proved.
    println!("  [leg 1 witness] {line}");

    // Present-but-wrong-cause is a DIFFERENT failure from absence, and says so.
    assert!(
        line.contains("Resolved(")
            && line.contains("active: false")
            && line.contains("remote: false")
            && line.contains("seated: true"),
        "the daemon reached the gate and resolved DIFFERENTLY. Expected a resolved session on a \
         non-foreground seat — Resolved(SessionSnapshot {{ active: false, remote: false, seated: \
         true }}). A `LookupNoData` or an all-false snapshot means the daemon's own \
         `LogindSource` did not resolve the shell's real session, which is exactly what leg 1 \
         exists to catch and could not before. Got:\n  {line}"
    );

    // The seam must be absent from a run whose gate we just witnessed — presence established
    // first (D0A-R5-05), and now by the witness itself rather than by a startup line.
    assert!(
        !witness.seen.contains("INSECURE TEST SEAM ACTIVE"),
        "the gate-bypass seam must NOT have engaged in this run. Output:\n{}",
        witness.seen
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
    assert!(store.grant(&id_a), "fixture: the entry must exist to be granted");

    let id_b = store.next_id();
    let action_b: PendingAction = canonicalize(&marker_proposal(&exe_b, "MARKER-B", &dir), id_b.clone()).unwrap();
    store.insert(action_b);
    assert!(store.grant(&id_b), "fixture: the entry must exist to be granted");

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
    assert!(store.grant(&id), "fixture: the entry must exist to be granted");
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

/// D0A-R15-03: a VALID token whose sealed snapshot does not hold the approved bytes.
///
/// The R14-03 digest check runs AFTER the ledger consume and returned `Unapproved` — the one
/// variant `present_and_execute` reads as "failed verification, ledger untouched". So the
/// ledger consumed, the store stayed Granted, and the two disagreed for the first time; the
/// denial also blamed the token, which had verified perfectly.
///
/// Both halves are asserted because either alone passes with the defect half-fixed: the STATE
/// (store agrees with the ledger) and the REASON (it names the snapshot, not the token).
#[test]
fn b1_a_snapshot_mismatch_consumes_the_approval_and_blames_the_snapshot() {
    if !bwrap_available() {
        eprintln!("SKIP b1_a_snapshot_mismatch: requires bwrap + unprivileged userns");
        return;
    }
    let _dir_tmp = tempfile::Builder::new().prefix("delphi-b1-mismatch-")
        .tempdir_in(std::env::temp_dir()).expect("tempdir");
    let dir = _dir_tmp.path().to_path_buf();
    std::fs::create_dir_all(&dir).unwrap();
    let result = dir.join("res");
    let exe = write_marker_exe(&dir, &result);

    let key = MintingKey::from_bytes(KEY);
    let mut store = PendingStore::new();
    let id = store.next_id();
    let mut action = canonicalize(&marker_proposal(&exe, "MISMATCH", &dir), id.clone()).unwrap();
    // The recorded digest no longer describes the sealed snapshot. The token is minted over
    // the action AFTER this, so the token VERIFIES — only the content identity is wrong,
    // which is exactly the case R14-03 added the check for.
    action.executable_digest = [0x11; 32];
    let digest = canonical_action_digest(&action);
    store.insert(action);
    assert!(store.grant(&id), "fixture: the entry must exist to be granted");
    let good = mint(&key, &digest, NOW).to_wire();
    let mut ledger = ConsumptionLedger::new();

    let d = present_and_execute(&mut store, &mut ledger, &key, &id, &good, NOW);
    println!("  outcome: {d:?}");
    let Outcome::Denied { reason, .. } = &d else {
        panic!("a snapshot mismatch must be denied, got {d:?}");
    };
    assert!(!result.exists(), "denied → nothing executed");
    assert_eq!(
        store.get(&id).unwrap().state,
        PendingState::Consumed,
        "D0A-R15-03: the ledger consumed when the token verified, so the store MUST advance \
         too. Leaving it Granted breaks the stated store/ledger agreement and leaves an \
         approval that reads as re-presentable while the ledger will refuse it."
    );
    assert!(
        reason.contains("snapshot"),
        "D0A-R15-03: the denial must name the SNAPSHOT. The token verified; blaming it sends \
         the operator to the wrong mechanism. reason: {reason}"
    );
    assert!(
        !reason.contains("token does not verify"),
        "D0A-R15-03: the token DID verify. reason: {reason}"
    );
    // Found by weaken (b): with the variant added but no explicit arm in `present_and_execute`,
    // the generic handler produced "execution failed (approval consumed — one-shot): …", which
    // contains "snapshot" and passed every assertion above. NOTHING EXECUTED — this is a
    // refusal BEFORE the run, and telling the operator the tool ran and failed sends them to
    // the tool's logs for an event that never happened.
    assert!(
        !reason.contains("execution failed"),
        "D0A-R15-03: nothing executed — this is a refusal, not a failed run. reason: {reason}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

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
    assert!(store.grant(&id), "fixture: the entry must exist to be granted");
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
        required_tier: RequiredTier::Confirm,
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
    assert!(store.grant(&id), "fixture: the entry must exist to be granted");
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
    // D0A-R14-03: A NATIVE INTERPRETER, ONE LEVEL. This used a `#!/bin/sh` recorder as the
    // interpreter of another script — a NESTED chain, which TRUST_MODEL v7 named limit 1 now
    // refuses at canonicalization. The property under test is unchanged (does the shebang's
    // interpreter ARG reach exec?); only the way it is observed had to stop depending on a
    // chain the contract no longer allows.
    //
    // `$-` carries the shell's active option flags, so a body that writes only when `e` is
    // present observes the ARG ITSELF rather than a recorder's `$1`. Drop the arg and the
    // file stays empty — the same discrimination, one hop shorter.
    let exe = dir.join("act.sh");
    std::fs::write(
        &exe,
        format!("#!/bin/sh -e\ncase $- in *e*) printf ARGPROOF > {} ;; esac\n", result.display()),
    )
    .unwrap();
    std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

    let key = MintingKey::from_bytes(KEY);
    let mut store = PendingStore::new();
    let id = store.next_id();
    let action = canonicalize(&marker_proposal(&exe, "ignored-argv", &dir), id.clone()).unwrap();
    let digest = canonical_action_digest(&action);
    store.insert(action);
    assert!(store.grant(&id), "fixture: the entry must exist to be granted");
    let token = mint(&key, &digest, NOW).to_wire();

    let mut ledger = ConsumptionLedger::new();
    let outcome = present_and_execute(&mut store, &mut ledger, &key, &id, &token, NOW);
    let ran = std::fs::read_to_string(&result).unwrap_or_default().trim().to_string();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(matches!(outcome, Outcome::Completed { .. }), "runs: {outcome:?}");
    assert_eq!(ran, "ARGPROOF", "the shebang interpreter arg reached exec (B1-02), not dropped");
}

// ── B1-01: the DAEMON BINARY's main runs the assembled flow (not parks) ───────

/// `comm` for a pid, as BYTES rendered lossily — never as a UTF-8 decode that can fail closed.
///
/// Same reasoning as `live_group_members` (D0A-R32-01): `comm` is arbitrary bytes chosen by the
/// process, so a strict decode lets a process hide from an identity check by being named badly.
fn comm_of(pid: i32) -> String {
    std::fs::read(format!("/proc/{pid}/comm"))
        .map(|b| String::from_utf8_lossy(&b).trim_end().to_owned())
        .unwrap_or_default()
}

/// D0A-R31-02 — `live_group_members` finds a live survivor, reports unknowns, and skips a
/// **DEMONSTRATED** zombie.
///
/// # The vacuity check the survivor assertion needs
///
/// `survivors_before_guard` being empty is evidence only if a non-empty result is reachable.
///
/// # D0A-R32-03: the previous zombie half PROVED NOTHING
///
/// It used `: &` for the corpse — a short-lived background job the shell reaps before anything
/// observes it, so **no zombie ever existed**. The reviewer ran that test 30/30 with the zombie
/// exclusion DELETED and it passed every time. Half of the check I had called the difference
/// between this closure and the previous one was inert.
///
/// The zombie is now CONSTRUCTED and CONFIRMED: a child is left terminal-but-unreaped, its
/// state is read from `/proc` and asserted to be `Z` **before** the scan runs, and the scan is
/// then asserted not to contain that specific pid. A fixture that cannot show the condition it
/// names is not a fixture.
#[test]
fn live_group_members_finds_a_survivor_reports_unknowns_and_skips_a_real_zombie() {
    use std::os::unix::process::CommandExt as _;

    // A leader in its own group with one long-lived child.
    let mut leader = Command::new("sh")
        .arg("-c")
        .arg("sleep 60 & sleep 60")
        .process_group(0)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn leader");
    #[allow(clippy::cast_possible_wrap)]
    let pgid = leader.id() as i32;

    // A zombie WE own, in our own group: exited and deliberately NOT reaped.
    let mut corpse = Command::new("true").spawn().expect("spawn corpse");
    #[allow(clippy::cast_possible_wrap)]
    let corpse_pid = corpse.id() as i32;
    // Wait for it to become terminal WITHOUT consuming the status, so it stays a zombie.
    // SAFETY: `waitid` writes a `siginfo_t` this frame owns; WNOWAIT leaves it reapable.
    let rc = unsafe {
        let mut si: nix::libc::siginfo_t = std::mem::zeroed();
        nix::libc::waitid(
            nix::libc::P_PID,
            corpse_pid as nix::libc::id_t,
            &mut si,
            nix::libc::WEXITED | nix::libc::WNOWAIT,
        )
    };
    assert_eq!(rc, 0, "waitid failed; no zombie was established (D0A-R32-03)");
    // CONFIRM the condition from /proc rather than assuming it.
    let stat = std::fs::read(format!("/proc/{corpse_pid}/stat")).expect("corpse stat");
    let close = stat.iter().rposition(|&b| b == b')').expect("comm close");
    let state = String::from_utf8_lossy(&stat[close + 1..])
        .split_whitespace()
        .next()
        .and_then(|s| s.chars().next())
        .expect("state field");
    assert_eq!(state, 'Z', "the corpse is in state {state}, not a zombie (D0A-R32-03)");

    std::thread::sleep(std::time::Duration::from_millis(400));
    let found = live_group_members(pgid, pgid);
    assert!(
        !found.is_empty(),
        "the scan found NO members of a group with live children — an empty \
         `survivors_before_guard` would then be vacuous, not evidence (D0A-R31-02)"
    );
    assert!(
        found.iter().all(|(pid, _)| *pid != pgid),
        "the leader must be excluded, it is the daemon itself: {found:?}"
    );

    // THE ZOMBIE HALF, now against a zombie that demonstrably exists. It is in OUR group, so
    // scan our own pgid to reach it.
    let our_pgid = nix::unistd::getpgrp().as_raw();
    let ours = live_group_members(our_pgid, -1);
    assert!(
        ours.iter().all(|(pid, _)| *pid != corpse_pid),
        "a CONFIRMED zombie (pid {corpse_pid}) was counted as a survivor: {ours:?}"
    );

    let _ = leader.kill();
    let _ = leader.wait();
    let _ = corpse.wait();
    // SAFETY: sweeping the group this test created.
    unsafe { nix::libc::kill(-pgid, nix::libc::SIGKILL) };
}

/// A daemon run, with **who was still alive when the guard was about to intervene**.
///
/// D0A-R31-02: `wait()` returned `(Output, killed)`, and `killed` says only whether the daemon
/// hit the guard's deadline. The guard then calls `kill_group` **unconditionally**, so it
/// supplies the cleanup the daemon may not have performed — and a counterfeit daemon that left
/// its child alive passed every assertion in the assembly test with `killed == false`.
///
/// The three outcomes the test must tell apart, which two values cannot:
///
/// | outcome | observation |
/// |---|---|
/// | the DAEMON cleaned up | `survivors_before_guard` is EMPTY |
/// | the daemon did not and the GUARD did | `survivors_before_guard` is non-empty — **the run proves nothing about the daemon** |
/// | neither | non-empty, and still alive afterwards |
struct DaemonRun {
    output: std::process::Output,
    /// The daemon had to be killed at the guard's deadline.
    killed: bool,
    /// Live (non-zombie) members of the daemon's process group, excluding the leader, sampled
    /// **immediately before** the guard's emergency `kill_group`.
    ///
    /// Non-empty is not a diagnostic to log — it **invalidates** any claim about the daemon's
    /// own cleanup, because from that point the harness is doing the work.
    survivors_before_guard: Vec<(i32, char)>,
}

/// Live members of process group `pgid`, excluding `leader`, as `(pid, state)`.
///
/// # D0A-R32-01: this read `/proc/<pid>/stat` as UTF-8 and SKIPPED failures
///
/// `comm` is an arbitrary byte string — whatever `execve` was handed, truncated to 15 bytes. A
/// child whose name is not valid UTF-8 made `read_to_string` fail, the `else { continue }`
/// dropped it, and **a live survivor vanished from the scan**. The counterfeit daemon would
/// then pass the assembly assertions again with the guard supplying the kill — the exact defect
/// this scanner exists to catch, reachable by naming a process badly.
///
/// So: bytes, not `String`. And **an observation error is not absence** — an entry that cannot
/// be read is reported as `?` rather than omitted, because "I could not tell" and "nothing was
/// there" are opposite answers and the caller treats any non-empty result as disqualifying.
///
/// Zombies are EXCLUDED: after the daemon exits, anything killed-but-unreaped is reparented and
/// collected by init, so a `Z` is a race with that rather than a child the daemon failed to
/// terminate. **A live `D`-state child is INCLUDED** — uninterruptible sleep is not death, and
/// D0A-R32 corrected the register where I claimed zombie exclusion hides every `Unreaped`
/// outcome. It hides only the already-collected case.
fn live_group_members(pgid: i32, leader: i32) -> Vec<(i32, char)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        // Cannot enumerate at all: one unknown, never an empty (= clean) answer.
        return vec![(-1, '?')];
    };
    for e in entries.flatten() {
        let name = e.file_name();
        let Some(pid) = name.to_str().and_then(|n| n.parse::<i32>().ok()) else {
            continue; // not a pid directory
        };
        if pid == leader {
            continue;
        }
        let raw = match std::fs::read(format!("/proc/{pid}/stat")) {
            Ok(b) => b,
            // The process genuinely went away between readdir and read.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                out.push((pid, '?'));
                continue;
            }
        };
        // `comm` is parenthesised and may contain spaces AND parens: fields follow the LAST ')'.
        let Some(close) = raw.iter().rposition(|&b| b == b')') else {
            out.push((pid, '?'));
            continue;
        };
        let rest = String::from_utf8_lossy(&raw[close + 1..]);
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // After comm: [0]=state [1]=ppid [2]=pgrp
        let (Some(state), Some(pgrp)) = (fields.first(), fields.get(2)) else {
            out.push((pid, '?'));
            continue;
        };
        let st = state.chars().next().unwrap_or('?');
        if st == 'Z' {
            continue;
        }
        if pgrp.parse::<i32>() == Ok(pgid) {
            out.push((pid, st));
        }
    }
    out
}

/// Strip ANSI SGR escapes from captured output before matching against it.
///
/// **D0A-R30: the fourth assertion in a row that I got wrong by reading a DISPLAY instead of
/// BYTES.** `tracing_subscriber::fmt()` renders structured field names with SGR escapes even
/// when stdout is a pipe, so the daemon's `child = "ai"` field is really
/// `\x1b[3mchild\x1b[0m\x1b[2m=\x1b[0m"ai"`. A terminal renders those as italics and the
/// transcript looks exactly like `child="ai"` — so an assertion written from the transcript can
/// never match, and the mismatch is invisible in the failure output because the panic message
/// prints the same escapes back through the same terminal.
///
/// Measured with `cat -v` against a probe using the daemon's own subscriber init, not inferred.
/// The message TEXT carries no internal escapes, which is why a `contains(MESSAGE)` assertion
/// passed while the field one could not.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // CSI ... final-byte. Consume through the terminator rather than guessing a length.
        if chars.next() == Some('[') {
            for t in chars.by_ref() {
                if ('@'..='~').contains(&t) {
                    break;
                }
            }
        }
    }
    out
}

/// D0A-R30 — `strip_ansi` against the bytes tracing ACTUALLY emits.
///
/// The input here is not invented: it is the exact line captured with `cat -v` from a probe
/// using `delphi-runtimed`'s own subscriber init. A helper that makes other assertions possible
/// is load-bearing, and this arc has now produced four assertions that could not match because
/// they were written from a rendered display.
#[test]
fn strip_ansi_recovers_the_field_text_tracing_actually_emits() {
    // \x1b[3mchild\x1b[0m\x1b[2m=\x1b[0m"ai"  — italic name, dim equals, quoted value.
    let raw = "child outlived the grace period and was terminated (D0A-R28-02) \
               \u{1b}[3mchild\u{1b}[0m\u{1b}[2m=\u{1b}[0m\"ai\"";
    let clean = strip_ansi(raw);
    assert!(
        clean.contains(r#"child="ai""#),
        "the field did not survive stripping: {clean:?}"
    );
    assert!(
        clean.contains(delphi_runtime::shutdown::TERMINATED_AFTER_GRACE),
        "the message did not survive stripping: {clean:?}"
    );
    // THE DISCRIMINATOR: the raw form must NOT match, or stripping is doing nothing and this
    // test would pass against a no-op helper.
    assert!(
        !raw.contains(r#"child="ai""#),
        "the raw bytes already matched — the fixture is not the escaped form and this test \
         proves nothing"
    );
    // A line with no escapes must pass through unchanged.
    assert_eq!(strip_ansi("plain child=\"ai\""), "plain child=\"ai\"");
}

/// **D0A-R30 decision A — ASSEMBLY COVERAGE for the bounded daemon exit (D0A-R28-02).**
///
/// # What this proves that the extraction's unit tests cannot
///
/// `runtime/src/shutdown.rs` proves the POLICY is correct. `the_daemon_delegates_shutdown_and_
/// does_not_reap_by_hand` proves `main` CONTAINS a call to it — but that guard is an
/// `include_str!` source read, so it proves the token is present, not that the branch is
/// TAKEN. This test is the missing half: the daemon, running as the real binary, actually
/// exercising the policy against an AI that refuses to exit.
///
/// # The five assertions, and why each is load-bearing
///
/// 1. **The bypass POSITIVELY REPORTED itself.** Without this the test is outcome coverage:
///    an untrusted AI staying alive and a daemon exiting anyway could both be true for reasons
///    unrelated to the fix. The report ties the outcome to the mechanism that produced it.
/// 2. **A specific terminal outcome occurred** — `Completed`, not merely "the daemon ended".
/// 3. **The AI acknowledged the terminal response AND remained alive past grace.** If it died
///    early the daemon's clean exit means nothing, so this is checked from the AI's own stderr
///    rather than assumed from the fixture's name.
/// 4. **The daemon attributed termination to that AI, cleaned up the shell, and exited within
///    the bound** — `!killed` is the whole property: `DaemonGuard` kills at its deadline, and a
///    kill means the daemon did NOT bound its own wait.
/// 5. **Removing the shutdown call makes this test fail.** It needs no special construction:
///    with a stubborn AI and no bounded exit, `main` blocks in `waitpid` forever, the guard
///    kills it at the deadline, and `!killed` fails. That is the RED the delegation guard could
///    not provide, and it is why this test — not that one — is the assembly evidence.
///
/// **Scope, stated so a green cannot be over-read:** this runs a binary built with
/// `insecure-test-seams`, whose logind gate is bypassable. It certifies the SHUTDOWN ASSEMBLY
/// and **nothing about the production logind gate**, which remains blocked on a seated lane.
/// Those are separate obligations and this closes only the first.
#[test]
fn b1_daemon_bounds_an_ai_that_completes_the_protocol_and_stays_alive() {
    if !cfg!(feature = "insecure-test-seams") {
        eprintln!(
            "SKIP b1_daemon_bounds_an_ai...: requires `--features insecure-test-seams` (the \
             gate-bypass seam AND the stubborn-AI fixture are both feature-gated). Run: \
             `cargo test -p delphi-runtime --features insecure-test-seams --test b1_integration`"
        );
        return;
    }
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP b1_daemon_bounds_an_ai...: requires root");
        return;
    }
    if !bwrap_available() {
        eprintln!("SKIP b1_daemon_bounds_an_ai...: requires bwrap + unprivileged userns");
        return;
    }
    let setup = Setup::new("stubborn");
    let _stage_tmp = tempfile::Builder::new()
        .prefix("delphi-r30asm-")
        .tempdir_in(std::env::temp_dir())
        .expect("tempdir");
    let stage = _stage_tmp.path().to_path_buf();
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o777)).unwrap();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &stage, "mshell");
    // THE ONLY DIFFERENCE FROM b1_daemon_binary_runs_the_assembled_flow. Same protocol, same
    // helpers; it just does not exit. Any behavioural difference is attributable to that.
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-stubborn-ai"), &stage, "sai");
    let result = stage.join("result");
    let exe = write_marker_exe(&stage, &result);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_delphi-runtimed"));
    cmd.args(["--session", &setup.user])
        .env("DELPHI_SHELL_BIN", &shell_bin)
        .env("DELPHI_AI_BIN", &ai_bin)
        .env(delphi_runtime::scaffold_env::PASSWORD, PASSWORD)
        .env(delphi_runtime::scaffold_env::AI_EXE, &exe)
        .env(delphi_runtime::scaffold_env::AI_ARG, "STUBBORN-FLOW")
        .env(delphi_runtime::scaffold_env::AI_BIND_RW, &stage)
        .env("DELPHI_SHELL_VT", "tty1")
        .env("DELPHI_INSECURE_ASSUME_ACTIVE_SESSION", "1");

    // ── THE POSITIVE CONTROL (D0A-R32-01) ───────────────────────────────────────────────
    // `survivors_before_guard` being EMPTY is the observation this test rests on. The fixture
    // `live_group_members_finds_a_survivor_…` shows the scanner works against a child spawned
    // by the TEST PROCESS with `.process_group(0)`. The reviewer's question was whether that
    // transfers: the assembly case is a real daemon, a fork/exec'd child, and a pgid inherited
    // across `execve`. It was an ARGUMENT — `launcher.rs` and `execute.rs` call neither
    // `setsid` nor `setpgid` — and this measures it instead.
    //
    // The probe polls the daemon's group WHILE IT RUNS and records whether the real AI was
    // ever seen there. If it never is, an empty sample at shutdown proves nothing about the
    // assembly, and this test's central assertion is vacuous for the case it actually covers.
    //
    // Identified by `comm` rather than by a pid the fixture reports: the AI is privilege-
    // dropped, and a fixture that announces its own identity is the harness supplying the
    // observation again (D0A-R31-02).
    let guard = DaemonGuard::spawn(cmd, &setup.user);
    let daemon_pid = guard.pid();
    let ai_comm = std::path::Path::new(&ai_bin)
        .file_name()
        .expect("ai binary name")
        .to_string_lossy()
        .into_owned();
    let probe_comm = ai_comm.clone();
    let probe = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(140);
        let mut seen: Vec<(i32, char, String)> = Vec::new();
        while std::time::Instant::now() < deadline {
            for (pid, state) in live_group_members(daemon_pid, daemon_pid) {
                let c = comm_of(pid);
                // `comm` is truncated to 15 bytes by the kernel, so compare on that prefix.
                let want: String = probe_comm.chars().take(15).collect();
                if c == want && !seen.iter().any(|(p, _, _)| *p == pid) {
                    seen.push((pid, state, c));
                }
            }
            if !seen.is_empty() {
                return seen;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        seen
    });

    let run = guard.wait();
    let ai_seen_live = probe.join().expect("probe thread");
    let (out, killed, survivors) = (run.output, run.killed, run.survivors_before_guard);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // WHICH STREAM CARRIES WHAT, measured rather than assumed — the first run of this test
    // failed on exactly this. `tracing_subscriber::fmt()` writes to **stdout** by default
    // (`delphi-runtimed.rs`), so every `tracing::{error,warn}!` the daemon emits — the seam
    // report and the shutdown attribution — lands there. The FIXTURES use `eprintln!`, so
    // their lines land on **stderr**. Asserting the daemon's own logging against stderr looked
    // reasonable and could never match.
    // ANSI-STRIPPED: tracing renders field names with SGR escapes even to a pipe, so matching
    // raw bytes against a transcript-derived literal cannot work. See `strip_ansi`.
    let daemon_log = strip_ansi(&stdout);
    let fixture_log = strip_ansi(&stderr);

    // (0a) **THE CONTROL, CHECKED BEFORE THE OBSERVATION IT VALIDATES (D0A-R32-01).**
    //
    // If the scanner cannot see the real AI in the daemon's group, then the empty sample below
    // is not evidence of the daemon cleaning up — it is a scan that was never going to find
    // anything. This is the same discipline as (0): the check that could invalidate the run
    // comes first, and fails the test rather than logging a caveat.
    assert!(
        !ai_seen_live.is_empty(),
        "POSITIVE CONTROL FAILED: the scanner never saw the AI (comm {ai_comm:?}) alive in the \
         daemon's process group {daemon_pid} at any point during the run. The empty \
         `survivors_before_guard` is therefore VACUOUS for the assembly case — it does not \
         distinguish `the daemon cleaned up` from `the scan cannot reach the daemon's children`. \
         The fixture demonstration transfers only if this holds.\n\
         daemon log:\n{daemon_log}\nfixture log:\n{fixture_log}"
    );

    // (0) **THE INVALIDATING OBSERVATION (D0A-R31-02), CHECKED FIRST.**
    //
    // Everything below reads either the daemon's own log or the fact that it beat the guard's
    // deadline. Neither can distinguish "the daemon cleaned up" from "the daemon did not and
    // the GUARD did", because `wait()` calls `kill_group` unconditionally. A counterfeit daemon
    // that reported termination and left its child alive passed all nine of the assertions
    // below with `killed == false`.
    //
    // So this is not a diagnostic to log — a survivor means the harness performed the cleanup
    // and **the run proves nothing about the daemon**. The test must fail rather than pass with
    // a note, which is the difference between recording an intervention and being invalidated
    // by one.
    assert!(
        survivors.is_empty(),
        "the daemon left {} process(es) of its own group ALIVE, and the guard was about to kill \
         them: {survivors:?}. The daemon did NOT perform the cleanup this test claims to \
         observe — every assertion below would pass anyway, because they read the daemon's own \
         log and its exit timing (D0A-R31-02).\nstdout:\n{stdout}",
        survivors.len()
    );
    // (4) THE PROPERTY. A kill at the deadline means the daemon did not bound its own wait —
    // which is exactly what an unbounded `waitpid` on a stubborn AI produces.
    assert!(
        !killed,
        "the daemon had to be KILLED at the deadline — it did not bound its wait on an AI that \
         completed the protocol and stayed alive (D0A-R28-02).\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // (1) The bypass reported itself, so the outcome is tied to the mechanism. DAEMON stream.
    assert!(
        daemon_log.contains("INSECURE TEST SEAM ACTIVE"),
        "the daemon did not report the gate bypass engaging — without that this is outcome \
         coverage, not assembly coverage.\nstdout:\n{stdout}"
    );
    // (3) The AI reached the stubborn state. FIXTURE stream. If it died early, the rest is
    // vacuous — the daemon would have had a cooperating child after all.
    assert!(
        fixture_log.contains("STUBBORN: terminal response acknowledged, NOT exiting"),
        "the AI never reached the stubborn state, so the daemon's clean exit proves \
         nothing.\nstderr:\n{stderr}"
    );
    assert!(
        !fixture_log.contains("without being killed — the daemon did NOT bound its wait"),
        "the stubborn AI slept to completion — it was never terminated.\nstderr:\n{stderr}"
    );
    // (2) A specific terminal outcome, not merely "it ended".
    assert!(
        stdout.contains("DELPHI_RUNTIMED_OUTCOME Completed"),
        "expected a Completed terminal outcome.\nstdout:\n{stdout}"
    );
    // (4, cont.) Termination attributed to the AI BY NAME. DAEMON stream. This is what
    // distinguishes "bounded the right child" from "exited somehow".
    // The literal comes from the PRODUCTION const, not from a copy in this file. The first
    // version of this assertion used the pre-extraction wording, reconstructed from memory —
    // it could never match, and it reported the property absent while the transcript showed it
    // happening (D0A-R2-05's lesson, one module over).
    assert!(
        daemon_log.contains(delphi_runtime::shutdown::TERMINATED_AFTER_GRACE),
        "the daemon did not log a grace-period termination at all.\nstdout:\n{stdout}"
    );
    assert!(
        daemon_log.lines().any(|l| {
            l.contains(delphi_runtime::shutdown::TERMINATED_AFTER_GRACE)
                && l.contains(r#"child="ai""#)
        }),
        "a grace-period termination was logged but not attributed to the AI on the same line — \
         which is what distinguishes 'bounded the right child' from 'exited somehow'.\nstdout:\n{stdout}"
    );
    assert!(
        out.status.success(),
        "the daemon reported a cleanup failure; a terminated-and-reaped child is CLEAN \
         cleanup (D0A-R29-05).\nstdout:\n{stdout}"
    );
    // The action still ran: bounding the AI must not break the flow it was serving.
    let marker = std::fs::read_to_string(&result).unwrap_or_default().trim().to_string();
    assert_eq!(marker, "STUBBORN-FLOW", "the action did not execute via delphi-runtimed's main");
}

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
    let run = DaemonGuard::spawn(cmd, &setup.user).wait();
    let (out, killed) = (run.output, run.killed);
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
        required_tier: pb::RequiredTier::TierConfirm as i32,
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
    // D0A-R21-01: a gate-DENIED action sends NO preview, so there is no approval-request
    // datagram to read here. This line used to assert one arrived — scaffolding that
    // established "there is data before release", not the property under test. The property
    // is the TERMINAL CONTRACT below: after `serve_one_action` returns, the daemon releases
    // the channel so the shell sees EOF instead of wedging. That is unchanged, and the
    // pre-release WouldBlock still distinguishes "not yet released" from "released".
    //
    // NOT a weakening: keeping the old assertion would require reverting a security fix, and
    // the discriminating question — would this edit be made if the test were passing? — is
    // answered by the weaken below, which removes the release and still fails.
    // PRE-RELEASE: the daemon has NOT closed → the read WOULD BLOCK (the wedge).
    assert!(matches!(nb_read(sfd), Rd::WouldBlock), "pre-release: no EOF → the shell would wedge");
    // THE TERMINAL CONTRACT: delphi-runtimed releases the daemon channel after serve.
    drop(daemon_ch);
    // POST-RELEASE: EOF → the host's recv_prompt → None → dismiss (no wedge).
    assert!(matches!(nb_read(sfd), Rd::Eof), "post-release: EOF → the host dismisses cleanly");
}

// ── THE CHAIN-GAP DEMONSTRATION (§3, 2026-08-26) ─────────────────────────────

/// `#!/usr/bin/env python3` + an approved `PATH` selects an IMPOSTOR — composed through the
/// real `canonicalize` → `preview` → gate → `execute` path, not reconstructed from argv.
///
/// Three assertions, and the third is what makes the first mean anything:
///
///   1. the impostor RAN — its marker, not a refusal;
///   2. the PREVIEW discloses the deciding directory rather than `PATH=[redacted]`;
///   3. CONTROL — the same action WITHOUT `PATH` succeeds and writes no marker.
///
/// **(3) must SUCCEED, not error.** A control that died at `execvp` would prove the impostor
/// was UNREACHABLE rather than UNSELECTED. So the script body is valid Python: without
/// `PATH`, `env` falls back to confstr `/bin:/usr/bin` (measured), the real `/usr/bin/python3`
/// runs it, and the only difference between the legs is which binary `python3` named.
///
/// Runs privileged AND unprivileged on purpose — `env_delta` reaches the tool by DIFFERENT
/// transports (a sealed memfd via `delphi-drop` when credentials exist; bwrap `--setenv`
/// tokens when they do not), so both runs are informative and the root lane exercises the
/// shipping one.
#[test]
fn chain_gap_approved_path_selects_the_impostor_and_the_preview_discloses_it() {
    if !bwrap_available() {
        eprintln!("SKIP chain_gap_approved_path: requires bwrap");
        return;
    }
    let _tmp = tempfile::Builder::new()
        .prefix("delphi-chain-gap-")
        .tempdir_in(std::env::temp_dir())
        .expect("tempdir");
    let dir = _tmp.path().to_path_buf();
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let marker = dir.join("impostor-marker");

    let impostor = bin.join("python3");
    std::fs::write(
        &impostor,
        format!("#!/bin/sh\nprintf IMPOSTOR-RAN > {}\n", marker.display()),
    )
    .unwrap();
    std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o755)).unwrap();

    // D0A-R18-01: the body writes a DISTINCT control marker, so the no-PATH leg has a
    // POSITIVE witness that the real python3 ran — absence of the impostor marker alone was
    // satisfiable by the real python failing, which `is_ok()` could not see.
    let control_marker = dir.join("control-marker");
    let script = dir.join("act.py");
    std::fs::write(
        &script,
        format!(
            // D0A-R19-08: the witness records WHICH interpreter ran, not merely that one
            // did. `REAL-PYTHON-RAN` was satisfied by any python on any path — including,
            // in principle, the impostor's directory — so it could not distinguish the
            // control from a leaked selection.
            // `sys.executable` is EMPTY when `env` resolved through its confstr fallback
            // (measured in this arc's own probe and not carried forward until D0A-R19-08's
            // first run failed on it), so the witness pairs it with something always
            // populated. Emptiness of the path is then data, not an absent witness.
            // D0A-R20-05: `sys.executable` is EMPTY under env's confstr fallback, so a
            // witness built on it permitted emptiness and then treated emptiness as proof of
            // LOCATION — `py3|` passed both assertions while saying nothing about where the
            // interpreter came from. `/proc/self/exe` is the kernel's own answer and is always
            // populated, so the location claim is measured rather than assumed.
            "#!/usr/bin/env python3\nimport os,sys\nopen({:?}, \"w\").write(\"py%d|%s\" % (sys.version_info[0], os.path.realpath(\"/proc/self/exe\")))\n",
            control_marker.display().to_string()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

    // `chown_to_tool` is NOT recursive. Every path the dropped tool must traverse, execute
    // or write gets it explicitly — the un-chowned nested path is the shape all four of this
    // arc's Class 20 defects took, and three presented as an empty marker with no error.
    credentials::chown_to_tool(&dir);
    credentials::chown_to_tool(&bin);
    credentials::chown_to_tool(&impostor);
    credentials::chown_to_tool(&script);

    let run = |with_path: bool| {
        let mut proposal = marker_proposal(&script, "unused-argv", &dir);
        // argv[0] MUST be `env` here, and finding that out is itself a result of composing
        // rather than reconstructing. `/usr/bin/env` on this box is uutils coreutils — a
        // MULTI-CALL binary that dispatches on argv[0] — so the approved argv[0] of `tool`
        // made the interpreter refuse (`coreutils: unknown program 'tool'`) before it
        // resolved anything. Fails CLOSED, so it is a functionality limit rather than a
        // hole, but it is invisible to `env -i PATH=... /usr/bin/env python3`, which carries
        // argv[0] = the path. See CONFORMANCE_REGISTER.md, the chain-gap row.
        proposal.argv[0] = "env".into();
        if with_path {
            proposal.env_delta = vec![pb::EnvVar {
                key: "PATH".into(),
                value: bin.display().to_string(),
            }];
        }
        let key = MintingKey::from_bytes(KEY);
        let action = canonicalize(&proposal, "chain-gap".into()).unwrap();
        let rendered = delphi_runtime::action::preview(&action);
        let digest = canonical_action_digest(&action);
        let token = mint(&key, &digest, NOW);
        let mut ledger = ConsumptionLedger::new();
        let out = delphi_runtime::execute::execute_approved(&action, &token, &key, NOW, &mut ledger);
        (rendered, out)
    };

    let (preview_with_path, exec_with_path) = run(true);
    let seen = std::fs::read_to_string(&marker).unwrap_or_default().trim().to_string();

    // CLASS 43 — `execvp: No such file or directory` cannot distinguish a missing fd from a
    // missing loader, and it has cost this arc two misdiagnoses. Print the CHILD's own
    // stderr before any assertion runs, so a failure is diagnosed rather than guessed.
    match &exec_with_path {
        Ok(o) => eprintln!(
            "chain-gap: exit={:?}\n  child stderr: {}\n  child stdout: {}",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim(),
            String::from_utf8_lossy(&o.stdout).trim()
        ),
        Err(e) => eprintln!("chain-gap: REFUSED before exec (no child ran): {e}"),
    }
    eprintln!("chain-gap: preview =\n{preview_with_path}");

    // D0A-R18-01: `is_ok()` proves only that the child was SPAWNED AND REAPED —
    // `Command::output()` returns Ok for a nonzero exit. Both legs must have SUCCEEDED.
    let ok_and_zero = |r: &Result<std::process::Output, delphi_runtime::RuntimeError>, leg: &str| {
        match r {
            Err(e) => panic!("{leg}: refused before exec, no child ran: {e}"),
            Ok(o) => assert!(
                o.status.success(),
                "{leg}: the child exited {:?} — a nonzero exit with no marker would otherwise \
                 read as the control succeeding. stderr: {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            ),
        }
    };

    ok_and_zero(&exec_with_path, "PATH leg");
    assert_eq!(
        seen, "IMPOSTOR-RAN",
        "the approved PATH selected an impostor `python3` through the real composed path — \
         empty here means the impostor did not run; check the child stderr above before \
         concluding which of the four shapes it was"
    );
    assert!(
        preview_with_path.contains(&bin.display().to_string()),
        "the preview must DISCLOSE the directory that decides which python3 runs:\n{preview_with_path}"
    );

    // CONTROL. Without PATH the same action must SUCCEED, write the CONTROL marker (positive
    // evidence the real python3 ran) and NOT write the impostor marker.
    std::fs::remove_file(&marker).ok();
    std::fs::remove_file(&control_marker).ok();
    let (_preview_no_path, exec_no_path) = run(false);
    let control_seen = std::fs::read_to_string(&marker).unwrap_or_default();
    let control_witness = std::fs::read_to_string(&control_marker).unwrap_or_default();
    if let Ok(o) = &exec_no_path {
        eprintln!(
            "chain-gap CONTROL: exit={:?} witness={control_witness:?} stderr={}",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    ok_and_zero(&exec_no_path, "CONTROL leg");
    assert!(
        control_witness.starts_with("py3"),
        "the CONTROL must show a PYTHON interpreter ran. Without this witness, 'no impostor \
         marker' is satisfied by the real python failing — which is what D0A-R18-01 found. \
         witness={control_witness:?}"
    );
    // D0A-R20-05: the location must be PRESENT before its content can mean anything. An
    // empty path trivially "does not contain" the impostor directory, which is how the
    // previous form passed while measuring nothing.
    let control_path = control_witness.split_once('|').map(|(_, p)| p).unwrap_or("");
    assert!(
        control_path.starts_with('/'),
        "the CONTROL produced no interpreter LOCATION, so 'not from the impostor dir' is \
         vacuous. witness={control_witness:?}"
    );
    assert!(
        !control_path.contains(&bin.display().to_string()),
        "the CONTROL's interpreter came from the IMPOSTOR directory ({}), so the leg does \
         not establish that PATH is what selected it. witness={control_witness:?}",
        bin.display()
    );
    assert!(
        control_seen.is_empty(),
        "without PATH the impostor must NOT run; it did, so the marker is not attributable \
         to PATH: {control_seen:?}"
    );
}
