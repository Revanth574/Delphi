// SPDX-License-Identifier: MIT

//! **Properties of the restructured shell child** (`docs/TRUST_MODEL.md` §4).
//!
//! Three tests sharing one harness, because each needs the same expensive setup (root, the
//! installed PAM stack, a real VT, and a launch through the real `fork_shell`):
//!
//! * `session_leader_is_the_shell_itself_r3_01c` — **B-1**, leader == shell (R3-01c).
//! * `shell_inherits_only_the_allowlisted_fds_fd_01` — **FD-01**, fd containment through
//!   the restructured child, which no existing test covers.
//! * `shell_child_drops_to_the_session_user_b3` — **B-3 / B′**, the privilege-drop EFFECT on
//!   the manual-fork path (the *order* is unit-proven on the function; nothing asserted the
//!   effect on `fork_shell` until this test).
//!
//! # B-1 — the leader == shell regression test (§4 R3-01c)
//!
//! The recon PROVED leader == shell nine times over on the seated lane. A recon proof is
//! not a shipped regression test: §4 R3-01c's "What remains outstanding" clause requires
//! this assertion to live in the runtime crate, **verified to FAIL against a leader != shell
//! (forked-grandchild) implementation**, so the property cannot silently regress.
//!
//! # What is asserted, and why it is not circular
//!
//! Two steps, and the split is the whole design:
//!
//! 1. **Resolve the session by CGROUP MEMBERSHIP** — `logind::session_id_for_pid(shell_pid)`.
//!    `sd_pid_get_session` answers "which session's cgroup contains this pid", so it
//!    resolves for a session **leader** and for any **descendant** alike (§4 A-1, measured).
//!    This step therefore succeeds under BOTH topologies and discriminates nothing — which
//!    is exactly what makes it a sound first step.
//! 2. **Compare that session's `Leader` to the shell's pid** — this is the discriminator.
//!
//! Resolving *by leadership* would be circular: it would find only the session it was about
//! to prove. Membership-then-leader is the non-circular order.
//!
//! # The verdict source is LOGIND, not the binary's self-report
//!
//! §4 R3-01c is explicit that the authoritative assertion is external
//! (`loginctl show-session -p Leader` + `sd_pid_get_session`), because "the binary reports
//! only pid-continuity by construction". A shell that printed its own pid and claimed to be
//! the leader would prove nothing — under the grandchild topology it would print the same
//! thing. So `Leader` is read from logind.
//!
//! # THE WEAKEN/RESTORE PROTOCOL (B-1's reason to exist)
//!
//! This test is only meaningful if it FAILS against the wrong topology. That is proven by a
//! **deliberate source edit**, not a `cfg`/feature flag — a compiled-in weakened path could
//! ship by accident, whereas an edit is visible in the diff (§4 R3-01c seam):
//!
//! * **WEAKEN:** in `runtime/src/launcher.rs`, `shell_child_become`'s final line, replace
//!   `exec_shell_in_place(spec)` with `fork_grandchild_then_exec(spec)`.
//! * Run this test → it MUST **FAIL** on the leader assertion (not skip, not error out
//!   early — see the precondition rules below).
//! * **RESTORE:** put `exec_shell_in_place(spec)` back.
//! * Run this test → it MUST **PASS**.
//!
//! Both transcripts belong in the commit body.
//!
//! # HOW TO RUN IT — build unprivileged, run the BINARY as root
//!
//! ```text
//! cargo test -p delphi-runtime --test leader_is_shell --no-run     # prints the binary path
//! sudo <that binary path> --nocapture --test-threads=1
//! ```
//!
//! **`sudo cargo` does NOT work on this lane** (measured 2026-07-22): `sudo` resets `PATH`
//! so `cargo` is not found, and `-E` is disabled by this system's sudoers. Building
//! unprivileged and running only the test binary as root is also strictly better hygiene —
//! it keeps root-owned artifacts out of the developer's `CARGO_TARGET_DIR`. (Several older
//! root-gated tests still carry doc-comments showing a WSL2 `/home/raven/.cargo/bin/cargo`
//! invocation; that form is stale on this lane twice over — wrong path AND cargo-as-root.)
//!
//! Two rules, each closing a way the transcript can LIE:
//!
//! 1. **`--test-threads=1`.** `terminal_contract_release_produces_eof_no_wedge` is flaky at
//!    ~7-10% under parallel execution (measured 3/30 at `d57442e`; pre-existing, tracked
//!    separately). **Always confirm the failing test NAME before drawing any conclusion.**
//! 2. **`--nocapture`, and A SKIP INVALIDATES THE RUN.** The harness swallows output from
//!    PASSING tests, so a SKIP is otherwise indistinguishable from a PASS — and a skipped
//!    test passes under BOTH topologies. If the weaken run does not print
//!    `B1-ASSERTION-EXECUTED` followed by a FAILURE, the topology was never exercised.
//!
//! # Why the shell under test is a `pause()` sleeper, not `delphi-minimal-shell`
//!
//! The first version launched `delphi-minimal-shell` on the premise that it would block in
//! `recv_approval_request`. It does not: that call errors on any datagram `< 32` bytes
//! (`service.rs:265`), and a 0-length read (EOF) hits exactly that path — so the shell
//! PANICKED AND EXITED before the measurement. Under leader == shell that is fatal to the
//! test's meaning: shell death IS session teardown, so a late measurement would find no
//! session and fail for a reason unrelated to topology.
//!
//! The measurement must not depend on the shell's protocol behaviour at all. So the shell
//! under test is a two-line C program that calls `pause()` — blocks forever on no
//! descriptors, produces no output, exits on SIGTERM. It is also a real ELF, which makes
//! leg 3 below an exact path comparison rather than an interpreter-resolution guess (a
//! `#!/bin/sh` script would make `/proc/<pid>/exe` resolve to the interpreter).

use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::Command;

use delphi_runtime::launcher::{launch, LaunchSpec, VtName, SHELL_CHANNEL_FD};
use delphi_runtime::logind::session_id_for_pid;
use delphi_runtime::{bind_approval_socket, ensure_runtime_dir, RuntimeError};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{geteuid, Gid, Pid, Uid, User};

#[path = "common/shell_fixtures.rs"]
mod shell_fixtures;

/// The installed production stack (C2). NOT written by this test — it is a system-config
/// artifact the operator installs, and a test that wrote it could mask its absence.
const PAM_FILE: &str = "/etc/pam.d/delphi-runtime";

/// Printed immediately before the discriminating assertion. Its presence in the transcript
/// is what distinguishes "the assertion ran and the topology was wrong" from "the test
/// skipped" — the FAIL/FAIL and PASS/PASS confusions this protocol exists to avoid.
const EXECUTED_MARKER: &str = "B1-ASSERTION-EXECUTED";

/// A throwaway session user, removed on drop.
struct Setup {
    user: String,
}

impl Setup {
    /// `tag` MUST be unique per test in this binary.
    ///
    /// Both tests here previously derived the SAME name from `std::process::id()`. Under
    /// `--test-threads=1` the first test's teardown can lose its race to reap the account
    /// (bounded wait expires, `userdel` fails, the account leaks) — and the second test's
    /// `useradd` then fails, panicking in `Setup::new` BEFORE any marker is printed. That is
    /// not a precondition skip and not an assertion failure: it is FIXTURE COLLISION, and it
    /// presents as a bare panic easily misread as the test's own verdict. Observed exactly
    /// once, as FD-01 "failing" with no `B1-ASSERTION-EXECUTED(FD-01)` line at all.
    fn new(tag: &str) -> Self {
        let user = format!("delphi-{tag}-{}", std::process::id());
        // A previous run that failed to reap may have leaked this exact account; clear it so
        // a stale leftover cannot fail an otherwise-valid run. GUARD on existence first: an
        // unconditional `userdel` prints `userdel: user '...' does not exist` on the common
        // (clean) path, and expected-error noise buries the real failures it sits next to.
        if User::from_name(&user).ok().flatten().is_some() {
            let _ = Command::new("userdel").args(["-r", &user]).status();
        }
        let ok = Command::new("useradd")
            .args(["-M", "-s", "/usr/sbin/nologin", &user])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        assert!(
            ok,
            "useradd {user} failed — this is FIXTURE SETUP, not a verdict on the property \
             under test. Check for a leaked delphi-* account from an earlier run."
        );
        Self { user }
    }

    fn ids(&self) -> (Uid, Gid) {
        let u = User::from_name(&self.user).unwrap().unwrap();
        (u.uid, u.gid)
    }
}

impl Drop for Setup {
    /// WAIT-AND-REAP, not kill-harder. The first version ran `userdel` immediately and
    /// DISCARDED its exit code, so `userdel: user ... is currently used by process N`
    /// failed silently and leaked a system account per run (two accumulated, uid 1001/1002,
    /// removed by hand). Diagnosis: the holders were not stuck — they exited on their own
    /// moments later — so cleanup was merely running too early. Hence a bounded wait for the
    /// account to be free, and the status is CHECKED. No `-r`: the account is created with
    /// `useradd -M` (no home, no mail spool), so `userdel -r` only prints
    /// `mail spool ... not found` / `home directory ... not found` on a SUCCESS exit —
    /// expected-error noise that buries the real failures it sits next to.
    fn drop(&mut self) {
        let uid = User::from_name(&self.user).ok().flatten().map(|u| u.uid);

        // Ask anything still running as this uid to leave, including processes we cannot
        // `waitpid` (under the weaken the real shell is a GRANDCHILD, reparented to init,
        // so it is not ours to reap — but it is ours to signal).
        // SESSION-LEVEL TEARDOWN FIRST — the layer the previous fix was missing.
        // `userdel` refuses while the user is REGISTERED AS LOGGED IN, which is logind/utmp
        // state, not process state. Signalling pids cannot clear it: a session survives its
        // last process briefly in `closing`, and utmp still names the user. Measured on the
        // lane: 1 account leaked per PASSING iteration for exactly the four tests that leave
        // a shell holding a PAM session (b1, b3, fd01, p1) — and NOT for r402, which asserts
        // the shell is gone before this runs. `/run` dirs stayed at 0 throughout, so the
        // directory cleanup was fine and only the account cleanup was short a layer.
        let _ = Command::new("loginctl").args(["terminate-user", &self.user]).status();
        // D0-R6-04: `terminate-user` returns BEFORE the sessions are gone. The pid wait below
        // covers processes; this covers the SESSION, which is the thing that holds the VT and
        // the thing `userdel` refuses over.
        for _ in 0..40 {
            let busy = Command::new("loginctl")
                .args(["list-sessions", "--no-legend"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains(self.user.as_str()))
                .unwrap_or(false);
            if !busy {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        if let Some(uid) = uid {
            for pid in pids_owned_by(uid) {
                let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
            }
            // Bounded wait for the account to be genuinely free (~2s worst case).
            for _ in 0..40 {
                if pids_owned_by(uid).is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let stragglers = pids_owned_by(uid);
            if !stragglers.is_empty() {
                eprintln!(
                    "WARN: {} still has processes {stragglers:?} after the bounded wait; \
                     userdel will likely fail and leak the account.",
                    self.user
                );
            }
        }

        // `.output()` not `.status()`: userdel's REASON goes to stderr, and inheriting it
        // buried the message in the surrounding test output. Capturing it makes the next
        // failure name its own cause instead of being rediscovered.
        let del = |extra: &[&str]| {
            let mut c = Command::new("userdel");
            c.args(extra).arg(&self.user);
            c.output()
        };
        match del(&[]) {
            Ok(o) if o.status.success() => {}
            Ok(o) => {
                // One escalation: -f removes the account even if logind/utmp still claims a
                // login. Reported either way — a forced removal means the teardown above did
                // not finish, which is information, not a success.
                let why = String::from_utf8_lossy(&o.stderr).trim().to_owned();
                match del(&["-f"]) {
                    Ok(f) if f.status.success() => eprintln!(
                        "WARN: `userdel {}` failed ({why}); `userdel -f` SUCCEEDED. The account \
                         is gone, but the session teardown above did not complete — if this \
                         recurs, the bounded wait is too short or a session is stuck `closing`.",
                        self.user
                    ),
                    Ok(f) => eprintln!(
                        "WARN: `userdel {}` failed ({why}) AND `userdel -f` exited {} ({}) — \
                         THE ACCOUNT HAS LEAKED. Remove by hand: `sudo userdel -f {}`.",
                        self.user, f.status, String::from_utf8_lossy(&f.stderr).trim(), self.user
                    ),
                    Err(e) => eprintln!("WARN: could not run `userdel -f` for {}: {e}", self.user),
                }
            }
            Err(e) => eprintln!("WARN: could not run userdel for {}: {e}", self.user),
        }
    }
}

/// Every pid currently running as `uid`, read from procfs — an independent source, and the
/// only way to see processes that are not ours to `waitpid` (reparented grandchildren).
fn pids_owned_by(uid: Uid) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue;
        };
        // "Uid:\treal\teffective\tsaved\tfs"
        if let Some(line) = status.lines().find(|l| l.starts_with("Uid:"))
            && line.split_whitespace().nth(1).and_then(|v| v.parse::<u32>().ok())
                == Some(uid.as_raw())
        {
            out.push(pid);
        }
    }
    out
}

/// The pid(s) whose `/proc/<pid>/exe` resolves to `target` — **leg 3's independent source**.
/// This is what actually answers "which process is executing the shell binary", as opposed
/// to "which pid did the daemon record". Under the forked-grandchild topology those differ,
/// and that difference is the whole point of the test.
fn pids_executing(target: &std::path::Path) -> Vec<i32> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in entries.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        if std::fs::read_link(format!("/proc/{pid}/exe")).is_ok_and(|p| p == target) {
            out.push(pid);
        }
    }
    out
}

/// Robustly reap the launched children — **BOUNDED so it can never hang the harness.**
///
/// DEMONSTRATED FAILURE (B-3 weaken, 2026-07-23). The earlier teardown killed only
/// `pids_owned_by(session_uid)` and then `waitpid(shell_pid, None)`. With the B-3 weaken's
/// `drop_privileges` no-op'd the shell keeps **root** (uid 0), so it is NOT in
/// `pids_owned_by(session_uid)`, is never signalled, and the unbounded `waitpid` blocks
/// forever on the `pause()`ing root sleeper — hanging the whole harness with no verdict. This
/// helper fixes all three defects that surfaced:
///
/// 1. **Kill by PID DIRECTLY** (`shell_pid`, `ai_pid`), not only by session uid — a
///    non-dropped (root) shell is signalled regardless of its uid. `pids_owned_by(uid)` is
///    *also* signalled, to catch a reparented session-uid grandchild (B-1 weaken).
/// 2. **Bounded wait** — `WNOHANG` poll with `SIGKILL` escalation after ~1s, giving up after
///    ~3s. A stuck child becomes a reaped child, never a hung harness.
///
/// The caller prints its `EXECUTED_MARKER` line *before* calling this, so the verdict data is
/// emitted even if reaping is slow. Note: a `Ctrl-C` before this runs still leaks a root
/// sleeper — that is inherent to `Ctrl-C` (no Drop runs) and is documented, not fixable here.
fn reap_children(shell_pid: i32, ai_pid: i32, uid: Uid) {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    for pid in [shell_pid, ai_pid].into_iter().chain(pids_owned_by(uid)) {
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
    }
    for pid in [shell_pid, ai_pid] {
        let p = Pid::from_raw(pid);
        for i in 0..60 {
            match waitpid(p, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {}
                _ => break, // reaped, or ECHILD (already gone) — either way, done
            }
            if i == 20 {
                let _ = kill(p, Signal::SIGKILL); // escalate after ~1s of SIGTERM
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}


/// The VT handed to PAM as `PAM_TTY`. Overridable because VT availability is a property of
/// the machine, not of the test; `tty1` is the default since the dev lane's own session sits
/// on `tty2` (§4 R3-02a: naming a VT does not take it over — it only labels the session).
fn test_vt() -> VtName {
    let name = std::env::var("DELPHI_TEST_VT").unwrap_or_else(|_| "tty1".to_string());
    VtName::new(&name).expect("DELPHI_TEST_VT must be a valid ttyN")
}

/// Read a session property from **logind** — the authoritative external source §4 R3-01c
/// names. Deliberately not the shell's self-report.
fn logind_session_property(session: &str, property: &str) -> Option<String> {
    let out = Command::new("loginctl")
        .args(["show-session", session, "-p", property, "--value"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let v = String::from_utf8(out.stdout).ok()?.trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Copy a built test binary somewhere the dropped-to user can execute it.
fn stage_bin(src: &str, dir: &std::path::Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dst = dir.join(name);
    std::fs::copy(src, &dst).expect("stage binary");
    std::fs::set_permissions(&dst, std::fs::Permissions::from_mode(0o755)).unwrap();
    dst
}

/// **THE B-1 REGRESSION TEST.** The session the shell belongs to must have the shell itself
/// as its `Leader` (§4 R3-01c). Under the forked-grandchild topology the session resolves
/// just the same but its leader is the intermediate holder — and this assertion fails.
#[test]
fn session_leader_is_the_shell_itself_r3_01c() {
    // ── Preconditions. Each SKIPs loudly; a skip INVALIDATES a weaken/restore run. ──
    if geteuid().as_raw() != 0 {
        eprintln!(
            "SKIP session_leader_is_the_shell: requires root (pam_open_session). \
             A SKIP INVALIDATES A WEAKEN/RESTORE RUN — it passes under both topologies."
        );
        return;
    }
    if !std::path::Path::new(PAM_FILE).exists() {
        eprintln!(
            "SKIP session_leader_is_the_shell: {PAM_FILE} is not installed. Install it from \
             installer/pam/delphi-runtime. A SKIP INVALIDATES A WEAKEN/RESTORE RUN."
        );
        return;
    }
    // An `auth`+`account`-only stack yields a cleanly-succeeding but SESSIONLESS launch
    // (pam_open_session returns 0 on an empty session group — measured 2026-07-22). That
    // would make this test fail under BOTH topologies: FAIL/FAIL is exactly as
    // non-discriminating as the PASS/PASS a skip gives, so it is refused up front.
    let stack = std::fs::read_to_string(PAM_FILE).unwrap_or_default();
    if !stack.lines().any(|l| l.trim_start().starts_with("session")) {
        eprintln!(
            "SKIP session_leader_is_the_shell: {PAM_FILE} has NO `session` group, so \
             pam_open_session would succeed while registering no session and this test \
             would fail for BOTH topologies. A SKIP INVALIDATES A WEAKEN/RESTORE RUN."
        );
        return;
    }
    let vt = test_vt();
    if !vt.exists_on_system() {
        eprintln!(
            "SKIP session_leader_is_the_shell: /dev/{} is absent; set DELPHI_TEST_VT. \
             A SKIP INVALIDATES A WEAKEN/RESTORE RUN.",
            vt.as_pam_tty()
        );
        return;
    }

    delphi_runtime::test_child_guard::assert_no_stale_session_on(test_vt().as_pam_tty());
    let setup = Setup::new("b1");
    let (uid, gid) = setup.ids();

    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = tempfile::Builder::new().prefix("delphi-b1leader-")
        .tempdir_in("/run").expect("tempdir");
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");

    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let Some(shell_bin) = shell_fixtures::signalling_c_sleeper(&work) else {
        eprintln!(
            "SKIP session_leader_is_the_shell: build_sleeper failed — SEE ITS DIAGNOSTIC ABOVE \
             for the ACTUAL cause (write / cc-spawn / cc-compile); it is NOT necessarily a \
             A SKIP INVALIDATES A WEAKEN/RESTORE RUN."
        );
        return;
    };
    let shell_bin = shell_bin.canonicalize().expect("canonical sleeper path");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");

    let spec = LaunchSpec {
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: &vt,
        shell_env: &[],
        // The AI is irrelevant here and will panic on the missing DELPHI_AI_EXE
        // (`delphi-minimal-ai.rs:29`) — EXPECTED, harmless noise. `launch()` always forks
        // both children; this test measures only the shell.
        ai_env: &[],
    };

    let children = launch(&spec).expect("launch shell + AI");
    let pinned_pid = children.shell_pid; // LEG 1: the pid the daemon pidfd-pins.

    // Let logind register the session pam_systemd just opened. A bounded POLL, not a fixed
    // sleep: a fixed wait is either flaky-if-too-short or slow-for-everyone, and this loop
    // exits as soon as the session appears.
    let mut session = None;
    for _ in 0..50 {
        session = session_id_for_pid(pinned_pid);
        if session.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }

    // LEG 2: the session's leader, from LOGIND (not the binary's self-report).
    let leader = session.as_deref().and_then(|s| logind_session_property(s, "Leader"));
    // LEG 3: who is ACTUALLY executing the shell binary, from procfs (independent source).
    let executors = pids_executing(&shell_bin);

    // Marker BEFORE teardown: the measurement is captured above, so emit the verdict data now
    // — a slow/edge-case teardown must never hide it (the B-3 hang lesson).
    println!(
        "{EXECUTED_MARKER}: pinned_pid={pinned_pid} session={session:?} leader={leader:?} \
         executing_shell={executors:?}"
    );
    reap_children(pinned_pid, children.ai_pid, uid);
    drop(children.daemon_channel);
    let _ = std::fs::remove_dir_all(&base);

    let session = session.unwrap_or_else(|| {
        panic!(
            "{EXECUTED_MARKER}: the pinned pid {pinned_pid} resolves to NO logind session. \
             This is NOT the leader != shell failure — no session was registered at all \
             (session-less PAM stack, or pam_systemd absent). Do not read this run as a \
             topology verdict."
        )
    });
    let leader: i32 = leader
        .unwrap_or_else(|| {
            panic!("{EXECUTED_MARKER}: logind knows session {session} but reports no Leader — void run.")
        })
        .parse()
        .expect("Leader is a pid");

    // ── LEG 3 IS THE DISCRIMINATOR ──────────────────────────────────────────────────
    // Legs 1 and 2 are EQUAL UNDER BOTH TOPOLOGIES — that was the original test's defect
    // (R2-03 again): under the weaken the forked child calls pam_open_session (so it IS the
    // leader) and only THEN forks the grandchild that execs the shell. Asserting
    // leader == pinned_pid is therefore trivially true either way, and the discriminating
    // fact — WHICH PID IS RUNNING THE SHELL BINARY — went unmeasured.
    //
    // Why this matters beyond mechanics: under the weaken the daemon pidfd-pins the HOLDER,
    // not the shell. It believes it is tracking the shell's lifetime while the real shell is
    // a process it has no handle on — precisely the failure R3-01c forecloses.
    assert_eq!(
        executors.len(),
        1,
        "{EXECUTED_MARKER}: expected exactly ONE process executing {} — found {executors:?}. \
         Cannot attribute the topology; treat as void.",
        shell_bin.display()
    );
    let executing = executors[0];

    assert_eq!(
        executing, pinned_pid,
        "{EXECUTED_MARKER}: R3-01c VIOLATED — leader != shell. The daemon pinned pid \
         {pinned_pid} and logind agrees that pid leads session {session} (leader={leader}), \
         BUT the process actually executing the shell binary is pid {executing}. That is the \
         forked-grandchild topology: the daemon holds a pidfd on a session-HOLDER while the \
         real shell runs unpinned, so it cannot see the shell die (recon Phase D: the session \
         goes `closing`, the orphaned shell SURVIVES and still cgroup-resolves to it). Under \
         leader == shell all three pids are one, and shell-death IS session teardown."
    );

    assert_eq!(
        leader, pinned_pid,
        "{EXECUTED_MARKER}: session {session}'s leader is {leader} but the daemon pinned \
         {pinned_pid}. (Equal under both topologies, so a failure here is a DIFFERENT \
         regression from the grandchild one above.)"
    );
}

/// **FD-01 — the sweep contains the DAEMON's own inherited fds** (§4, R3-01c FD-01).
///
/// # What this proves, and what CHANGED after the first draft proved nothing
///
/// The first draft asserted "PAM's D-Bus fd does not survive the `execve`" and tried to
/// prove it by moving the sweep to *before* `open_own_session` (so PAM's fd would be opened
/// after the sweep and ride the exec). It **passed under that weaken** — PASS/PASS, worthless.
/// The null result was itself the finding: under that weaken, `pam_start`, `pam_open_session`
/// (pam_systemd's sd-bus connection) AND `sd_pid_get_session` all open fds *after* the sweep,
/// yet NONE survived — because **libsystemd/libpam CLOEXEC or close every fd they open**. The
/// sweep's ordering-after-PAM is therefore not the containment for PAM's fds; the stack
/// provides that (see `docs/TRUST_MODEL.md` §4 FD-01, amended).
///
/// The sweep's **load-bearing** role is a DIFFERENT fd class: the daemon's OWN inherited fds
/// — the approval-socket listener, the daemon end of the consent channel, the spawn pipe —
/// which have **no self-containment discipline** (a plain `socketpair`/`pipe` is not CLOEXEC
/// unless someone sets it). One of those riding the `execve` into the shell is exactly the
/// B2A-R2-01 relay-bypass class. So this test injects a proxy for them and proves the sweep
/// closes it.
///
/// # The injection (both operator additions)
///
/// A **non-CLOEXEC socket** is opened (non-CLOEXEC) in the test process
/// before `launch()`. `launch()` forks from THIS process, so the child inherits it; the
/// production sweep marks every fd >= 3 outside the allowlist CLOEXEC, so it must be gone
/// after the `execve`. A **socket** specifically, because that is the shape the daemon's real
/// inherited fds take. Rust opens all fds CLOEXEC by default, which would make the injection
/// vacuous — so the test **asserts the fd is open AND non-CLOEXEC in the parent immediately
/// before `launch()`** (addition 1). And "injected fd ABSENT in the child under the weaken"
/// is treated as **VOID, not pass** (the injection failed to inherit) — the run prints
/// `injected_in_child` so the operator can apply that rule.
///
/// # WEAKEN (RED-proof) — remove the sweep ENTIRELY
///
/// In `shell_child_become`, no-op the `mark_cloexec_except_raw` block (the marked FD-01
/// WEAKEN banner). With no sweep, the injected non-CLOEXEC socket survives the `execve` and
/// this test FAILS (extra fd listed); restore the sweep and it PASSES. Run serially
/// (`--test-threads=1`) — FD-01 was shown stable serially, flaky only under within-binary
/// parallelism.
#[test]
fn shell_inherits_only_the_allowlisted_fds_fd_01() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP fd01: requires root. A SKIP PROVES NOTHING.");
        return;
    }
    if !std::path::Path::new(PAM_FILE).exists() {
        eprintln!("SKIP fd01: {PAM_FILE} not installed. A SKIP PROVES NOTHING.");
        return;
    }
    let stack = std::fs::read_to_string(PAM_FILE).unwrap_or_default();
    if !stack.lines().any(|l| l.trim_start().starts_with("session")) {
        eprintln!("SKIP fd01: {PAM_FILE} has no `session` group. A SKIP PROVES NOTHING.");
        return;
    }
    let vt = test_vt();
    if !vt.exists_on_system() {
        eprintln!("SKIP fd01: /dev/{} absent.", vt.as_pam_tty());
        return;
    }

    delphi_runtime::test_child_guard::assert_no_stale_session_on(test_vt().as_pam_tty());
    let setup = Setup::new("fd01");
    let (uid, gid) = setup.ids();
    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = tempfile::Builder::new().prefix("delphi-fd01-")
        .tempdir_in("/run").expect("tempdir");
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let Some(shell_bin) = shell_fixtures::signalling_c_sleeper(&work) else {
        eprintln!("SKIP fd01: build_sleeper failed — see its diagnostic above for the ACTUAL cause.");
        return;
    };
    let shell_bin = shell_bin.canonicalize().expect("canonical sleeper path");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");

    // ── THE INJECTION: a non-CLOEXEC SOCKET, inherited across launch()'s fork ──
    // A socketpair (not a pipe/file) because that is the shape of the daemon's real inherited
    // fds — the approval listener and the consent channel are sockets. Use the socket's OWN fd
    // number (dynamic), NOT a fixed dup2 target: a fixed number could clobber an fd the cargo
    // harness already holds — the harness-self-corruption class this arc keeps hitting. Rust
    // opens all fds CLOEXEC by default, so clear it explicitly; that non-CLOEXEC state is what
    // makes the socket inherit across the fork+execve, and is exactly the "no self-containment"
    // property the daemon's real inherited fds have (unlike libsystemd's, which self-CLOEXEC).
    let (inj_a, _inj_b) = std::os::unix::net::UnixStream::pair().expect("inject socketpair");
    let injected_fd = inj_a.as_raw_fd();
    assert!(
        injected_fd > SHELL_CHANNEL_FD,
        "fd01 SETUP: injected fd {injected_fd} collides with the allowlist/channel — VOID"
    );
    let cur = unsafe { nix::libc::fcntl(injected_fd, nix::libc::F_GETFD) };
    assert!(cur >= 0, "fd01 SETUP: injected fd {injected_fd} not open — VOID");
    unsafe { nix::libc::fcntl(injected_fd, nix::libc::F_SETFD, cur & !nix::libc::FD_CLOEXEC) };

    // ADDITION 1 — prove the injection SETUP before launch(): OPEN and NON-CLOEXEC, or it would
    // not inherit and the test would go vacuous the same way the first draft did. Rust's
    // default-CLOEXEC is exactly this trap.
    let flags = unsafe { nix::libc::fcntl(injected_fd, nix::libc::F_GETFD) };
    assert!(flags >= 0, "fd01 SETUP: injected fd {injected_fd} is not open before launch — VOID");
    assert!(
        flags & nix::libc::FD_CLOEXEC == 0,
        "fd01 SETUP: injected fd {injected_fd} is still CLOEXEC before launch — it would not \
         inherit and the test would be VACUOUS."
    );

    let spec = LaunchSpec {
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: &vt,
        shell_env: &[],
        ai_env: &[],
    };
    let children = launch(&spec).expect("launch shell + AI");
    let shell_pid = children.shell_pid;

    let mut exec_done = false;
    for _ in 0..50 {
        if std::fs::read_link(format!("/proc/{shell_pid}/exe")).is_ok_and(|p| p == shell_bin) {
            exec_done = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }

    let mut fds: Vec<(i32, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(format!("/proc/{shell_pid}/fd")) {
        for e in entries.flatten() {
            if let Ok(n) = e.file_name().to_string_lossy().parse::<i32>() {
                let target = std::fs::read_link(e.path())
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<unreadable>".into());
                fds.push((n, target));
            }
        }
    }
    fds.sort_by_key(|(n, _)| *n);
    let injected_in_child = fds.iter().any(|(n, _)| *n == injected_fd);

    // Marker BEFORE teardown (the B-3 hang lesson) — the fd table is captured above.
    println!(
        "{EXECUTED_MARKER}(FD-01): shell_pid={shell_pid} exec_done={exec_done} \
         injected_fd={injected_fd} injected_in_child={injected_in_child} fds={fds:?}"
    );
    reap_children(shell_pid, children.ai_pid, uid);
    drop(children.daemon_channel);
    drop(inj_a); // keep the injected socket alive until AFTER the child was inspected
    let _ = std::fs::remove_dir_all(&base);

    assert!(
        exec_done,
        "{EXECUTED_MARKER}(FD-01): the sleeper never reached its execve; the fd table read would          be PRE-sweep. VOID, not an fd-containment verdict."
    );

    // VOID GUARD (addition 1, second half): under the WEAKEN the injected fd must be PRESENT
    // (that is the bite). If it is ABSENT here, decide which case: production sweep removed it
    // (correct PASS), or the injection never inherited (VOID). We cannot know the topology from
    // inside the test — but the parent-side non-CLOEXEC assertion above means inheritance was
    // guaranteed at fork, so ABSENCE can only be the sweep. Under the weaken (no sweep) absence
    // would contradict that guarantee → the operator reads `injected_in_child=false` on the
    // WEAKEN run as VOID. The assertion below is the PRODUCTION property.
    let want: Vec<i32> = vec![0, 1, 2, SHELL_CHANNEL_FD];
    let got: Vec<i32> = fds.iter().map(|(n, _)| *n).collect();
    let extras: Vec<&(i32, String)> = fds.iter().filter(|(n, _)| !want.contains(n)).collect();
    assert_eq!(
        got, want,
        "{EXECUTED_MARKER}(FD-01): fd containment VIOLATED.\n\
         \x20 child fds : {fds:?}\n\
         \x20 allowlist : {want:?} (stdio + SHELL_CHANNEL_FD)\n\
         \x20 EXTRAS    : {extras:?}\n\
         The injected non-CLOEXEC SOCKET (fd {injected_fd}) — a proxy for the daemon's own          inherited fds (approval listener, consent channel, spawn pipe) — SURVIVED the execve          into the shell. The sweep did not contain it. That is the B2A-R2-01 relay-bypass          class: an inherited daemon fd one exec away from the shell (§4 FD-01). If          injected_in_child=true above, this is the injected fd; restore the          `mark_cloexec_except_raw` sweep in `shell_child_become`."
    );
}

/// Read the `Uid:` / `Gid:` / `Groups:` fields from `/proc/<pid>/status`. `Uid:`/`Gid:` each
/// carry four values (real, effective, saved, fs); `Groups:` carries the supplementary set.
fn proc_status_ids(pid: i32) -> Option<(Vec<u32>, Vec<u32>, Vec<u32>)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let field = |prefix: &str| -> Vec<u32> {
        status
            .lines()
            .find(|l| l.starts_with(prefix))
            .map(|l| l.split_whitespace().skip(1).filter_map(|v| v.parse().ok()).collect())
            .unwrap_or_default()
    };
    Some((field("Uid:"), field("Gid:"), field("Groups:")))
}

/// **B-3 / B′ — the manual-fork shell child actually DROPS PRIVILEGES** (§4 R3-01).
///
/// # The gap this closes
///
/// The privilege drop moved from a `Command`/`pre_exec` closure to inline manual-fork code in
/// `shell_child_become`. The ORDER (`setgroups([]) → setgid → setuid`) is unit-proven on
/// `drop_privileges` via a mock seam (`drops_in_canonical_..._order`), but that tests the
/// FUNCTION, not the `fork_shell` call site. Nothing asserted the EFFECT on the path: that the
/// resulting shell runs as the session `(uid, gid)` with **no supplementary groups**. A
/// `launch()`-traversing test is the only thing that exercises the restructured drop.
///
/// # What is asserted (post-`execve`, from `/proc/<shell_pid>/status`)
///
/// * `Uid:` all four fields == the session uid — `setuid` dropped real/effective/saved/fs.
/// * `Gid:` all four == the session gid — `setgid` did likewise.
/// * `Groups:` empty — `setgroups([])` cleared the root supplementary set.
///
/// The uid check is the primary discriminator; gid and groups cover the other two syscalls.
///
/// # WEAKEN (RED-proof)
///
/// In `shell_child_become`, delete/no-op the `drop_privileges(&RealPrivDropOps, ...)` block.
/// The shell then `execve`s **as root** — `Uid:` becomes `0 0 0 0` — and this test FAILS.
/// Restore the call and it PASSES. Run serially (`--test-threads=1`).
#[test]
fn shell_child_drops_to_the_session_user_b3() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP b3: requires root. A SKIP PROVES NOTHING.");
        return;
    }
    if !std::path::Path::new(PAM_FILE).exists() {
        eprintln!("SKIP b3: {PAM_FILE} not installed. A SKIP PROVES NOTHING.");
        return;
    }
    let stack = std::fs::read_to_string(PAM_FILE).unwrap_or_default();
    if !stack.lines().any(|l| l.trim_start().starts_with("session")) {
        eprintln!("SKIP b3: {PAM_FILE} has no `session` group. A SKIP PROVES NOTHING.");
        return;
    }
    let vt = test_vt();
    if !vt.exists_on_system() {
        eprintln!("SKIP b3: /dev/{} absent.", vt.as_pam_tty());
        return;
    }

    delphi_runtime::test_child_guard::assert_no_stale_session_on(test_vt().as_pam_tty());
    let setup = Setup::new("b3");
    let (uid, gid) = setup.ids();
    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = tempfile::Builder::new().prefix("delphi-b3-")
        .tempdir_in("/run").expect("tempdir");
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let Some(shell_bin) = shell_fixtures::signalling_c_sleeper(&work) else {
        eprintln!("SKIP b3: build_sleeper failed — see its diagnostic above for the ACTUAL cause.");
        return;
    };
    let shell_bin = shell_bin.canonicalize().expect("canonical sleeper path");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");

    let spec = LaunchSpec {
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: &vt,
        shell_env: &[],
        ai_env: &[],
    };
    let children = launch(&spec).expect("launch shell + AI");
    let shell_pid = children.shell_pid;

    let mut exec_done = false;
    for _ in 0..50 {
        if std::fs::read_link(format!("/proc/{shell_pid}/exe")).is_ok_and(|p| p == shell_bin) {
            exec_done = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(40));
    }
    let ids = proc_status_ids(shell_pid);

    // Marker BEFORE teardown — this is the test whose weaken (shell keeps ROOT) demonstrated
    // the hang, so emitting the verdict data before reaping is not optional here.
    println!("{EXECUTED_MARKER}(B3): shell_pid={shell_pid} exec_done={exec_done} ids={ids:?}");
    reap_children(shell_pid, children.ai_pid, uid);
    drop(children.daemon_channel);
    let _ = std::fs::remove_dir_all(&base);

    assert!(
        exec_done,
        "{EXECUTED_MARKER}(B3): the sleeper never reached its execve; /proc/status would be \
         PRE-drop. VOID, not a privilege-drop verdict."
    );
    let (uids, gids, groups) =
        ids.expect("{EXECUTED_MARKER}(B3): /proc/<shell_pid>/status unreadable — VOID");
    let (want_u, want_g) = (uid.as_raw(), gid.as_raw());

    // PRIMARY discriminator: setuid dropped every uid field. Root (0 0 0 0) fails this.
    assert!(
        uids.len() == 4 && uids.iter().all(|&u| u == want_u),
        "{EXECUTED_MARKER}(B3): shell did NOT drop uid — /proc/status Uid: {uids:?}, want all \
         == {want_u}. Uid `0 0 0 0` means `drop_privileges` did not run in the manual-fork \
         child: the shell execs as ROOT. Restore the `drop_privileges` call in \
         `shell_child_become`."
    );
    assert!(
        gids.len() == 4 && gids.iter().all(|&g| g == want_g),
        "{EXECUTED_MARKER}(B3): shell did NOT drop gid — /proc/status Gid: {gids:?}, want all == {want_g}."
    );
    // setgroups([]) cleared the root supplementary set.
    assert!(
        groups.is_empty(),
        "{EXECUTED_MARKER}(B3): shell retained supplementary groups {groups:?} — setgroups([]) \
         did not run. A same-uid attacker inheriting root's supplementary groups is a \
         privilege the drop is supposed to remove."
    );
}

/// **B2A-C-R1-01 end-to-end — `launch()` RETURNS `Err` when the shell child dies pre-`execve`.**
///
/// The unit test `setup_sync_reports_child_failure_and_success_b2a_c_r1_01` proves the sync
/// MECHANISM; this proves the whole `launch()` path: point `shell_path` at a non-existent
/// binary so the child completes dup2/stdio/PAM/sweep/priv-drop and then FAILS at `execve`
/// (ENOENT) → `child_bail` → sync byte → the parent must return `Err`, not a false `Ok` with a
/// dead shell (the Codex round-1 P1 regression). RED-proof: against the pre-fix launcher (which
/// returned `Ok` immediately after `fork`) this asserts `Err` and FAILS.
/// **D0-R4-02 — the COMPOSITION, which the guard-mechanism unit test does not prove.**
///
/// `an_armed_shell_guard_kills_its_child_on_drop` proves the guard works. It does NOT prove
/// `launch()` uses it, and that gap was described as covered twice before Codex named it —
/// the third class-6 occurrence in this increment. This is the boundary test: a valid shell
/// with an INVALID `ai_path`, so `fork_ai` fails AFTER the shell is up, and the shell must
/// be gone by the time `launch()` returns `Err`.
///
/// **UNTESTED UNTIL THE LANE RUNS IT.** It needs root for PAM and SKIPs everywhere else, so
/// on any developer box this boundary has no coverage at all. Recorded in PROGRESS as an
/// owed lane item beside the B-1 / FD-01 / B-3 serial >=30.
#[test]
fn launch_kills_the_shell_when_a_later_step_fails_d0_r4_02() {
    if geteuid().as_raw() != 0 {
        eprintln!(
            "SKIP launch_kills_the_shell_when_a_later_step_fails: requires root (PAM). \
             A SKIP PROVES NOTHING — and this is the ONLY test of the launch() transaction \
             boundary, so until the lane runs it that boundary is UNTESTED, not passing."
        );
        return;
    }
    delphi_runtime::test_child_guard::assert_no_stale_session_on(test_vt().as_pam_tty());
    let setup = Setup::new("r402");
    let (uid, gid) = setup.ids();

    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = tempfile::Builder::new().prefix("delphi-r402-")
        .tempdir_in("/run").expect("tempdir");
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let Some(shell_bin) = shell_fixtures::signalling_c_sleeper(&work) else {
        eprintln!("SKIP r402: signalling_c_sleeper failed — see its diagnostic above.");
        return;
    };
    let shell_bin = shell_bin.canonicalize().expect("canonical sleeper path");

    // The shell is valid and DOES signal readiness; the AI path does not exist, so `fork_ai`
    // fails only after the shell is fully up — the exact window the guard exists to cover.
    let missing_ai = work.join("does-not-exist-ai");
    let spec = LaunchSpec {
        shell_path: &shell_bin,
        ai_path: &missing_ai,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: &test_vt(),
        shell_env: &[],
        ai_env: &[],
    };

    // D0-R5-03: assert the EXACT error, not merely `is_err()`. PAM, setup and readiness
    // failures all produce an Err with no surviving shell — the same two observations this
    // test makes — *before* `fork_ai` is ever evaluated. So `is_err()` would have passed on
    // the root lane while proving the boundary was never crossed, which is worse than not
    // having run: it manufactures confidence at the moment someone finally runs it.
    //
    // `Filesystem { op: "spawn child", path: <the missing AI>, source: NotFound }` is
    // constructed at exactly one site (`spawn_pid`, via `fork_ai`) and is reachable only
    // after readiness has already succeeded.
    // `Children` is not Debug, so unwrap the Result by hand rather than via expect_err.
    let err = match launch(&spec) {
        Err(e) => e,
        Ok(_) => panic!("a missing ai_path must fail the launch"),
    };
    match &err {
        RuntimeError::Filesystem { path, source, .. } => {
            assert_eq!(
                path, &missing_ai,
                "failed on the wrong path — the launch died before reaching fork_ai"
            );
            assert_eq!(
                source.kind(),
                std::io::ErrorKind::NotFound,
                "expected ENOENT from spawning the missing AI, got: {source}"
            );
        }
        other => panic!(
            "expected a Filesystem error from fork_ai (proving readiness SUCCEEDED and the \
             failure came after it); got {other:?} — the launch failed earlier, so this run \
             says nothing about the transaction boundary"
        ),
    }

    // The shell must be GONE. `launch()` returned `Err`, so it handed back no pid — the
    // check is that NOTHING owned by the session uid is executing the shell binary.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let survivors = pids_executing(&shell_bin);
    assert!(
        survivors.is_empty(),
        "launch() returned Err but left {survivors:?} executing {} — the shell escaped the \
         transaction guard with its logind session and VT",
        shell_bin.display()
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn launch_returns_err_when_shell_child_fails_before_execve_b2a_c_r1_01() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP launch_returns_err_when_shell_child_fails: requires root (PAM). A SKIP PROVES NOTHING.");
        return;
    }
    if !std::path::Path::new(PAM_FILE).exists() {
        eprintln!("SKIP launch_returns_err_when_shell_child_fails: {PAM_FILE} not installed.");
        return;
    }
    let stack = std::fs::read_to_string(PAM_FILE).unwrap_or_default();
    if !stack.lines().any(|l| l.trim_start().starts_with("session")) {
        eprintln!("SKIP launch_returns_err_when_shell_child_fails: {PAM_FILE} has no `session` group.");
        return;
    }
    let vt = test_vt();
    if !vt.exists_on_system() {
        eprintln!("SKIP launch_returns_err_when_shell_child_fails: /dev/{} absent.", vt.as_pam_tty());
        return;
    }

    delphi_runtime::test_child_guard::assert_no_stale_session_on(test_vt().as_pam_tty());
    let setup = Setup::new("p1");
    let (uid, gid) = setup.ids();
    // RAII: removed on drop, INCLUDING the panic path. `base` stays a PathBuf, so
    // nothing downstream changes.
    let _base_tmp = tempfile::Builder::new().prefix("delphi-p1-")
        .tempdir_in("/run").expect("tempdir");
    let base = _base_tmp.path().to_path_buf();
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    // A shell path that does not exist → the child reaches `execve` and fails ENOENT.
    let missing_shell = work.join("does-not-exist-shell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &work, "mai");

    let spec = LaunchSpec {
        shell_path: &missing_shell,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        tty: &vt,
        shell_env: &[],
        ai_env: &[],
    };
    let result = launch(&spec);
    let _ = std::fs::remove_dir_all(&base);

    assert!(
        result.is_err(),
        "B2A-C-R1-01: launch() MUST return Err when the shell child dies before execve (a \
         missing shell binary → ENOENT at execve). Pre-fix it returned Ok with a dead shell."
    );
}
