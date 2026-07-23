// SPDX-License-Identifier: MIT

//! **Properties of the restructured shell child** (`docs/TRUST_MODEL.md` §4).
//!
//! Two tests sharing one harness, because both need the same expensive setup (root, the
//! installed PAM stack, a real VT, and a launch through the real `fork_shell`):
//!
//! * `session_leader_is_the_shell_itself_r3_01c` — **B-1**, leader == shell (R3-01c).
//! * `shell_inherits_only_the_allowlisted_fds_fd_01` — **FD-01**, fd containment through
//!   the restructured child, which no existing test covers.
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

use std::path::PathBuf;
use std::process::Command;

use delphi_runtime::launcher::{launch, LaunchSpec, VtName, SHELL_CHANNEL_FD};
use delphi_runtime::logind::session_id_for_pid;
use delphi_runtime::{bind_approval_socket, ensure_runtime_dir};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{geteuid, Gid, Pid, Uid, User};

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
    /// account to be free, `-r` to take the home directory, and the status is CHECKED.
    fn drop(&mut self) {
        let uid = User::from_name(&self.user).ok().flatten().map(|u| u.uid);

        // Ask anything still running as this uid to leave, including processes we cannot
        // `waitpid` (under the weaken the real shell is a GRANDCHILD, reparented to init,
        // so it is not ours to reap — but it is ours to signal).
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

        match Command::new("userdel").args(["-r", &self.user]).status() {
            Ok(st) if st.success() => {}
            Ok(st) => eprintln!(
                "WARN: `userdel -r {}` exited {st} — THE ACCOUNT MAY HAVE LEAKED. Check \
                 `getent passwd | grep delphi-b1` and remove it by hand.",
                self.user
            ),
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

/// Build the `pause()` sleeper used as the shell under test. See the module docs for why
/// this is not `delphi-minimal-shell`.
fn build_sleeper(dir: &std::path::Path) -> Option<PathBuf> {
    let src = dir.join("sleeper.c");
    let bin = dir.join("sleeper");
    std::fs::write(&src, "#include <unistd.h>\nint main(void){ pause(); return 0; }\n").ok()?;
    let ok = Command::new("cc")
        .args([src.to_str()?, "-o", bin.to_str()?])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some(bin)
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

    let setup = Setup::new("b1");
    let (uid, gid) = setup.ids();

    let base = PathBuf::from(format!("/run/delphi-b1leader-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");

    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let Some(shell_bin) = build_sleeper(&work) else {
        eprintln!(
            "SKIP session_leader_is_the_shell: no working `cc` to build the pause() sleeper. \
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

    // Tear down before asserting, so a failing run cannot leave a session or account behind.
    for pid in pids_owned_by(uid) {
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
    }
    let _ = nix::sys::wait::waitpid(Pid::from_raw(pinned_pid), None);
    let _ = nix::sys::wait::waitpid(Pid::from_raw(children.ai_pid), None);
    drop(children.daemon_channel);
    let _ = std::fs::remove_dir_all(&base);

    println!(
        "{EXECUTED_MARKER}: pinned_pid={pinned_pid} session={session:?} leader={leader:?} \
         executing_shell={executors:?}"
    );

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

/// **FD-01 — the shell inherits EXACTLY the allowlist, nothing else.**
///
/// # Why re-running `sibling_fd_theft` does not replace this
///
/// `sibling_fd_theft` imports only `approval_socketpair`, `drop_privileges` and
/// `RealPrivDropOps`, then hand-rolls its child (`be_the_shell`: `dup2`/`prctl`/`pause`).
/// **It never calls `launch()` or `fork_shell`.** It proves the *primitive* in an isolated
/// context the shape-(b) restructure never touched, so a green run there says nothing about
/// the launcher's actual pre-`execve` sequence.
///
/// The restructured child does `dup2` -> stdio policy -> `pam_start`/`open_session` (opening
/// PAM's D-Bus connection to logind AND `sd_pid_get_session`'s cgroup descriptors) -> **then**
/// sweeps -> priv-drops -> `execve`. The ORDERING is the property, and FD-01 (P1) exists
/// because a PAM/D-Bus fd riding into the shell recreates the B2A-R2-01 relay-bypass one exec
/// away. Nothing exercised that ordering.
///
/// # WEAKEN (RED-proof) — NOT YET RUN
///
/// In `shell_child_become`, move the `mark_cloexec_except_raw` block to **before** the
/// `open_own_session(spec)` call: the sweep then precedes PAM, PAM's descriptors are never
/// marked, and they survive the `execve`. This test must FAIL with extra fds listed, and PASS
/// on restore. Until that is done this test is written but UNPROVEN — it has passed on correct
/// code, which a vacuous test also does.
#[test]
fn shell_inherits_only_the_allowlisted_fds_fd_01() {
    if geteuid().as_raw() != 0 {
        eprintln!("SKIP shell_inherits_only_the_allowlisted_fds: requires root. A SKIP PROVES NOTHING.");
        return;
    }
    if !std::path::Path::new(PAM_FILE).exists() {
        eprintln!(
            "SKIP shell_inherits_only_the_allowlisted_fds: {PAM_FILE} not installed — and \
             WITHOUT IT PAM OPENS NO DESCRIPTORS, so this test would pass VACUOUSLY."
        );
        return;
    }
    let stack = std::fs::read_to_string(PAM_FILE).unwrap_or_default();
    if !stack.lines().any(|l| l.trim_start().starts_with("session")) {
        eprintln!(
            "SKIP shell_inherits_only_the_allowlisted_fds: {PAM_FILE} has no `session` group, \
             so pam_systemd never runs and opens no D-Bus fd — the leak this test hunts cannot \
             occur and it would pass VACUOUSLY."
        );
        return;
    }
    let vt = test_vt();
    if !vt.exists_on_system() {
        eprintln!("SKIP shell_inherits_only_the_allowlisted_fds: /dev/{} absent.", vt.as_pam_tty());
        return;
    }

    let setup = Setup::new("fd01");
    let (uid, gid) = setup.ids();
    let base = PathBuf::from(format!("/run/delphi-fd01-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");
    let work = base.join("work");
    std::fs::create_dir_all(&work).unwrap();
    let Some(shell_bin) = build_sleeper(&work) else {
        eprintln!("SKIP shell_inherits_only_the_allowlisted_fds: no working `cc`.");
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

    // Wait for the execve — inspecting earlier would read the PRE-sweep fd table and fail
    // for the wrong reason.
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

    for pid in pids_owned_by(uid) {
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
    }
    let _ = nix::sys::wait::waitpid(Pid::from_raw(shell_pid), None);
    let _ = nix::sys::wait::waitpid(Pid::from_raw(children.ai_pid), None);
    drop(children.daemon_channel);
    let _ = std::fs::remove_dir_all(&base);

    println!("{EXECUTED_MARKER}(FD-01): shell_pid={shell_pid} exec_done={exec_done} fds={fds:?}");

    assert!(
        exec_done,
        "{EXECUTED_MARKER}(FD-01): the sleeper never reached its execve, so the fd table read \
         would be the PRE-sweep one. Treat this run as VOID, not an fd-containment verdict."
    );
    let got: Vec<i32> = fds.iter().map(|(n, _)| *n).collect();
    let want = vec![0, 1, 2, SHELL_CHANNEL_FD];

    // The EXTRAS are the finding. Report them with their link targets, never as a count:
    // "an extra fd survived" and "PAM's D-Bus descriptor survived" are DIFFERENT CLAIMS, and
    // only the second proves the property FD-01 exists to protect. A count cannot tell them
    // apart, so the assertion prints the resolved targets and flags socket-shaped ones —
    // `pam_systemd`'s connection to logind appears as `socket:[NNNN]`.
    let extras: Vec<&(i32, String)> =
        fds.iter().filter(|(n, _)| !want.contains(n)).collect();
    let socket_shaped: Vec<&&(i32, String)> = extras
        .iter()
        .filter(|(_, t)| t.starts_with("socket:") || t.starts_with("anon_inode:"))
        .collect();

    assert_eq!(
        got, want,
        "{EXECUTED_MARKER}(FD-01): fd containment VIOLATED.\n\
         \x20 full table : {fds:?}\n\
         \x20 allowlist  : {want:?} (stdio + SHELL_CHANNEL_FD)\n\
         \x20 EXTRAS     : {extras:?}\n\
         \x20 socket-shaped extras (PAM/D-Bus candidates): {socket_shaped:?}\n\
         Any descriptor in EXTRAS rode through the `execve`. If a socket-shaped one is \
         present it is very likely `pam_systemd`'s D-Bus connection to logind — that is the \
         B2A-R2-01 relay-bypass class reopened one exec away (§4 FD-01, P1), and it is the \
         specific claim this test is for. Extras that are NOT socket-shaped still fail the \
         allowlist but prove a WEAKER claim: something leaked, not that the PAM descriptor \
         did. Check that `mark_cloexec_except_raw` still runs AFTER `open_own_session`."
    );
}
