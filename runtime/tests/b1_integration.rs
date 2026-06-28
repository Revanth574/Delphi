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
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use nix::sys::wait::waitpid;
use nix::unistd::{geteuid, Gid, Uid, User};

use delphi_runtime::action::{canonical_action_digest, PendingAction};
use delphi_runtime::canonicalize::canonicalize;
use delphi_runtime::execute::ConsumptionLedger;
use delphi_runtime::launcher::{launch, LaunchSpec};
use delphi_runtime::logind::SessionVerdict;
use delphi_runtime::service::{
    accept_requester, present_and_execute, serve_one_action, Clock, Outcome, ServiceCtx,
};
use delphi_runtime::store::{PendingState, PendingStore};
use delphi_runtime::token::{mint, MintingKey, TOKEN_TTL_SECS};
use delphi_runtime::wire::pb;
use delphi_runtime::{bind_approval_socket, ensure_runtime_dir};

const SERVICE: &str = "delphi-runtime";
const PAM_FILE: &str = "/etc/pam.d/delphi-runtime";
const PASSWORD: &str = "Delphi-B1-Spine!";
const NOW: u64 = 1_000;
const KEY: [u8; 32] = [0x5B; 32];

/// A logind verdict mock — the GATE is composed in the loop; the verdict source is
/// injected (WSL2 sessions are ephemeral, so a real `for_pid` query is unreliable —
/// the `logind_gate` test proves the real `LogindVerdict`).
struct Verdict {
    active: bool,
    remote: bool,
}
impl SessionVerdict for Verdict {
    fn is_active(&self) -> bool {
        self.active
    }
    fn is_remote(&self) -> bool {
        self.remote
    }
}
const PASS: Verdict = Verdict { active: true, remote: false };

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
}
impl Setup {
    fn new(tag: &str) -> Self {
        let user = format!("db1{tag}{}", std::process::id() % 10_000);
        let _ = Command::new("userdel").arg(&user).status();
        assert!(Command::new("useradd").args(["-M", "-s", "/usr/sbin/nologin", &user]).status().unwrap().success());
        let mut ch = Command::new("chpasswd").stdin(Stdio::piped()).spawn().unwrap();
        ch.stdin.take().unwrap().write_all(format!("{user}:{PASSWORD}").as_bytes()).unwrap();
        assert!(ch.wait().unwrap().success());
        std::fs::write(PAM_FILE, "auth required pam_unix.so\naccount required pam_unix.so\n").unwrap();
        Self { user }
    }
    fn ids(&self) -> (Uid, Gid) {
        let u = User::from_name(&self.user).unwrap().unwrap();
        (u.uid, u.gid)
    }
}
impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(PAM_FILE);
        let _ = Command::new("userdel").arg(&self.user).status();
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

    let base = PathBuf::from(format!("/run/delphi-b1-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
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
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        shell_env: &[("DELPHI_PASSWORD", PASSWORD)],
        ai_env: &[
            ("DELPHI_AI_EXE", &exe_str),
            ("DELPHI_AI_ARG", "B1-LIVES"),
            ("DELPHI_AI_BIND_RW", &work_str),
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
        session_verdict: &PASS,
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
    let base = PathBuf::from(format!("/run/delphi-b1exp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
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
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        shell_env: &[("DELPHI_PASSWORD", PASSWORD)],
        ai_env: &[
            ("DELPHI_AI_EXE", &exe_str),
            ("DELPHI_AI_ARG", "SHOULD-NOT-RUN"),
            ("DELPHI_AI_BIND_RW", &work_str),
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
        session_verdict: &PASS,
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
    let dir = PathBuf::from(format!("/tmp/delphi-b1-aeb-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
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
    let dir = PathBuf::from(format!("/tmp/delphi-b1-swap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
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
    let dir = PathBuf::from(format!("/tmp/delphi-b1-burn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
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

// ── B1-02: the shebang interpreter arg REACHES exec (not dropped) ────────────

#[test]
fn b1_shebang_interpreter_arg_reaches_exec() {
    if !bwrap_available() {
        eprintln!("SKIP b1_shebang_arg: requires bwrap + unprivileged userns");
        return;
    }
    let dir = PathBuf::from(format!("/tmp/delphi-b1-arg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
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
    let stage = PathBuf::from(format!("/tmp/delphi-b1bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o777)).unwrap();
    let shell_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-shell"), &stage, "mshell");
    let ai_bin = stage_bin(env!("CARGO_BIN_EXE_delphi-minimal-ai"), &stage, "mai");
    let result = stage.join("result");
    let exe = write_marker_exe(&stage, &result);

    // Run the actual delphi-runtimed BINARY — it does anchor + launch + serve itself.
    let out = Command::new(env!("CARGO_BIN_EXE_delphi-runtimed"))
        .args(["--session", &setup.user])
        .env("DELPHI_SHELL_BIN", &shell_bin)
        .env("DELPHI_AI_BIN", &ai_bin)
        .env("DELPHI_PASSWORD", PASSWORD)
        .env("DELPHI_AI_EXE", &exe)
        .env("DELPHI_AI_ARG", "BINARY-FLOW")
        .env("DELPHI_AI_BIND_RW", &stage)
        // The compile-time test seam (the binary is built with --features
        // insecure-test-seams in the lane); WSL has no real logind session.
        .env("DELPHI_INSECURE_ASSUME_ACTIVE_SESSION", "1")
        .output()
        .expect("run delphi-runtimed");

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
    let base = PathBuf::from(format!("/run/delphi-b1fd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let dir = ensure_runtime_dir(&base, &setup.user).expect("anchor dir");
    let (paths, _listener) = bind_approval_socket(&dir, gid.as_raw()).expect("anchor socket");

    // Both children are a 2s sleeper script so /proc/<pid>/fd is readable mid-life.
    let sleeper = base.join("sleeper.sh");
    std::fs::write(&sleeper, "#!/bin/sh\nsleep 2\n").unwrap();
    std::fs::set_permissions(&sleeper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let spec = LaunchSpec {
        shell_path: &sleeper,
        ai_path: &sleeper,
        uid,
        gid,
        socket_path: &paths.socket,
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
    let base = PathBuf::from(format!("/run/delphi-b1l-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
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
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid,
        gid,
        socket_path: &paths.socket,
        shell_env: &[("DELPHI_PASSWORD", PASSWORD)],
        ai_env: &[
            ("DELPHI_AI_EXE", &exe_str),
            ("DELPHI_AI_ARG", "SHOULD-NOT-RUN"),
            ("DELPHI_AI_BIND_RW", &work_str),
        ],
    };
    let children = launch(&spec).expect("launch");
    let mut ai = accept_requester(&listener, uid.as_raw()).expect("accept AI");
    let mut store = PendingStore::new();
    let mut ledger = ConsumptionLedger::new();
    let key = MintingKey::from_bytes(KEY);
    // A NON-active session: the logind gate must DENY before PAM/execute.
    let deny_verdict = Verdict { active: false, remote: false };
    let mut ctx = ServiceCtx {
        channel_fd: children.daemon_channel.as_raw_fd(),
        session_verdict: &deny_verdict,
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
