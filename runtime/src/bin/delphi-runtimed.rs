// SPDX-License-Identifier: MIT

//! `delphi-runtimed` — the root runtime daemon entrypoint.
//!
//! systemd starts this as **root** via `delphi-runtimed@.service` (no `User=`), so
//! the runtime directory it establishes is root-owned (`docs/TRUST_MODEL.md` §4,
//! R3-01). The daemon:
//!
//! 1. **1a** — establishes the root anchor (root-owned `/run/delphi/<session>` +
//!    the group-connectable approval socket).
//! 2. **B1** — assembles the proven 1a–1d primitives into the running boundary:
//!    creates the root-held minting key + the pending store + the one-shot ledger,
//!    **launches** the shell + AI as same-uid siblings (the channel fork-passed to
//!    the shell, never the AI), derives the **real logind verdict** for the
//!    pidfd-pinned shell (fail-closed if it has no active session), **accepts** the
//!    AI on the general socket, and runs the **service loop** (Propose →
//!    canonicalize → preview → logind → PAM → mint → Present → execute the stored
//!    object → audit).
//!
//! B1 services ONE action then exits (the spine); B2 loops and plugs in the real
//! React-WRY shell + Brain. The shell/AI binaries are taken from `DELPHI_SHELL_BIN`
//! / `DELPHI_AI_BIN` (fixed install paths in production).
//!
//! Usage: `delphi-runtimed --session <username>`

use std::io::Read;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use nix::sys::wait::waitpid;
use nix::unistd::{Pid, User};

use delphi_runtime::anchor::DEFAULT_RUNTIME_BASE;
use delphi_runtime::execute::ConsumptionLedger;
use delphi_runtime::launcher::{launch, LaunchSpec, VtName};
use delphi_runtime::logind::{LogindVerdict, SessionVerdict};
use delphi_runtime::service::{accept_requester, serve_one_action, ServiceCtx, SystemClock};
use delphi_runtime::store::PendingStore;
use delphi_runtime::token::MintingKey;
use delphi_runtime::{bind_approval_socket, ensure_runtime_dir};

const PAM_SERVICE: &str = "delphi-runtime";

/// A fixed active/local/seated verdict (the fail-closed default, or the real query result).
struct FixedVerdict {
    active: bool,
    remote: bool,
    seated: bool,
}
impl SessionVerdict for FixedVerdict {
    fn is_active(&self) -> bool {
        self.active
    }
    fn is_remote(&self) -> bool {
        self.remote
    }
    fn is_seated(&self) -> bool {
        self.seated
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let session = parse_session_arg(std::env::args().skip(1))?;
    let user = User::from_name(&session)
        .with_context(|| format!("resolving session user `{session}`"))?
        .with_context(|| format!("no such session user `{session}`"))?;

    // ── 1a: the root anchor ──────────────────────────────────────────────────
    let dir = ensure_runtime_dir(std::path::Path::new(DEFAULT_RUNTIME_BASE), &session)
        .context("establishing the root-owned runtime directory")?;
    let (paths, listener) =
        bind_approval_socket(&dir, user.gid.as_raw()).context("binding the approval socket")?;

    // ── B1: the running boundary ─────────────────────────────────────────────
    let key = MintingKey::from_bytes(random_key().context("seeding the minting key")?);
    let mut store = PendingStore::new();
    let mut ledger = ConsumptionLedger::new();

    let shell_bin = bin_path("DELPHI_SHELL_BIN", "/usr/libexec/delphi-shell");
    let ai_bin = bin_path("DELPHI_AI_BIN", "/usr/libexec/delphi-ai");
    // The seat's VT the shell is provisioned on (§4 R3-02a PRIMARY). Deliberately has NO
    // default: which VT the seat holds is a deployment fact, and silently guessing one would
    // either collide with another session's VT or open a SEATLESS session that the
    // active-local-seated gate then denies forever — the exact silent failure `VtName`
    // exists to make loud. The operator states it (the unit file's `Environment=`).
    // VT ALLOCATION POLICY (choosing a free VT) is out of scope here: the launcher takes
    // what its caller supplies.
    let vt = std::env::var("DELPHI_SHELL_VT")
        .context("`DELPHI_SHELL_VT` is not set; it must name the seat's virtual terminal \
                  (e.g. `tty1`) — see TRUST_MODEL.md §4 R3-02a")?;
    let tty = VtName::new(&vt).with_context(|| format!("`DELPHI_SHELL_VT={vt}`"))?;
    // NO `/dev/ttyN`-existence preflight here — DELIBERATELY (B2A-C-R2-02, reverting the
    // round-1 B2A-C-R1-02 addition). The launch path never OPENS the tty device: it passes
    // `ttyN` as `PAM_TTY` (a string), and `pam_systemd` derives the seat from the tty NAME, not
    // by opening `/dev/ttyN` (see `launcher.rs` `set_tty` — the only use). So device-node
    // presence is the WRONG predicate: it does not validate seating, and it would FALSELY
    // refuse startup on minimal images / containers that do not populate `/dev/tty1..63` even
    // though the VT name is valid for PAM/logind. The real defense against a wrong VT is the
    // consent-time active-local-SEATED gate (§4 R3-02), which denies a session that did not
    // seat — a runtime check on the authority, not a startup guess from the local /dev layout.
    let spec = LaunchSpec {
        shell_path: &shell_bin,
        ai_path: &ai_bin,
        uid: user.uid,
        gid: user.gid,
        socket_path: &paths.socket,
        tty: &tty,
        // The children inherit the daemon's env; no per-child overrides needed.
        shell_env: &[],
        ai_env: &[],
    };
    let children = launch(&spec).context("launching the shell + AI siblings")?;
    tracing::info!(
        session = %session,
        shell_pid = children.shell_pid,
        ai_pid = children.ai_pid,
        socket = %paths.socket.display(),
        "B1: anchor + launcher up; serving one action"
    );

    let verdict = logind_verdict(children.shell_pid);
    // Real wall-clock — read fresh at mint and at Present-verify so the token TTL is a
    // real control (B1-R2-01), not a frozen-`now` no-op.
    let clock = SystemClock;

    // B1: service exactly one action, then exit (B2 loops).
    let mut ai = accept_requester(&listener, user.uid.as_raw()).context("accepting the requester")?;
    let mut ctx = ServiceCtx {
        channel_fd: children.daemon_channel.as_raw_fd(),
        session_verdict: verdict.as_ref(),
        key: &key,
        pam_service: PAM_SERVICE,
        session_user: &session,
        store: &mut store,
        ledger: &mut ledger,
        clock: &clock,
    };
    let outcome = serve_one_action(&mut ai, &mut ctx).context("servicing the action")?;
    tracing::info!(?outcome, "B1: served one action");
    // A line the binary-flow test can observe to confirm main ran the loops.
    println!("DELPHI_RUNTIMED_OUTCOME {outcome:?}");

    // TERMINAL CONTRACT (B2A-R2-02): the shell interaction is terminal once
    // serve_one_action returns — release the daemon's channel end BEFORE reaping. This
    // produces the EOF a shell blocked in its consent read (a gate/PAM denial that never
    // reached the PAM prompt) dismisses on; without it the shell would WEDGE waiting for a
    // prompt + an EOF that never come. (ctx borrows only the local store/ledger, not the
    // channel, so releasing the channel here is sound.)
    drop(children.daemon_channel);

    // NOTE (lifecycle, lane-dependent): blocking on the shell fits the ONE-SHOT minimal
    // shell (which exits after mint-confirm, or on the EOF above at denial). The real
    // LONG-LIVED WRY host does not exit per action — the daemon must not block on it; that
    // is the lane-dependent half's B2 service loop, where the real host actually runs.
    let _ = waitpid(Pid::from_raw(children.shell_pid), None);
    let _ = waitpid(Pid::from_raw(children.ai_pid), None);
    Ok(())
}

/// The logind active-session verdict for the pidfd-pinned shell — **fail-closed**:
/// a shell with no active-and-local session is treated as not active. (A compile-
/// time test seam, excluded from production, lets the binary-flow test pass on a
/// seatless WSL2 where no real session exists.)
fn logind_verdict(shell_pid: i32) -> Box<dyn SessionVerdict> {
    #[cfg(feature = "insecure-test-seams")]
    if std::env::var("DELPHI_INSECURE_ASSUME_ACTIVE_SESSION").is_ok() {
        tracing::error!(
            "INSECURE TEST SEAM ACTIVE — logind gate overridden by \
             DELPHI_INSECURE_ASSUME_ACTIVE_SESSION; this MUST NOT appear in production"
        );
        // The seam also asserts `seated` — the B2a gate requires it, so an override that
        // stopped at active+local would fail the tightened gate on a seatless WSL2.
        return Box::new(FixedVerdict { active: true, remote: false, seated: true });
    }
    match LogindVerdict::for_pid(shell_pid) {
        Some(v) => Box::new(v),
        // No logind session for the shell ⇒ fail-closed (not active, not seated).
        None => Box::new(FixedVerdict { active: false, remote: false, seated: false }),
    }
}

/// 32 random bytes from `/dev/urandom` (no `rand` dependency).
fn random_key() -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut key)?;
    Ok(key)
}

fn bin_path(env: &str, default: &str) -> PathBuf {
    std::env::var_os(env).map_or_else(|| PathBuf::from(default), PathBuf::from)
}

/// Parse `--session <username>` from the argument iterator.
fn parse_session_arg(mut args: impl Iterator<Item = String>) -> Result<String> {
    match args.next().as_deref() {
        Some("--session") => args.next().context("`--session` requires a <username> argument"),
        Some(other) => bail!("unexpected argument `{other}`; usage: delphi-runtimed --session <username>"),
        None => bail!("missing `--session <username>`; usage: delphi-runtimed --session <username>"),
    }
}
