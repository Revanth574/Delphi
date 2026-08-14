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
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::sys::wait::waitpid;
use nix::unistd::{Pid, User};

use delphi_runtime::anchor::DEFAULT_RUNTIME_BASE;
use delphi_runtime::execute::ConsumptionLedger;
use delphi_runtime::launcher::{launch, LaunchSpec, VtName};
use delphi_runtime::logind::{LogindSource, SessionSource};
use delphi_runtime::service::{accept_requester_within, serve_one_action, ServiceCtx, SystemClock};
use delphi_runtime::store::PendingStore;
use delphi_runtime::token::MintingKey;
use delphi_runtime::{bind_approval_socket, ensure_runtime_dir};

const PAM_SERVICE: &str = "delphi-runtime";

/// Kills the launched children if the daemon leaves by an error path (D0A-R5-03).
///
/// Disarmed on the success path, where the terminal contract lets the shell exit on its own.
struct ChildReaper {
    shell: i32,
    ai: i32,
    armed: bool,
}

impl Drop for ChildReaper {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for pid in [self.shell, self.ai] {
            // D0A-R5-01's lesson: never signal a non-positive pid — kill(-1) reaches every
            // process this root daemon may signal, kill(0) takes the process group.
            if pid > 0 {
                // SAFETY: signalling children this process created.
                unsafe { nix::libc::kill(pid, nix::libc::SIGKILL) };
                // D0A-R6-03: BOUNDED. An unbounded `waitpid` after SIGKILL wedges the daemon
                // forever on a child in uninterruptible sleep — the very failure R5-03 added
                // this guard to prevent, reintroduced inside it. The launcher already had the
                // bounded implementation and the reasoning; this shares it rather than writing
                // a second one that could drift.
                if !delphi_runtime::reap_within(pid, Duration::from_secs(5)) {
                    tracing::error!(pid, "child did not reap within 5s — leaked UNREAPED rather \
                                          than wedging the daemon");
                }
            }
        }
        tracing::error!(
            shell = self.shell,
            ai = self.ai,
            "daemon leaving by an ERROR path — shell and AI killed so they cannot outlive it, \
             and the shell's logind session with them (D0A-R5-03)"
        );
    }
}


/// Where the system declares the lowest uid it considers a regular login user.
const LOGIN_DEFS: &str = "/etc/login.defs";

/// Used when `/etc/login.defs` is absent or declares no bound.
const DEFAULT_UID_MIN: u32 = 1000;
const DEFAULT_UID_MAX: u32 = 60000;

fn login_defs_key(text: &str, key: &str, default: u32) -> u32 {
    text.lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .find(|(k, _)| k.trim() == key)
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or(default)
}

/// Read the system's own regular-login-user range rather than hardcoding a threshold
/// (`docs/DEFECT_CLASSES.md` class 4 — authoritative category, not hand-enumeration).
///
/// **Both ends are load-bearing.** `UID_MIN` alone would admit `nobody`, whose uid is
/// 65534 on Debian/Ubuntu — above `UID_MIN`, and above `UID_MAX` (60000), which is the
/// bound that actually excludes it.
fn login_defs_uid_range(path: &std::path::Path) -> (u32, u32) {
    let Ok(text) = std::fs::read_to_string(path) else {
        return (DEFAULT_UID_MIN, DEFAULT_UID_MAX);
    };
    (
        login_defs_key(&text, "UID_MIN", DEFAULT_UID_MIN),
        login_defs_key(&text, "UID_MAX", DEFAULT_UID_MAX),
    )
}

/// Refuse to serve a system account. `--session` comes from the unit's `%i` and is
/// unvalidated, so `delphi-runtimed@root` instantiates as readily as a real user —
/// and then `expected_uid` is 0, the requester check compares 0 to 0, and the
/// root-launched tool is admitted as its own approver (D0A-R9-11).
///
/// The class, not the instance: `@daemon` and `@nobody` instantiate just as easily.
fn refuse_system_account(name: &str, uid: u32, (uid_min, uid_max): (u32, u32)) -> Result<()> {
    // `uid == 0` is held separately so the guard survives a `UID_MIN` of 0, which would
    // otherwise disable it at the one value that matters most.
    if uid == 0 || uid < uid_min || uid > uid_max {
        bail!(
            "refusing to serve system account `{name}` (uid {uid}): --session must name a \
             regular login user ({uid_min}..={uid_max}, per {LOGIN_DEFS}). A system account \
             makes the requester check vacuous — at uid 0 it compares 0 to 0 and admits the \
             sandboxed tool itself as the approver (D0A-R9-11)."
        );
    }
    Ok(())
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
    // BEFORE the anchor: a refusal here must precede any system-state change.
    refuse_system_account(
        &session,
        user.uid.as_raw(),
        login_defs_uid_range(std::path::Path::new(LOGIN_DEFS)),
    )?;

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
        // Production requires the SURFACE-LIVE claim: a scaffold marker is refused (D0-A A1).
        ready: delphi_runtime::readiness::ReadySemantics::SurfaceLive,
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

    // D0A-R5-03: PRODUCTION orphan path. Every `?` between here and the terminal contract
    // below exits main and leaves the shell and AI ALIVE — and the shell holds a logind
    // session on a VT, so the next start fails and a privileged process survives the daemon
    // that owns it. The requester timeout is the likeliest such exit, but it is not the only
    // one; the guard covers the class rather than that instance.
    //
    // RAII, not statements: an error path unwinds past any cleanup written after it. That is
    // exactly how the test harness leaked four root daemons (D0A-R4-07), and the daemon had
    // the same shape.
    let mut reaper = ChildReaper { shell: children.shell_pid, ai: children.ai_pid, armed: true };

    let session_source = logind_source(children.shell_pidfd.as_fd());
    // B2A-C-R3-02: surface a false startup verdict LOUDLY — but do NOT abort, because for a
    // valid `ttyN` the only axis that can be false here is ACTIVE, and that one tracks which VT
    // holds the seat's foreground, so it is a race at boot rather than a config error.
    //
    // THE PREMISE OF THAT DECISION IS NOW TRUE (D0-A A3): the counter-argument accepted against
    // aborting was "the gate re-checks per request" — and until A3 it did not. This read and
    // every gate read now go through `gate_allows`, so a VT switch after this point does change
    // the answer. Same conclusion, different standing. docs/READINESS_CONTRACT.md A3.
    // D0A-R6-01: THE GATE WITNESS, emitted from the value the decision consumes.
    //
    // Leg 1 of the R4-03 test proved only that `gate_allows` returned false, so a
    // `SessionSnapshot::DENIED` substitution, a wrong pidfd, or any fail-closed path passed it
    // — cause-blind, and it accepted a PRE-GATE line for two rounds before that. A witness
    // derived from a line printed NEAR the gate would be decoration; this one is the
    // resolution the decision is made on, so it cannot exist unless the gate was reached.
    //
    // `println!`, not `tracing`: an `EnvFilter` can suppress a log line, and a witness that a
    // filter can erase is a witness that can go absent for a reason unrelated to the gate.
    let startup_resolution = session_source.current();
    // D0A-R7-04: `println!` PANICS on a write error (closed pipe, full disk), which would turn
    // a diagnostic into a daemon crash — and under systemd, a restart loop. The witness is
    // worth emitting, never worth dying for.
    {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        if writeln!(out, "DELPHI_GATE_WITNESS {startup_resolution:?}").is_err() {
            tracing::warn!("could not emit the gate witness (stdout unwritable); continuing");
        }
        let _ = out.flush();
    }
    if !delphi_runtime::logind::session_passes_gate(startup_resolution.snapshot_or_denied()) {
        tracing::warn!(
            shell_pid = children.shell_pid,
            vt = %vt,
            "shell session is NOT active-local-seated at startup — consent will be DENIED while \
             this holds. Check DELPHI_SHELL_VT names the seat's FOREGROUND VT (§4 R3-02a PRIMARY \
             shape). NOT aborting: the gate re-reads the verdict at EVERY decision (D0-A A3), so \
             switching to the shell's VT clears this without a restart."
        );
    }
    // Real wall-clock — read fresh at mint and at Present-verify so the token TTL is a
    // real control (B1-R2-01), not a frozen-`now` no-op.
    let clock = SystemClock;

    // B1: service exactly one action, then exit (B2 loops).
    // D0A-R4-07: BOUNDED. An unbounded accept orphaned FOUR root daemons on the operator's
    // machine — the AI child died before connect (a bad DELPHI_AI_BIN), the daemon blocked
    // here forever, each holding its VT and a pam_systemd user manager. R2-01 built this
    // deadline for the test path and left the daemon on the blocking call; the leak is what
    // that gap cost. 120 s is generous for a real AI start and finite for a dead one.
    let mut ai = accept_requester_within(&listener, user.uid.as_raw(), Duration::from_secs(120))
        .context("accepting the requester")?;
    let mut ctx = ServiceCtx {
        channel_fd: children.daemon_channel.as_raw_fd(),
        session: session_source.as_ref(),
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
    //
    // D0A-R8-05: non-fatal, for the reason R7-04 gave — `println!` PANICS on a write error, so
    // a closed pipe or full disk turns a diagnostic into a daemon crash and, under systemd, a
    // restart loop. R7-04 fixed the WITNESS and left this one, which is the same Class 17 shape
    // the rest of this round is made of.
    {
        use std::io::Write as _;
        let mut out = std::io::stdout().lock();
        if writeln!(out, "DELPHI_RUNTIMED_OUTCOME {outcome:?}").is_err() {
            tracing::warn!("could not emit the outcome line (stdout unwritable); continuing");
        }
        let _ = out.flush();
    }

    // TERMINAL CONTRACT (B2A-R2-02): the shell interaction is terminal once
    // serve_one_action returns — release the daemon's channel end BEFORE reaping. This
    // produces the EOF a shell blocked in its consent read (a gate/PAM denial that never
    // reached the PAM prompt) dismisses on; without it the shell would WEDGE waiting for a
    // prompt + an EOF that never come. (ctx borrows only the local store/ledger, not the
    // channel, so releasing the channel here is sound.)
    // The success path owns the children from here: the terminal contract below deliberately
    // lets the shell run to its own exit, so the guard must not pre-empt it.
    reaper.armed = false;
    drop(children.daemon_channel);

    // NOTE (lifecycle, lane-dependent): blocking on the shell fits the ONE-SHOT minimal
    // shell (which exits after mint-confirm, or on the EOF above at denial). The real
    // LONG-LIVED WRY host does not exit per action — the daemon must not block on it; that
    // is the lane-dependent half's B2 service loop, where the real host actually runs.
    let _ = waitpid(Pid::from_raw(children.shell_pid), None);
    let _ = waitpid(Pid::from_raw(children.ai_pid), None);
    Ok(())
}

/// Where the shell's logind verdict is read from — **fail-closed**, re-read at every gate
/// decision rather than captured once (A3), and resolved through the **pidfd** rather than a
/// reusable pid (A2). (A compile-time test seam, excluded
/// from production, lets the binary-flow test pass on a seatless WSL2.)
fn logind_source(shell_pidfd: std::os::fd::BorrowedFd<'_>) -> Box<dyn SessionSource + '_> {
    #[cfg(feature = "insecure-test-seams")]
    if std::env::var("DELPHI_INSECURE_ASSUME_ACTIVE_SESSION").is_ok() {
        tracing::error!(
            "INSECURE TEST SEAM ACTIVE — logind gate overridden by \
             DELPHI_INSECURE_ASSUME_ACTIVE_SESSION; this MUST NOT appear in production"
        );
        // The seam also asserts `seated` — the B2a gate requires it.
        return Box::new(delphi_runtime::logind::SessionSnapshot {
            active: true,
            remote: false,
            seated: true,
        });
    }
    Box::new(LogindSource::for_pidfd(shell_pidfd))
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

#[cfg(test)]
mod system_account_guard {
    use super::*;

    /// The CLASS, enumerated (`docs/DEFECT_CLASSES.md` class 17): the reported instance
    /// was `root`, and it is one of several. `nobody` is the one a `UID_MIN`-only guard
    /// admits, which is why `UID_MAX` is in the range.
    #[test]
    fn every_system_account_shape_is_refused() {
        let range = (1000, 60000);
        for (name, uid) in [("root", 0), ("daemon", 1), ("bin", 2), ("nobody", 65534)] {
            let err = refuse_system_account(name, uid, range)
                .expect_err("system account must be refused")
                .to_string();
            assert!(err.contains(name) && err.contains(&uid.to_string()), "got: {err}");
        }
    }

    #[test]
    fn a_regular_uid_is_admitted() {
        assert!(refuse_system_account("alice", 1000, (1000, 60000)).is_ok());
        assert!(refuse_system_account("bob", 60000, (1000, 60000)).is_ok());
    }

    /// A `UID_MIN` of 0 must not disable the guard for root.
    #[test]
    fn root_is_refused_even_when_the_range_would_admit_it() {
        assert!(refuse_system_account("root", 0, (0, 60000)).is_err());
    }

    #[test]
    fn range_is_read_from_login_defs_and_falls_back_when_absent() {
        let dir = std::env::temp_dir().join(format!("delphi-logindefs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("login.defs");
        std::fs::write(&f, "# comment\nUID_MIN\t\t 500\nUID_MAX\t\t 50000\n").unwrap();
        assert_eq!(login_defs_uid_range(&f), (500, 50000));
        assert_eq!(
            login_defs_uid_range(&dir.join("absent")),
            (DEFAULT_UID_MIN, DEFAULT_UID_MAX)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
