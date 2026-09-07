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
//!    object). **No audit step: §7 is unwired** — `RuntimeAuditEntry::record` has no
//!    production caller (D0A-R25-08, and R24-03 for the same correction one layer down
//!    in `service.rs`). See the open row in `docs/CONFORMANCE_REGISTER.md`.
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

/// `strtoul(v, NULL, 0)`'s accepted forms and no others: an optional `+`, then `0x`/`0X`
/// hex, a leading-`0` octal, or decimal — the whole value or nothing.
///
/// Deliberate divergence, the only one: a value above `u32::MAX` yields `None` (and so the
/// built-in default) where shadow takes it as `unsigned long` and truncates — measured,
/// `UID_MIN 4294967296` made `useradd` allocate uid **0**. Falling back beats wrapping.
fn parse_c_ulong(v: &str) -> Option<u32> {
    let v = v.strip_prefix('+').unwrap_or(v);
    let (digits, radix) = match v.as_bytes() {
        [b'0', b'x' | b'X', rest @ ..] if !rest.is_empty() => (&v[2..], 16),
        [b'0', rest @ ..] if !rest.is_empty() => (&v[1..], 8),
        _ => (v, 10),
    };
    // `from_str_radix` accepts its own sign prefix; `strtoul` does not accept one after the
    // radix prefix (`0x+1388` is rejected — measured). Admit alphanumerics only.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    u32::from_str_radix(digits, radix).ok()
}

/// PHASE 1 — the last RAW value `key` is given, exactly as shadow stores it.
///
/// **Raw, and separated from interpretation, because shadow separates them** (D0A-R11-05).
/// The previous version parsed each line and kept the last one that *parsed*, so
/// `UID_MIN 5000` followed by `UID_MIN garbage` resurrected 5000 where shadow stores
/// `garbage`, fails to parse it, and uses its built-in default. Measured both ways:
/// `5000` then `garbage` → shadow allocates **1000**; `garbage` then `5000` → **5000**.
///
/// A line that gives no value does not define the key at all — measured: `UID_MIN 5000`
/// followed by a bare `UID_MIN ` still allocates 5000.
fn login_defs_raw<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let mut found = None;
    // `split('\n')`, NOT `.lines()`: `lines()` strips a trailing `\r` and shadow does not —
    // it rejects `5000\r` and falls back to its default. Measured in both directions.
    for line in text.split('\n') {
        let line = line.trim_start_matches([' ', '\t']);
        if line.starts_with('#') {
            continue;
        }
        let Some((k, value)) = line.split_once([' ', '\t']) else { continue };
        if k != key {
            continue;
        }
        let value = value.trim_end_matches([' ', '\t']);
        if value.is_empty() {
            continue;
        }
        found = Some(value);
    }
    found
}

/// PHASE 2 — shadow's quote handling, then `strtoul` base 0.
///
/// **A SCAN, not a strip (D0A-R11-05).** Stripping one quote from each end got three
/// measured forms wrong. Shadow skips **any number** of leading quotes and then terminates
/// at the **first subsequent** quote, which is why `"50"00"` yields **50** — the sharpest
/// of the measurements, because no strip-based reading produces that.
///
/// | form | shadow |
/// |---|---|
/// | `"5000" # comment` | 5000 — the comment is past the terminating quote |
/// | `""5000` | 5000 |
/// | `5000"ignored` | 5000 |
/// | `"""5000"""` | 5000 |
/// | `"50"00"` | **50** |
/// | `""` | no value → default |
fn login_defs_interpret(raw: &str) -> Option<u32> {
    // LEADING BLANKS COME OFF BEFORE THE QUOTE SCAN (D0A-R12-07). Without this,
    // `UID_MIN   "5000"` scans a value that starts with spaces: no quote is skipped, the
    // scan then takes everything up to the FIRST quote — which is the blanks — and the
    // parse fails into the default. Measured: shadow allocates 5000; we allocated 1000.
    // The quote handling and the blank handling interact, and the probe that found the
    // other 38 forms never generated one with both.
    let raw = raw.trim_start_matches([' ', '\t']);
    let scanned = raw.trim_start_matches('"');
    let scanned = scanned.split('"').next().unwrap_or(scanned);
    // `strtoul` skips leading whitespace of its own accord; trailing whitespace INSIDE the
    // quotes is not trimmed and must still fail, as it does for shadow (`" 5000 "` → default).
    parse_c_ulong(scanned.trim_start_matches([' ', '\t']))
}

/// D0A-R10-07 / R11-05: the value shadow itself would use for `key`.
///
/// **The grammar must be shadow's, not a reasonable one.** These bounds classify accounts
/// (`refuse_system_account`, `refuse_unsafe_tool_account`), and shadow's `useradd` is what
/// hands out the uids being classified. A parser that disagrees about a form disagrees about
/// which accounts are login accounts — which is the class D0A-R9-11 closed, reopened one
/// level down.
///
/// **Three rounds found forms in this parser, so the METHOD changed rather than the form
/// list**: collect the last raw value (phase 1), then interpret it once (phase 2), which is
/// the shape shadow's own `getdef` has. Adding a fourth special case to a single-pass
/// strip-and-parse was the approach that kept losing.
fn login_defs_key(text: &str, key: &str, default: u32) -> u32 {
    login_defs_raw(text, key).and_then(login_defs_interpret).unwrap_or(default)
}

/// Read the system's own regular-login-user range rather than hardcoding a threshold
/// (`docs/DEFECT_CLASSES.md` class 4 — authoritative category, not hand-enumeration).
///
/// **Both ends are load-bearing.** `UID_MIN` alone would admit `nobody`, whose uid is
/// 65534 on Debian/Ubuntu — above `UID_MIN`, and above `UID_MAX` (60000), which is the
/// bound that actually excludes it.
/// Returns `Err` on an inverted range rather than leaving that to a call the next edit can
/// forget: the validation lives on the ONLY path that produces a range, so a caller cannot
/// hold one that was not checked (`docs/DEFECT_CLASSES.md` class 8 — one choke point).
fn login_defs_uid_range(path: &std::path::Path) -> Result<(u32, u32)> {
    // ABSENT is not the same as UNREADABLE (D0A-R11-05). shadow uses its built-in defaults
    // when the file is not there, so we do too — but a permission error, an I/O error or
    // non-UTF-8 content meant the same silent defaults, which is a guard quietly widening
    // its own range because it could not read the authority. Those refuse.
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((DEFAULT_UID_MIN, DEFAULT_UID_MAX))
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context(format!(
                "reading {} — the login-uid range decides which accounts are system \
                 accounts, so an unreadable file is refused rather than defaulted",
                path.display()
            )))
        }
    };
    let range = (
        login_defs_key(&text, "UID_MIN", DEFAULT_UID_MIN),
        login_defs_key(&text, "UID_MAX", DEFAULT_UID_MAX),
    );
    refuse_inverted_uid_range(range)?;
    Ok(range)
}

/// Refuse an inverted range (D0A-R10-07). Not defensiveness for its own sake: under
/// `UID_MIN > UID_MAX` the login-range leg of `refuse_unsafe_tool_account` can never fire,
/// so every tool account passes the check that exists to keep it out of the login range —
/// a guard silently disabled by a config file. `useradd` refuses to allocate under the same
/// condition (`Invalid configuration: UID_MIN (60000), UID_MAX (5000)`, rc=4, measured), so
/// refusing here follows the system rather than departing from it.
fn refuse_inverted_uid_range((uid_min, uid_max): (u32, u32)) -> Result<()> {
    if uid_min > uid_max {
        bail!(
            "refusing to run: {LOGIN_DEFS} declares an inverted login range (UID_MIN {uid_min} \
             > UID_MAX {uid_max}). No uid is inside it, so the tool account's login-range \
             check could never refuse anything (D0A-R10-07). `useradd` refuses to allocate \
             under this configuration too — fix {LOGIN_DEFS}."
        );
    }
    Ok(())
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


/// Refuse a tool account that is not a distinct, non-login identity (D0A-R10-06).
///
/// The name `delphi-tool` is not a credential. The installer creates the account only if
/// it is absent, so a **pre-existing** entry — or an NSS alias — sharing the session's
/// uid or gid would make the helper drop to precisely the identity `SO_PEERCRED` and the
/// socket's `0660 root:<session-gid>` are built to admit. Validated at startup against
/// the session actually being served, because that is the comparison that matters and it
/// is not knowable at install time.
fn refuse_unsafe_tool_account(
    tool: (u32, u32),
    session: (u32, u32),
    (uid_min, uid_max): (u32, u32),
) -> Result<()> {
    let (tuid, tgid) = tool;
    let (suid, sgid) = session;
    if tuid == suid || tgid == sgid {
        bail!(
            "refusing to run: the tool account shares the served session's identity \
             (tool {tuid}:{tgid}, session {suid}:{sgid}). The drop would land on exactly \
             the uid/gid the requester check and the socket's group admit (D0A-R10-06)."
        );
    }
    if tuid == 0 || tgid == 0 {
        bail!("refusing to run: the tool account is root ({tuid}:{tgid}) — the drop would be a no-op (D0A-R10-06)");
    }
    if tuid >= uid_min && tuid <= uid_max {
        bail!(
            "refusing to run: the tool account uid {tuid} is inside the LOGIN range \
             {uid_min}..={uid_max}; it must be a system account, so a human session can \
             never share it (D0A-R10-06)."
        );
    }
    Ok(())
}

/// D0A-R11-06 — resolve the tool identity ONCE, validate THAT tuple, and hand back the
/// exact tuple execution will use.
///
/// The previous shape had three independent resolutions (startup validation,
/// `preopen_drop_helper`, and every action) and validated only the first, so an NSS change
/// or a transient failure landed execution on credentials nothing checked. Worse, the
/// startup check was written `if let Ok(Some(tool)) = …`, which silently skipped validation
/// on a lookup ERROR — the one case where skipping is least defensible.
///
/// `lookup` is injected so the decision and its wiring are provable unprivileged. What
/// still needs a root lane is that the drop TAKES; that is
/// `an_approved_action_runs_with_the_tool_account_credentials`.
fn plan_tool_credentials<E: std::fmt::Display>(
    euid: u32,
    lookup: impl FnOnce(&str) -> std::result::Result<Option<(u32, u32)>, E>,
    session: (u32, u32),
    range: (u32, u32),
) -> Result<Option<(u32, u32)>> {
    if euid != 0 {
        // Nothing to drop: an unprivileged daemon cannot acquire another identity, and the
        // action already runs as a non-root uid.
        return Ok(None);
    }
    let tool = lookup(delphi_runtime::execute::TOOL_ACCOUNT)
        .map_err(|e| anyhow::anyhow!("resolving the tool account `{}`: {e}", delphi_runtime::execute::TOOL_ACCOUNT))?
        .with_context(|| {
            format!(
                "the tool account `{}` does not exist; approved actions have no \
                 unprivileged identity to drop to",
                delphi_runtime::execute::TOOL_ACCOUNT
            )
        })?;
    refuse_unsafe_tool_account(tool, session, range)?;
    Ok(Some(tool))
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
    // Read ONCE and hand the same value to both guards: two reads could see two different
    // files, and the second guard's decision would then rest on a range the first never saw.
    let uid_range = login_defs_uid_range(std::path::Path::new(LOGIN_DEFS))?;
    // BEFORE the anchor: a refusal here must precede any system-state change.
    refuse_system_account(&session, user.uid.as_raw(), uid_range)?;

    // D0A-R10-06 / R11-06: the tool identity is resolved ONCE, validated against the
    // session being served, and RECORDED — so the tuple that was checked is the tuple the
    // action drops to. Errors propagate; the previous `if let Ok(Some(…))` skipped
    // validation entirely when the lookup failed.
    let planned = plan_tool_credentials(
        nix::unistd::geteuid().as_raw(),
        |name| {
            User::from_name(name).map(|u| u.map(|u| (u.uid.as_raw(), u.gid.as_raw())))
        },
        (user.uid.as_raw(), user.gid.as_raw()),
        uid_range,
    )?;
    delphi_runtime::execute::set_tool_credentials(planned)
        .context("recording the validated tool identity")?;

    // D0A-R9-01: pin the credential-drop helper BEFORE any action runs, so the
    // substitution window is process start rather than per-action, and a missing
    // helper is a startup failure rather than an action that silently runs as root.
    delphi_runtime::execute::preopen_drop_helper()
        .context("pinning the credential-drop helper")?;

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
    //
    // D0A-R28-02: the disarm MOVED to after the bounded reap below. Disarming here meant that
    // if the daemon left this function by any path while a child was still alive, nothing
    // cleaned it up — and the unbounded waits that followed could not be left by any path at
    // all. Cleanup stays armed until the children are actually reaped.
    drop(children.daemon_channel);

    // NOTE (lifecycle, lane-dependent): waiting on the shell fits the ONE-SHOT minimal shell
    // (which exits after mint-confirm, or on the EOF above at denial). The real LONG-LIVED WRY
    // host does not exit per action — the daemon must not block on it; that is the
    // lane-dependent half's B2 service loop, where the real host actually runs.
    //
    // D0A-R28-02: BOTH WAITS WERE UNBOUNDED, AND ONE OF THEM IS ON AN UNTRUSTED PEER. The AI
    // is untrusted by construction (`docs/TRUST_MODEL.md` §2) — it can take its terminal
    // response and simply not exit, and the ROOT daemon then blocks here forever. "B1 services
    // one action and exits" was therefore a property that depended on the AI's cooperation,
    // which is exactly the thing this boundary refuses to depend on anywhere else.
    //
    // Bounded now, and the reaper stays ARMED across the wait so a child that outlives the
    // grace period is killed rather than left. Grace over kill-immediately because the ordinary
    // case is a child already exiting, and SIGKILLing it would lose its exit status.
    let grace = std::time::Duration::from_secs(5);
    for (what, pid) in [("shell", children.shell_pid), ("ai", children.ai_pid)] {
        if !delphi_runtime::launcher::reap_within(pid, grace) {
            tracing::warn!(
                child = what,
                pid,
                grace_secs = grace.as_secs(),
                "child did not exit within the grace period after the action completed; \
                 terminating (D0A-R28-02)"
            );
            let _ = nix::sys::signal::kill(Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
            // Bounded again: a SIGKILLed child is reaped promptly or it is unreapable (a
            // zombie whose parent we are, or an already-gone pid), and blocking would
            // reintroduce the defect this closes.
            let _ = delphi_runtime::launcher::reap_within(pid, std::time::Duration::from_secs(2));
        }
    }
    reaper.armed = false;
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

    /// D0A-R10-06 — the tool identity is validated, not trusted by name. Each rejection
    /// leg is exercised independently so weakening any one of them bites.
    #[test]
    fn a_tool_account_sharing_the_session_identity_is_refused() {
        let range = (1000, 60000);
        let session = (1000, 1000);
        // Shared uid, shared gid, root, and inside the login range — four distinct ways
        // the drop lands somewhere it must not.
        for tool in [(1000, 972), (997, 1000), (0, 0), (997, 0), (1500, 972)] {
            assert!(
                refuse_unsafe_tool_account(tool, session, range).is_err(),
                "must refuse tool {tool:?} against session {session:?}"
            );
        }
    }

    /// POSITIVE CONTROL: a genuine system account distinct from the session is admitted,
    /// so "shared identity is refused" cannot be confused with "everything is refused".
    #[test]
    fn a_distinct_system_tool_account_is_admitted() {
        assert!(refuse_unsafe_tool_account((997, 972), (1000, 1000), (1000, 60000)).is_ok());
    }

    /// D0A-R11-06 — the planner's decisions, provable without root because the resolver
    /// is injected. Each leg is a distinct way the old shape went wrong.
    #[test]
    fn the_credential_plan_is_resolved_once_validated_and_propagates_errors() {
        let session = (1000, 1000);
        let range = (1000, 60000);
        let ok = |_: &str| Ok::<_, String>(Some((997, 972)));

        // Unprivileged: nothing to drop, and the resolver is never consulted.
        let never = |_: &str| -> std::result::Result<Option<(u32, u32)>, String> {
            panic!("the resolver must not be called when euid != 0")
        };
        assert_eq!(plan_tool_credentials(1000, never, session, range).unwrap(), None);

        // Privileged and healthy: the validated tuple comes back, and it is the SAME tuple
        // the caller will hand to execution.
        assert_eq!(plan_tool_credentials(0, ok, session, range).unwrap(), Some((997, 972)));

        // A lookup ERROR must propagate. The old code was `if let Ok(Some(tool)) = …`,
        // which skipped validation entirely in exactly this case.
        let err = plan_tool_credentials(0, |_: &str| Err::<Option<(u32, u32)>, _>("nss is down"), session, range)
            .expect_err("a lookup error must not be silently skipped");
        assert!(err.to_string().contains("resolving the tool account"), "got: {err}");

        // Account absent: refuse, naming it.
        let err = plan_tool_credentials(0, |_: &str| Ok::<_, String>(None), session, range)
            .expect_err("an absent tool account must refuse");
        assert!(err.to_string().contains("does not exist"), "got: {err}");

        // And the validation still runs on the resolved tuple — a shared uid is refused.
        let err = plan_tool_credentials(0, |_: &str| Ok::<_, String>(Some((1000, 972))), session, range)
            .expect_err("a tool account sharing the session uid must refuse");
        assert!(err.to_string().contains("shares the served session"), "got: {err}");
    }

    /// A `UID_MIN` of 0 must not disable the guard for root.
    #[test]
    fn root_is_refused_even_when_the_range_would_admit_it() {
        assert!(refuse_system_account("root", 0, (0, 60000)).is_err());
    }

    /// D0A-R10-07 — every row here is a MEASUREMENT of shadow 1:4.17.4, taken by
    /// `scratch/d1-login-defs-probe.sh`: it writes the body into a throwaway
    /// `useradd --prefix` tree and reads back the uid `useradd` actually allocated.
    /// `1000` means shadow did not honour the form and fell back to its own built-in
    /// default — agreement in the fallback is as load-bearing as agreement in the value,
    /// since a form we honour and shadow rejects widens our range against the system's.
    ///
    /// The transcript prints, so a pass shows the grammar it agreed on rather than `ok`
    /// (`docs/DEFECT_CLASSES.md` class 38).
    #[test]
    fn the_grammar_agrees_with_shadows_measured_behaviour() {
        // (what the file says, what `useradd` allocated under it)
        let measured: &[(&str, &str, u32)] = &[
            ("plain", "UID_MIN 5000\n", 5000),
            ("leading spaces", "   UID_MIN 5000\n", 5000),
            ("leading tab", "\tUID_MIN 5000\n", 5000),
            ("hex", "UID_MIN 0x1388\n", 5000),
            ("hex, capital X", "UID_MIN 0X1388\n", 5000),
            ("octal", "UID_MIN 011610\n", 5000),
            ("plus-prefixed", "UID_MIN +5000\n", 5000),
            ("many blanks before the value", "UID_MIN    5000\n", 5000),
            ("trailing blanks", "UID_MIN 5000   \n", 5000),
            ("double-quoted", "UID_MIN \"5000\"\n", 5000),
            ("opening quote only", "UID_MIN \"5000\n", 5000),
            ("closing quote only", "UID_MIN 5000\"\n", 5000),
            ("quoted, then trailing blanks", "UID_MIN \"5000\"  \n", 5000),
            ("quoted hex", "UID_MIN \"0x1388\"\n", 5000),
            ("no trailing newline", "UID_MAX 50000\nUID_MIN 5000", 5000),
            ("bare zero", "UID_MIN 0\n", 0),
            // Forms shadow REFUSES — it reports `cannot parse UID_MIN value` (or never sees
            // the key) and uses its built-in default.
            ("trailing comment", "UID_MIN 5000 # x\n", 1000),
            ("single-quoted", "UID_MIN '5000'\n", 1000),
            ("blanks inside the quotes", "UID_MIN \" 5000 \"\n", 1000),
            ("CRLF line ending", "UID_MIN 5000\r\n", 1000),
            ("sign after the radix prefix", "UID_MIN 0x+1388\n", 1000),
            ("key=value", "UID_MIN=5000\n", 1000),
            ("commented out", "#UID_MIN 5000\n", 1000),
            ("indented comment", "   #UID_MIN 5000\n", 1000),
            ("lowercase key", "uid_min 5000\n", 1000),
            ("negative", "UID_MIN -1\n", 1000),
            ("empty value", "UID_MIN \nUID_MAX 50000\n", 1000),
            // Precedence: the LAST definition is the one `useradd` allocated under.
            ("duplicate keys — last wins", "UID_MIN 5000\nUID_MIN 6000\n", 6000),
            // D0A-R11-05: the quote SCAN, and last-RAW-then-parse. Every row measured the
            // same way; `"50"00"` is the one no strip-based reading can produce.
            ("quoted, then a comment", "UID_MIN \"5000\" # comment\n", 5000),
            ("two leading quotes", "UID_MIN \"\"5000\n", 5000),
            ("terminates at the first quote", "UID_MIN 5000\"ignored\n", 5000),
            ("three quotes each side", "UID_MIN \"\"\"5000\"\"\"\n", 5000),
            ("quotes around a hex value", "UID_MIN \"0x1388\" # x\n", 5000),
            ("a quote INSIDE the digits", "UID_MIN \"50\"00\"\n", 50),
            ("empty quotes", "UID_MIN \"\"\n", 1000),
            ("last raw wins even UNPARSEABLE", "UID_MIN 5000\nUID_MIN garbage\n", 1000),
            ("unparseable then good", "UID_MIN garbage\nUID_MIN 5000\n", 5000),
            ("a valueless line does not define", "UID_MIN 5000\nUID_MIN \n", 5000),
            // D0A-R12-07: blanks AND quotes together — the interaction neither the 28-form
            // nor the 38-form probe generated.
            ("blanks then a quoted value", "UID_MIN   \"5000\"\n", 5000),
            ("a tab then a quoted value", "UID_MIN \t\"5000\"\n", 5000),
            ("blanks then two quotes", "UID_MIN  \"\"5000\n", 5000),
            ("blanks, quoted, then a comment", "UID_MIN  \"5000\" # x\n", 5000),
        ];
        let mut disagreed = Vec::new();
        for (form, body, shadow) in measured {
            let ours = login_defs_key(body, "UID_MIN", DEFAULT_UID_MIN);
            println!(
                "  {:<30} shadow={:<6} ours={:<6} {}",
                form,
                shadow,
                ours,
                if ours == *shadow { "agree" } else { "DISAGREE" }
            );
            if ours != *shadow {
                disagreed.push(*form);
            }
        }
        assert!(
            disagreed.is_empty(),
            "the parser disagrees with shadow on {} form(s): {disagreed:?} — it would \
             classify accounts differently from the tool that assigns their uids",
            disagreed.len()
        );
    }

    /// The ONE deliberate divergence, in its own test so it cannot be read as agreement:
    /// above `u32::MAX` shadow keeps parsing as `unsigned long` and the value truncates
    /// (measured: `UID_MIN 4294967296` made `useradd` allocate uid **0** — root's). We
    /// refuse the value and take the built-in default instead of wrapping.
    #[test]
    fn an_out_of_range_value_falls_back_rather_than_truncating() {
        assert_eq!(login_defs_key("UID_MIN 4294967296\n", "UID_MIN", DEFAULT_UID_MIN), DEFAULT_UID_MIN);
        assert_eq!(parse_c_ulong("4294967296"), None);
        assert_eq!(parse_c_ulong("4294967295"), Some(u32::MAX));
    }

    /// An inverted range disables the tool-account login-range check silently, so the
    /// daemon refuses to start under it — as `useradd` refuses to allocate under it.
    ///
    /// Asserted THROUGH `login_defs_uid_range`, the only path that produces a range, not
    /// only against the predicate: a test that calls the predicate alone would pass just as
    /// happily with the call site deleted.
    #[test]
    fn an_inverted_login_range_is_refused_and_a_normal_one_is_not() {
        let err = refuse_inverted_uid_range((60000, 5000)).expect_err("inverted must refuse");
        assert!(err.to_string().contains("inverted login range"), "got: {err}");
        // POSITIVE CONTROL — including the degenerate single-value range, which is valid.
        assert!(refuse_inverted_uid_range((1000, 60000)).is_ok());
        assert!(refuse_inverted_uid_range((1000, 1000)).is_ok());

        let dir = tmpdir("inverted");
        let f = dir.join("login.defs");
        std::fs::write(&f, "UID_MIN 60000\nUID_MAX 5000\n").unwrap();
        let err = login_defs_uid_range(&f).expect_err("the range reader must refuse it too");
        assert!(err.to_string().contains("inverted login range"), "got: {err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("delphi-logindefs-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// D0A-R11-05 — ABSENT and UNREADABLE are different answers.
    ///
    /// shadow uses its built-in defaults when the file is not there, so we do too. But any
    /// other read failure previously took the same silent path: a guard widening its own
    /// range because it could not read the authority that defines it.
    #[test]
    fn an_unreadable_login_defs_refuses_where_an_absent_one_defaults() {
        let dir = tmpdir("unreadable");
        let f = dir.join("login.defs");
        std::fs::write(&f, "UID_MIN 5000\nUID_MAX 50000\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_to_string(&f).is_ok() {
            // Running as root, where mode 000 is not a barrier. A SKIP proves nothing, so
            // say which condition was absent rather than claiming a pass.
            eprintln!("SKIP an_unreadable_login_defs_refuses…: measured blocker: this uid can read a 0000 file");
            std::fs::remove_dir_all(&dir).unwrap();
            return;
        }
        let err = login_defs_uid_range(&f).expect_err("an unreadable login.defs must refuse");
        assert!(err.to_string().contains("unreadable file is refused"), "got: {err}");
        // POSITIVE CONTROL: absent still defaults, so "refuses" is not "refuses everything".
        assert_eq!(
            login_defs_uid_range(&dir.join("absent")).unwrap(),
            (DEFAULT_UID_MIN, DEFAULT_UID_MAX)
        );
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn range_is_read_from_login_defs_and_falls_back_when_absent() {
        let dir = tmpdir("range");
        let f = dir.join("login.defs");
        std::fs::write(&f, "# comment\nUID_MIN\t\t 500\nUID_MAX\t\t 50000\n").unwrap();
        assert_eq!(login_defs_uid_range(&f).unwrap(), (500, 50000));
        assert_eq!(
            login_defs_uid_range(&dir.join("absent")).unwrap(),
            (DEFAULT_UID_MIN, DEFAULT_UID_MAX)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
