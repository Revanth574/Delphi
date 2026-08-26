// SPDX-License-Identifier: MIT

//! Execute the approved action in the sandbox — the gate + the swap-proof fd-exec
//! (Increment 1d, R3-04 + `docs/TRUST_MODEL.md` §4 step 5).
//!
//! Four bindings make "execute = approval" hold:
//!
//! 1. **The gate.** [`execute_approved`] verifies the 1c capability token against
//!    `canonical_action_digest(action)` **before any exec path**. The digest covers
//!    `executable_digest` (the hashed executable content, piece 1), so a token that
//!    verifies means the human approved *this exact action including this exact
//!    executable* — unapproved or substituted actions never reach the exec.
//! 2. **One-shot (§4).** The approval is **consumed** via the [`ConsumptionLedger`]
//!    on first use; a second execution of the same action is denied
//!    ([`RuntimeError::AlreadyConsumed`]). One human approval authorizes one
//!    execution — the digest-binding closes approve-A/execute-B; the ledger closes
//!    approve-once/execute-many.
//! 3. **The fd-pin (anti-TOCTOU).** The program is exec'd as `/proc/self/fd/N`
//!    **inside the bwrap jail** — `execve` resolves the magic symlink to the
//!    **pinned inode** (the one whose bytes were hashed), not a re-resolvable path
//!    (verified: binding the path re-resolves and is NOT swap-proof; exec'ing the fd
//!    is). For a **script** (R4-02) the **pinned interpreter** fd is exec'd with the
//!    script memfd as its argument — never the script fd, whose shebang would
//!    re-resolve the interpreter by PATH. The script memfd's **full immutability
//!    seal set is verified** (`F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW |
//!    F_SEAL_SEAL` via `F_GET_SEALS`) before any exec path, so neither its content
//!    (write) nor its length (`ftruncate` shrink/grow) can mutate between the digest
//!    and the exec — interpreter-pinning defeats interpreter-PATH-swap, full sealing
//!    defeats script-CONTENT/LENGTH-mutation, and the two together are the full R4-02
//!    mechanism. `--proc /proc` in the [`SandboxProfile`] makes `/proc/self/fd/N`
//!    resolve.
//! 4. **fd-discipline (§6).** The 1b `fdsec` close-range runs in the child before
//!    bwrap's exec, so no daemon fd (the approval channel, the anchor socket) leaks
//!    into bwrap or the jailed tool; only the pinned program fd(s) survive.

use std::collections::HashSet;
use std::os::fd::{AsFd, AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Output};

use nix::errno::Errno;

use crate::action::{canonical_action_digest, PendingAction, ScriptPin};
use crate::sandbox::SandboxProfile;
use crate::token::{self, ApprovalToken, MintingKey};
use crate::RuntimeError;

/// The daemon's one-shot consumption ledger (`docs/TRUST_MODEL.md` §4 — "the
/// arbiter consumes it one-shot").
///
/// Each approved action (keyed by its single-use `pending_id`) executes **at most
/// once**: one human approval authorizes one execution, not repeated execution of
/// the same destructive action within the token TTL. The digest-binding closes
/// approve-A/execute-B; this ledger closes approve-once/execute-many.
#[derive(Debug, Default)]
pub struct ConsumptionLedger {
    consumed: HashSet<String>,
}

impl ConsumptionLedger {
    /// A fresh, empty ledger (the daemon holds one in memory).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume `pending_id`. Returns `true` if newly consumed, `false` if it was
    /// already consumed (a replay).
    fn consume(&mut self, pending_id: &str) -> bool {
        self.consumed.insert(pending_id.to_string())
    }
}

/// Execute `action` in its derived sandbox **iff** `token` verifies against the
/// action's canonical digest at `now` AND the action has not already been consumed.
///
/// # Errors
///
/// [`RuntimeError::Unapproved`] if the token does not verify (the gate);
/// [`RuntimeError::AlreadyConsumed`] if this action was already executed (one-shot);
/// [`RuntimeError::Filesystem`] if the bwrap spawn fails.
pub fn execute_approved(
    action: &PendingAction,
    token: &ApprovalToken,
    key: &MintingKey,
    now: u64,
    ledger: &mut ConsumptionLedger,
) -> Result<Output, RuntimeError> {
    // THE GATE — before any exec path.
    let digest = canonical_action_digest(action);
    if !token::verify(key, token, &digest, now) {
        return Err(RuntimeError::Unapproved);
    }
    // ONE-SHOT (§4) — consume the approval; a second execution is denied.
    if !ledger.consume(&action.pending_id) {
        return Err(RuntimeError::AlreadyConsumed);
    }
    run_fd_pinned(action)
}

/// The dedicated account the approved action runs as — never root, and never the
/// session user (`SO_PEERCRED` equality against the session uid is what would make
/// the requester check admit the tool itself).
pub const TOOL_ACCOUNT: &str = "delphi-tool";

/// Where the installer places the credential-drop helper.
///
/// A fixed path with **no environment override**: a redirectable helper path would be
/// an attack vector in precisely the component that grants uid control.
pub const DROP_HELPER: &str = "/usr/libexec/delphi-drop";

/// The helper, opened **once per process** rather than per action.
///
/// It is opened by PATH, so it inherits D0A-R9-02's own gap (inode-pinned, not
/// content-pinned) for itself. Opening once shrinks the substitution window from
/// every action to process start; closing it fully is recorded as an obligation on
/// R9-02 in `docs/CONFORMANCE_REGISTER.md`.
static DROP_HELPER_FD: std::sync::OnceLock<Option<std::os::fd::OwnedFd>> = std::sync::OnceLock::new();

/// The helper's SHA-256, fixed when this daemon was built (`build.rs`).
///
/// D0A-R9-02 step 6. The helper was opened by PATH, so it carried the same inode-vs-content
/// gap v7 closed for the tool — and it is the one component whose substitution grants **uid
/// control**, because it is what calls `setresuid`. A build-time constant is what lets the
/// daemon tell "the helper I was built against" from "whatever is at that path now".
pub const DROP_HELPER_DIGEST: &str = env!("DELPHI_DROP_DIGEST");

/// Compare a candidate helper's bytes against the compiled-in digest.
///
/// Pure, so the refusal is provable without root or an installed helper.
///
/// # Errors
///
/// [`RuntimeError::MissingDropHelper`] naming the mismatch — a helper that is not the one
/// this daemon was built against is refused, not run.
fn verify_helper_digest(bytes: &[u8], expected_hex: &str) -> Result<(), RuntimeError> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let got: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if got != expected_hex {
        return Err(RuntimeError::MissingDropHelper {
            path: format!(
                "{DROP_HELPER} is not the helper this daemon was built against \
                 (built {expected_hex}, installed {got}) — re-run installer/install.sh"
            ),
        });
    }
    Ok(())
}

/// The helper, read once, **verified against the compiled digest**, and held as a sealed
/// executable snapshot.
///
/// After this, path substitution is irrelevant: what executes is a sealed memfd whose bytes
/// were checked against a constant fixed at build time.
fn drop_helper() -> Result<std::os::fd::BorrowedFd<'static>, RuntimeError> {
    let cell = DROP_HELPER_FD.get_or_init(|| {
        let bytes = std::fs::read(DROP_HELPER).ok()?;
        verify_helper_digest(&bytes, DROP_HELPER_DIGEST).ok()?;
        crate::action::seal_executable_snapshot(&bytes).ok()
    });
    match cell {
        Some(fd) => Ok(fd.as_fd()),
        None => {
            // Distinguish "absent" from "wrong bytes" for the operator, at the cost of one
            // extra read on a path that is already failing.
            match std::fs::read(DROP_HELPER) {
                Ok(bytes) => verify_helper_digest(&bytes, DROP_HELPER_DIGEST)
                    .and(Err(RuntimeError::MissingDropHelper { path: DROP_HELPER.to_string() })),
                Err(_) => Err(RuntimeError::MissingDropHelper { path: DROP_HELPER.to_string() }),
            }
        }
    }
}

/// Open the drop helper at daemon startup, so the pin is taken before any action runs.
///
/// # Errors
///
/// [`RuntimeError::MissingDropHelper`] if it is not installed.
pub fn preopen_drop_helper() -> Result<(), RuntimeError> {
    // Whether the helper is NEEDED is decided in exactly one place — the same call the
    // exec path uses — so startup and execution cannot disagree about it.
    if tool_credentials()?.is_none() {
        return Ok(());
    }
    drop_helper().map(|_| ())
}

/// The one tuple the daemon resolved AND validated, recorded once (D0A-R11-06).
static TOOL_CREDENTIALS: std::sync::OnceLock<Option<(u32, u32)>> = std::sync::OnceLock::new();

/// Record the credentials the daemon validated against the session it is serving.
///
/// # Errors
///
/// [`RuntimeError::CredentialsNotPlanned`] if called twice — a second plan would mean two
/// answers exist and the later caller decides which, which is the divergence this closes.
pub fn set_tool_credentials(creds: Option<(u32, u32)>) -> Result<(), RuntimeError> {
    TOOL_CREDENTIALS.set(creds).map_err(|_| RuntimeError::CredentialsNotPlanned)
}

/// Credentials to drop to, or `None` when there is no privilege to drop.
///
/// **READ, never resolved (D0A-R11-06).** This used to call `User::from_name` itself, and
/// so did `preopen_drop_helper`, and so did the daemon's startup validation — three
/// independent lookups, of which only one was checked against the session. An NSS change
/// between them, or a transient first failure, meant the action dropped to a tuple nothing
/// had validated. Now there is exactly one resolution and it is the validated one.
///
/// Unprivileged callers cannot acquire another identity, so `None` is the honest answer,
/// not a bypass — and that case needs no plan, which keeps the unprivileged test suite
/// working without a seam that could weaken the privileged path.
fn tool_credentials() -> Result<Option<(u32, u32)>, RuntimeError> {
    decide_credentials(nix::unistd::geteuid().as_raw(), TOOL_CREDENTIALS.get())
}

/// The decision, separated from the two global reads so it is provable unprivileged
/// (D0A-R12-08). Its root branch is the one that mattered and the one no unprivileged test
/// could reach: with euid 0 and no plan recorded, execution REFUSES — correct for
/// production, and the reason every root-lane execution test failed before reaching the
/// drop it exists to test until `build_action` began planning.
fn decide_credentials(
    euid: u32,
    planned: Option<&Option<(u32, u32)>>,
) -> Result<Option<(u32, u32)>, RuntimeError> {
    if let Some(planned) = planned {
        return Ok(*planned);
    }
    if euid != 0 {
        return Ok(None);
    }
    // Privileged with no plan: refuse. Resolving here is exactly what created the gap.
    Err(RuntimeError::CredentialsNotPlanned)
}

/// R4-02: a pinned script's content fd MUST carry the FULL immutability seal set
/// ([`ScriptPin::FULL_SEALS`] — `F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW |
/// F_SEAL_SEAL`) so neither its content (write) nor its length (`ftruncate`
/// shrink/grow) can mutate between the digest and the exec. A write-seal ALONE is
/// insufficient: it does not stop shrink/grow. Refuse a script memfd missing any of
/// the four seals.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if `F_GET_SEALS` fails; [`RuntimeError::UnsealedScript`]
/// if the memfd lacks any required seal.
fn require_fully_sealed(script_fd: RawFd) -> Result<(), RuntimeError> {
    // SAFETY: F_GET_SEALS reads the memfd's seal bitmask; it touches no caller memory
    // and returns the seals (>= 0) or -1 with errno set.
    let seals = unsafe { nix::libc::fcntl(script_fd, nix::libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(RuntimeError::Syscall { op: "fcntl F_GET_SEALS", source: Errno::last() });
    }
    if seals & ScriptPin::FULL_SEALS != ScriptPin::FULL_SEALS {
        return Err(RuntimeError::UnsealedScript);
    }
    Ok(())
}

/// Absolute candidates for the sandbox binary, in order.
///
/// D0A-R15-01: `Command::new("bwrap")` resolves through `PATH`, and the approved
/// `env_delta` used to be on that `Command` — so the caller could name the binary that
/// would build its jail. The list is absolute and fixed at compile time; nothing an action
/// carries can extend or reorder it.
const BWRAP_CANDIDATES: [&str; 3] = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

/// The first trusted candidate: a regular file, owned by root, not group- or world-writable.
///
/// # Errors
///
/// [`RuntimeError::MissingSandboxBinary`] naming every path tried, rather than falling back
/// to a `PATH` lookup.
pub(crate) fn bwrap_path() -> Result<&'static str, RuntimeError> {
    use std::os::unix::fs::MetadataExt;
    for cand in BWRAP_CANDIDATES {
        let Ok(md) = std::fs::metadata(cand) else { continue };
        if md.is_file() && md.uid() == 0 && md.mode() & 0o022 == 0 {
            return Ok(cand);
        }
    }
    Err(RuntimeError::MissingSandboxBinary { tried: BWRAP_CANDIDATES.join(", ") })
}

/// How the approved environment travels to the tool (D0A-R15-01).
///
/// **There is deliberately no field for the parent `Command`'s environment.** That is the
/// property, encoded where it cannot be forgotten: the delta is untrusted, and applying it
/// to the process that IS bwrap gave it `LD_PRELOAD` and `PATH` over a root process running
/// before the sandbox existed and before `delphi-drop` lowered credentials.
pub(crate) struct EnvTransport {
    /// `--setenv K V` tokens for bwrap, carried on an fd via `--args` so no approved value
    /// reaches `/proc/<pid>/cmdline` (D0A-R9-06). Used only where there is no gradient.
    pub(crate) setenv_tokens: Vec<String>,
    /// NUL-separated `KEY=VALUE`, read by `delphi-drop` and applied with `execve` AFTER
    /// `setresuid`. Used wherever a drop happens.
    pub(crate) helper_blob: Option<Vec<u8>>,
}

/// Choose the transport from whether a privilege gradient exists.
///
/// With credentials to drop, bwrap and `delphi-drop` both run as root, so the delta must
/// reach neither: it stays inert bytes until the helper `execve`s the tool. Without them,
/// bwrap and the tool run as the same uid — there is no more-privileged process for the
/// delta to influence — so bwrap sets it, still off argv.
pub(crate) fn plan_env_transport(delta: &[(String, String)], creds: Option<(u32, u32)>) -> EnvTransport {
    if creds.is_some() {
        let mut blob = Vec::new();
        for (k, v) in delta {
            blob.extend_from_slice(k.as_bytes());
            blob.push(b'=');
            blob.extend_from_slice(v.as_bytes());
            blob.push(0);
        }
        return EnvTransport { setenv_tokens: Vec::new(), helper_blob: Some(blob) };
    }
    let mut setenv_tokens = Vec::new();
    for (k, v) in delta {
        setenv_tokens.push("--setenv".to_string());
        setenv_tokens.push(k.clone());
        setenv_tokens.push(v.clone());
    }
    EnvTransport { setenv_tokens, helper_blob: None }
}

/// The bwrap tail: the `--argv0` flag when nothing is interposed, `--`, and the payload.
///
/// **Extracted to be provable without root (D0A-R10).** The interposition only happens
/// when `tool_credentials()` returns `Some`, which requires euid 0, so an unprivileged
/// suite never reaches it: a mutation audit measured that removing the helper entirely,
/// and dropping the tool's approved `argv[0]`, both passed the whole suite. Those are
/// argument-assembly properties, and a pure function makes them testable with injected
/// credentials rather than only on a root lane.
///
/// Layout with the helper: `<helper> <uid> <gid> <envfd> <program> <argv0> [interp_arg] [script] [args…]`
/// Without it: `--argv0 <argv0> -- <program> [interp_arg] [script] [args…]`
fn exec_tail(
    action: &PendingAction,
    helper_fd: Option<RawFd>,
    creds: Option<(u32, u32)>,
    program_fd: RawFd,
    script_arg_fd: Option<RawFd>,
    env_fd: Option<RawFd>,
) -> Vec<String> {
    let mut args = Vec::new();
    // `--argv0` names whatever bwrap execs. With the helper interposed that is the
    // HELPER, so the flag is dropped and the helper applies argv0 to the tool itself.
    // WITHOUT a helper bwrap execs the tool directly and the flag is still correct —
    // omitting it in both cases would silently give the tool `argv[0] =
    // /proc/self/fd/N`, which nothing in the audit would show.
    if helper_fd.is_none()
        && let Some(argv0) = action.argv.first()
    {
        args.push("--argv0".to_string());
        args.push(argv0.clone());
    }
    args.push("--".to_string());
    if let (Some(h), Some((uid, gid))) = (helper_fd, creds) {
        args.push(format!("/proc/self/fd/{h}"));
        args.push(uid.to_string());
        args.push(gid.to_string());
        // The approved environment, as a sealed fd the helper reads and applies at `execve`
        // AFTER the drop (D0A-R15-01). The NUMBER is on the command line; no value is.
        args.push(env_fd.map_or_else(|| "-".to_string(), |fd| fd.to_string()));
    }
    args.push(format!("/proc/self/fd/{program_fd}"));
    // The approved argv[0], passed through the helper rather than via `--argv0`.
    if helper_fd.is_some() {
        args.push(action.argv.first().cloned().unwrap_or_else(|| format!("/proc/self/fd/{program_fd}")));
    }
    if let Some(script) = script_arg_fd {
        // The shebang's optional interpreter arg (e.g. `-I`), passed BEFORE the
        // script exactly as the kernel would — it is part of what executes, bound by
        // the digest + previewed, so execute == approved (B1-02).
        if let Some(arg) = action.script.as_ref().and_then(|sp| sp.interpreter_arg.as_deref()) {
            args.push(arg.to_string());
        }
        // The sealed script, passed to the pinned interpreter (not exec'd directly).
        args.push(format!("/proc/self/fd/{script}"));
    }
    for arg in action.argv.iter().skip(1) {
        args.push(arg.clone());
    }
    args
}

/// The profile as production assembles it, including the credential-drop decision.
///
/// D0A-R16-02: this exists so tests exercise the DECISION and not just the method. A test
/// calling `with_credential_drop()` directly stays green when the `creds.is_some()` branch is
/// deleted from the caller — the wiring, not the method, is what ships. The restriction rides
/// the returned `SandboxProfile`, which is what `sandbox_profile_digest` hashes.
///
/// **That coverage is not in effect and is not merely "pending".** The `audit` module has no
/// production entry point — `RuntimeAuditEntry::record` is called only from tests — so no
/// approved action has ever produced an entry outside a test run. The restriction is enforced
/// regardless; what does not exist is the record of it. `docs/CONFORMANCE_REGISTER.md`, §7
/// "audit = reality is RECORDED AT ALL".
pub(crate) fn assemble_profile(action: &PendingAction, creds: Option<(u32, u32)>) -> SandboxProfile {
    let profile = SandboxProfile::derive(action);
    if creds.is_some() {
        profile.with_credential_drop()
    } else {
        profile
    }
}

/// TRUST_MODEL v7: refuse a program fd that is not a fully sealed executable snapshot.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if `F_GET_SEALS` fails; [`RuntimeError::UnsealedScript`] if any
/// seal in [`crate::action::EXEC_SEALS`] is missing.
fn require_exec_sealed(fd: RawFd) -> Result<(), RuntimeError> {
    // SAFETY: F_GET_SEALS reads the memfd's seal bitmask; it touches no caller memory.
    let seals = unsafe { nix::libc::fcntl(fd, nix::libc::F_GET_SEALS) };
    if seals < 0 {
        return Err(RuntimeError::Syscall { op: "fcntl F_GET_SEALS (program fd)", source: Errno::last() });
    }
    if seals & crate::action::EXEC_SEALS != crate::action::EXEC_SEALS {
        return Err(RuntimeError::UnsealedScript);
    }
    Ok(())
}

/// TRUST_MODEL v7 + D0A-R14-03: the sealed fd's CONTENTS must be what the action's digest
/// says, checked at the choke point rather than trusted from canonicalization.
///
/// # Errors
///
/// [`RuntimeError::Unapproved`] if the snapshot does not hash to the recorded digest — the
/// same error an unverifiable token gets, because it is the same failure: what is about to
/// run is not what was approved.
fn require_digest_matches(fd: RawFd, expected: &[u8; 32], what: &str) -> Result<(), RuntimeError> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    // SAFETY: borrow the fd for the read without taking ownership — the action still owns it
    // and must keep it open for the exec.
    let mut f = std::mem::ManuallyDrop::new(unsafe {
        <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd)
    });
    // The snapshot is sealed, so its length cannot change under us; a fresh read from offset
    // 0 sees exactly the bytes the digest covered.
    use std::io::Seek;
    f.rewind().map_err(|source| RuntimeError::Filesystem {
        op: "rewind the sealed snapshot",
        path: std::path::PathBuf::from(format!("<{what} snapshot>")),
        source,
    })?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|source| RuntimeError::Filesystem {
            op: "read the sealed snapshot",
            path: std::path::PathBuf::from(format!("<{what} snapshot>")),
            source,
        })?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    let got: [u8; 32] = h.finalize().into();
    if got != *expected {
        return Err(RuntimeError::SnapshotMismatch { what: what.to_string() });
    }
    Ok(())
}

/// Build the bwrap invocation and execute the **fd-pinned** program inside it
/// (`/proc/self/fd/N` — the swap-proof inode).
///
/// * **Binary** (`script: None`): exec `/proc/self/fd/<executable_fd>`.
/// * **Script** (`script: Some`, R4-02): exec the **pinned interpreter** fd with
///   the **sealed script memfd** as its argument — never the script fd, whose
///   shebang would re-resolve the interpreter by PATH.
fn run_fd_pinned(action: &PendingAction) -> Result<Output, RuntimeError> {
    // R4-02 (the OTHER half of script-pinning): a pinned script's content memfd must
    // be FULLY sealed, so neither its bytes nor its length can change after the digest
    // was taken. Interpreter-pinning alone defeats interpreter-PATH-swap; the full
    // seal set defeats script-CONTENT/LENGTH-mutation. Refuse before any exec path.
    if let Some(sp) = &action.script {
        require_fully_sealed(sp.script_memfd.as_raw_fd())?;
    }
    // TRUST_MODEL v7 (D0A-R9-02): the program fd must be a fully sealed SNAPSHOT. Verified
    // HERE, at the one choke point every execution passes, rather than trusting the
    // constructor — the same reason the script's seals are re-checked here despite
    // `ScriptPin::sealed` having applied them. A fd that arrived by any other path, or a
    // future constructor that forgets, is refused instead of exec'd.
    require_exec_sealed(action.executable_fd.as_raw_fd())?;
    // D0A-R14-03: SEALS ARE NOT IDENTITY. The check above proves the bytes cannot change;
    // it says nothing about WHICH bytes. An action could carry a perfectly sealed snapshot
    // of something other than what was approved — and the digest binding, which §3 calls
    // "the binding for preview = approval = sandbox = audit", was established at
    // canonicalization and never checked again at the point of use.
    //
    // Hashing here is race-free ONLY BECAUSE the fd is sealed: that is what re-hashing
    // before `execve` could not achieve on a plain file (fexecve does not prevent same-inode
    // modification), and it is the property v7 bought. Cost is one pass over the snapshot.
    require_digest_matches(action.executable_fd.as_raw_fd(), &action.executable_digest, "executable")?;
    if let Some(sp) = &action.script {
        require_exec_sealed(sp.interpreter_fd.as_raw_fd())?;
        require_digest_matches(sp.interpreter_fd.as_raw_fd(), &sp.interpreter_digest, "interpreter")?;
        require_digest_matches(sp.script_memfd.as_raw_fd(), &sp.script_digest, "script")?;
    }
    // D0A-R9-10: refuse before any jail exists. See `refuse_denied_bind` for why this
    // is defence in depth on top of the uid drop rather than the barrier itself.
    // ORDER IS PART OF THE CONTRACT (D0A-R10-08). The SECURITY denial classifies
    // first: a bind naming the daemon's runtime directory must report DeniedBind even
    // when it also does not exist. My R10-01 guard was appended in front and silently
    // reclassified that case as BindWouldCreateOnHost — a fix breaking the contract of
    // the check it was added beside.
    for (path, _) in &action.fs_binds {
        crate::sandbox::refuse_denied_bind(
            path,
            std::path::Path::new(crate::anchor::DEFAULT_RUNTIME_BASE),
        )?;
    }
    // D0A-R10-01: only then, refuse a bind bwrap would have to CREATE.
    crate::sandbox::refuse_host_creating_bind(&action.fs_binds)?;
    // Which fd(s) the jailed tool must keep (the rest are closed before its exec).
    let (program_fd, script_arg_fd, mut keep): (RawFd, Option<RawFd>, Vec<RawFd>) =
        match &action.script {
            Some(sp) => {
                let interp = sp.interpreter_fd.as_raw_fd();
                let script = sp.script_memfd.as_raw_fd();
                (interp, Some(script), vec![interp, script])
            }
            None => {
                let exe = action.executable_fd.as_raw_fd();
                (exe, None, vec![exe])
            }
        };

    // D0A-R9-01: the credential drop is bwrap's PAYLOAD, not bwrap itself. Dropping
    // before bwrap drops BWRAP, which then cannot build its own sandbox (leg C:
    // `loopback: Failed RTM_NEWADDR`), and bwrap's `--uid` is namespace-internal
    // (leg B). The helper goes in by FD, so it needs no bind and cannot widen the
    // approved mount set.
    let creds = tool_credentials()?;
    let helper_fd = match creds {
        Some(_) => Some(drop_helper()?.as_raw_fd()),
        None => None,
    };
    if let Some(h) = helper_fd {
        keep.push(h);
    }

    // D0A-R15-01. The delta is UNTRUSTED and never becomes anyone's environment before the
    // tool's: with a gradient it stays sealed bytes until `delphi-drop` execve's past the
    // drop; without one bwrap sets it, carried on an fd so argv stays clean (D0A-R9-06).
    let transport = plan_env_transport(&action.env_delta, creds);
    let env_snapshot = match &transport.helper_blob {
        Some(blob) => Some(crate::action::seal_data_snapshot(blob)?),
        None => None,
    };
    let env_fd = env_snapshot.as_ref().map(|fd| fd.as_raw_fd());
    if let Some(fd) = env_fd {
        keep.push(fd);
    }
    let args_snapshot = if transport.setenv_tokens.is_empty() {
        None
    } else {
        let mut blob = Vec::new();
        for tok in &transport.setenv_tokens {
            blob.extend_from_slice(tok.as_bytes());
            blob.push(0);
        }
        Some(crate::action::seal_data_snapshot(&blob)?)
    };

    let mut args = assemble_profile(action, creds).args().to_vec();
    if let Some(fd) = args_snapshot.as_ref().map(|fd| fd.as_raw_fd()) {
        keep.push(fd);
        args.push("--args".to_string());
        args.push(fd.to_string());
    }
    args.extend(exec_tail(action, helper_fd, creds, program_fd, script_arg_fd, env_fd));

    // An absolute, verified binary — NOT a PATH lookup, which the delta could steer.
    let mut cmd = Command::new(bwrap_path()?);
    cmd.args(&args);
    // Sterile, and nothing is added back. The parent of the sandbox carries no approved byte.
    cmd.env_clear();
    // 1D-03 / §6: extend the 1b fd-discipline to execute. In the child, before
    // bwrap's exec, mark every inherited fd >= 3 close-on-exec and un-mark only the
    // program fd(s). No daemon fd (the approval channel, the anchor socket, ...)
    // leaks into bwrap or the jailed tool; only the pinned program survives so
    // `/proc/self/fd/N` resolves.
    // SAFETY: pre_exec runs in the forked child between fork and execve, so it must
    // be async-signal-safe and MUST NOT allocate (a malloc could deadlock on the
    // allocator lock if a non-surviving thread held it). `mark_cloexec_except_raw`
    // performs only `close_range`/`fcntl` + an errno read (no allocation), and
    // `io::Error::from_raw_os_error` wraps the errno integer inline — never
    // `io::Error::other`, which would `Box` (allocate).
    // SAFETY: pre_exec runs in the forked child between fork and execve, so it must
    // be async-signal-safe and MUST NOT allocate (a malloc could deadlock on the
    // allocator lock if a non-surviving thread held it). `mark_cloexec_except_raw`
    // performs only `close_range`/`fcntl` + an errno read (no allocation), and
    // `io::Error::from_raw_os_error` wraps the errno integer inline.
    unsafe {
        cmd.pre_exec(move || {
            crate::fdsec::mark_cloexec_except_raw(&keep)
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
        });
    }
    cmd.output().map_err(|source| RuntimeError::Filesystem {
        op: "spawn bwrap",
        path: std::path::PathBuf::from("bwrap"),
        source,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use sha2::{Digest, Sha256};

    use crate::action::{BindMode, NetPolicy, RequiredTier};
    use crate::token::mint;

    const KEY: [u8; 32] = [1u8; 32];
    const NOW: u64 = 1_000;

    fn bwrap_available() -> bool {
        Command::new("bwrap")
            .args([
                "--ro-bind", "/usr", "/usr", "--ro-bind", "/lib", "/lib", "--ro-bind", "/lib64",
                "/lib64", "--unshare-all", "--die-with-parent", "--", "/usr/bin/true",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    /// Write a `#!/bin/sh` script that echoes `marker` to `out`; return its bytes.
    fn write_script(path: &Path, marker: &str, out: &Path) -> Vec<u8> {
        let content = format!("#!/bin/sh\necho {marker} > {}\n", out.display());
        fs::write(path, &content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        content.into_bytes()
    }

    /// Rewrite `path`'s CONTENT in place — **same inode, no rename**. `fs::write`
    /// opens the existing file `O_TRUNC`, so an fd already open on it observes the
    /// new bytes. Returns (inode before, inode after) so a caller can PROVE the pin
    /// was intact and simply did not apply (D0A-R9-02).
    fn write_script_with_interp(path: &Path, interp: &Path) -> Vec<u8> {
        let content = format!("#!{}\n", interp.display());
        fs::write(path, &content).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        content.into_bytes()
    }

    /// Replace the script at `path` with a NEW inode (rename-over), so a fd opened
    /// on the old inode keeps the original content — the swap the fd-pin must defeat.
    fn swap_script(path: &Path, marker: &str, out: &Path) {
        let tmp = path.with_extension("swap");
        write_script(&tmp, marker, out);
        fs::rename(&tmp, path).unwrap();
    }

    /// **The guard that replaces the sentence that was wrong seven times — and then the
    /// assumption that fixing it was enough.**
    ///
    /// A doc comment claimed every execution fixture goes through `build_action`, "so no test
    /// can forget it". Lane run 3 found `audit.rs` had. The whole-suite root run then found
    /// SEVEN more — five `b1_integration` fixtures, `end_to_end`, `divergence` — all failing
    /// with "no validated tool identity was recorded before this action", and `end_to_end`
    /// and `divergence` reporting it as an EMPTY result string, two inferences from the cause.
    ///
    /// A rule cannot enforce this; enumeration can. Every source that BUILDS an action and
    /// EXECUTES one must also plan credentials, or it silently never runs at root — and a
    /// test that never runs is the failure this whole arc exists to prevent.
    #[test]
    fn every_fixture_that_executes_an_action_plans_its_credentials() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        walk(&root.join("src"), &mut files);
        walk(&root.join("tests"), &mut files);
        files.sort();

        let mut checked = 0usize;
        let mut missing = Vec::new();
        for f in &files {
            let Ok(text) = std::fs::read_to_string(f) else { continue };
            let builds = text.contains("PendingAction {");
            let executes = text.contains("execute_approved(") || text.contains("present_and_execute(");
            if !(builds && executes) {
                continue;
            }
            checked += 1;
            let path = f.strip_prefix(root).unwrap_or(f).display().to_string();
            if !(text.contains("plan_credentials_once") || text.contains("set_tool_credentials")) {
                missing.push(format!("{path} (never plans credentials)"));
            }
            // LANE RUN 4: planning was necessary and not sufficient. Five fixtures then ran
            // as `delphi-tool` into a directory the TEST process owned, wrote nothing, and
            // asserted `left: ""`. Applied uniformly — a fixture whose tool writes nothing
            // loses nothing by chowning, and a per-fixture judgement is what drifts.
            if !text.contains("chown") {
                missing.push(format!("{path} (never chowns an out dir to the planned tuple)"));
            }
        }
        // POSITIVE CONTROL: a guard that matched nothing would pass forever. It must have
        // found the files it is about.
        assert!(checked >= 4, "the guard matched only {checked} files — its pattern has drifted \
                               off the fixtures it exists to check");
        assert!(
            missing.is_empty(),
            "these build an action AND execute one, so at euid 0 they must BOTH plan \
             credentials (or be refused before running, D0A-R11-06) AND chown what the tool \
             writes to (or run as delphi-tool into a root-owned dir and write nothing): \
             {missing:#?}"
        );
        println!("  {checked} files build-and-execute; all plan credentials and chown");
        // NAMED LIMIT, because lane run 5 walked through it. This guard is FILE-granular: it
        // asks whether the file chowns SOMEWHERE, not whether THIS fixture does.
        // `b1_integration.rs` chowned in `write_marker_exe` and passed, while
        // `b1_shebang_interpreter_arg_reaches_exec` wrote its own executable, never went
        // through that helper, and stayed red with the same empty-marker signature. Closing
        // it needs per-`#[test]` granularity plus a list of helpers that chown on a fixture's
        // behalf — a predicate with two ways to drift. Left open deliberately, and the
        // mitigation is elsewhere: the fixtures now assert the RESULT before the marker, so a
        // fourth cause names itself instead of arriving as `left: ""`.
    }

    /// D0A-R12-08 — plan the credentials the way the DAEMON does, once per test process.
    ///
    /// R11-06 made `tool_credentials()` READ a recorded plan and refuse when running
    /// privileged with none, which is right for production: re-resolving is exactly how the
    /// validated tuple and the used tuple diverged. But every root-lane execution test then
    /// failed with `CredentialsNotPlanned` BEFORE reaching the drop it exists to test — a
    /// test that dies before its subject proves nothing about the subject, and on the lane
    /// it would have read as the drop being broken.
    ///
    /// **The previous sentence here claimed "called from `build_action`, which every
    /// execution test already goes through, so no test can forget it". That was false, and
    /// saying it is why nobody checked** — `audit.rs`'s `exit7_action` builds its own action,
    /// never called this, and at root `execute_approved` therefore refused before running. It
    /// surfaced on lane run 3 as `exit_code: None` where 7 was expected, one step removed from
    /// its cause. A totality claim about a mechanism, in a doc comment (D0A-R15-02's shape).
    ///
    /// The callers are `build_action` and `audit::tests::exit7_action`. Any future fixture
    /// that constructs a `PendingAction` by hand owes this call; nothing enforces it, which is
    /// the honest statement of where the mechanism stops. Unprivileged it is a no-op:
    /// `tool_credentials()` answers `None` without a plan, exactly as production does.
    /// Chown a directory the action will WRITE to, to the planned tuple.
    ///
    /// At root the tool is not root (D0A-R12-11): a dir created by the test process is not
    /// writable by `delphi-tool`, and the action then writes nothing — which presents as an
    /// EMPTY result, not as a permission error, because the failure is inside the jail.
    /// Applied uniformly, including where the fixture's tool writes nothing, so there is no
    /// per-fixture judgement to get wrong.
    pub(crate) fn chown_to_tool(dir: &std::path::Path) {
        plan_credentials_once();
        if let Ok(Some((uid, gid))) = tool_credentials() {
            std::os::unix::fs::chown(dir, Some(uid), Some(gid))
                .expect("chown the out dir to the tool account");
        }
    }

    pub(crate) fn plan_credentials_once() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            if nix::unistd::geteuid().as_raw() != 0 {
                return;
            }
            let planned = nix::unistd::User::from_name(TOOL_ACCOUNT)
                .ok()
                .flatten()
                .map(|u| (u.uid.as_raw(), u.gid.as_raw()));
            // A missing account at root is a real condition the root test asserts on
            // separately; recording `None` here would MASK it by making the drop silently
            // not happen, so it is left unplanned and `tool_credentials()` refuses.
            if let Some(creds) = planned {
                let _ = set_tool_credentials(Some(creds));
            }
        });
    }

    /// D0A-R13-01 — build the action the way PRODUCTION does.
    ///
    /// `build_action` below hand-constructs a `PendingAction` with `script: None`, which
    /// is right for most tests and WRONG for the R9-02 reproductions: a shebang executable
    /// canonicalizes to a sealed `ScriptPin`, so a hand-built action with `script: None`
    /// tests a configuration the daemon never creates. Anything asserting a property of
    /// the exec path against a shebang must come through here.
    /// The fallible form, for tests asserting that canonicalization REFUSES.
    fn canonicalize_for_test_err(exe: &Path) -> Result<PendingAction, RuntimeError> {
        plan_credentials_once();
        use crate::wire::pb;
        let proposal = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            fs_binds: vec![],
            exe_path: exe.to_string_lossy().into_owned(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 30,
            required_tier: pb::RequiredTier::TierBiometric as i32,
        };
        crate::canonicalize::canonicalize(&proposal, "act-exec".into())
    }

    fn canonicalize_for_test(exe: &Path) -> PendingAction {
        plan_credentials_once();
        use crate::wire::pb;
        let proposal = pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            // THE SAME BINDS `build_action` USES. Empty binds gave
            // `bwrap: execvp /proc/self/fd/4: No such file or directory` — which reads as
            // "the fd did not survive" and is in fact "the dynamic loader is not in the
            // jail", the exact ambiguity `runtime/helper/delphi-drop.rs` documents for its
            // own first false RED. gnutrue is dynamically linked; the snapshot is fine.
            fs_binds: vec![
                pb::Bind { path: "/usr".into(), mode: pb::BindMode::BindReadOnly as i32 },
                pb::Bind { path: "/bin".into(), mode: pb::BindMode::BindReadOnly as i32 },
                pb::Bind { path: "/lib".into(), mode: pb::BindMode::BindReadOnly as i32 },
                pb::Bind { path: "/lib64".into(), mode: pb::BindMode::BindReadOnly as i32 },
            ],
            exe_path: exe.to_string_lossy().into_owned(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 30,
            required_tier: pb::RequiredTier::TierBiometric as i32,
        };
        crate::canonicalize::canonicalize(&proposal, "act-exec".into())
            .expect("canonicalize the proposal")
    }

    /// TRUST_MODEL v7: builds from BYTES, not a path — the action binds content, so the
    /// fixture no longer needs to know where the content came from.
    fn build_action(exe_bytes: &[u8], out_dir: &Path) -> PendingAction {
        plan_credentials_once();
        PendingAction {
            pending_id: "act-exec".into(),
            preview_version: 1,
            // TRUST_MODEL v7: a SEALED SNAPSHOT, as canonicalize builds. A plain
            // `File::open` fd is refused at the exec choke point now, which is the point —
            // a fixture that can construct an action production cannot is a fixture that
            // tests a shape production never has (D0A-R13-01, generalized).
            executable_fd: crate::action::seal_executable_snapshot(exe_bytes).unwrap(),
            executable_digest: sha256(exe_bytes),
            argv: vec!["tool".into()],
            cwd: PathBuf::from("/"),
            env_delta: vec![],
            fs_binds: vec![
                (PathBuf::from("/usr"), BindMode::ReadOnly),
                (PathBuf::from("/bin"), BindMode::ReadOnly),
                (PathBuf::from("/lib"), BindMode::ReadOnly),
                (PathBuf::from("/lib64"), BindMode::ReadOnly),
                (out_dir.to_path_buf(), BindMode::ReadWrite),
            ],
            net_policy: NetPolicy::None,
            timeout: Duration::from_secs(30),
            required_tier: RequiredTier::Biometric,
            script: None,
        }
    }

    /// D0A-R14-03 — a SEALED snapshot that is not the APPROVED one is refused.
    ///
    /// Seals prove the bytes cannot change; they say nothing about WHICH bytes. The digest
    /// binding §3 calls "the binding for preview = approval = sandbox = audit" was
    /// established at canonicalization and never checked again at the point of use — so an
    /// action carrying a perfectly sealed snapshot of something else would have executed it.
    ///
    /// Hashing at exec is race-free ONLY BECAUSE the fd is sealed. That is exactly what
    /// re-hashing a plain file could not achieve (`fexecve` does not prevent same-inode
    /// modification), and it is the property v7 bought.
    #[test]
    fn a_sealed_snapshot_that_is_not_the_approved_one_is_refused() {
        if !bwrap_available() {
            eprintln!("SKIP a_sealed_snapshot_that_is_not_the_approved_one_is_refused: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("digest-mismatch");
        let approved = write_script(&env.exe, "APPROVED", &env.result);
        let mut action = build_action(&approved, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        // POSITIVE CONTROL FIRST: the honest action runs, so the refusal below cannot be
        // "everything is refused".
        let ok = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("the approved action must run");
        assert!(ok.status.success(), "bwrap: {}", String::from_utf8_lossy(&ok.stderr));

        // Now swap the SNAPSHOT for a sealed one holding different bytes, leaving the
        // digest — and the token minted over it — untouched. Seals are intact; identity is
        // not. This is the case seal-checking alone admits.
        let other = format!("#!/bin/sh\necho SUBSTITUTED > {}\n", env.result.display());
        action.executable_fd = crate::action::seal_executable_snapshot(other.as_bytes()).unwrap();
        let token2 = mint(&key, &canonical_action_digest(&action), NOW);
        let err = execute_approved(&action, &token2, &key, NOW, &mut ConsumptionLedger::new())
            .expect_err("a sealed snapshot that is not the approved one must be refused");
        // D0A-R15-03: a STRICTER variant than the `Unapproved` this originally asserted.
        // `Unapproved` means "the token failed to verify, so nothing was consumed" — and this
        // refusal happens AFTER the consume, so reusing it made the store and the ledger
        // disagree. Narrowing, not relaxing: every `SnapshotMismatch` is a refusal, and now
        // only a genuine verification failure can claim the ledger is untouched.
        assert!(
            matches!(err, RuntimeError::SnapshotMismatch { .. }),
            "must be refused — what is about to run is not what was approved: {err:?}"
        );
        assert!(
            !matches!(err, RuntimeError::Unapproved),
            "must NOT be Unapproved: that variant tells the caller the ledger is untouched, \
             and by this point it has consumed: {err:?}"
        );
    }

    /// D0A-R9-02 step 6 — the helper is bound to a BUILD-TIME digest, provable without
    /// root and without an installed helper.
    ///
    /// The helper opened by PATH was the last piece of R9-02: sealing the tool's snapshot
    /// while leaving the component that calls `setresuid` substitutable fixes the smaller
    /// half. The daemon now refuses a helper that is not the one it was built against.
    #[test]
    fn the_drop_helper_is_bound_to_the_digest_this_daemon_was_built_with() {
        // The constant exists and is a SHA-256 — a build script that silently emitted
        // nothing would otherwise make every comparison below vacuous.
        assert_eq!(DROP_HELPER_DIGEST.len(), 64, "digest: {DROP_HELPER_DIGEST}");
        assert!(DROP_HELPER_DIGEST.bytes().all(|b| b.is_ascii_hexdigit()));

        // The bytes it was built from verify against it. Read from the build's own copy,
        // so this also proves the constant matches the artifact rather than itself.
        let built = std::path::Path::new(env!("OUT_DIR")).join("delphi-drop");
        let bytes = fs::read(&built).expect("the build script's helper");
        verify_helper_digest(&bytes, DROP_HELPER_DIGEST).expect("built bytes must verify");

        // ONE BYTE CHANGED IS REFUSED, and the refusal names both digests.
        let mut tampered = bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        let err = verify_helper_digest(&tampered, DROP_HELPER_DIGEST)
            .expect_err("a modified helper must be refused");
        let msg = err.to_string();
        assert!(
            msg.contains("built") && msg.contains("installed") && msg.contains(DROP_HELPER_DIGEST),
            "the refusal must name what was expected and what was found: {msg}"
        );
    }

    /// D0A-R12-08 — the credential DECISION, all four combinations, without root.
    ///
    /// The root branch is what broke the lane: R11-06 made execution refuse when running
    /// privileged with no recorded plan, which is right, and then every root execution test
    /// hit it BEFORE reaching the drop — a test that dies before its subject proves nothing
    /// about the subject. Nothing unprivileged could observe that, because the branch needs
    /// euid 0. Reading the two globals in the caller and deciding here makes it observable.
    #[test]
    fn the_credential_decision_covers_the_root_branch_no_unprivileged_run_can_reach() {
        // Unprivileged, unplanned: nothing to drop. Production's honest answer.
        assert_eq!(decide_credentials(1000, None).unwrap(), None);
        // Unprivileged with a plan recorded: the plan wins — the daemon's answer, not a
        // second resolution.
        assert_eq!(decide_credentials(1000, Some(&Some((997, 972)))).unwrap(), Some((997, 972)));
        // ROOT with a plan: exactly the planned tuple, never a re-resolution.
        assert_eq!(decide_credentials(0, Some(&Some((997, 972)))).unwrap(), Some((997, 972)));
        // ROOT, unplanned: REFUSE. This is the branch the lane hit.
        let err = decide_credentials(0, None).expect_err("root with no plan must refuse");
        assert!(matches!(err, RuntimeError::CredentialsNotPlanned), "got: {err:?}");
        // And a plan of None at root is a RECORDED decision (no privilege to drop), which
        // is different from no plan at all — the distinction the OnceLock exists to carry.
        assert_eq!(decide_credentials(0, Some(&None)).unwrap(), None);
    }

    /// D0A-R10 — THE INTERPOSITION, PROVEN WITHOUT ROOT.
    ///
    /// The credential drop only engages when `tool_credentials()` returns `Some`, which
    /// needs euid 0, so on an unprivileged box the whole helper path is dead code and the
    /// root test that covers it SKIPs. A mutation audit measured the consequence: removing
    /// the helper entirely, and dropping the tool's approved `argv[0]`, each passed the
    /// entire suite. `exec_tail` is pure, so the assembly is checkable here with injected
    /// credentials; what still needs root is that the drop TAKES, which is
    /// `an_approved_action_runs_with_the_tool_account_credentials`.
    #[test]
    fn the_helper_is_interposed_with_the_credentials_and_the_approved_argv0() {
        let dir = std::env::temp_dir().join(format!("delphi-tail-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("t");
        fs::write(&exe, b"x").unwrap();
        let mut action = build_action(b"x", &dir);
        action.argv = vec!["approved-name".into(), "--flag".into()];

        let with = exec_tail(&action, Some(9), Some((997, 972)), 7, None, Some(11));
        println!("  with helper:    {with:?}");
        assert_eq!(
            with,
            vec!["--", "/proc/self/fd/9", "997", "972", "11", "/proc/self/fd/7", "approved-name", "--flag"],
            "the helper must be exec'd with uid, gid, the ENV FD, the pinned program, and the \
             APPROVED argv[0]"
        );
        // `--argv0` would name the HELPER, not the tool, so it must not be emitted here.
        assert!(!with.iter().any(|a| a == "--argv0"), "--argv0 names the helper when one is interposed");

        // Without credentials nothing is interposed and the flag carries argv0 instead —
        // the POSITIVE CONTROL, so "the helper is present" cannot be satisfied vacuously.
        let without = exec_tail(&action, None, None, 7, None, None);
        println!("  without helper: {without:?}");
        assert_eq!(
            without,
            vec!["--argv0", "approved-name", "--", "/proc/self/fd/7", "--flag"],
            "with no helper bwrap execs the tool directly and --argv0 is the only way to name it"
        );
        // In BOTH shapes the tool's argv[0] is the approved name, never /proc/self/fd/N.
        assert!(with.contains(&"approved-name".to_string()) && without.contains(&"approved-name".to_string()));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// A script action keeps the interpreter/script ordering the kernel would use, with
    /// the helper interposed in front of it.
    #[test]
    fn a_script_tail_passes_interp_arg_then_script_after_the_helper() {
        let dir = std::env::temp_dir().join(format!("delphi-tail-s-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("t");
        fs::write(&exe, b"x").unwrap();
        let mut action = build_action(b"x", &dir);
        action.argv = vec!["approved-name".into(), "rest".into()];
        action.script = Some(ScriptPin {
            interpreter_fd: crate::action::seal_executable_snapshot(&fs::read("/bin/sh").unwrap()).unwrap(),
            interpreter_digest: [0u8; 32],
            interpreter_arg: Some("-e".into()),
            script_memfd: write_sealed_only_memfd(b"#!/bin/sh\n"),
            script_digest: [0u8; 32],
        });
        let tail = exec_tail(&action, Some(9), Some((997, 972)), 7, Some(8), Some(11));
        println!("  script tail: {tail:?}");
        assert_eq!(
            tail,
            vec![
                "--", "/proc/self/fd/9", "997", "972", "11", "/proc/self/fd/7", "approved-name",
                "-e", "/proc/self/fd/8", "rest"
            ]
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    /// **RESTORED 2026-08-20.** This test was DELETED by `f380085`, a commit whose
    /// message describes only widening a different test and renaming it — 135 lines came
    /// out of this file and the removal was not mentioned. Round 10 named this test as a
    /// green it did not trust; by then it no longer existed. The mutation audit then
    /// measured the consequence: "the approved argv[0] never reaches the tool" survived
    /// the whole suite.
    ///
    /// It observes `$0` IN THE RUNNING TOOL, which is the layer the property lives in;
    /// `the_helper_is_interposed_with_the_credentials_and_the_approved_argv0` observes
    /// the assembled arguments. Both are kept: the unit test covers the helper shape
    /// unprivileged, this one covers what the process actually receives.
    ///
    /// Caught as a regression while wiring the drop helper: `--argv0` names whatever
    /// bwrap execs, so once the helper is interposed the flag would name the HELPER.
    /// Dropping it unconditionally would leave the tool with `argv[0] =
    /// /proc/self/fd/N` — it still runs, still exits 0, and the audit shows nothing
    /// wrong, while anything dispatching on its own name behaves differently.
    ///
    /// **The subject is a real BINARY, deliberately.** The first version of this test
    /// used a `#!/bin/sh` script and failed with `left: "/proc/self/fd/3"` — but for a
    /// shebang script the KERNEL builds the interpreter's argv from the script path,
    /// so `$0` cannot observe `--argv0` at all. That was the test being wrong, not the
    /// code, and a fix aimed at the code would have been aimed at nothing.
    #[test]
    fn the_tool_receives_its_approved_argv0() {
        if !bwrap_available() {
            eprintln!("SKIP the_tool_receives_its_approved_argv0: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("argv0");
        let shell = PathBuf::from("/bin/sh");
        let Ok(bytes) = fs::read(&shell) else {
            eprintln!("SKIP the_tool_receives_its_approved_argv0: measured blocker: cannot read /bin/sh");
            return;
        };
        let mut action = build_action(&bytes, &env.out_dir);
        // `sh -c CMD` with no operand leaves `$0` as the shell's own argv[0] — which
        // is exactly what `--argv0` (or the helper) sets, so it is observable.
        action.argv = vec![
            "tool".into(),
            "-c".into(),
            format!("echo \"$0\" > {}", env.result.display()),
        ];
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("approved exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "tool",
            "the tool must see its approved argv[0], not the fd path"
        );
    }

    /// **RESTORED 2026-08-20**, deleted by the same commit (`f380085`) and equally
    /// unmentioned. It measures the mechanism the shipped helper DEPENDS on — a kept fd
    /// surviving a second `execve` and remaining executable. A premise measurement is
    /// not spent once the thing is built: it is what tells you the premise still holds.
    ///
    /// D0A-R9-01 **PREMISE CHECK**, before any code is built on it.
    ///
    /// E's shape needs a drop-helper between bwrap and the tool, passed **by fd** so it
    /// needs no bind. That rests on a claim the existing code does *not* demonstrate:
    /// the script path keeps two fds, but fd B is **opened** by the interpreter — here
    /// fd B must survive a **second `execve`** (the helper's) and then be **exec'd**.
    ///
    /// Assuming it because it resembles the existing mechanism is the shape that was
    /// wrong twice already this session (`--uid` being namespace-internal; `--userns`
    /// taking an fd, not a path). So it is measured.
    ///
    /// Scope: proves fd survival across a second exec. It does **not** show the helper
    /// can be a shell script in production — `/usr` is not guaranteed bound for an
    /// arbitrary action, which is why the shipped helper must be a real binary.
    #[test]
    fn a_second_kept_fd_survives_a_second_exec_and_is_executable() {
        if !bwrap_available() {
            eprintln!("SKIP a_second_kept_fd_survives_a_second_exec_and_is_executable: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("twofd");
        // Helper: execs whatever path it is handed — the drop-helper's exec shape.
        let helper = env.dir.join("helper.sh");
        fs::write(&helper, "#!/bin/sh\nexec \"$1\"\n").unwrap();
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let bytes = write_script(&env.exe, "REACHED-VIA-HELPER", &env.result);

        let hf = fs::File::open(&helper).unwrap();
        let pf = fs::File::open(&env.exe).unwrap();
        let (h, p) = (hf.as_raw_fd(), pf.as_raw_fd());

        let action = build_action(&bytes, &env.out_dir);
        let mut args = SandboxProfile::derive(&action).args().to_vec();
        args.push("--".into());
        args.push(format!("/proc/self/fd/{h}"));
        args.push(format!("/proc/self/fd/{p}"));

        let keep = vec![h, p];
        let mut cmd = Command::new("bwrap");
        cmd.args(&args);
        // SAFETY: as the production path — async-signal-safe, no allocation.
        unsafe {
            cmd.pre_exec(move || {
                crate::fdsec::mark_cloexec_except_raw(&keep)
                    .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
            });
        }
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "REACHED-VIA-HELPER",
            "a second kept fd must survive the helper's own execve and remain executable"
        );
    }

    /// The RED exec variant: bind the executable PATH and exec it (re-resolvable),
    /// instead of the pinned fd.
    fn execute_via_path(action: &PendingAction, exe_path: &Path) -> Output {
        let mut args = SandboxProfile::derive(action).args().to_vec();
        args.push("--ro-bind".into());
        args.push(exe_path.display().to_string());
        args.push("/exe".into());
        args.push("--".into());
        args.push("/exe".into());
        Command::new("bwrap").args(&args).output().unwrap()
    }

    struct Env {
        dir: PathBuf,
        exe: PathBuf,
        out_dir: PathBuf,
        result: PathBuf,
    }
    impl Env {
        fn new(tag: &str) -> Self {
            // The credential plan must exist before the chown below can know what to chown
            // TO — and every execution test comes through here or through `build_action`.
            plan_credentials_once();
            let dir = PathBuf::from(format!("/tmp/delphi-exec-{}-{tag}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let out_dir = dir.join("out");
            fs::create_dir_all(&out_dir).unwrap();
            // AT ROOT THE TOOL IS NOT ROOT (D0A-R12-11). Shape E drops the action to
            // `delphi-tool`, so an `out/` created by the test process — root — is not
            // writable by the thing under test, and seven tests failed at root with
            // `cannot create …/out/result: Permission denied`. That is the predicted
            // consequence of the drop, recorded twice before E shipped: a test that fails
            // because the tool lost root is CORRECT, and the fixture is what must change.
            //
            // Chowned to the PLANNED tuple, never a fresh lookup — the same discipline
            // R11-06 imposed on production, for the same reason: two resolutions can
            // disagree. Unprivileged there is no plan and this is a no-op.
            chown_to_tool(&out_dir);
            Self { exe: dir.join("tool.sh"), result: out_dir.join("result"), out_dir, dir }
        }
    }
    impl Drop for Env {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// CORRECT: the fd-pinned, gated exec runs the digest-bound (pinned) inode — a
    /// path swap after approval does not take effect.
    #[test]
    fn fd_pinned_gated_exec_runs_the_approved_content() {
        if !bwrap_available() {
            eprintln!("SKIP fd_pinned_gated_exec_runs_the_approved_content: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("ok");
        let bytes = write_script(&env.exe, "APPROVED", &env.result);
        let action = build_action(&bytes, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);
        // Swap the PATH (new inode) after approval; the fd keeps the original.
        swap_script(&env.exe, "SWAPPED", &env.result);

        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("approved exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "APPROVED",
            "fd-pinned exec runs the digest-bound (pinned) inode, not the swapped path"
        );
    }

    /// RED-proof (fd-pin): a path-re-resolving exec runs the SWAPPED content — the
    /// swap window the fd-pin closes and path-exec reopens.
    #[test]
    fn red_proof_path_exec_runs_the_swapped_content() {
        if !bwrap_available() {
            eprintln!("SKIP red_proof_path_exec_runs_the_swapped_content: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("swap");
        let bytes = write_script(&env.exe, "APPROVED", &env.result);
        let action = build_action(&bytes, &env.out_dir);
        swap_script(&env.exe, "SWAPPED", &env.result);

        let out = execute_via_path(&action, &env.exe);
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "SWAPPED",
            "RED: path-exec re-resolves the path → the swapped binary runs → executed != approved"
        );
    }

    /// D0A-R9-01 — the approved action runs with the **tool account's credentials**.
    ///
    /// **The name states what it proves, and no more (D0A-R10 review).** The previous
    /// version was called `..._as_the_tool_account_not_root` and observed `id -u`
    /// alone — one of the six things it was cited for. It is widened here to every
    /// credential observable from inside the jail, and its name stops claiming the one
    /// that is not: the **daemon-IPC refusal**, which needs a real daemon socket to
    /// connect against and cannot be constructed here. That clause rests on P's
    /// production probe leg instead, and `docs/CONFORMANCE_REGISTER.md` now cites the
    /// two proofs separately rather than letting this test stand for both.
    ///
    /// `/proc/self/status` is the right altitude (class 41): `Uid:`/`Gid:` carry
    /// real/effective/**saved**/fs, so a partial drop that left a saved id is visible —
    /// which `id -u` could never show.
    /// D0A-R15-01 at euid 0 — the branch the unprivileged suite cannot reach.
    ///
    /// Unprivileged there is no gradient, so the delta travels through bwrap's `--setenv`.
    /// The branch this arc actually changed is the other one: a sealed memfd the helper reads
    /// and applies with `execve` AFTER `setresuid`. Nothing has ever executed it.
    ///
    /// One artifact carries both facts on purpose. The delta ARRIVING proves the transport
    /// works; the recording process running as `delphi-tool` proves it arrived on the far
    /// side of the drop. Either alone is satisfiable with the defect present — the pre-fix
    /// code also delivered the value, just to root first.
    #[test]
    fn the_approved_env_reaches_the_tool_through_the_helper_after_the_drop() {
        if !bwrap_available() {
            eprintln!("SKIP the_approved_env_reaches_the_tool_through_the_helper_after_the_drop: requires bwrap + unprivileged userns");
            return;
        }
        if nix::unistd::geteuid().as_raw() != 0 {
            eprintln!("SKIP the_approved_env_reaches_the_tool_through_the_helper_after_the_drop: requires root — measured blocker: geteuid() != 0, so there is no gradient and the helper is not interposed");
            return;
        }
        let Ok(Some(tool)) = nix::unistd::User::from_name(TOOL_ACCOUNT) else {
            eprintln!("SKIP the_approved_env_reaches_the_tool_through_the_helper_after_the_drop: measured blocker: getpwnam(\"{TOOL_ACCOUNT}\") returned no entry — installer/install.sh creates it");
            return;
        };
        if !std::path::Path::new(DROP_HELPER).exists() {
            eprintln!("SKIP the_approved_env_reaches_the_tool_through_the_helper_after_the_drop: measured blocker: {DROP_HELPER} does not exist — installer/install.sh installs it");
            return;
        }
        let env = Env::new("tool-env");
        let content = format!(
            "#!/bin/sh\n{{ grep -E '^Uid:' /proc/self/status; env; }} > {}\n",
            env.result.display()
        );
        fs::write(&env.exe, &content).unwrap();
        fs::set_permissions(&env.exe, fs::Permissions::from_mode(0o755)).unwrap();
        let mut action = build_action(content.as_bytes(), &env.out_dir);
        action.env_delta = vec![("DELPHI_SECRET".into(), "s3cret-value".into())];
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("approved exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        let seen = fs::read_to_string(&env.result).unwrap();
        eprintln!("[R15-01] the tool's uid line and environment:\n{seen}");

        let uid = tool.uid.as_raw().to_string();
        let uids: Vec<String> = seen
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .expect("no Uid: line")
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        assert_eq!(uids, vec![uid; 4], "the environment must arrive on the far side of the drop");
        assert!(seen.contains("DELPHI_SECRET=s3cret-value"), "the approved value must arrive: {seen}");
        for leaked in ["CARGO", "HOME=", "PATH=/usr/local/sbin"] {
            assert!(!seen.contains(leaked), "the daemon's environment leaked past the helper: {seen}");
        }
    }

    /// D0A-R10-12: the pre-drop payload holds ONLY `CAP_SETUID`/`CAP_SETGID`, and still
    /// holds only those AFTER a further `execve`.
    ///
    /// THE ASSERTION IS TAKEN AFTER A FURTHER EXEC ON PURPOSE. Measured (leg 4b): a root
    /// process whose permitted/effective are lowered recovers `P' = bounding` on its next
    /// exec, and bwrap leaves the bounding set FULL on the privileged path (leg 5a). So the
    /// immediate state reads `c0` in BOTH the biting and the cosmetic case — an assertion
    /// on it cannot tell them apart. What makes it bite is bwrap's `no_new_privs=1`, which
    /// is bwrap's default and not ours; this test exists to fail if that ever changes.
    ///
    /// ROOT-GATED DELIBERATELY. Unprivileged, bwrap needs a userns and drops the BOUNDING
    /// set too (measured `c0`) — under which the assertion passes for the wrong reason,
    /// via bounding rather than NNP. A green off the privileged path would not cover the
    /// configuration that ships.
    ///
    /// **WEAKEN-PROVABLE AFTER ALL (D0A-R16-01).** This carried a claim that the NNP-absent
    /// shape could not be built in-tree, so the guard's discrimination rested on a probe
    /// rather than a RED. The round-16 reviewer falsified it: bwrap is dynamically linked
    /// and calls `prctl` through the PLT, is not setuid and holds no file capabilities, so
    /// `LD_PRELOAD` reaches it even as root. `scratch/nnp-shim/nnp_suppress.c` suppresses
    /// `PR_SET_NO_NEW_PRIVS` (measured: `no-new-privs=1` → `0`), and leg A of
    /// `scratch/d0a-r10-12-red-proof.sh` runs this guard under it — the real RED.
    /// The withdrawn claim is recorded in `docs/CONFORMANCE_REGISTER.md` D0A-R10-12.
    #[test]
    fn the_predrop_payload_cannot_recover_capabilities_across_a_further_exec() {
        const NAME: &str = "the_predrop_payload_cannot_recover_capabilities_across_a_further_exec";
        if !bwrap_available() {
            eprintln!("SKIP {NAME}: requires bwrap");
            return;
        }
        if nix::unistd::geteuid().as_raw() != 0 {
            eprintln!(
                "SKIP {NAME}: requires root — measured blocker: geteuid() != 0, so bwrap takes \
                 the userns path, which drops the bounding set as well and makes this pass for \
                 the wrong reason"
            );
            return;
        }
        let out = tempfile::tempdir().unwrap();
        let action = build_action(b"#!/bin/sh\n:\n", out.path());

        // Read CapPrm after replacing the image — the recovery, performed rather than
        // inferred.
        const AFTER_EXEC: &str =
            "exec /bin/sh -c 'grep ^CapPrm: /proc/self/status'";

        // D0A-R16-02: through `assemble_profile` — the production decision — so deleting the
        // `creds.is_some()` branch turns this test red instead of leaving it green.
        let run = |restricted: bool| -> String {
            let creds = if restricted { Some((997, 997)) } else { None };
            let mut args = assemble_profile(&action, creds).args().to_vec();
            args.push("--".to_string());
            args.push("/bin/sh".to_string());
            args.push("-c".to_string());
            args.push(AFTER_EXEC.to_string());
            let o = Command::new(bwrap_path().unwrap()).args(&args).output().unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_string()
        };

        let restricted = run(true);
        let control = run(false);

        // A PASSING RUN MUST NOT LOOK LIKE A VACUOUS ONE. This test's whole premise is that
        // the property can stop holding silently (bwrap's `no_new_privs=1` is not ours); a
        // green with nothing to read would leave a reader nothing to check that against.
        // Both legs are printed BEFORE the assertions, so a failure carries them too.
        eprintln!("{NAME}: restricted (--cap-drop ALL --cap-add SETUID,SETGID) -> {restricted}");
        eprintln!("{NAME}: control    (no cap flags)                          -> {control}");

        // THE CONTROL IS A PRECONDITION, CHECKED FIRST — not a paired comparison.
        // A paired `assert_ne!` fired BEFORE the specific assertions and therefore stole the
        // failure from them: under the real regression (bwrap stops setting no_new_privs)
        // both legs read full, so the reader got "they read alike", which names no cause.
        // With both specific assertions present, "the legs differ" is implied anyway.
        assert!(
            control.contains("000001ffffffffff"),
            "PRECONDITION FAILED: an unflagged payload did not recover the full set across a \
             further exec, so this platform cannot demonstrate the property either way. \
             got={control:?}"
        );
        assert!(
            restricted.contains("00000000000000c0"),
            "the pre-drop payload recovered capabilities across a further exec — the \
             restriction is cosmetic. Check whether bwrap still sets no_new_privs=1 \
             (D0A-R10-12). got={restricted:?}"
        );
    }

    #[test]
    fn an_approved_action_runs_with_the_tool_account_credentials() {
        if !bwrap_available() {
            eprintln!("SKIP an_approved_action_runs_with_the_tool_account_credentials: requires bwrap + unprivileged userns");
            return;
        }
        if nix::unistd::geteuid().as_raw() != 0 {
            eprintln!("SKIP an_approved_action_runs_with_the_tool_account_credentials: requires root — measured blocker: geteuid() != 0, so no credential drop is possible at all");
            return;
        }
        let Ok(Some(tool)) = nix::unistd::User::from_name(TOOL_ACCOUNT) else {
            eprintln!("SKIP an_approved_action_runs_with_the_tool_account_credentials: measured blocker: getpwnam(\"{TOOL_ACCOUNT}\") returned no entry — installer/install.sh creates it");
            return;
        };
        if !std::path::Path::new(DROP_HELPER).exists() {
            eprintln!("SKIP an_approved_action_runs_with_the_tool_account_credentials: measured blocker: {DROP_HELPER} does not exist — installer/install.sh installs it");
            return;
        }
        // `Env::new` chowns the out dir to the planned tuple; this test used to do it
        // itself, which is why it was the ONE root test that passed while seven others
        // failed for want of the same line (D0A-R12-11).
        let env = Env::new("tool-uid");
        let content = format!(
            "#!/bin/sh\ngrep -E '^(Uid|Gid|Groups|CapEff):' /proc/self/status > {}\n",
            env.result.display()
        );
        fs::write(&env.exe, &content).unwrap();
        fs::set_permissions(&env.exe, fs::Permissions::from_mode(0o755)).unwrap();
        let action = build_action(content.as_bytes(), &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let (uid, gid) = (tool.uid.as_raw(), tool.gid.as_raw());
        eprintln!("[R9-01] euid=0, {TOOL_ACCOUNT} uid={uid} gid={gid}, helper={DROP_HELPER}");
        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("approved exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        let status = fs::read_to_string(&env.result).unwrap();
        eprintln!("[R9-01] the action's own /proc/self/status:\n{status}");

        let field = |k: &str| -> Vec<String> {
            status
                .lines()
                .find(|l| l.starts_with(k))
                .unwrap_or_else(|| panic!("no `{k}` line in:\n{status}"))
                .split_whitespace()
                .skip(1)
                .map(str::to_string)
                .collect()
        };
        // real, effective, SAVED and fs — a partial drop leaving a saved id is the
        // failure `id -u` cannot see.
        assert_eq!(field("Uid:"), vec![uid.to_string(); 4], "all four uids must be the tool's");
        assert_eq!(field("Gid:"), vec![gid.to_string(); 4], "all four gids must be the tool's");
        assert!(field("Groups:").is_empty(), "supplementary groups must be cleared");
        assert!(
            field("CapEff:").first().is_some_and(|c| c.trim_start_matches('0').is_empty()),
            "effective capabilities must be empty; got {:?}",
            field("CapEff:")
        );
    }

    /// D0A-R9-10, **WIRING**. `sandbox::tests` proves the predicate refuses; this
    /// proves execution actually consults it. A guard that is defined and never called
    /// passes its own unit tests forever.
    #[test]
    fn an_action_binding_the_daemon_runtime_directory_is_refused() {
        let env = Env::new("denied-bind");
        let bytes = write_script(&env.exe, "SHOULD-NOT-RUN", &env.result);
        let mut action = build_action(&bytes, &env.out_dir);
        action
            .fs_binds
            .push((PathBuf::from("/run/delphi/alice"), BindMode::ReadWrite));
        // Minted AFTER the bind is added: the digest covers `fs_binds`, so this is a
        // genuinely APPROVED action naming the runtime directory — which is the threat.
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let err = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect_err("a bind of the daemon's runtime directory must be refused");
        assert!(
            matches!(err, RuntimeError::DeniedBind { .. }),
            "must be refused AS a denied bind, not incidentally; got: {err}"
        );
        assert!(!env.result.exists(), "nothing may have executed");
    }

    /// D0A-R9-02, reviewer reproduction 1 — **SAME-INODE substitution**.
    ///
    /// `red_proof_path_exec_runs_the_swapped_content` above attacks the property the
    /// pin HAS: rename-over creates a new inode, and the pin catches it. This attacks
    /// the property it does NOT have — **the pin fixes an inode, not bytes.** Here the
    /// pin is intact and simply does not apply.
    #[test]
    fn same_inode_overwrite_executes_unapproved_content() {
        if !bwrap_available() {
            eprintln!("SKIP same_inode_overwrite_executes_unapproved_content: requires bwrap + unprivileged userns");
            return;
        }
        // D0A-R13-01: THROUGH PRODUCTION CANONICALIZATION, and with a REAL ELF.
        //
        // This used a `#!/bin/sh` fixture and a hand-built `PendingAction` with
        // `script: None` — a configuration `canonicalize` never produces, because a
        // shebang there becomes a SEALED ScriptPin. So the reproduction attacked a shape
        // production does not have, and a correct fix could have left it red: unsafe as
        // an acceptance criterion, which is what R9-02 was being held to.
        //
        // An ELF has no ScriptPin either way, so the binary path is the one under test.
        // gnutrue/gnufalse are two real 35KB ELFs on this box differing in EXIT STATUS,
        // which is the observable that survives an in-place byte swap.
        let (approved_elf, substituted_elf) = ("/usr/bin/gnutrue", "/usr/bin/gnufalse");
        for p in [approved_elf, substituted_elf] {
            if !std::path::Path::new(p).exists() {
                eprintln!("SKIP same_inode_overwrite_executes_unapproved_content: measured blocker: {p} does not exist");
                return;
            }
        }
        let env = Env::new("same-inode");
        fs::copy(approved_elf, &env.exe).unwrap();
        fs::set_permissions(&env.exe, fs::Permissions::from_mode(0o755)).unwrap();

        let action = canonicalize_for_test(&env.exe);
        assert!(action.script.is_none(), "harness: an ELF must canonicalize WITHOUT a ScriptPin");
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        // Overwrite the SAME inode with the other ELF's bytes.
        use std::os::unix::fs::MetadataExt;
        let ino_before = fs::metadata(&env.exe).unwrap().ino();
        let sub_bytes = fs::read(substituted_elf).unwrap();
        {
            use std::io::{Seek, Write};
            let mut f = fs::OpenOptions::new().write(true).truncate(true).open(&env.exe).unwrap();
            f.seek(std::io::SeekFrom::Start(0)).unwrap();
            f.write_all(&sub_bytes).unwrap();
        }
        let ino_after = fs::metadata(&env.exe).unwrap().ino();
        assert_eq!(
            ino_before, ino_after,
            "harness: the overwrite must keep the SAME inode, else this silently \
             reproduces the rename case the pin already catches"
        );

        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("approved exec");
        // The APPROVED bytes exit 0; the SUBSTITUTED bytes exit 1. The pinned fd resolves
        // to the same inode either way — which is the whole point.
        assert!(
            out.status.success(),
            "D0A-R9-02: bytes written behind the pinned inode execute — the digest bound \
             content that is no longer there (exit {:?} is gnufalse's, not gnutrue's).\n\
             bwrap stderr: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// D0A-R9-02, reviewer reproduction 2 — **NESTED-INTERPRETER substitution**, now a
    /// REJECTION test (TRUST_MODEL v7, named limit 1).
    ///
    /// It reproduced a substitution: the pinned interpreter was itself a `#!` script, so
    /// the kernel re-resolved ITS interpreter by path after the pin, and unapproved bytes
    /// ran. v7 refuses the shape at canonicalization instead of trying to pin a chain —
    /// the kernel opens every element by path recursively (`fs/binfmt_script.c`), the
    /// chain's length is attacker-influenced, and a recursive snapshot that misses one
    /// element fails SILENTLY at exec, which is this finding's own shape.
    ///
    /// So the assertion changes from "unapproved bytes ran" to "the action is never built",
    /// which is a stronger claim about an earlier moment. The substitution it used to
    /// perform is unreachable: there is no action to execute.
    #[test]
    fn a_nested_shebang_interpreter_is_refused_at_canonicalization() {
        let env = Env::new("nested");
        // interpreter → itself a script. This is the chain v7 refuses.
        let interp = env.out_dir.join("interp");
        write_script(&interp, "SUBSTITUTABLE-INTERP", &env.result);
        let bytes = write_script_with_interp(&env.exe, &interp);
        assert!(bytes.starts_with(b"#!"), "harness: the outer file must be a script");

        // `expect_err` needs Debug on the Ok type, which PendingAction deliberately lacks
        // (it holds fds and a digest that must not be casually printed).
        let msg = match canonicalize_for_test_err(&env.exe) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a nested shebang must be REFUSED at canonicalization"),
        };
        assert!(
            msg.contains("itself a `#!` script") && msg.contains("named limit 1"),
            "must refuse for the NESTED-SHEBANG reason, naming the limit: {msg}"
        );

        // POSITIVE CONTROL: the same shape with a REAL interpreter canonicalizes fine, so
        // "nested is refused" cannot be confused with "scripts are refused".
        let ok_interp = env.out_dir.join("sh-copy");
        fs::copy("/bin/sh", &ok_interp).unwrap();
        fs::set_permissions(&ok_interp, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = write_script_with_interp(&env.exe, &ok_interp);
        let action = canonicalize_for_test(&env.exe);
        assert!(action.script.is_some(), "a single-level script must still canonicalize");
    }

    /// The gate: an invalid token is rejected (no execution); the ungated path runs
    /// the unapproved action (RED — the gate is what blocks unapproved execution).
    #[test]
    fn gate_blocks_unapproved_but_ungated_would_run() {
        if !bwrap_available() {
            eprintln!("SKIP gate_blocks_unapproved_but_ungated_would_run: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("gate");
        let bytes = write_script(&env.exe, "UNAPPROVED", &env.result);
        let action = build_action(&bytes, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        // A token minted for a DIFFERENT digest — does not verify against this action.
        let wrong = mint(&key, &[0xFF; 32], NOW);

        let gated = execute_approved(&action, &wrong, &key, NOW, &mut ConsumptionLedger::new());
        assert!(matches!(gated, Err(RuntimeError::Unapproved)), "gate must reject an invalid token");
        assert!(!env.result.exists(), "gated rejection → no execution → no output");

        // RED: bypass the gate → the unapproved action executes.
        let out = run_fd_pinned(&action).expect("ungated exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert!(
            env.result.exists(),
            "RED: skipping the gate executes the UNAPPROVED action — the token gate is what \
             stands between an unapproved action and the exec"
        );
    }

    /// RUNTIME-1D-02 — ONE-SHOT: the same approval executes once; a second
    /// execution of the same action is denied (approve-once/execute-many closed).
    #[test]
    fn token_is_one_shot_second_execution_denied() {
        if !bwrap_available() {
            eprintln!("SKIP token_is_one_shot_second_execution_denied: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("oneshot");
        let bytes = write_script(&env.exe, "ONCE", &env.result);
        let action = build_action(&bytes, &env.out_dir);
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);
        let mut ledger = ConsumptionLedger::new();

        let first = execute_approved(&action, &token, &key, NOW, &mut ledger);
        assert!(first.is_ok(), "first execution of the approved action runs");
        assert_eq!(fs::read_to_string(&env.result).unwrap().trim(), "ONCE");

        // RED: same token, same action, SECOND execution → DENIED.
        let second = execute_approved(&action, &token, &key, NOW, &mut ledger);
        assert!(
            matches!(second, Err(RuntimeError::AlreadyConsumed)),
            "RED: a second execution with the same approval must be DENIED — one PAM approval \
             authorizes ONE execution, not repeated execution within the token TTL"
        );
    }

    /// A memfd holding `content` with ONLY `F_SEAL_WRITE` (NOT shrink/grow/seal) —
    /// the PARTIAL-seal case: write-sealed but still `ftruncate`-able, so its content
    /// length is mutable after the digest. The negative case that proves the exec
    /// check requires the FULL seal set, not a subset.
    fn write_sealed_only_memfd(content: &[u8]) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        // SAFETY: fresh memfd; write content, apply ONLY F_SEAL_WRITE, wrap once.
        unsafe {
            let fd = nix::libc::memfd_create(
                c"delphi-script-partial".as_ptr(),
                (nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING) as nix::libc::c_uint,
            );
            assert!(fd >= 0, "memfd_create");
            let n = nix::libc::write(fd, content.as_ptr().cast(), content.len());
            assert_eq!(n, content.len() as isize, "write memfd");
            assert_eq!(
                nix::libc::fcntl(fd, nix::libc::F_ADD_SEALS, nix::libc::F_SEAL_WRITE),
                0,
                "seal write-only"
            );
            std::os::fd::OwnedFd::from_raw_fd(fd)
        }
    }

    /// An UNSEALED memfd holding `content` (`MFD_ALLOW_SEALING` but NO seals applied,
    /// so its bytes can still be mutated) — the negative case for R4-02 sealing.
    fn unsealed_memfd(content: &[u8]) -> std::os::fd::OwnedFd {
        use std::os::fd::FromRawFd;
        // SAFETY: memfd_create returns a fresh fd; we write it and wrap once, applying
        // NO seals — its content remains mutable.
        unsafe {
            let fd = nix::libc::memfd_create(
                c"delphi-script-unsealed".as_ptr(),
                (nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING) as nix::libc::c_uint,
            );
            assert!(fd >= 0, "memfd_create");
            let n = nix::libc::write(fd, content.as_ptr().cast(), content.len());
            assert_eq!(n, content.len() as isize, "write memfd");
            std::os::fd::OwnedFd::from_raw_fd(fd)
        }
    }

    /// RUNTIME-1D-01 (SEALING half) — the ratified R4-02 mechanism is interpreter-
    /// pinned AND script-FULLY-SEALED. A FULLY-UNSEALED script memfd (its content
    /// could be swapped after the digest) is REFUSED before any exec path — so the
    /// guarantee bites the script-CONTENT-mutation threat, not only interpreter-PATH-
    /// swap. No bwrap: the seal check precedes the spawn, so this runs in plain CI.
    #[test]
    fn unsealed_script_memfd_is_refused() {
        let env = Env::new("unsealed");
        let script_src = b"#!/bin/sh\n:\n";
        let mut action =
            build_action(&write_script(&env.exe, "UNUSED", &env.result), &env.out_dir);
        action.script = Some(crate::action::ScriptPin {
            interpreter_fd: crate::action::seal_executable_snapshot(&fs::read("/bin/sh").unwrap()).unwrap(),
            interpreter_digest: sha256(b"interp"),
            interpreter_arg: None,
            script_memfd: unsealed_memfd(script_src), // NOT sealed
            script_digest: sha256(script_src),
        });
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        // The token verifies (the digest binds the script_digest, not the seal state),
        // the ledger consumes — then the seal check refuses before any exec.
        let res = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new());
        assert!(
            matches!(res, Err(RuntimeError::UnsealedScript)),
            "RED: a FULLY-UNSEALED script memfd must be REFUSED before exec — its content could \
             be mutated after the digest was taken; only a fully-sealed script may run (R4-02). \
             got {res:?}"
        );
        assert!(!env.result.exists(), "refused before any exec → no output");
    }

    /// RUNTIME-1D-01 (SEAL SET, round-3) — the ratified §3 immutability is the FULL
    /// seal set (`WRITE|SHRINK|GROW|SEAL`). `F_SEAL_WRITE` alone does NOT stop
    /// `ftruncate` shrink/grow, so a WRITE-only-sealed memfd's content/length is still
    /// mutable after the digest. A PARTIAL (write-only) seal is REFUSED, proving the
    /// exec check requires ALL FOUR — distinct from the fully-unsealed RED above. No
    /// bwrap (the seal check precedes the spawn).
    #[test]
    fn partial_seal_write_only_is_refused() {
        let env = Env::new("partialseal");
        let script_src = b"#!/bin/sh\n:\n";
        let mut action =
            build_action(&write_script(&env.exe, "UNUSED", &env.result), &env.out_dir);
        action.script = Some(crate::action::ScriptPin {
            interpreter_fd: crate::action::seal_executable_snapshot(&fs::read("/bin/sh").unwrap()).unwrap(),
            interpreter_digest: sha256(b"interp"),
            interpreter_arg: None,
            script_memfd: write_sealed_only_memfd(script_src), // ONLY F_SEAL_WRITE
            script_digest: sha256(script_src),
        });
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        let res = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new());
        assert!(
            matches!(res, Err(RuntimeError::UnsealedScript)),
            "RED: a WRITE-only-sealed script memfd must be REFUSED — F_SEAL_WRITE does not stop \
             ftruncate shrink/grow, so its content/length is still mutable after the digest; the \
             exec path must require the FULL seal set (WRITE|SHRINK|GROW|SEAL). got {res:?}"
        );
        assert!(!env.result.exists(), "refused before any exec → no output");
    }

    /// RUNTIME-1D-01 — SCRIPT PINNING (R4-02): the pinned INTERPRETER fd runs even
    /// when the interpreter PATH is swapped; the RED (exec the script fd, whose
    /// shebang re-resolves the interpreter by PATH) runs the SWAPPED interpreter.
    #[test]
    fn script_interpreter_is_pinned_against_path_swap() {
        if !bwrap_available() {
            eprintln!("SKIP script_interpreter_is_pinned_against_path_swap: requires bwrap + unprivileged userns");
            return;
        }
        let env = Env::new("scriptpin");
        let interp = env.dir.join("interp");
        let write_interp = |marker: &str| {
            let tmp = env.dir.join("interp.tmp");
            fs::write(&tmp, format!("#!/bin/sh\necho {marker} > {}\n", env.result.display())).unwrap();
            fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
            fs::rename(&tmp, &interp).unwrap(); // new inode each time (so the fd pins v1)
        };
        write_interp("INTERP-V1");
        // TRUST_MODEL v7: the interpreter is a SEALED SNAPSHOT, as canonicalize builds it.
        // A plain open is refused at the exec choke point now — which is what makes this
        // test's own subject (the pin defeating a PATH swap) still meaningful: the snapshot
        // is taken from v1's bytes, so v2 appearing at the path afterwards changes nothing.
        let interp_v1_bytes = fs::read(&interp).unwrap();
        let interp_fd = crate::action::seal_executable_snapshot(&interp_v1_bytes).unwrap();
        // The script: shebang points at the interpreter PATH (the RED re-resolves it).
        let script_src = format!("#!{}\n:\n", interp.display());

        let mut action = build_action(&write_script(&env.exe, "UNUSED", &env.result), &env.out_dir);
        // Bind the dir holding the interpreter (so the RED's shebang path resolves).
        action.fs_binds.push((env.dir.clone(), BindMode::ReadWrite));
        // The sanctioned constructor: a FULLY-sealed script memfd (so the exec-time
        // require_fully_sealed check passes on the legitimate path).
        action.script = Some(
            // D0A-R14-03: the REAL digest of the interpreter bytes. This was
            // `sha256(b"INTERP-V1")` — the marker string, not the interpreter — so the
            // action carried a digest describing nothing it held. Harmless while nothing
            // checked it; the choke-point check found it immediately.
            ScriptPin::sealed(interp_fd, sha256(&interp_v1_bytes), None, script_src.as_bytes())
                .expect("seal script memfd"),
        );
        let key = MintingKey::from_bytes(KEY);
        let token = mint(&key, &canonical_action_digest(&action), NOW);

        // Swap the interpreter PATH to v2 AFTER opening the pinned fd.
        write_interp("INTERP-V2");

        // CORRECT (R4-02): exec the PINNED interpreter fd → v1 still runs.
        let _ = fs::remove_file(&env.result);
        let out = execute_approved(&action, &token, &key, NOW, &mut ConsumptionLedger::new())
            .expect("script exec");
        assert!(out.status.success(), "bwrap: {}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "INTERP-V1",
            "the PINNED interpreter fd runs despite the path swap (R4-02)"
        );

        // RED: exec the SCRIPT fd → shebang re-resolves the interpreter by PATH → v2.
        let _ = fs::remove_file(&env.result);
        let script_fd = action.script.as_ref().unwrap().script_memfd.as_raw_fd();
        crate::fdsec::clear_cloexec(script_fd).unwrap();
        let mut red = SandboxProfile::derive(&action).args().to_vec();
        red.push("--".into());
        red.push(format!("/proc/self/fd/{script_fd}"));
        let rout = Command::new("bwrap").args(&red).output().unwrap();
        assert!(rout.status.success(), "bwrap: {}", String::from_utf8_lossy(&rout.stderr));
        assert_eq!(
            fs::read_to_string(&env.result).unwrap().trim(),
            "INTERP-V2",
            "RED: exec'ing the SCRIPT fd re-resolves the interpreter by PATH → the swapped \
             interpreter runs. Pinning the interpreter fd (the CORRECT path) defeats this."
        );
    }

    /// RUNTIME-1D-03 — fd-DISCIPLINE: `mark_cloexec_except_raw` run in `pre_exec`
    /// (exactly as `run_fd_pinned` wires it) marks every inherited fd `>= 3` CLOEXEC
    /// except the keep-list, so a non-CLOEXEC daemon fd is CLOSED at the child's
    /// `execve`.
    ///
    /// Tested by a DIRECT fork+exec of `/bin/sh`, exercising `mark_cloexec_except_raw`
    /// in `pre_exec` exactly as `run_fd_pinned` wires it — rather than through bwrap, a
    /// confound-prone proxy for the fd-close discipline. Testing the runtime's OWN
    /// primitive directly is the right design independent of bwrap's fd behaviour, and
    /// is what makes the discipline load-bearing: bwrap does NOT sanitise inherited fds
    /// (a non-CLOEXEC fd reaches the jailed command — verified via `/proc/self/fd`), so
    /// `close_range` in `pre_exec` is the PRIMARY defence, closing daemon fds at
    /// `execve(bwrap)` before bwrap's process or the jail can see them. The child
    /// probes its own fd table via `/proc/self/fd/N` (no shell `>&N` redirect quirks)
    /// and reports to a FILE: deterministic and parallelism-robust. No bwrap/root → it
    /// runs everywhere.
    #[test]
    fn fd_discipline_closes_a_daemon_fd_at_exec() {
        // Fork+exec /bin/sh with a non-CLOEXEC "daemon" fd open; the child tries to
        // write "LEAKED" to it. `close_range` selects whether the 1D-03 pre_exec
        // discipline runs. Returns the file's contents after the child exits.
        fn probe(close_range: bool) -> String {
            let dir = PathBuf::from(format!(
                "/tmp/delphi-fdleak-{}-{}",
                std::process::id(),
                u8::from(close_range)
            ));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            let ran_path = dir.join("ran");
            let leaked_path = dir.join("leaked");
            // The "daemon" fd: a non-CLOEXEC fd the child must NOT see after the
            // discipline runs. The child probes its OWN fd table via /proc/self/fd/N
            // (robust — no shell `>&N` redirect quirks) and reports to a FILE.
            let f = fs::File::open("/dev/null").unwrap();
            let leak = f.as_raw_fd();
            crate::fdsec::clear_cloexec(leak).unwrap();

            let mut cmd = Command::new("/bin/sh");
            // `echo RAN` proves the child exec'd; the `test -e /proc/self/fd/N` is true
            // iff the daemon fd is still OPEN in the exec'd child.
            cmd.arg("-c").arg(format!(
                "echo RAN > {}; if test -e /proc/self/fd/{leak}; then echo LEAKED > {}; fi",
                ran_path.display(),
                leaked_path.display()
            ));
            if close_range {
                let keep: Vec<RawFd> = Vec::new(); // exec by PATH → keep no fd
                // SAFETY: pre_exec runs post-fork/pre-execve; mark_cloexec_except_raw
                // is allocation-free + async-signal-safe, and from_raw_os_error wraps
                // the errno int inline (no Box) — the exact wiring run_fd_pinned uses.
                unsafe {
                    cmd.pre_exec(move || {
                        crate::fdsec::mark_cloexec_except_raw(&keep)
                            .map_err(|e| std::io::Error::from_raw_os_error(e as i32))
                    });
                }
            }
            let out = cmd.output().unwrap();
            assert!(out.status.success(), "/bin/sh: {}", String::from_utf8_lossy(&out.stderr));
            drop(f);
            // The child RAN regardless of the fd's state — so an absent LEAKED means
            // "fd closed", not "the child never ran".
            assert_eq!(
                fs::read_to_string(&ran_path).unwrap_or_default().trim(),
                "RAN",
                "the child exec'd"
            );
            let s = fs::read_to_string(&leaked_path).unwrap_or_default();
            let _ = fs::remove_dir_all(&dir);
            s
        }

        // RED: WITHOUT the fd-discipline, the non-CLOEXEC daemon fd survives execve →
        // the child writes to it.
        assert!(
            probe(false).contains("LEAKED"),
            "RED: without the close_range fd-discipline a non-CLOEXEC daemon fd survives execve \
             into the child — it wrote to it"
        );
        // CORRECT: the discipline marks it CLOEXEC → closed at execve → child can't write.
        assert!(
            !probe(true).contains("LEAKED"),
            "the fd-discipline (mark_cloexec_except_raw in pre_exec) closes the daemon fd at execve"
        );
    }
}
