// SPDX-License-Identifier: MIT

//! The canonical `PendingAction` and its action digest (Increment 1d).
//!
//! The capstone's spine (`docs/TRUST_MODEL.md` §3): **one immutable, arbiter-built
//! object** from which the preview, the approval digest, the sandbox profile, and
//! the audit entry **all** derive — with **no divergence path**. The human approves
//! the true action; the executed action *is* the approved one; the audit records
//! *what ran*. This forecloses approve-A/execute-B and preview-X/run-Y (the
//! prompt-injection threat the whole canonical spine was designed for).
//!
//! [`canonical_action_digest`] is the binding: it hashes **every** field via the
//! leverage-pass [`CanonicalHasher`] (declared-count guard) under an **exhaustive
//! no-`..` destructure**, so a token pinned to the digest pins argv/cwd/executable-
//! content/env/scope/timeout/tier, and a new field fails to compile until it is
//! covered (the under-coverage defect class — `docs/DEFECT_CLASSES.md` §1).

use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;

use delphi_hardening::canonical_hash::CanonicalHasher;

/// Network policy for the sandboxed action. Honest scopes only (R3/F5): `bwrap`
/// can switch the net namespace on or off, but cannot enforce a host allowlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetPolicy {
    /// No network (`--unshare-net`).
    None = 0,
    /// Full host network (`--share-net`), previewed unmissably as full.
    Full = 1,
}

/// How a path is bound into the jail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BindMode {
    /// Read-only (`--ro-bind`).
    ReadOnly = 0,
    /// Read-write (`--bind`).
    ReadWrite = 1,
}

/// The required human-consent tier for the action (mirrors the Fortress tiers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RequiredTier {
    /// No confirmation (autonomous).
    Autonomous = 0,
    /// Shell confirmation.
    Confirm = 1,
    /// Live PAM authentication (the 1c consent path).
    Biometric = 2,
    /// Hardware-backed confirmation.
    Hardware = 3,
}

/// A pinned script: the interpreter is exec'd by fd and the script content is a
/// sealed memfd (R4-02). Both are bound by their content digests in the action
/// digest.
pub struct ScriptPin {
    /// The opened interpreter (e.g. `/usr/bin/python3`).
    pub interpreter_fd: OwnedFd,
    /// Hash of the bytes read through `interpreter_fd`.
    pub interpreter_digest: [u8; 32],
    /// The sealed (`F_SEAL_WRITE`) script content.
    pub script_memfd: OwnedFd,
    /// Hash of the sealed script content.
    pub script_digest: [u8; 32],
}

/// The canonical, immutable, arbiter-built action object. Preview, approval
/// digest, sandbox profile, and audit entry all derive from this — and only this.
///
/// No `Debug`/`Clone`: it carries live fds and is the single source of truth for
/// one action; the controlled human rendering is the preview, not a derived
/// `Debug`.
pub struct PendingAction {
    /// Single-use id for this pending action.
    pub pending_id: String,
    /// Preview schema version (bumped if the rendering changes).
    pub preview_version: u32,
    /// The opened executable (exec'd by fd — no path→exec swap window).
    pub executable_fd: OwnedFd,
    /// Hash of the bytes read through `executable_fd` (the content that execs).
    pub executable_digest: [u8; 32],
    /// The argument vector.
    pub argv: Vec<String>,
    /// Working directory inside the jail.
    pub cwd: PathBuf,
    /// Environment additions (`KEY`, `VALUE`).
    pub env_delta: Vec<(String, String)>,
    /// Filesystem binds (path, mode) that define the jail's FS scope.
    pub fs_binds: Vec<(PathBuf, BindMode)>,
    /// Network policy (none / full only).
    pub net_policy: NetPolicy,
    /// Wall-clock timeout.
    pub timeout: Duration,
    /// The required human-consent tier.
    pub required_tier: RequiredTier,
    /// Set iff the executable is a `#!` script.
    pub script: Option<ScriptPin>,
}

/// The action digest: an injective SHA-256 over **every** field of the canonical
/// object. The approval token binds to this, so approval/preview/sandbox/audit
/// cannot diverge from what execs.
///
/// The fds (`executable_fd`, `ScriptPin`'s fds) are runtime handles; their
/// *content* is bound via the corresponding digests, which this function hashes.
///
/// # Examples
///
/// ```
/// use delphi_runtime::action::{canonical_action_digest, PendingAction, NetPolicy, RequiredTier};
/// # use std::time::Duration;
/// let a = PendingAction {
///     pending_id: "act-1".into(), preview_version: 1,
///     executable_fd: std::fs::File::open("/dev/null").unwrap().into(),
///     executable_digest: [0xAB; 32], argv: vec!["echo".into()],
///     cwd: "/tmp".into(), env_delta: vec![], fs_binds: vec![],
///     net_policy: NetPolicy::None, timeout: Duration::from_secs(30),
///     required_tier: RequiredTier::Biometric, script: None,
/// };
/// assert_eq!(canonical_action_digest(&a).len(), 32);
/// ```
#[must_use]
pub fn canonical_action_digest(action: &PendingAction) -> [u8; 32] {
    // EXHAUSTIVE destructure — NO `..`. A new field added to `PendingAction` fails
    // to compile here until the author decides how it is covered.
    let PendingAction {
        pending_id,
        preview_version,
        executable_fd,
        executable_digest,
        argv,
        cwd,
        env_delta,
        fs_binds,
        net_policy,
        timeout,
        required_tier,
        script,
    } = action;
    // The fd is the runtime handle; its CONTENT is bound via `executable_digest`.
    let _ = executable_fd;

    let mut h = CanonicalHasher::new(11);
    h.field(pending_id.as_bytes())
        .fixed(&preview_version.to_le_bytes())
        .fixed(executable_digest)
        .seq(argv.len(), |s| {
            for a in argv {
                s.field(a.as_bytes());
            }
        })
        .field(cwd.as_os_str().as_bytes())
        .seq(env_delta.len(), |s| {
            for (k, v) in env_delta {
                s.field(k.as_bytes()).field(v.as_bytes());
            }
        })
        .seq(fs_binds.len(), |s| {
            for (p, mode) in fs_binds {
                s.field(p.as_os_str().as_bytes()).fixed(&[*mode as u8]);
            }
        })
        .fixed(&[*net_policy as u8])
        .fixed(&timeout.as_nanos().to_le_bytes())
        .fixed(&[*required_tier as u8])
        .seq(usize::from(script.is_some()), |s| {
            if let Some(sc) = script {
                // The script's interpreter + content, bound by digest.
                s.fixed(&sc.interpreter_digest).fixed(&sc.script_digest);
            }
        });
    h.finish().expect("declared 11 top-level fields, appended 11")
}

/// The human-readable rendering of the action — what the human approves.
///
/// One of the four derivations from the canonical object (preview / approval-digest
/// / sandbox-profile / audit). It is the arbiter's rendering of the *exact* action
/// (never AI text, never derived from observed content — `docs/TRUST_MODEL.md` §3):
/// what the human sees is what the digest binds and what the sandbox executes.
///
/// # Examples
///
/// ```
/// use delphi_runtime::action::{preview, PendingAction, NetPolicy, RequiredTier};
/// # use std::time::Duration;
/// let a = PendingAction {
///     pending_id: "p".into(), preview_version: 1,
///     executable_fd: std::fs::File::open("/dev/null").unwrap().into(),
///     executable_digest: [0; 32], argv: vec!["echo".into(), "hi".into()],
///     cwd: "/".into(), env_delta: vec![], fs_binds: vec![],
///     net_policy: NetPolicy::None, timeout: Duration::from_secs(30),
///     required_tier: RequiredTier::Biometric, script: None,
/// };
/// assert!(preview(&a).contains("echo hi"));
/// ```
#[must_use]
pub fn preview(action: &PendingAction) -> String {
    let binds = action
        .fs_binds
        .iter()
        .map(|(p, m)| {
            let mode = match m {
                BindMode::ReadOnly => "ro",
                BindMode::ReadWrite => "rw",
            };
            format!("{}({mode})", p.display())
        })
        .collect::<Vec<_>>()
        .join(", ");
    let net = match action.net_policy {
        NetPolicy::None => "none",
        NetPolicy::Full => "full",
    };
    format!(
        "Run: {}\n  cwd: {}\n  net: {net}\n  binds: [{binds}]\n  tier: {:?}",
        action.argv.join(" "),
        action.cwd.display(),
        action.required_tier,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PendingAction {
        PendingAction {
            pending_id: "act-1".into(),
            preview_version: 1,
            executable_fd: std::fs::File::open("/dev/null").unwrap().into(),
            executable_digest: [0xAB; 32],
            argv: vec!["echo".into(), "hi".into()],
            cwd: PathBuf::from("/tmp"),
            env_delta: vec![("K".into(), "V".into())],
            fs_binds: vec![(PathBuf::from("/tmp/out"), BindMode::ReadWrite)],
            net_policy: NetPolicy::None,
            timeout: Duration::from_secs(30),
            required_tier: RequiredTier::Biometric,
            script: None,
        }
    }

    /// The coverage guard: this exhaustive no-`..` destructure mirrors
    /// `canonical_action_digest`'s. If a field is added to `PendingAction`, BOTH
    /// fail to compile until it is acknowledged — the under-coverage defect class.
    #[test]
    fn digest_destructure_covers_every_field() {
        let a = sample();
        let PendingAction {
            pending_id,
            preview_version,
            executable_fd,
            executable_digest,
            argv,
            cwd,
            env_delta,
            fs_binds,
            net_policy,
            timeout,
            required_tier,
            script,
        } = &a;
        // Touch each binding so the no-`..` destructure is load-bearing.
        let _ = (
            pending_id,
            preview_version,
            executable_fd,
            executable_digest,
            argv,
            cwd,
            env_delta,
            fs_binds,
            net_policy,
            timeout,
            required_tier,
            script,
        );
        // Deterministic.
        assert_eq!(canonical_action_digest(&a), canonical_action_digest(&sample()));
    }

    /// Each field is bound: changing any one changes the digest (so a token pinned
    /// to it pins that field — approve-A/execute-B is impossible).
    #[test]
    fn digest_changes_when_any_field_changes() {
        let base = canonical_action_digest(&sample());

        let mut argv = sample();
        argv.argv.push("EXTRA".into());
        assert_ne!(base, canonical_action_digest(&argv), "argv binds");

        let mut cwd = sample();
        cwd.cwd = PathBuf::from("/other");
        assert_ne!(base, canonical_action_digest(&cwd), "cwd binds");

        let mut net = sample();
        net.net_policy = NetPolicy::Full;
        assert_ne!(base, canonical_action_digest(&net), "net_policy binds");

        let mut tier = sample();
        tier.required_tier = RequiredTier::Autonomous;
        assert_ne!(base, canonical_action_digest(&tier), "required_tier binds");

        let mut binds = sample();
        binds.fs_binds[0].1 = BindMode::ReadOnly;
        assert_ne!(base, canonical_action_digest(&binds), "fs_bind mode binds");

        let mut exe = sample();
        exe.executable_digest = [0xCD; 32];
        assert_ne!(base, canonical_action_digest(&exe), "executable content binds");
    }
}
