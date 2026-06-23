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
use sha2::{Digest, Sha256};

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

/// Lowercase hex of a 32-byte digest (a content fingerprint for the preview).
fn hex32(d: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in d {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A short, non-reversible fingerprint of an env value (first 8 bytes of its
/// SHA-256, hex). The preview shows WHICH env vars are set and whether a value
/// changed — without exposing the value itself. Env values are a classic secret
/// location (API keys, tokens, passwords), so the preview renders their presence
/// and identity, never their plaintext; the digest still binds the full value.
fn value_fingerprint(v: &str) -> String {
    use std::fmt::Write as _;
    let mut h = Sha256::new();
    h.update(v.as_bytes());
    let d: [u8; 32] = h.finalize().into();
    let mut s = String::with_capacity(16);
    for b in &d[..8] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The human-readable rendering of the action — what the human approves.
///
/// One of the four derivations from the canonical object (preview / approval-digest
/// / sandbox-profile / audit). It is the arbiter's rendering (never AI text, never
/// derived from observed content — `docs/TRUST_MODEL.md` §3): what the human sees is
/// what the digest binds and what the sandbox executes.
///
/// It renders **every behaviour-affecting field** — argv, cwd, env-delta, fs-binds,
/// net policy, timeout, tier, the executable content fingerprint, and (for scripts)
/// the interpreter + script content fingerprints — so the prompt-injection defence
/// holds: the human can inspect everything that affects what runs, and any change to
/// a behaviour-affecting field changes the preview.
///
/// Two renderings are deliberate, so "render everything" does not become "leak
/// secrets" or "round away precision":
/// * **env values** are shown as `KEY=#<fingerprint>` (key + a non-reversible
///   SHA-256 prefix), never plaintext — env values are a classic secret location
///   (API keys, tokens, passwords). The human sees WHICH vars are set and whether a
///   value changed, without the secret being displayed; the digest still binds the
///   full value.
/// * **timeout** is rendered via `Duration`'s `Debug` (e.g. `30s`, `30.9s`), which
///   carries the same nanosecond precision the digest binds (`timeout.as_nanos()`),
///   so a sub-second change is visible — not rounded to whole seconds.
///
/// The only fields NOT rendered are `pending_id` (a single-use id) and
/// `preview_version` (the rendering's own schema version) — metadata that does not
/// affect what executes; both are still bound by the digest.
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
///     cwd: "/".into(), env_delta: vec![("K".into(), "V".into())],
///     fs_binds: vec![], net_policy: NetPolicy::None, timeout: Duration::from_secs(30),
///     required_tier: RequiredTier::Biometric, script: None,
/// };
/// let p = preview(&a);
/// // env value is fingerprinted (key shown, value not), timeout at full precision.
/// assert!(p.contains("echo hi") && p.contains("K=#") && !p.contains("K=V"));
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
    let env = action
        .env_delta
        .iter()
        .map(|(k, v)| format!("{k}=#{}", value_fingerprint(v)))
        .collect::<Vec<_>>()
        .join(", ");
    let net = match action.net_policy {
        NetPolicy::None => "none",
        NetPolicy::Full => "full",
    };
    let script = match &action.script {
        None => "none".to_string(),
        Some(sp) => format!(
            "interp:{} content:{}",
            hex32(&sp.interpreter_digest),
            hex32(&sp.script_digest)
        ),
    };
    format!(
        "Run: {}\n  cwd: {}\n  env: [{env}]\n  net: {net}\n  binds: [{binds}]\n  \
         timeout: {:?}\n  tier: {:?}\n  exe: {}\n  script: {script}",
        action.argv.join(" "),
        action.cwd.display(),
        action.timeout,
        action.required_tier,
        hex32(&action.executable_digest),
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

    /// RUNTIME-1D-04: the preview renders EVERY behaviour-affecting field — changing
    /// any one changes the rendered preview (so the human inspects what execs).
    #[test]
    fn preview_renders_every_behavior_affecting_field() {
        let base = preview(&sample());
        let with = |f: &dyn Fn(&mut PendingAction)| {
            let mut a = sample();
            f(&mut a);
            preview(&a)
        };
        assert_ne!(base, with(&|a| a.argv.push("EXTRA".into())), "argv rendered");
        assert_ne!(base, with(&|a| a.cwd = PathBuf::from("/other")), "cwd rendered");
        assert_ne!(base, with(&|a| a.env_delta.push(("X".into(), "Y".into()))), "env_delta rendered");
        assert_ne!(
            base,
            with(&|a| a.fs_binds.push((PathBuf::from("/extra"), BindMode::ReadWrite))),
            "fs_binds rendered"
        );
        assert_ne!(base, with(&|a| a.net_policy = NetPolicy::Full), "net_policy rendered");
        // SUB-SECOND change (30.0s → 30.9s): the digest binds `as_nanos()`, so the
        // preview must too — `as_secs()` would round both to "30s" and miss this.
        assert_ne!(
            base,
            with(&|a| a.timeout = Duration::from_millis(30_900)),
            "timeout rendered at the digest's (nanosecond) granularity, not whole seconds"
        );
        assert_ne!(base, with(&|a| a.required_tier = RequiredTier::Autonomous), "tier rendered");
        assert_ne!(base, with(&|a| a.executable_digest = [0xCD; 32]), "executable fingerprint rendered");
        assert_ne!(
            base,
            with(&|a| {
                a.script = Some(ScriptPin {
                    interpreter_fd: std::fs::File::open("/dev/null").unwrap().into(),
                    interpreter_digest: [0x01; 32],
                    script_memfd: std::fs::File::open("/dev/null").unwrap().into(),
                    script_digest: [0x02; 32],
                });
            }),
            "script interpreter/content fingerprints rendered"
        );
    }

    /// RUNTIME-1D-04 (#4): the preview shows WHICH env vars are set and reflects a
    /// value change (via a non-reversible fingerprint), but NEVER the plaintext
    /// value — "render everything" must not become "leak secrets".
    #[test]
    fn preview_fingerprints_env_values_without_exposing_them() {
        // A secret-shaped value must not appear in the preview.
        let mut a = sample();
        a.env_delta = vec![("API_KEY".into(), "sk-live-SUPERSECRET-9z".into())];
        let p = preview(&a);
        assert!(p.contains("API_KEY"), "the human sees WHICH env var is set");
        assert!(
            !p.contains("sk-live-SUPERSECRET-9z"),
            "the secret VALUE must NOT appear in the preview — only key + fingerprint"
        );

        // A value change changes the preview (so the value's influence IS rendered),
        // without either plaintext leaking.
        let mut a1 = sample();
        a1.env_delta = vec![("K".into(), "value-one".into())];
        let mut a2 = sample();
        a2.env_delta = vec![("K".into(), "value-two".into())];
        assert_ne!(preview(&a1), preview(&a2), "an env value change changes the preview");
        assert!(
            !preview(&a1).contains("value-one") && !preview(&a2).contains("value-two"),
            "neither raw value appears in its preview"
        );
    }
}
