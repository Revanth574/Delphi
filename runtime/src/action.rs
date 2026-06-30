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
use nix::errno::Errno;
use sha2::{Digest, Sha256};

use crate::RuntimeError;

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
    /// The shebang's single optional interpreter argument (e.g. `-I` in
    /// `#!/usr/bin/python3 -I`), as the kernel parses it: everything after the
    /// interpreter path, as ONE arg (`None` if absent). It is part of WHAT EXECUTES,
    /// so it is bound by the digest, rendered in the preview, and passed to the
    /// interpreter **before** the script — dropping it would run a different command
    /// than the human approved (B1-02, an approve-X/execute-Y at the flags level).
    pub interpreter_arg: Option<String>,
    /// The fully-sealed (immutable) script content memfd.
    pub script_memfd: OwnedFd,
    /// Hash of the sealed script content.
    pub script_digest: [u8; 32],
}

impl ScriptPin {
    /// The full immutability seal set required of a pinned script's content memfd
    /// (`docs/TRUST_MODEL.md` §3): `F_SEAL_WRITE` prevents content mutation,
    /// `F_SEAL_SHRINK` + `F_SEAL_GROW` prevent length mutation (a write-seal alone
    /// does NOT stop `ftruncate`), and `F_SEAL_SEAL` locks the seal set itself so it
    /// cannot be relaxed. The execute path re-validates exactly this set.
    pub(crate) const FULL_SEALS: i32 = nix::libc::F_SEAL_WRITE
        | nix::libc::F_SEAL_SHRINK
        | nix::libc::F_SEAL_GROW
        | nix::libc::F_SEAL_SEAL;

    /// Build a pinned script whose content memfd is FULLY sealed (immutable) and
    /// whose `script_digest` is the SHA-256 of exactly those sealed bytes.
    ///
    /// This is the sanctioned constructor (defense in depth, R4-02): it applies the
    /// full [`FULL_SEALS`](Self::FULL_SEALS) set at construction so the sealed bytes
    /// and `script_digest` cannot disagree, and the execute path re-validates the
    /// full set before any exec — content cannot mutate (write) and length cannot
    /// mutate (shrink/grow) between the digest and the exec.
    ///
    /// # Errors
    ///
    /// [`RuntimeError::Syscall`] if `memfd_create` / `write` / `fcntl` fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_runtime::action::ScriptPin;
    /// let interp = std::fs::File::open("/bin/sh").unwrap().into();
    /// let pin = ScriptPin::sealed(interp, [0u8; 32], None, b"#!/bin/sh\n:\n").unwrap();
    /// assert_eq!(pin.script_digest.len(), 32);
    /// ```
    pub fn sealed(
        interpreter_fd: OwnedFd,
        interpreter_digest: [u8; 32],
        interpreter_arg: Option<String>,
        script_content: &[u8],
    ) -> Result<Self, RuntimeError> {
        let script_memfd = seal_immutable_memfd(script_content)?;
        Ok(Self {
            interpreter_fd,
            interpreter_digest,
            interpreter_arg,
            script_memfd,
            script_digest: sha256(script_content),
        })
    }
}

/// Create a memfd holding `content` and seal it fully immutable
/// ([`ScriptPin::FULL_SEALS`]).
fn seal_immutable_memfd(content: &[u8]) -> Result<OwnedFd, RuntimeError> {
    use std::os::fd::FromRawFd;
    // SAFETY: memfd_create returns a fresh owned fd; we wrap it once (RAII closes it
    // on every error path), write the content, then apply the full seal set.
    unsafe {
        let fd = nix::libc::memfd_create(
            c"delphi-script".as_ptr(),
            (nix::libc::MFD_CLOEXEC | nix::libc::MFD_ALLOW_SEALING) as nix::libc::c_uint,
        );
        if fd < 0 {
            return Err(RuntimeError::Syscall { op: "memfd_create", source: Errno::last() });
        }
        let owned = OwnedFd::from_raw_fd(fd);
        let mut written = 0usize;
        while written < content.len() {
            let n = nix::libc::write(
                fd,
                content[written..].as_ptr().cast(),
                content.len() - written,
            );
            if n < 0 {
                return Err(RuntimeError::Syscall { op: "write script memfd", source: Errno::last() });
            }
            written += n as usize;
        }
        if nix::libc::fcntl(fd, nix::libc::F_ADD_SEALS, ScriptPin::FULL_SEALS) < 0 {
            return Err(RuntimeError::Syscall { op: "fcntl F_ADD_SEALS", source: Errno::last() });
        }
        Ok(owned)
    }
}

/// SHA-256 of `bytes` (the content-binding digest for a sealed script).
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
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
                // EXHAUSTIVE no-`..` destructure (mirrors the PendingAction guard): a
                // new ScriptPin field fails to compile here until it is bound.
                let ScriptPin {
                    interpreter_fd,
                    interpreter_digest,
                    interpreter_arg,
                    script_memfd,
                    script_digest,
                } = sc;
                // fds are runtime handles; their CONTENT is bound via the digests.
                let _ = (interpreter_fd, script_memfd);
                // The script's interpreter object + ITS arg + content, all bound. The
                // arg's OPTION PRESENCE is encoded explicitly (a presence byte, then the
                // value) so `None` and `Some("")` — which execute differently
                // (`interp script` vs `interp "" script`) — get DISTINCT digests
                // (B1-R2-02: `unwrap_or("")` would collapse them, breaking injectivity).
                s.fixed(interpreter_digest);
                match interpreter_arg {
                    None => s.fixed(&[0u8]),
                    Some(arg) => s.fixed(&[1u8]).field(arg.as_bytes()),
                };
                s.fixed(script_digest);
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
/// * **env values** are rendered as `KEY=[redacted]` — the key (structure) is shown,
///   the value is NOT. Env values are a classic secret location (API keys, tokens,
///   passwords), and the preview is handed to the UNTRUSTED requester (§3:
///   `{pending_id, preview}`). Plaintext would leak; an *unkeyed* value fingerprint
///   would be an offline dictionary oracle for low-entropy values (the attacker holds
///   the hash and enumerates guesses). The human's one-shot approval acts on WHICH
///   vars are set (an injected `LD_PRELOAD`/`API_KEY` is the high-signal threat), and
///   a human cannot verify a value fingerprint against intent anyway — so the value
///   is redacted, not fingerprinted. The digest still binds the full value, so the
///   approval covers the exact bytes that execute.
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
/// // env value is redacted (key shown, value not), timeout at full precision.
/// assert!(p.contains("echo hi") && p.contains("K=[redacted]") && !p.contains("K=V"));
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
        .map(|(k, _v)| format!("{k}=[redacted]"))
        .collect::<Vec<_>>()
        .join(", ");
    let net = match action.net_policy {
        NetPolicy::None => "none",
        NetPolicy::Full => "full",
    };
    let script = match &action.script {
        None => "none".to_string(),
        Some(sp) => format!(
            "interp:{} arg:{} content:{}",
            hex32(&sp.interpreter_digest),
            sp.interpreter_arg.as_deref().unwrap_or("(none)"),
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
                    interpreter_arg: None,
                    script_memfd: std::fs::File::open("/dev/null").unwrap().into(),
                    script_digest: [0x02; 32],
                });
            }),
            "script interpreter/content fingerprints rendered"
        );
    }

    /// RUNTIME-1D-04 (#2, round-3): the preview shows WHICH env vars are set but the
    /// value is `[redacted]` — neither plaintext (the round-2 finding) NOR a
    /// value-derived token. The latter is the subtle one: an UNKEYED fingerprint is
    /// an offline dictionary ORACLE for low-entropy values (the untrusted requester
    /// sees the preview, holds the hash, and enumerates guesses). Redaction carries
    /// no value-derived data, so it is unconditionally non-oracle.
    #[test]
    fn preview_redacts_env_values_no_oracle() {
        // A low-entropy, enumerable value — exactly the oracle threat.
        let mut a = sample();
        a.env_delta = vec![("DEPLOY".into(), "production".into())];
        let p = preview(&a);
        assert!(p.contains("DEPLOY"), "the human sees WHICH env var is set (structure)");
        assert!(!p.contains("production"), "the value plaintext must NOT appear");

        // NON-ORACLE (distinct from not-plaintext): the unkeyed SHA-256 prefix an
        // attacker would compute for the guess is ABSENT — the round-2 fingerprint
        // scheme rendered exactly this, making the preview a dictionary oracle.
        let unkeyed_guess = {
            let d = sha256(b"production");
            let mut s = String::with_capacity(16);
            for b in &d[..8] {
                use std::fmt::Write as _;
                let _ = write!(s, "{b:02x}");
            }
            s
        };
        assert!(
            !p.contains(&unkeyed_guess),
            "no value-derived fingerprint the untrusted requester could dictionary-match \
             (an unkeyed hash of a low-entropy value is an offline oracle)"
        );
    }

    /// B1-02: the shebang interpreter arg is BOUND by the digest and RENDERED in the
    /// preview — so what the human approves (preview + digest) includes the
    /// interpreter flags that affect what executes (isolating the arg: same
    /// interpreter/script digests, different arg → different action digest).
    #[test]
    fn shebang_interpreter_arg_is_bound_and_previewed() {
        let pin = |arg: Option<&str>| -> ScriptPin {
            ScriptPin {
                interpreter_fd: std::fs::File::open("/dev/null").unwrap().into(),
                interpreter_digest: [0x11; 32],
                interpreter_arg: arg.map(String::from),
                script_memfd: std::fs::File::open("/dev/null").unwrap().into(),
                script_digest: [0x22; 32],
            }
        };
        let digest = |arg: Option<&str>| {
            let mut a = sample();
            a.script = Some(pin(arg));
            canonical_action_digest(&a)
        };
        assert_ne!(digest(Some("-I")), digest(None), "the interpreter arg is bound by the digest");
        assert_ne!(digest(Some("-I")), digest(Some("-B")), "different args → different digest");
        // B1-R2-02 injectivity: None and Some("") execute differently (`interp script`
        // vs `interp "" script`), so their digests MUST differ (explicit presence byte).
        assert_ne!(digest(None), digest(Some("")), "None and Some(\"\") must NOT collide in the digest");

        let mut a = sample();
        a.script = Some(pin(Some("-I")));
        assert!(preview(&a).contains("arg:-I"), "the preview renders the interpreter arg");
    }
}
