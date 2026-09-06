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
///
/// `Ord` is derived and MEANINGFUL: the discriminants ascend with the strength of the human
/// factor demanded, so `Autonomous < Confirm < Biometric < Hardware`. D0A-R25-01 relies on
/// that ordering to refuse a tier the daemon cannot enforce rather than silently satisfying
/// it with a weaker factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
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

/// `MFD_EXEC` — memfd_create(2)'s "this memfd may be exec'd" flag.
///
/// Defined here because this `libc` release does not export it; the value is the kernel's
/// own, from `/usr/include/linux/memfd.h:14` (`#define MFD_EXEC 0x0010U`). Without it a
/// memfd created while `vm.memfd_noexec` is 1 or 2 is non-executable, and the exec fails —
/// which is the fail-closed direction, but for a reason nobody would recognise.
const MFD_EXEC: nix::libc::c_uint = 0x0010;

/// The seal set an executable snapshot must carry (TRUST_MODEL v7, D0A-R9-02).
///
/// Beyond [`ScriptPin::FULL_SEALS`]: `F_SEAL_EXEC` (the exec bits cannot change) and
/// `F_SEAL_FUTURE_WRITE` (no new writable mapping, even from a fd opened before sealing).
/// The set is **verified after being applied** — `F_ADD_SEALS` reporting success is not the
/// same as the seals being present, and the whole property rests on them being present.
pub(crate) const EXEC_SEALS: i32 = nix::libc::F_SEAL_SEAL
    | nix::libc::F_SEAL_EXEC
    | nix::libc::F_SEAL_WRITE
    | nix::libc::F_SEAL_FUTURE_WRITE
    | nix::libc::F_SEAL_SHRINK
    | nix::libc::F_SEAL_GROW;

/// TRUST_MODEL v7 (D0A-R9-02): the immutable snapshot the action binds and the sandbox
/// executes — **not** the filesystem object it was copied from.
///
/// The inode pin this replaces fixed WHICH object ran and never fixed WHAT WAS IN IT: two
/// reproductions executed unapproved bytes through a correct, unmodified pin. Re-hashing
/// before `execve` does not close that — `fexecve` does not prevent same-inode modification.
/// Sealing does, and the kernel enforces it against the exact fd that is exec'd.
///
/// # Errors
///
/// [`RuntimeError::Syscall`] if `memfd_create` / `write` / `fcntl` fails, or if the seals
/// are not present after being added.
/// Public so an INTEGRATION test can build the shape production builds (D0A-R13-01): a
/// fixture that can construct an action production cannot is a fixture testing a shape
/// production never has.
pub fn seal_executable_snapshot(content: &[u8]) -> Result<OwnedFd, RuntimeError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    // SAFETY: memfd_create returns a fresh owned fd, wrapped once so RAII closes it on
    // every error path; the writes are bounded by `content.len()`.
    let owned = unsafe {
        let fd = nix::libc::memfd_create(
            c"delphi-exec".as_ptr(),
            nix::libc::MFD_CLOEXEC as nix::libc::c_uint
                | nix::libc::MFD_ALLOW_SEALING as nix::libc::c_uint
                | MFD_EXEC,
        );
        if fd < 0 {
            return Err(RuntimeError::Syscall { op: "memfd_create (executable snapshot)", source: Errno::last() });
        }
        let owned = OwnedFd::from_raw_fd(fd);
        let mut written = 0usize;
        while written < content.len() {
            let n = nix::libc::write(fd, content[written..].as_ptr().cast(), content.len() - written);
            if n < 0 {
                return Err(RuntimeError::Syscall { op: "write executable snapshot", source: Errno::last() });
            }
            written += n as usize;
        }
        owned
    };
    // SAFETY: fcntl on an fd this function owns; no caller memory is touched.
    unsafe {
        if nix::libc::fcntl(owned.as_raw_fd(), nix::libc::F_ADD_SEALS, EXEC_SEALS) < 0 {
            return Err(RuntimeError::Syscall { op: "fcntl F_ADD_SEALS (executable snapshot)", source: Errno::last() });
        }
        // VERIFIED, not assumed. A successful F_ADD_SEALS is not evidence the seals are
        // present, and every claim v7 makes rests on their presence.
        let seals = nix::libc::fcntl(owned.as_raw_fd(), nix::libc::F_GET_SEALS);
        if seals < 0 {
            return Err(RuntimeError::Syscall { op: "fcntl F_GET_SEALS (executable snapshot)", source: Errno::last() });
        }
        if seals & EXEC_SEALS != EXEC_SEALS {
            return Err(RuntimeError::Syscall { op: "executable snapshot is not fully sealed", source: Errno::EPERM });
        }
    }
    Ok(owned)
}

/// A sealed, NON-executable snapshot of `content`, rewound to offset 0.
///
/// D0A-R15-01. Same immutability as a script pin, but it is DATA that a reader consumes with
/// `read(2)` — bwrap's `--args` and `delphi-drop`'s environment blob — so the offset is part
/// of the contract; a snapshot left at EOF reads as empty and would silently carry nothing.
pub(crate) fn seal_data_snapshot(content: &[u8]) -> Result<OwnedFd, RuntimeError> {
    use std::os::fd::AsRawFd;
    let fd = seal_immutable_memfd(content)?;
    // SAFETY: lseek on an fd this function owns; seals forbid writes, not seeks.
    if unsafe { nix::libc::lseek(fd.as_raw_fd(), 0, nix::libc::SEEK_SET) } < 0 {
        return Err(RuntimeError::Syscall { op: "lseek (data snapshot)", source: Errno::last() });
    }
    Ok(fd)
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

/// Quote and escape one field so the rendering is INJECTIVE (D0A-R18-02).
///
/// The previous prose joined fields with `", "` and `" "`, which two DIFFERENT actions could
/// render identically — `[("PATH", "/safe, LD_PRELOAD=/tmp/evil.so")]` and
/// `[("PATH","/safe"), ("LD_PRELOAD","/tmp/evil.so")]` produced the same text while only the
/// second defines `LD_PRELOAD`. The digest told them apart; the human could not, which is
/// exactly the "preview = approval" property inverted. `escape_debug` escapes quotes,
/// backslashes and control characters, so no value can forge a delimiter.
///
/// **NAMED LIMIT (D0A-R19-03): this is MACHINE injectivity, not human
/// distinguishability.** Distinct strings always render distinctly, so the collision
/// R18-02 closed cannot recur. Two renderings a HUMAN reads as identical can still
/// differ — NFC/NFD normalisation forms, and homoglyphs across scripts. And `cwd` and
/// bind paths reach this through `to_string_lossy`, which is itself not injective on
/// non-UTF-8 bytes. The digest binds the true values in every case; the preview's
/// guarantee is that it cannot MERGE two actions, not that a reader cannot be fooled.
fn q(s: &str) -> String {
    format!("\"{}\"", s.escape_debug())
}

/// The arbiter's rendering of the canonical object — INJECTIVE, and complete.
///
/// **Environment values are shown in full (D0A-R18-05).** They used to be `[redacted]`
/// against a disclosure that does not occur: production sends the AI only `Pending {
/// pending_id }` (`service.rs`), and the preview goes to the PINNED SHELL over the private
/// channel. Redaction hid the fields that decide which code runs from the only party
/// entitled to see them. A rendering for an untrusted audience, if one is ever needed, is a
/// separate rendering — not a security allowlist doing double duty.
///
/// # Examples
///
/// ```
/// use delphi_runtime::action::{preview, PendingAction, NetPolicy, RequiredTier};
/// # use std::time::Duration;
/// let a = PendingAction {
///     pending_id: "p".into(), preview_version: 2,
///     executable_fd: std::fs::File::open("/dev/null").unwrap().into(),
///     executable_digest: [0; 32], argv: vec!["echo".into(), "hi".into()],
///     cwd: "/".into(), env_delta: vec![("K".into(), "V".into())],
///     fs_binds: vec![], net_policy: NetPolicy::None,
///     timeout: Duration::from_secs(30),
///     required_tier: RequiredTier::Biometric, script: None,
/// };
/// let p = preview(&a);
/// // Every field is quoted + indexed (D0A-R18-02) and the COMPLETE action is shown
/// // (D0A-R20-01) — §3 ratifies the renderer as a trusted audience.
/// assert!(p.contains(r#"env[0]: name="K" value="V""#));
/// assert!(p.contains(r#"argv[1]="hi""#));
/// ```
#[must_use]
pub fn preview(action: &PendingAction) -> String {
    let mut out = String::new();
    // D0A-R21-03: RENDER THE BOUND FIELD, never a literal. Hardcoding it meant the
    // redacted and complete-value formats both declared version 2 — one schema number for two
    // renderings — and it meant two actions differing ONLY in `preview_version` had different
    // digests and an identical preview, which is the injectivity break §3 claims cannot
    // happen. Version 3 is the complete-value rendering.
    out.push_str(&format!("preview_version={}\n", action.preview_version));
    for (i, a) in action.argv.iter().enumerate() {
        out.push_str(&format!("  argv[{i}]={}\n", q(a)));
    }
    out.push_str(&format!("  cwd={}\n", q(&action.cwd.to_string_lossy())));
    for (i, (k, v)) in action.env_delta.iter().enumerate() {
        // D0A-R20-01, ratified in §3: the renderer is untrusted as an ACTOR and trusted as
        // an AUDIENCE — it already receives the user's PAM password and the full argv, so
        // withholding other values protected nothing while BREAKING INJECTIVITY (measured:
        // DEPLOY=production and DEPLOY=staging rendered identically with differing digests).
        out.push_str(&format!("  env[{i}]: name={} value={}\n", q(k), q(v)));
    }
    out.push_str(&format!(
        "  net={}\n",
        match action.net_policy {
            NetPolicy::None => "none",
            NetPolicy::Full => "full",
        }
    ));
    for (i, (path, mode)) in action.fs_binds.iter().enumerate() {
        let m = match mode {
            BindMode::ReadOnly => "ro",
            BindMode::ReadWrite => "rw",
        };
        out.push_str(&format!("  bind[{i}]: mode={m} path={}\n", q(&path.to_string_lossy())));
    }
    out.push_str(&format!("  timeout={:?}\n", action.timeout));
    out.push_str(&format!("  tier={:?}\n", action.required_tier));
    out.push_str(&format!("  exe_digest={}\n", hex32(&action.executable_digest)));
    match &action.script {
        None => out.push_str("  script=none\n"),
        Some(sp) => {
            out.push_str(&format!("  script.interp_digest={}\n", hex32(&sp.interpreter_digest)));
            // D0A-R18-06: EVERY interpreter argument is marked, not only the ones that do not
            // start with `-`. `#!/usr/bin/env -S python3 -I` begins with a dash and GNU `env`
            // still splits it and resolves `python3` through PATH — so a leading-dash test
            // exempted the exact multi-argument form it needed to catch. The digest binds the
            // interpreter's BYTES and the argument STRING; it never binds what the argument
            // NAMES, and that is true of every argument.
            match sp.interpreter_arg.as_deref() {
                None => out.push_str("  script.interp_arg=(none)\n"),
                // D0A-R19-07: "NOT bound" was FALSE for an ordinary flag — `-I` IS bound, as
                // a string, and names no program at all. The statement now says what is true
                // of every argument: the string is bound, and any PROGRAM it names is not.
                // That covers `-S python3 -I` without asserting something false about `-I`.
                Some(a) => out.push_str(&format!(
                    "  script.interp_arg={} (the string is bound; any PROGRAM it names is \
resolved by the interpreter at run time and is NOT bound)\n",
                    q(a)
                )),
            }
            out.push_str(&format!("  script.content_digest={}\n", hex32(&sp.script_digest)));
        }
    }
    out
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

    /// D0A-R18-02 — THE RENDERING IS INJECTIVE. This is the collision the reviewer
    /// constructed: one entry whose VALUE contains the old delimiter, versus two entries.
    /// Under the previous `", "` join they rendered identically while only the second
    /// defines `LD_PRELOAD` — the digest told them apart and the human could not, which
    /// inverts the property the preview exists to provide.
    #[test]
    fn preview_cannot_render_two_different_actions_identically() {
        let mut smuggled = sample();
        smuggled.env_delta = vec![("PATH".into(), "/safe, LD_PRELOAD=/tmp/evil.so".into())];
        let mut genuine = sample();
        genuine.env_delta = vec![
            ("PATH".into(), "/safe".into()),
            ("LD_PRELOAD".into(), "/tmp/evil.so".into()),
        ];
        assert_ne!(
            preview(&smuggled),
            preview(&genuine),
            "two actions with DIFFERENT env_delta rendered identically — the human cannot \
             tell apart what the digest can"
        );
        let mut one = sample();
        one.argv = vec!["a b".into()];
        let mut two = sample();
        two.argv = vec!["a".into(), "b".into()];
        assert_ne!(preview(&one), preview(&two), "argv collision: one arg `a b` vs two args");
    }

    /// D0A-R21-03 — the preview renders the BOUND schema version, not a literal.
    ///
    /// Two actions differing only in `preview_version` have different digests. With the
    /// version hardcoded they had an IDENTICAL preview — the same injectivity break §3 says
    /// cannot occur, on the one field that describes the rendering itself.
    #[test]
    fn preview_renders_the_bound_schema_version() {
        let mut a = sample();
        a.preview_version = 3;
        let mut b = sample();
        b.preview_version = 4;
        assert_ne!(
            canonical_action_digest(&a),
            canonical_action_digest(&b),
            "precondition: preview_version must be digest-bound"
        );
        assert_ne!(
            preview(&a),
            preview(&b),
            "the rendering declared one version for two different actions — hardcoding it \
             made the schema number a constant rather than a rendered field (D0A-R21-03)"
        );
        assert!(preview(&a).contains("preview_version=3"), "the bound value is rendered");
    }

    /// D0A-R20-01 — TWO DIFFERENT NON-ALLOWLISTED VALUES CANNOT SHARE AN APPROVAL DISPLAY.
    /// This is the regression the finding required, and it is the exact pair that failed
    /// under redaction: same name, different value, differing digests, one preview. It is
    /// listed separately from the delimiter-collision test because the two break injectivity
    /// by different mechanisms — one by joining, one by withholding.
    #[test]
    fn preview_distinguishes_two_values_of_the_same_variable() {
        let mut prod = sample();
        prod.env_delta = vec![("DEPLOY".into(), "production".into())];
        let mut stage = sample();
        stage.env_delta = vec![("DEPLOY".into(), "staging".into())];

        assert_ne!(
            canonical_action_digest(&prod),
            canonical_action_digest(&stage),
            "precondition: these must be different ACTIONS, or the test proves nothing"
        );
        assert_ne!(
            preview(&prod),
            preview(&stage),
            "two different actions produced one approval display — the human approves \
             `production` while `staging` runs, and the digest cannot repair what was never \
             shown (D0A-R20-01)"
        );
    }

    /// D0A-R20-01 — the complete action is rendered. No value is withheld, because §3 now
    /// ratifies the renderer as a trusted AUDIENCE: it already holds the PAM password.
    #[test]
    fn preview_shows_every_env_value() {
        let mut a = sample();
        a.env_delta = vec![
            ("PATH".into(), "/tmp/evil/bin".into()),
            ("PYTHONPATH".into(), "/tmp/evil/mods".into()),
            ("API_TOKEN".into(), "s3cret-value".into()),
        ];
        let p = preview(&a);
        for v in ["/tmp/evil/bin", "/tmp/evil/mods", "s3cret-value"] {
            assert!(p.contains(v), "every value is shown to the approving human: {v}\n{p}");
        }
        assert!(
            !p.contains("[redacted]"),
            "nothing is withheld — an allowlist that hid PYTHONPATH while showing PATH was \
             both incoherent and injectivity-breaking:\n{p}"
        );
    }

    /// D0A-R18-06, as corrected by R19-07 and R20-06 — the marking is on WHAT THE ARGUMENT
    /// NAMES, not on the argument.
    ///
    /// The two cases are asserted separately because they differ semantically even though
    /// the rendering treats them alike: `-I` is a flag, is bound by the digest, and names no
    /// program; `-S python3 -I` is bound as a string and names `python3`, which `env`
    /// resolves through `PATH` at run time. An earlier version exempted leading-dash
    /// arguments, which excluded exactly the second form.
    #[test]
    fn preview_marks_what_an_interpreter_arg_names_not_the_arg() {
        let pin_with = |arg: Option<&str>| ScriptPin {
            interpreter_fd: std::fs::File::open("/dev/null").unwrap().into(),
            interpreter_digest: [0x11; 32],
            interpreter_arg: arg.map(str::to_string),
            script_memfd: std::fs::File::open("/dev/null").unwrap().into(),
            script_digest: [0x22; 32],
        };
        let render = |arg: Option<&str>| {
            let mut a = sample();
            a.script = Some(pin_with(arg));
            preview(&a)
        };

        // A BOUND FLAG. It is shown, and the qualification travels with it — the statement
        // "the string is bound; any program it names is not" is TRUE of a flag vacuously,
        // which is why the wording had to change rather than the coverage.
        let flag = render(Some("-I"));
        assert!(flag.contains(r#"script.interp_arg="-I""#), "the flag is shown:\n{flag}");
        assert!(flag.contains("the string is bound"), "the qualification travels:\n{flag}");

        // AN ARGUMENT NAMING AN UNBOUND PROGRAM — the form a leading-dash exemption missed.
        let names = render(Some("-S python3 -I"));
        assert!(names.contains("NOT bound"), "the named program is marked:\n{names}");

        // NO ARGUMENT: nothing is named, so nothing is marked.
        assert!(
            !render(None).contains("NOT bound"),
            "with no argument there is nothing to resolve; marking it would empty the mark"
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
        // The rendering changed shape in D0A-R18-02 (quoted + indexed); the PROPERTY this
        // line asserts is unchanged — the arg is visible to the human who approves.
        assert!(
            preview(&a).contains(r#"script.interp_arg="-I""#),
            "the preview renders the interpreter arg"
        );
    }
}
