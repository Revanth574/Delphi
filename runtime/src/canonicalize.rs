// SPDX-License-Identifier: MIT

//! Canonicalization — AI `Propose` → the ONE canonical `PendingAction` (Increment B1).
//!
//! `docs/TRUST_MODEL.md` §3: "the arbiter `open`s the executable **before** preview,
//! hashes the bytes read *through that fd*, and execs **that exact fd**." This is the
//! BUILT piece of B1 — new glue over proven parts:
//!
//! * **open + hash-through-the-held-fd** — the TOCTOU-safe difference from the test
//!   helper's read-bytes-separately: the bytes hashed into `executable_digest` are
//!   read through the very fd [`execute`](crate::execute) later exec's, so there is
//!   no path→exec swap window.
//! * **`#!` detect/parse** — the only other new logic.
//! * **reused-proven** — [`ScriptPin::sealed`](crate::action::ScriptPin::sealed)
//!   (round-3 full seal set), [`canonical_action_digest`](crate::action), and
//!   `execute`'s fd-exec are unchanged.
//!
//! The AI never sees this object or its fds; it gets only a `pending_id`.

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::action::{BindMode, NetPolicy, PendingAction, RequiredTier, ScriptPin};
use crate::wire::pb;
use crate::RuntimeError;

/// SHA-256 of `bytes`.
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Ceiling on bytes read from a proposed executable or script interpreter (D0A-R25-02).
///
/// DERIVED from what a legitimate action references, not chosen round. Measured across
/// `/usr/bin`, `/bin` and `/usr/libexec` on a full desktop install (1449 executables): the
/// largest is `x86_64-linux-gnu-lto-dump-15` at 34.5 MiB, 5 exceed 16 MiB, 1 exceeds 32 MiB,
/// and **0 exceed 64 MiB**. 64 MiB is the next power of two above the observed maximum — a
/// 1.85x margin over the largest real binary, and it admits every executable on the system.
/// A proposal above it is not a legitimate tool; it is the exhaustion case.
const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;

/// Open `path` and read it, bounded in both TYPE and SIZE, before anything is bound
/// (D0A-R25-02).
///
/// Unbounded `read_to_end` on an AI-selected path let a proposal stall or exhaust the ROOT
/// daemon **before** the pending action exists and therefore before any human gate:
///
/// * a **FIFO** blocks — and it blocks in `open(2)`, not in the read, which is why this
///   opens with `O_NONBLOCK` rather than only checking the type afterwards. On a regular
///   file the flag is a no-op, so it costs nothing in the legitimate case.
/// * a **character device** such as `/dev/zero` never ends.
/// * an oversized regular file exhausts memory.
///
/// The type and size are taken from the HELD fd, never the path: the fd is the object that
/// gets hashed and exec'd, so checking anything else would reintroduce the swap window that
/// hashing-through-the-fd exists to close.
fn open_and_read_bounded(path: &str, what: &'static str) -> Result<Vec<u8>, RuntimeError> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| RuntimeError::Filesystem {
            op: what,
            path: PathBuf::from(path),
            source,
        })?;

    let meta = file.metadata().map_err(|source| RuntimeError::Filesystem {
        op: "stat the opened object",
        path: PathBuf::from(path),
        source,
    })?;

    let ft = meta.file_type();
    if !ft.is_file() {
        let kind = if ft.is_fifo() {
            "a FIFO (would block the root daemon indefinitely)"
        } else if ft.is_char_device() {
            "a character device (an endless read, e.g. /dev/zero)"
        } else if ft.is_block_device() {
            "a block device"
        } else if ft.is_socket() {
            "a socket"
        } else if ft.is_dir() {
            "a directory"
        } else {
            "not a regular file"
        };
        return Err(RuntimeError::Protocol(format!(
            "{what}: `{}` is {kind} — only a regular file can be hashed and exec'd, and the \
             read happens BEFORE any human gate (D0A-R25-02)",
            path.escape_debug()
        )));
    }

    if meta.len() > MAX_EXECUTABLE_BYTES {
        return Err(RuntimeError::Protocol(format!(
            "{what}: `{}` is {} bytes, over the {MAX_EXECUTABLE_BYTES}-byte ceiling \
             (D0A-R25-02)",
            path.escape_debug(),
            meta.len()
        )));
    }

    // Bounded read DESPITE the size check above: a regular file can grow between the `fstat`
    // and the read, so the ceiling has to hold at the read itself. `+ 1` so exceeding it is
    // observable rather than silently truncated into a digest over partial bytes.
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.by_ref()
        .take(MAX_EXECUTABLE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| RuntimeError::Filesystem {
            op: what,
            path: PathBuf::from(path),
            source,
        })?;
    if bytes.len() as u64 > MAX_EXECUTABLE_BYTES {
        return Err(RuntimeError::Protocol(format!(
            "{what}: `{}` grew past the {MAX_EXECUTABLE_BYTES}-byte ceiling while being read \
             (D0A-R25-02)",
            path.escape_debug()
        )));
    }
    Ok(bytes)
}

/// Build the canonical [`PendingAction`] from an AI [`pb::Propose`], assigning
/// `pending_id`.
///
/// # Errors
///
/// [`RuntimeError::Filesystem`] if the proposed executable (or a script's
/// interpreter) cannot be opened/read; [`RuntimeError::Protocol`] for a malformed
/// shebang; [`RuntimeError::Syscall`] if sealing a script memfd fails.
pub fn canonicalize(
    proposal: &pb::Propose,
    pending_id: String,
) -> Result<PendingAction, RuntimeError> {
    // Open the executable, then hash the bytes READ THROUGH the held fd — the same
    // fd `execute` re-exec's, so the hash and the exec see the same kernel object.
    // Type- and size-bounded (D0A-R25-02): this runs in the root daemon before any gate.
    let bytes = open_and_read_bounded(&proposal.exe_path, "open proposed executable")?;
    // TRUST_MODEL v7 (D0A-R9-02): bind an IMMUTABLE SNAPSHOT, not the filesystem object.
    // Nothing after this line can be changed by whoever owns the path.
    let executable_fd = crate::action::seal_executable_snapshot(&bytes)?;
    let executable_digest = sha256(&bytes);

    // Shebang → pin the interpreter object + seal the script content (R3-04).
    let script = if bytes.starts_with(b"#!") {
        Some(build_script_pin(&bytes)?)
    } else {
        None
    };

    // VALIDATE untrusted wire enums (fail-CLOSED): prost's enum accessors silently
    // normalize an out-of-range i32 to the default (`required_tier` → the most
    // permissive AUTONOMOUS) — the opposite of fail-closed. Reject unknown instead.
    let net_policy = map_net(
        pb::NetPolicy::try_from(proposal.net_policy)
            .map_err(|_| RuntimeError::Protocol(format!("invalid net_policy {}", proposal.net_policy)))?,
    );
    let required_tier = map_tier(
        pb::RequiredTier::try_from(proposal.required_tier)
            .map_err(|_| RuntimeError::Protocol(format!("invalid required_tier {}", proposal.required_tier)))?,
    );
    // D0A-R25-03: refuse an empty argv HERE as well as at the execute choke point. `execve`
    // has no representation for it, so both transport shapes invent an argv0 — see the
    // matching check in `execute`. Rejecting at proposal time means the AI gets a Protocol
    // error naming the field instead of a pending action that can never be executed.
    if proposal.argv.is_empty() {
        return Err(RuntimeError::Protocol(
            "argv is empty — argv[0] would be synthesised at exec rather than approved \
             (D0A-R25-03)"
                .into(),
        ));
    }
    let fs_binds = proposal
        .fs_binds
        .iter()
        .map(|b| {
            let mode = pb::BindMode::try_from(b.mode)
                .map_err(|_| RuntimeError::Protocol(format!("invalid bind mode {}", b.mode)))?;
            Ok((PathBuf::from(&b.path), map_bind_mode(mode)))
        })
        .collect::<Result<Vec<_>, RuntimeError>>()?;

    Ok(PendingAction {
        pending_id,
        preview_version: 3,
        executable_fd,
        executable_digest,
        argv: proposal.argv.clone(),
        cwd: PathBuf::from(&proposal.cwd),
        env_delta: validate_env_delta(&proposal.env_delta)?,
        fs_binds,
        net_policy,
        timeout: Duration::from_secs(proposal.timeout_secs),
        required_tier,
        script,
    })
}


/// Reject environment entries `execve` cannot represent, BEFORE preview/digest/execution
/// (D0A-R18-03).
///
/// Protobuf strings may contain U+0000; a Unix environment name or value may not, and a name
/// may not contain `=`. The privileged transport serialises entries as `key=value\0` and
/// `delphi-drop` splits on NUL, so a value of `x\0PATH=/attacker/bin` PREVIEWS as one entry
/// and EXECUTES as two — the second invisible to the human who approved it. Validation lives
/// here because this is the one place every proposal passes before anything is bound.
///
/// # Errors
///
/// [`RuntimeError::Protocol`] naming the offending key.
fn validate_env_delta(entries: &[pb::EnvVar]) -> Result<Vec<(String, String)>, RuntimeError> {
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        if e.key.is_empty() {
            return Err(RuntimeError::Protocol("environment entry with an empty name".into()));
        }
        if e.key.contains('\0') || e.value.contains('\0') {
            return Err(RuntimeError::Protocol(format!(
                "environment entry `{}` contains an embedded NUL. execve cannot represent it, \
                 and on the privileged transport it would split into entries the preview never \
                 showed (D0A-R18-03).",
                e.key.escape_debug()
            )));
        }
        if e.key.contains('=') {
            return Err(RuntimeError::Protocol(format!(
                "environment name `{}` contains `=`, which makes the name/value boundary \
                 ambiguous (environ(7)).",
                e.key.escape_debug()
            )));
        }
        out.push((e.key.clone(), e.value.clone()));
    }
    Ok(out)
}

/// Parse the shebang, open + hash the interpreter through its fd, and seal the
/// script content (`ScriptPin::sealed` applies the full immutability seal set).
fn build_script_pin(script_bytes: &[u8]) -> Result<ScriptPin, RuntimeError> {
    let line_end = script_bytes.iter().position(|&b| b == b'\n').unwrap_or(script_bytes.len());
    // Kernel cap (BINPRM_BUF_SIZE): the interpreted `#!` line is bounded; a longer one
    // is malformed/hostile — reject before parsing.
    if line_end > 255 {
        return Err(RuntimeError::Protocol("shebang line exceeds the kernel length cap".into()));
    }
    let shebang = std::str::from_utf8(&script_bytes[2..line_end])
        .map_err(|_| RuntimeError::Protocol("non-UTF-8 shebang line".into()))?
        .trim();
    // Kernel semantics: interpreter = the first token; everything after the first
    // whitespace is ONE optional argument (e.g. `-I` in `#!/usr/bin/python3 -I`).
    let mut parts = shebang.splitn(2, char::is_whitespace);
    let interp_path = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| RuntimeError::Protocol("empty shebang interpreter".into()))?;
    let interpreter_arg = parts.next().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);

    // Same bounds as the executable (D0A-R25-02): the interpreter path comes from the
    // script's own shebang, which is AI-selected content, so it is the second door to the
    // same FIFO / endless-device / oversize stall in the root daemon.
    let interp_bytes = open_and_read_bounded(interp_path, "open script interpreter")?;
    // TRUST_MODEL v7 NAMED LIMIT 1: a nested shebang is REFUSED, here, before anything
    // executes. The kernel opens every interpreter in a chain BY PATH, recursively
    // (fs/binfmt_script.c), so pinning one interpreter leaves the rest unpinned; and
    // recursively snapshotting a chain fails SILENTLY at exec if it misses an element,
    // which is R9-02's own shape. Refusing fails closed, loudly, where a human can be told.
    if interp_bytes.starts_with(b"#!") {
        return Err(RuntimeError::Protocol(format!(
            "the script's interpreter `{interp_path}` is itself a `#!` script. The kernel \
             resolves each interpreter in the chain by PATH, so only the first can be \
             pinned — a nested chain is refused rather than partially bound \
             (TRUST_MODEL.md §3 v7, named limit 1)."
        )));
    }
    let interpreter_digest = sha256(&interp_bytes);
    // Snapshotted too: for a script it is the interpreter that actually executes.
    let interpreter_fd = crate::action::seal_executable_snapshot(&interp_bytes)?;

    ScriptPin::sealed(interpreter_fd, interpreter_digest, interpreter_arg, script_bytes)
}

fn map_bind_mode(m: pb::BindMode) -> BindMode {
    match m {
        pb::BindMode::BindReadOnly => BindMode::ReadOnly,
        pb::BindMode::BindReadWrite => BindMode::ReadWrite,
    }
}

fn map_net(n: pb::NetPolicy) -> NetPolicy {
    match n {
        pb::NetPolicy::NetNone => NetPolicy::None,
        pb::NetPolicy::NetFull => NetPolicy::Full,
    }
}

fn map_tier(t: pb::RequiredTier) -> RequiredTier {
    match t {
        pb::RequiredTier::TierAutonomous => RequiredTier::Autonomous,
        pb::RequiredTier::TierConfirm => RequiredTier::Confirm,
        pb::RequiredTier::TierBiometric => RequiredTier::Biometric,
        pb::RequiredTier::TierHardware => RequiredTier::Hardware,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::canonical_action_digest;
    use std::os::unix::fs::PermissionsExt;

    fn write_exe(dir: &std::path::Path, name: &str, content: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, content).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// D0A-R18-03 — an embedded NUL in a VALUE would smuggle a second environment entry
    /// past the preview. The privileged transport writes `key=value\0` and `delphi-drop`
    /// splits on NUL, so `API_TOKEN=x\0PATH=/attacker/bin` previews as ONE entry and
    /// executes as TWO — the second choosing which binary runs, and never shown to the
    /// human who approved it. Refused at canonicalization, before preview/digest/exec.
    #[test]
    fn an_embedded_nul_or_equals_in_the_environment_is_refused() {
        // D0A-R19-01: a PREDICTABLE /tmp path written with `fs::write`, in a test the lane
        // runs AS ROOT — pre-creating a symlink there truncates an arbitrary root-writable
        // target. RAII tempdir instead: unpredictable name, 0700, removed on drop including
        // the panic path.
        let tmp = tempfile::Builder::new()
            .prefix("delphi-r1803-")
            .tempdir()
            .expect("tempdir");
        let exe = tmp.path().join("exe");
        std::fs::write(&exe, b"#!/bin/sh\n:\n").unwrap();

        let with_env = |k: &str, v: &str| {
            let mut p = base_proposal(&exe.display().to_string());
            p.env_delta = vec![pb::EnvVar { key: k.into(), value: v.into() }];
            canonicalize(&p, "r1803".into())
        };

        // The smuggling shape itself.
        // `PendingAction` has no `Debug` (it holds fds), so match on the ERROR rather than
        // formatting the Result.
        match with_env("API_TOKEN", "x\0PATH=/attacker/bin") {
            Err(RuntimeError::Protocol(m)) => {
                assert!(m.contains("NUL"), "refused, but not for the NUL: {m}");
            }
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!("a NUL in a value was ACCEPTED — it would smuggle a second entry"),
        }
        // A NUL in the NAME is the same hazard from the other side.
        assert!(
            with_env("A\0B", "v").is_err(),
            "a NUL in a name must be refused"
        );
        // `=` in a name makes the boundary ambiguous (environ(7)).
        assert!(with_env("A=B", "v").is_err(), "`=` in a name must be refused");
        // An empty name is not representable.
        assert!(with_env("", "v").is_err(), "an empty name must be refused");
        // POSITIVE CONTROL — an ordinary entry still canonicalizes, or the refusals above
        // would be satisfied by everything failing.
        assert!(with_env("PATH", "/usr/bin").is_ok(), "an ordinary entry must still pass");

        // `tmp` drops here and removes the directory; no manual cleanup that a panic skips.
    }

    fn base_proposal(exe_path: &str) -> pb::Propose {
        pb::Propose {
            argv: vec!["tool".into()],
            cwd: "/".into(),
            env_delta: vec![],
            fs_binds: vec![],
            exe_path: exe_path.into(),
            net_policy: pb::NetPolicy::NetNone as i32,
            timeout_secs: 30,
            required_tier: pb::RequiredTier::TierBiometric as i32,
        }
    }

    /// Canonicalization hashes the bytes read THROUGH the opened fd — so
    /// `executable_digest` equals the on-disk content's SHA-256, and the digest is
    /// stable/derivable.
    #[test]
    fn canonicalize_binary_hashes_through_the_held_fd() {
        let dir = tempdir();
        let content = b"\x7fELF not-really but binary-ish";
        let exe = write_exe(dir.path(), "tool", content);
        let action = canonicalize(&base_proposal(exe.to_str().unwrap()), "act-1".into()).unwrap();

        assert_eq!(action.executable_digest, sha256(content), "digest = content hash through fd");
        assert_eq!(action.pending_id, "act-1");
        assert!(action.script.is_none(), "no shebang → binary, no ScriptPin");
        // The canonical digest is well-formed over the whole object.
        assert_eq!(canonical_action_digest(&action).len(), 32);
    }

    /// A `#!` proposal yields a ScriptPin (interpreter pinned + script sealed).
    #[test]
    fn canonicalize_script_builds_a_sealed_scriptpin() {
        let dir = tempdir();
        let script = b"#!/bin/sh\necho hi\n";
        let exe = write_exe(dir.path(), "tool.sh", script);
        let action = canonicalize(&base_proposal(exe.to_str().unwrap()), "act-2".into()).unwrap();

        let sp = action.script.as_ref().expect("shebang → ScriptPin");
        assert_eq!(sp.script_digest, sha256(script), "script content bound");
        // /bin/sh exists on the build host; its interpreter digest is non-zero.
        assert_ne!(sp.interpreter_digest, [0u8; 32]);
    }

    /// D0A-R25-02 — a FIFO proposed as the executable is refused PROMPTLY, not waited on.
    ///
    /// The property is "the root daemon does not block", so the test must be able to OBSERVE
    /// blocking: the call runs on a worker thread and the assertion is a `recv_timeout`. A
    /// plain `is_err()` could not distinguish a refusal from a hang, and the hang is the
    /// finding — `open(2)` on a FIFO with no writer blocks forever, before the pending action
    /// exists and therefore before any human gate.
    ///
    /// This is also why the fix opens with `O_NONBLOCK` rather than only checking the type
    /// after opening: the type check is unreachable if the open never returns.
    #[test]
    fn a_fifo_executable_is_refused_promptly_rather_than_blocking_the_daemon() {
        let tmp = tempfile::Builder::new().prefix("delphi-r2502-fifo-").tempdir().unwrap();
        let fifo = tmp.path().join("tool");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o644))
            .expect("mkfifo");

        let (tx, rx) = std::sync::mpsc::channel();
        let path = fifo.display().to_string();
        std::thread::spawn(move || {
            let refused = matches!(
                canonicalize(&base_proposal(&path), "r2502-fifo".into()),
                Err(RuntimeError::Protocol(ref m)) if m.contains("FIFO")
            );
            let _ = tx.send(refused);
        });

        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
            Ok(true) => {}
            Ok(false) => panic!("returned, but not with the FIFO refusal"),
            Err(_) => panic!(
                "canonicalize did not return within 5s on a FIFO — the ROOT daemon is blocked \
                 in open(2), before any human gate (D0A-R25-02)"
            ),
        }
    }

    /// D0A-R25-02 — a character device (`/dev/zero`) is refused on TYPE, before any read.
    ///
    /// NOTE ON ITS WEAKEN, recorded rather than performed: removing the type check and running
    /// this test would read `/dev/zero` without end and exhaust the machine's memory. That
    /// outcome IS the finding, so it is reasoned rather than executed — the FIFO leg above and
    /// the oversize leg below are the two that carry the executed weaken proof for this guard,
    /// and all three refusals come from the same `is_file()` / ceiling code path.
    #[test]
    fn a_character_device_executable_is_refused_on_type() {
        match canonicalize(&base_proposal("/dev/zero"), "r2502-chr".into()) {
            Err(RuntimeError::Protocol(m)) => assert!(
                m.contains("character device"),
                "refused, but not for the device type: {m}"
            ),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!(
                "/dev/zero canonicalized — an endless read in the root daemon (D0A-R25-02)"
            ),
        }
    }

    /// D0A-R25-02 — a regular file above `MAX_EXECUTABLE_BYTES` is refused on SIZE.
    ///
    /// Uses `set_len` for a SPARSE file: the metadata length exceeds the ceiling while no
    /// blocks are allocated, so the rejection is exercised without writing 64 MiB to disk.
    /// That is legitimate here because the guard reads `metadata().len()`, which is exactly
    /// what a sparse file sets.
    #[test]
    fn an_oversized_executable_is_refused_on_size() {
        let tmp = tempfile::Builder::new().prefix("delphi-r2502-big-").tempdir().unwrap();
        let big = tmp.path().join("tool");
        let f = std::fs::File::create(&big).unwrap();
        f.set_len(MAX_EXECUTABLE_BYTES + 1).expect("sparse set_len");
        drop(f);

        match canonicalize(&base_proposal(&big.display().to_string()), "r2502-big".into()) {
            // NAMES WHICH GUARD FIRED. `contains("ceiling")` was the first draft and it
            // PASSED under the weaken that removes this guard, because the bounded `take`
            // below catches the same file with a message that also says "ceiling" — a
            // PASS/PASS, worthless (Iron Law #15 clause 2). The two are deliberately
            // redundant in the product and must therefore be distinguishable in the test.
            Err(RuntimeError::Protocol(m)) => assert!(
                m.contains("bytes, over the"),
                "refused, but not by the fstat size check — this is the message the BOUNDED \
                 READ produces, so the fstat ceiling may be gone: {m}"
            ),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!(
                "a {} byte executable canonicalized — over the ceiling (D0A-R25-02)",
                MAX_EXECUTABLE_BYTES + 1
            ),
        }
    }

    /// D0A-R25-02 — the ceiling admits every real executable it was derived from.
    ///
    /// The positive control for the two refusals above: a guard that rejected everything
    /// would pass them both. `coreutils` (11.4 MiB) is the largest binary this system's own
    /// sandbox actually runs, and it canonicalizes.
    #[test]
    fn a_real_large_executable_is_still_accepted() {
        let path = "/usr/bin/coreutils";
        if !std::path::Path::new(path).exists() {
            eprintln!("SKIP a_real_large_executable_is_still_accepted: {path} not present");
            return;
        }
        let len = std::fs::metadata(path).unwrap().len();
        assert!(len > 8 * 1024 * 1024, "control is only meaningful if the binary is large: {len}");
        assert!(
            canonicalize(&base_proposal(path), "r2502-ok".into()).is_ok(),
            "a {len}-byte real executable was refused — the ceiling is too low (D0A-R25-02)"
        );
    }

    /// D0A-R25-03 — an empty argv is refused at proposal time.
    ///
    /// The pair to `a_directly_built_action_with_an_empty_argv_is_refused_at_execute`: this
    /// leg closes the door the AI can reach, that one closes the door a direct builder can.
    /// Neither substitutes for the other (R19-05).
    #[test]
    fn an_empty_argv_is_refused_during_canonicalization() {
        let dir = tempdir();
        let exe = write_exe(dir.path(), "tool", b"\x7fELF binary-ish");
        let mut proposal = base_proposal(exe.to_str().unwrap());
        proposal.argv = vec![];

        match canonicalize(&proposal, "act-argv0".into()) {
            Err(RuntimeError::Protocol(m)) => {
                assert!(m.contains("argv is empty"), "refused, but not for argv: {m}");
            }
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!(
                "an empty argv canonicalized — the resulting action names an argv0 that only \
                 the transport can invent (D0A-R25-03)"
            ),
        }
    }

    /// A missing executable surfaces a typed, actionable error (not a panic).
    #[test]
    fn missing_executable_is_a_typed_error() {
        // `PendingAction` has no `Debug` (live fds), so match the Result rather than
        // `unwrap_err` (which would need the Ok value to be Debug).
        let result = canonicalize(&base_proposal("/no/such/binary"), "act-3".into());
        assert!(matches!(result, Err(RuntimeError::Filesystem { .. })), "missing exe → typed error");
    }

    /// B1-02: the shebang's optional interpreter arg is parsed + stored (kernel
    /// semantics — the first token is the interpreter, the rest is ONE arg).
    #[test]
    fn canonicalize_parses_the_shebang_interpreter_arg() {
        let dir = tempdir();
        let exe = write_exe(dir.path(), "iso.py", b"#!/usr/bin/python3 -I\nprint(1)\n");
        let action = canonicalize(&base_proposal(exe.to_str().unwrap()), "act-arg".into()).unwrap();
        let sp = action.script.as_ref().expect("shebang → ScriptPin");
        assert_eq!(sp.interpreter_arg.as_deref(), Some("-I"), "the interpreter arg is bound, not dropped");

        // No arg → None.
        let plain = write_exe(dir.path(), "plain.sh", b"#!/bin/sh\n:\n");
        let a2 = canonicalize(&base_proposal(plain.to_str().unwrap()), "act-na".into()).unwrap();
        assert_eq!(a2.script.as_ref().unwrap().interpreter_arg, None);
    }

    /// B1-03: an out-of-range wire enum is REJECTED (fail-closed), not normalized to
    /// the default (required_tier → AUTONOMOUS, the most permissive).
    #[test]
    fn out_of_range_wire_enum_is_rejected() {
        let dir = tempdir();
        let exe = write_exe(dir.path(), "tool", b"binary");
        let mut p = base_proposal(exe.to_str().unwrap());
        p.required_tier = 99; // not a valid RequiredTier
        assert!(
            matches!(canonicalize(&p, "x".into()), Err(RuntimeError::Protocol(_))),
            "RED: an out-of-range required_tier must be rejected, not normalized to AUTONOMOUS"
        );
        let mut p2 = base_proposal(exe.to_str().unwrap());
        p2.net_policy = 42;
        assert!(matches!(canonicalize(&p2, "y".into()), Err(RuntimeError::Protocol(_))), "invalid net_policy rejected");
    }

    /// A temp dir that removes itself on drop — including when a test panics.
    ///
    /// The previous version built `/tmp/delphi-canon-<pid>` by hand and **never removed it**,
    /// on any path. It was the only site in this crate with no cleanup at all, and it is the
    /// source of the `delphi-canon-*` accumulation on `/tmp` (8 present when this was fixed).
    /// Callers bind the returned `TempDir`, so the directory lives exactly as long as the
    /// test does.
    fn tempdir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("delphi-canon-")
            .tempdir()
            .expect("tempdir")
    }
}
