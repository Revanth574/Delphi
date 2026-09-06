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

/// Environment variable, set by the root-owned systemd unit, overriding the read ceiling.
///
/// Root-controlled deployment configuration, in the same place and by the same mechanism as
/// `DELPHI_AI_BIN` and `DELPHI_SHELL_VT` (D0A-R26-04). The daemon runs as root from a
/// root-owned unit file; nothing the AI or the user's session controls can reach this.
pub const MAX_EXECUTABLE_BYTES_ENV: &str = "DELPHI_MAX_EXECUTABLE_BYTES";

/// Peak resident content, as a multiple of the per-proposal budget — **a property of the code
/// in this module, not of any observed workload** (D0A-R27-01).
///
/// Derived by reading `canonicalize` + `build_script_pin`, for a script proposal of `S` bytes
/// naming an interpreter of `I` bytes:
///
/// | object | bytes | why it exists |
/// |---|---|---|
/// | `executable_fd` | `S` | `seal_executable_snapshot` of the script — RETAINED |
/// | `interpreter_fd` | `I` | `seal_executable_snapshot` of the interpreter — RETAINED |
/// | `script_memfd` | `S` | `ScriptPin::sealed` snapshots the script **a second time** — RETAINED |
/// | `bytes` | `S` | the read buffer, live until end of scope |
/// | `interp_bytes` | `I` | the interpreter read buffer, live until end of scope |
///
/// Retained `2S + I`; peak during construction `3S + 2I`. Under an AGGREGATE budget `B` where
/// `S + I <= B`, the worst case is `S = B, I = 0`, giving **peak = 3B**.
///
/// **D0A-R27-01 found this at 5x, not the 2x the previous derivation claimed.** That claim
/// rested on a parenthetical — "a script is small and its interpreter is the only large
/// object" — which **nothing enforced**: the ceiling was per-object, so a proposal could carry
/// a 512 MiB script AND a 512 MiB interpreter. A reviewer's probe canonicalized a 1 MiB script
/// referencing a 1 MiB interpreter and retained 3 MiB of sealed objects under a 1 MiB ceiling.
///
/// **CHANGING `canonicalize` CHANGES THIS NUMBER.** Removing the duplicate script snapshot
/// would take it to 2; adding another retained copy would take it to 4. It is derived from the
/// table above and must be re-derived when that table changes — it is not a tuning constant.
const PEAK_MULTIPLE_OF_BUDGET: u64 = 3;

/// Pre-consent memory the daemon may hold for one proposal.
///
/// **1/8 of the target deployment class's RAM floor.** Phase 3B/3C targets developer
/// workstations; taking 8 GiB as that floor gives 1 GiB. This is the number to attack — it is
/// a deployment assumption, and it is the only free choice in the derivation below.
const PRE_CONSENT_BUDGET_BYTES: u64 = 1024 * 1024 * 1024;

/// Default AGGREGATE byte budget for one proposal: everything `canonicalize` reads, summed.
///
/// **`budget / peak_multiplier`, COMPUTED, not written down** (D0A-R27-01). Both inputs are
/// stated above: [`PRE_CONSENT_BUDGET_BYTES`] is the deployment assumption,
/// [`PEAK_MULTIPLE_OF_BUDGET`] is read off this module's own allocation table. `1 GiB / 3 =
/// 357,913,941 bytes` (341.3 MiB).
///
/// It is an expression rather than a literal on purpose: a literal would let the derivation
/// and the value drift, and drift is what produced 64 MiB. **Change the allocation table and
/// the ceiling changes with it** — which is the property that makes the multiplier a fact
/// about `canonicalize` rather than a tuning knob. There is no rounding to a pretty number,
/// because a pretty number is a second, undocumented choice.
///
/// **AGGREGATE, not per object.** The previous ceiling applied to each read separately, so a
/// script proposal could spend it twice (once on the script, once on the interpreter). This
/// budget is consumed across every read in one proposal.
///
/// **THE LARGEST-KNOWN-BINARY CHECK IS A SANITY TEST ON THE RESULT, NOT PART OF THE
/// DERIVATION.** That distinction is the whole lesson of D0A-R26-04, where 64 MiB was chosen
/// *because* it exceeded the largest thing then observed — and was wrong on the machine it was
/// measured on. Applied to this result: the largest executables found on any searched path here
/// are 262 MiB, 246 MiB and 207 MiB, all of which fit with margin. **If they had not fit, the
/// correct response would be to revisit the BUDGET or the MULTIPLIER — not to raise the
/// ceiling to accommodate them.**
///
/// **Bounded scope, stated rather than implied:** this bounds ONE proposal. The pending store
/// has no cap, so a daemon that loops (B2; B1 services one action and exits) can accumulate
/// sealed memfds across proposals. Separate bound; not closed here.
pub const DEFAULT_MAX_EXECUTABLE_BYTES: u64 = PRE_CONSENT_BUDGET_BYTES / PEAK_MULTIPLE_OF_BUDGET;

/// The aggregate byte budget for one proposal, consumed across every read it performs.
///
/// Exists because a PER-OBJECT ceiling is not a bound on a proposal (D0A-R27-01): a script and
/// its interpreter are two reads, and the old ceiling admitted the full amount twice.
struct ReadBudget {
    remaining: u64,
}

impl ReadBudget {
    fn new(total: u64) -> Self {
        Self { remaining: total }
    }

    /// Deduct `n` bytes already read.
    ///
    /// INFALLIBLE ON PURPOSE. The enforcement happens at the read itself, whose ceiling IS
    /// `remaining` — so by the time this is called the bytes are known to fit, and a guard
    /// here could never fire. An unreachable error path is worse than none: it reads as a
    /// second check and is not one. There is exactly ONE enforcement site, in
    /// `read_bounded_inner`, and its messages name the aggregate so the mechanism is legible
    /// from the failure alone.
    fn spend(&mut self, n: u64) {
        self.remaining = self.remaining.saturating_sub(n);
    }
}

/// The active ceiling: [`MAX_EXECUTABLE_BYTES_ENV`] if set, else
/// [`DEFAULT_MAX_EXECUTABLE_BYTES`].
///
/// A malformed or zero value is an ERROR, not a silent fall back to the default — a
/// deployment that meant to tighten this must not be given a looser bound because it made a
/// typo (fail-closed, D0A-R26-04).
fn max_executable_bytes() -> Result<u64, RuntimeError> {
    ceiling_from_var(std::env::var(MAX_EXECUTABLE_BYTES_ENV))
}

/// The env-boundary decision as a PURE function of what `std::env::var` returned.
///
/// **D0A-R27-03 lived in the call `.ok()`, not in the parser** — `.ok()` maps BOTH
/// `NotPresent` and `NotUnicode` to `None`, so a non-UTF-8 configured value fell through to
/// the DEFAULT, which is looser than anything a deployment bothers to set. That is fail-OPEN,
/// in the function whose own doc promised fail-closed.
///
/// The reviewer's point was that testing [`parse_ceiling`] alone could never catch it, and
/// that was right: the collapse happened one level up, in code no test could reach without
/// mutating process-global env. So the decision moved DOWN into a function that takes the
/// `Result` itself. No `set_var`, no subprocess, and the `NotUnicode` branch is reachable.
fn ceiling_from_var(v: Result<String, std::env::VarError>) -> Result<u64, RuntimeError> {
    match v {
        Err(std::env::VarError::NotPresent) => parse_ceiling(None),
        Err(std::env::VarError::NotUnicode(raw)) => Err(RuntimeError::Protocol(format!(
            "{MAX_EXECUTABLE_BYTES_ENV} is set to a non-UTF-8 value ({raw:?}), which cannot be \
             a byte count. Refusing rather than falling back to the default (D0A-R27-03)"
        ))),
        Ok(raw) => parse_ceiling(Some(&raw)),
    }
}

/// The ceiling decision as a PURE function of the configured string.
///
/// Separated from the `std::env` read so it is testable without mutating process-global state:
/// `set_var` races every other test in the binary under the default parallel runner, and a
/// flaky test is worse than a failing one (CLAUDE.md §6). The env lookup is the trivial half;
/// this is the half with a decision in it.
fn parse_ceiling(configured: Option<&str>) -> Result<u64, RuntimeError> {
    match configured {
        None => Ok(DEFAULT_MAX_EXECUTABLE_BYTES),
        Some(raw) => match raw.trim().parse::<u64>() {
            Ok(n) if n > 0 => Ok(n),
            _ => Err(RuntimeError::Protocol(format!(
                "{MAX_EXECUTABLE_BYTES_ENV} is `{}`, which is not a positive byte count. \
                 Refusing rather than falling back to the {DEFAULT_MAX_EXECUTABLE_BYTES}-byte \
                 default, which could be LOOSER than the deployment intended (D0A-R26-04)",
                raw.escape_debug()
            ))),
        },
    }
}

/// How long the root daemon will wait for a proposed path to be opened and read
/// (D0A-R26-02).
///
/// Generous by design: a legitimate 512 MiB read from a cold local disk must not trip it, so
/// this is not a performance bound. It is the bound that keeps a stalled network filesystem
/// from wedging the daemon, and only a filesystem that has stopped answering reaches it.
const READ_DEADLINE: Duration = Duration::from_secs(30);

/// Run `f` on a disposable thread, giving up at `deadline`.
///
/// Factored out so the DECIDING mechanism is directly testable. A stalled FUSE/NFS mount
/// cannot be constructed in-process, so a test that only exercised the file path could never
/// reach the timeout branch — and an untimed-out timeout is decoration. Here a test supplies
/// a closure that simply sleeps, which is the same branch the stalled filesystem takes.
fn under_deadline<T, F>(deadline: Duration, f: F, on_timeout: &str) -> Result<T, RuntimeError>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, RuntimeError> + Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(deadline)
        .unwrap_or_else(|_| Err(RuntimeError::Protocol(on_timeout.to_string())))
}

/// [`read_bounded_inner`] under [`READ_DEADLINE`], on a disposable thread.
fn open_and_read_bounded(
    path: &str,
    what: &'static str,
    budget: &mut ReadBudget,
) -> Result<Vec<u8>, RuntimeError> {
    let ceiling = budget.remaining;
    let owned = path.to_string();
    let timeout_msg = format!(
        "{what}: `{}` did not open-and-read within {}s — a stalled filesystem (FUSE, NFS) \
         blocks in read even on a regular file, where O_NONBLOCK does not apply. Refused so \
         the root daemon is not wedged before any human gate (D0A-R26-02)",
        path.escape_debug(),
        READ_DEADLINE.as_secs()
    );
    let bytes = under_deadline(
        READ_DEADLINE,
        move || read_bounded_inner(&owned, what, ceiling),
        &timeout_msg,
    )?;
    budget.spend(bytes.len() as u64);
    Ok(bytes)
}

/// Open `path` and read it, bounded in both TYPE and SIZE, before anything is bound
/// (D0A-R25-02).
///
/// Unbounded `read_to_end` on an AI-selected path let a proposal stall or exhaust the ROOT
/// daemon **before** the pending action exists and therefore before any human gate:
///
/// * a **FIFO** blocks — and it blocks in `open(2)`, not in the read, which is why this
///   opens with `O_NONBLOCK` rather than only checking the type afterwards.
/// * a **character device** such as `/dev/zero` never ends.
/// * an oversized regular file exhausts memory.
/// * a **regular file on a stalled FUSE or NFS mount blocks in `read`**, and `O_NONBLOCK`
///   does NOT help there — Linux ignores it for regular files. D0A-R26-02: the previous
///   version of this comment noted the no-op as a benefit ("costs nothing in the legitimate
///   case") when it was the gap. Type and size bounds are not TIME bounds.
///
/// So the whole open-and-read runs on a **disposable worker thread** with a deadline. On
/// timeout the daemon abandons the thread and refuses the proposal. **The abandoned thread is
/// a real cost, stated rather than hidden:** it holds one fd and its buffer until the
/// filesystem responds, and nothing reaps it. That is accepted because the alternative is the
/// single-threaded ROOT daemon wedging before any human gate — a leaked thread degrades, a
/// wedged daemon stops. A deployment seeing these accumulate has a filesystem problem the
/// daemon is correctly surviving.
///
/// The type and size are taken from the HELD fd, never the path: the fd is the object that
/// gets hashed and exec'd, so checking anything else would reintroduce the swap window that
/// hashing-through-the-fd exists to close.
fn read_bounded_inner(
    path: &str,
    what: &'static str,
    ceiling: u64,
) -> Result<Vec<u8>, RuntimeError> {
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

    if meta.len() > ceiling {
        return Err(RuntimeError::Protocol(format!(
            "{what}: `{}` is {} bytes, over the {ceiling} bytes REMAINING of this proposal's \
             aggregate budget. The budget is spent across every read one proposal performs, \
             not reset per object — a script and its interpreter would otherwise each spend it \
             in full (D0A-R25-02, D0A-R26-04, D0A-R27-01). Total is set by \
             {MAX_EXECUTABLE_BYTES_ENV} or its default",
            path.escape_debug(),
            meta.len()
        )));
    }

    // Bounded read DESPITE the size check above: a regular file can grow between the `fstat`
    // and the read, so the ceiling has to hold at the read itself. `+ 1` so exceeding it is
    // observable rather than silently truncated into a digest over partial bytes.
    let mut bytes = Vec::with_capacity(meta.len() as usize);
    file.by_ref()
        .take(ceiling + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| RuntimeError::Filesystem {
            op: what,
            path: PathBuf::from(path),
            source,
        })?;
    if bytes.len() as u64 > ceiling {
        return Err(RuntimeError::Protocol(format!(
            "{what}: `{}` grew past the {ceiling} bytes remaining of this proposal's aggregate \
             budget while being read (D0A-R25-02, D0A-R27-01)",
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
    let mut budget = ReadBudget::new(max_executable_bytes()?);
    let bytes = open_and_read_bounded(&proposal.exe_path, "open proposed executable", &mut budget)?;
    // TRUST_MODEL v7 (D0A-R9-02): bind an IMMUTABLE SNAPSHOT, not the filesystem object.
    // Nothing after this line can be changed by whoever owns the path.
    let executable_fd = crate::action::seal_executable_snapshot(&bytes)?;
    let executable_digest = sha256(&bytes);

    // Shebang → pin the interpreter object + seal the script content (R3-04).
    let script = if bytes.starts_with(b"#!") {
        Some(build_script_pin(&bytes, &mut budget)?)
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
    // D0A-R27 (the argv/env asymmetry the round-26 prompt raised and round 26 left open).
    // `env_delta` has been NUL-validated at both doors since R18-03/R19-05; argv was checked
    // only for emptiness. The reviewer established the exec side FAILS CLOSED — `Command`
    // returns InvalidInput ("nul byte found in provided data") and never splits the argument —
    // so this is NOT the env-smuggling shape. What it changes is WHEN the refusal happens: an
    // action carrying a NUL is unexecutable, and without this check it is previewed,
    // consented to by a human, minted a token, and CONSUMES the one-shot approval before
    // failing to spawn. Refusing here means nobody authenticates for an action that cannot run.
    if let Some(bad) = proposal.argv.iter().find(|a| a.contains('\0')) {
        return Err(RuntimeError::Protocol(format!(
            "argv entry `{}` contains an embedded NUL, which execve cannot represent. Refused \
             at proposal time so it does not reach a human for consent and consume the \
             one-shot approval on an action that cannot spawn (D0A-R27)",
            bad.escape_debug()
        )));
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
fn build_script_pin(script_bytes: &[u8], budget: &mut ReadBudget) -> Result<ScriptPin, RuntimeError> {
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
    let interp_bytes = open_and_read_bounded(interp_path, "open script interpreter", budget)?;
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
            required_tier: pb::RequiredTier::TierConfirm as i32,
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

    /// D0A-R26-04 — a malformed ceiling is REFUSED, never silently replaced by the default.
    ///
    /// The direction matters: the default (512 MiB) is LOOSER than most deployments that
    /// bother to set this will want. Falling back on a typo would hand a deployment that meant
    /// to tighten the bound a wider one, silently — which is the fail-OPEN direction.
    #[test]
    fn a_malformed_ceiling_is_refused_rather_than_defaulted() {
        assert_eq!(
            parse_ceiling(None).expect("unset -> default"),
            DEFAULT_MAX_EXECUTABLE_BYTES
        );
        assert_eq!(parse_ceiling(Some(" 1048576 ")).expect("valid"), 1_048_576, "trimmed + parsed");
        for bad in ["0", "-1", "many", "", "64MiB", "1e9"] {
            match parse_ceiling(Some(bad)) {
                Err(RuntimeError::Protocol(m)) => assert!(
                    m.contains(MAX_EXECUTABLE_BYTES_ENV),
                    "refusal must name the variable so the operator can fix it: {m}"
                ),
                Err(other) => panic!("`{bad}` refused with the wrong variant: {other}"),
                Ok(n) => panic!("`{bad}` was accepted as a ceiling of {n} bytes"),
            }
        }
    }

    /// D0A-R27-01 — the SANITY CHECK on the derived ceiling. **Not part of the derivation.**
    ///
    /// The distinction is the whole lesson of D0A-R26-04, where 64 MiB was chosen *because* it
    /// cleared the largest binary then observed — and was wrong on the machine it was measured
    /// on. Here the ceiling comes from `budget / multiplier` and this test merely CHECKS the
    /// result against reality. **If it failed, the correct response would be to revisit the
    /// budget or the multiplier — never to raise the ceiling to accommodate a binary.**
    #[test]
    fn the_derived_ceiling_admits_the_largest_executables_known_on_this_class_of_machine() {
        assert_eq!(
            DEFAULT_MAX_EXECUTABLE_BYTES,
            PRE_CONSENT_BUDGET_BYTES / PEAK_MULTIPLE_OF_BUDGET,
            "the ceiling must remain the quotient, not a literal that drifted from it"
        );
        // Measured on this host (D0A-R26-04): the three executables that broke the 64 MiB
        // ceiling. Named as data, with their sizes, so a future reader can re-measure.
        for (name, bytes) in [
            ("claude", 275_012_592u64),
            ("codex", 258_638_944),
            ("claude-desktop", 217_799_896),
        ] {
            assert!(
                bytes < DEFAULT_MAX_EXECUTABLE_BYTES,
                "{name} ({bytes} bytes) exceeds the derived ceiling ({}) — revisit the BUDGET \
                 or the MULTIPLIER, do not raise the ceiling to fit it",
                DEFAULT_MAX_EXECUTABLE_BYTES
            );
        }
    }

    /// D0A-R27-01 — the budget is AGGREGATE across a proposal's reads, not per object.
    ///
    /// The defect: the ceiling applied to each read separately, so a script proposal spent it
    /// TWICE — once on the script, once on its interpreter — and the retained snapshots
    /// (`2S + I`, because `ScriptPin::sealed` copies the script a second time) blew the
    /// derived memory budget by 2.5x. A reviewer's probe canonicalized a 1 MiB script naming a
    /// 1 MiB interpreter under a 1 MiB ceiling and retained 3 MiB.
    ///
    /// Exercises `ReadBudget` + `open_and_read_bounded` directly, so the budget can be small
    /// enough to test without touching the 320 MiB default or process-global env.
    #[test]
    fn the_read_budget_is_spent_across_reads_not_reset_per_object() {
        let tmp = tempfile::Builder::new().prefix("delphi-r2701-").tempdir().unwrap();
        let a = write_exe(tmp.path(), "a", &vec![b'x'; 600]);
        let b = write_exe(tmp.path(), "b", &vec![b'y'; 600]);

        // POSITIVE CONTROL FIRST: 600 + 300 fits in 1000, so the budget is not simply refusing.
        let small = write_exe(tmp.path(), "small", &vec![b'z'; 300]);
        let mut ok_budget = ReadBudget::new(1000);
        assert!(open_and_read_bounded(a.to_str().unwrap(), "first", &mut ok_budget).is_ok());
        assert!(
            open_and_read_bounded(small.to_str().unwrap(), "second", &mut ok_budget).is_ok(),
            "600 + 300 must fit a 1000-byte budget, or this test proves only that reads fail"
        );

        // THE PROPERTY: each read fits alone; together they do not.
        let mut budget = ReadBudget::new(1000);
        assert!(
            open_and_read_bounded(a.to_str().unwrap(), "first", &mut budget).is_ok(),
            "600 alone must fit a 1000-byte budget"
        );
        match open_and_read_bounded(b.to_str().unwrap(), "second", &mut budget) {
            Err(RuntimeError::Protocol(m)) => assert!(
                m.contains("aggregate"),
                "refused, but not by the aggregate budget: {m}"
            ),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!(
                "a second 600-byte read succeeded against a 1000-byte budget already charged \
                 600 — the budget resets per object, which is D0A-R27-01"
            ),
        }
    }

    /// D0A-R27-03 — a non-UTF-8 configured ceiling is REFUSED, not silently defaulted.
    ///
    /// The bug was in the `.ok()` at the env boundary, which `parse_ceiling`'s test could not
    /// reach — so the decision moved into `ceiling_from_var`, which takes the `Result` and is
    /// therefore testable without `set_var` or a subprocess.
    #[test]
    fn a_non_utf8_configured_ceiling_is_refused_not_defaulted() {
        use std::env::VarError;
        use std::os::unix::ffi::OsStringExt;

        // NotPresent -> default. This is the branch that must KEEP working.
        assert_eq!(
            ceiling_from_var(Err(VarError::NotPresent)).expect("unset -> default"),
            DEFAULT_MAX_EXECUTABLE_BYTES
        );
        // A valid value is honoured.
        assert_eq!(ceiling_from_var(Ok("4096".into())).expect("valid"), 4096);
        // NotUnicode must NOT become the default.
        let bad = std::ffi::OsString::from_vec(vec![0xFF, 0xFE]);
        match ceiling_from_var(Err(VarError::NotUnicode(bad))) {
            Err(RuntimeError::Protocol(m)) => assert!(
                m.contains("non-UTF-8"),
                "refused, but not for the encoding: {m}"
            ),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(n) => panic!(
                "a non-UTF-8 ceiling silently became {n} bytes — `.ok()` collapsed NotUnicode \
                 into unset and fell through to the default (D0A-R27-03)"
            ),
        }
    }

    /// D0A-R26-02 — the read deadline fires, and the daemon survives the thing that would
    /// have wedged it.
    ///
    /// Exercises `under_deadline` directly with a sleeping closure, because a stalled FUSE/NFS
    /// mount cannot be built in-process — and the timeout branch is precisely what a
    /// file-based test could never reach. The closure is the same branch the stalled
    /// filesystem takes: work that does not return.
    ///
    /// The RESIDUAL, stated: this proves the deadline mechanism decides correctly. It does not
    /// prove that a real stalled mount reaches it rather than failing some earlier way. That
    /// is a property of the filesystem, not of this code.
    #[test]
    fn a_read_that_does_not_return_is_refused_by_the_deadline() {
        let started = std::time::Instant::now();
        let r: Result<Vec<u8>, RuntimeError> = under_deadline(
            Duration::from_millis(150),
            || {
                std::thread::sleep(Duration::from_secs(60));
                Ok(Vec::new())
            },
            "TIMEOUT-MARKER",
        );
        match r {
            Err(RuntimeError::Protocol(m)) => assert_eq!(m, "TIMEOUT-MARKER", "wrong refusal"),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!("a closure that never returns was allowed to succeed"),
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the deadline did not bound the wait — the daemon would be wedged"
        );
    }

    /// D0A-R26-02 — the positive control: the deadline does not refuse ordinary work.
    #[test]
    fn work_that_completes_within_the_deadline_is_not_refused() {
        let r = under_deadline(Duration::from_secs(5), || Ok(vec![1u8, 2, 3]), "unused");
        assert_eq!(r.expect("must succeed"), vec![1u8, 2, 3]);
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
        f.set_len(DEFAULT_MAX_EXECUTABLE_BYTES + 1).expect("sparse set_len");
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
                DEFAULT_MAX_EXECUTABLE_BYTES + 1
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

    /// D0A-R27 — an argv entry carrying a NUL is refused at proposal time.
    ///
    /// The asymmetry the round-26 prompt raised and round 26 did not answer: `env_delta` had
    /// been NUL-checked at both doors since R18-03/R19-05; argv was checked only for
    /// emptiness. The reviewer then established that the exec side FAILS CLOSED — `Command`
    /// returns `InvalidInput` and never splits the argument — so this is not the
    /// env-smuggling shape, and the fix is about WHEN, not WHETHER.
    ///
    /// Without it the action is previewed, a human authenticates, a token is minted, and the
    /// ONE-SHOT APPROVAL IS CONSUMED before the spawn fails. That is a human asked to consent
    /// to something that cannot run, and an approval burned on it.
    #[test]
    fn an_argv_entry_with_an_embedded_nul_is_refused_at_proposal_time() {
        let dir = tempdir();
        let exe = write_exe(dir.path(), "tool", b"\x7fELF binary-ish");
        let mut p = base_proposal(exe.to_str().unwrap());
        p.argv = vec!["tool".into(), "a\0b".into()];

        match canonicalize(&p, "act-nul".into()) {
            Err(RuntimeError::Protocol(m)) => assert!(
                m.contains("embedded NUL"),
                "refused, but not for the NUL: {m}"
            ),
            Err(other) => panic!("refused with the wrong variant: {other}"),
            Ok(_) => panic!(
                "an argv NUL canonicalized — it will reach a human for consent and burn the \
                 one-shot approval on an action Command cannot spawn (D0A-R27)"
            ),
        }
        // POSITIVE CONTROL: an ordinary argv is untouched.
        let mut ok = base_proposal(exe.to_str().unwrap());
        ok.argv = vec!["tool".into(), "--flag".into()];
        assert!(canonicalize(&ok, "act-ok".into()).is_ok(), "a normal argv must still pass");
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
