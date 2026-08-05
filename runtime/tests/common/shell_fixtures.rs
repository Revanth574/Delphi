// SPDX-License-Identifier: MIT

//! Shell fixtures that satisfy the D0 readiness contract **by construction**.
//!
//! Included by the integration tests with
//! `#[path = "common/shell_fixtures.rs"] mod shell_fixtures;`. A `tests/` SUBDIRECTORY is not
//! auto-compiled as its own test target, so this is shared code, not a test binary.
//!
//! # Why this module exists — D0-R1-03
//!
//! D0 made every `LaunchSpec::shell_path` binary owe a readiness marker. The D0 change
//! updated the fixtures **in the files it happened to touch** and missed a fourth
//! (`b1_integration`'s `sleep 2` script), which then timed out on the root lane. That is
//! Class 17 — a defect propagated by copy — occurring inside a fix for Class 17. The
//! remedy is to stop having N independently-written fixtures at all.
//!
//! # What is and is NOT foreclosed here — stated precisely, because the earlier note
//! ("a doc table is weaker than a type") implied a stronger remedy exists than does
//!
//! **A type cannot verify that a binary writes a datagram.** No signature checks the
//! behaviour of an `execve`'d program, so "a silent shell fixture is unconstructible" is not
//! achievable in the type system and should not be claimed. What IS achieved:
//!
//! 1. **One construction site.** Both sleeper shapes are built here, from
//!    the SCAFFOLD marker (these sleepers have no surface — D0-A A1), so a change to the
//!    constant reaches every fixture. Previously two
//!    files generated their own and a third wrote none.
//! 2. **The obligation is named where a fixture is created.** These functions say
//!    `signalling_` in their names; reaching for one is how a test author learns the
//!    contract exists, without having to already know it.
//! 3. **Detection is already structural — from D0 itself.** A fixture that does not signal
//!    cannot pass: `launch()` refuses it after `DEFAULT_READY_TIMEOUT` and now kills and
//!    reaps it (D0-R1-04). The failure is loud, bounded and fail-closed — which is exactly
//!    how R1-03 was caught. The gap this module closes is therefore **duplication**, not
//!    detection.
//!
//! A hand-rolled fixture remains possible. It will fail loudly rather than silently, and
//! that is the honest limit of the foreclosure.

#![allow(dead_code)] // each test binary uses a subset; unused-in-one is not dead overall

use std::path::{Path, PathBuf};
use std::process::Command;

use delphi_runtime::launcher::SHELL_CHANNEL_FD;
use delphi_runtime::readiness::SCAFFOLD_READY_DATAGRAM as READY_DATAGRAM;

/// The readiness marker as C string-literal octal escapes (`\144\145...`).
///
/// Generated, never transcribed: `READY_DATAGRAM` contains a NUL, and octal escapes are the
/// only form that survives both a C literal and a `printf`-style writer unambiguously.
fn c_escaped_marker() -> String {
    READY_DATAGRAM.iter().map(|b| format!("\\{b:03o}")).collect()
}

/// Compile the `pause()` sleeper used as the shell under test by the B-1 / FD-01 / B-3
/// regression tests: it **signals readiness, then blocks forever**.
///
/// `pause()` is the load-bearing half — the shell must outlive the measurement. The
/// readiness write is what lets `launch()` return at all under D0; it perturbs none of the
/// measured properties (leader identity, inherited-fd containment, privilege drop).
///
/// Returns `None` with a precise diagnostic on stderr if the fixture cannot be built —
/// write failure, `cc` missing, or `cc` failing — so a SKIP names its actual cause instead
/// of blaming a toolchain that may be fine.
pub fn signalling_c_sleeper(dir: &Path) -> Option<PathBuf> {
    let src = dir.join("sleeper.c");
    let bin = dir.join("sleeper");
    let body = format!(
        "#include <unistd.h>\n\
         int main(void){{ write({SHELL_CHANNEL_FD}, \"{}\", {}); pause(); return 0; }}\n",
        c_escaped_marker(),
        READY_DATAGRAM.len()
    );
    if let Err(e) = std::fs::write(&src, body) {
        eprintln!("signalling_c_sleeper: cannot write {}: {e}", src.display());
        return None;
    }
    match Command::new("cc").args([src.to_str()?, "-o", bin.to_str()?]).output() {
        Ok(o) if o.status.success() => Some(bin),
        Ok(o) => {
            eprintln!(
                "signalling_c_sleeper: `cc` ran but exited {} — NOT a missing toolchain. \
                 stderr:\n{}\nstdout:\n{}",
                o.status,
                String::from_utf8_lossy(&o.stderr),
                String::from_utf8_lossy(&o.stdout),
            );
            None
        }
        Err(e) => {
            eprintln!(
                "signalling_c_sleeper: cannot SPAWN `cc`: {e} — PATH={:?}, cwd={:?}",
                std::env::var("PATH").unwrap_or_default(),
                std::env::current_dir(),
            );
            None
        }
    }
}

/// Write a `/bin/sh` sleeper that signals readiness and then sleeps `secs`.
///
/// # Why the marker comes from a FILE rather than a shell literal
///
/// `READY_DATAGRAM` contains a NUL, and a POSIX shell cannot carry a NUL in an argument or a
/// variable. The bytes are written to a sibling file and `cat`ed to the channel — one
/// `write(2)`, therefore one `SOCK_SEQPACKET` datagram.
///
/// # Why the redirection is tolerant of failure
///
/// The same script is frequently used as BOTH `shell_path` and `ai_path`. The AI child
/// deliberately never receives the channel (`fork_ai` runs the FD-01 sweep), so there fd 3 is
/// closed and the redirection fails with `EBADF`. `|| :` and `2>/dev/null` keep the AI
/// reaching its sleep exactly as before, and keep a spurious diagnostic out of test output.
///
/// # Panics
///
/// If the fixture files cannot be written or made executable — a broken harness, not a
/// product failure, and it must be loud.
pub fn signalling_sh_sleeper(dir: &Path, secs: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let marker = dir.join("ready.bin");
    std::fs::write(&marker, READY_DATAGRAM).expect("write readiness marker fixture");
    let script = dir.join("sleeper.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat {} >&{SHELL_CHANNEL_FD} 2>/dev/null || :\nsleep {secs}\n",
            marker.display()
        ),
    )
    .expect("write sh sleeper fixture");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("chmod sh sleeper fixture");
    script
}
