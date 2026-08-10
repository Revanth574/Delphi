// SPDX-License-Identifier: MIT

//! A test shell that writes the SURFACE readiness marker.
//!
//! # Why a separate BINARY and not a `cfg` inside `delphi-minimal-shell` (D0A-R5-10)
//!
//! Codex asked for this in D0A-R1-03 and I substituted a `#[cfg(feature = …)]` seam inside the
//! minimal shell, which is cheaper and is DEFEATED BY PATH SHARING: both feature
//! configurations build to `debug/delphi-minimal-shell`, and `CARGO_BIN_EXE_…` resolves to a
//! PATH, not to a build. Any later `cargo clippy --all-targets` or `cargo test` without the
//! feature silently overwrites the surface-marker build with the scaffold one, and the next
//! root run launches a shell whose marker the daemon then refuses.
//!
//! A distinct target has a distinct path, so no non-feature build can clobber it — and
//! `required-features` means it does not exist at all in a production build.
//!
//! It claims SURFACE-LIVE while having no surface. That is a lie, deliberately, and confined
//! to a binary that cannot be built without the gate-bypass feature already enabled.

use std::os::fd::RawFd;

fn main() {
    let chan: RawFd = std::env::var(delphi_runtime::scaffold_env::CHANNEL_FD)
        .expect("DELPHI_CHANNEL_FD")
        .parse()
        .expect("channel fd");
    delphi_runtime::readiness::signal_ready(chan).expect("signal readiness");
    let password = std::env::var(delphi_runtime::scaffold_env::PASSWORD).unwrap_or_default();
    let _ = password;
    // Nothing else: this shell exists to satisfy the readiness contract at the strong level so
    // the daemon proceeds to the GATE, which is what the test measures.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
