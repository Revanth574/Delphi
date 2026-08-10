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
    // D0A-R5-11: THE SHELL MUST BE ABLE TO LEAVE. The first version slept forever here, and
    // the daemon's terminal contract — drop the channel, then wait for the shell — blocked on
    // a process that would never exit. That path has NO bound, so the daemon's own 120 s
    // accept deadline never came near it and the test's 150 s backstop was what fired.
    //
    // The contract the daemon relies on (B2A-R2-02): once the interaction is terminal the
    // daemon RELEASES its channel end, and a shell blocked on the consent read sees EOF and
    // dismisses. So block on that read and exit when it ends, exactly as the minimal shell
    // does — a `read` of 0 is the EOF the daemon just produced.
    let mut buf = [0u8; 64];
    loop {
        // SAFETY: `chan` is the inherited channel fd; the read is bounded by the buffer.
        let n = unsafe {
            nix::libc::read(chan, buf.as_mut_ptr().cast(), buf.len())
        };
        if n <= 0 {
            // EOF (0) or error: the daemon is done with us. Leave, so it can finish.
            break;
        }
    }
}
