// SPDX-License-Identifier: MIT

//! **A DELIBERATE TOPOLOGY DEFECT** — the AI, in a process group that is not the daemon's.
//!
//! # Why this fixture exists (D0A-R35, the negative control the three greens leave owed)
//!
//! The assembly test's positive control has returned `Reached` three times. `Topology`, `Scan`
//! and `Unresolved` have been produced only against constructed records in a unit test, never
//! in the environment they exist to discriminate. Three confirmations and zero discriminations
//! is `DEFECT_CLASSES` 49's silence: a region that stops producing findings is either exhausted
//! or unexamined, and the absence of findings cannot tell you which.
//!
//! **Producing `Topology` from a synthetic record proves the classifier's arithmetic. It does
//! not prove the control detects a topology defect it would otherwise pass.** Only a real
//! daemon whose child sits outside its group can do that, so this is that daemon's AI.
//!
//! It calls `setpgid(0, 0)` — becoming its own group leader — and then `exec`s the real
//! stubborn AI. Because `exec` replaces the image in the SAME process, `ppid` still points at
//! the daemon: the resulting child is **verified as the daemon's own** and **outside its
//! group**, which is exactly the input `ControlVerdict::Topology` names.
//!
//! Neither `launcher.rs` nor `execute.rs` calls `setsid`/`setpgid`; that is the reasoning the
//! supplementary scan rests on, and this fixture is what tests it rather than restating it.

use std::os::unix::process::CommandExt as _;

fn main() {
    let real = std::env::var("DELPHI_DETACHED_AI_REAL")
        .expect("DELPHI_DETACHED_AI_REAL must name the real AI binary to exec");

    // SAFETY: `setpgid(0, 0)` moves the calling process into a new group of its own. It affects
    // this process only, takes no pointers, and is async-signal-safe. Failure is reported rather
    // than ignored: a fixture that silently does not detach would be observed as `Reached` and
    // read as the control working, which is the false-green this exists to prevent.
    let rc = unsafe { nix::libc::setpgid(0, 0) };
    assert_eq!(
        rc,
        0,
        "setpgid(0,0) failed ({}) — this fixture did NOT detach, so any verdict it produces is \
         about a topology it does not have",
        std::io::Error::last_os_error()
    );

    let err = std::process::Command::new(&real).exec();
    panic!("exec of {real} failed: {err}");
}
