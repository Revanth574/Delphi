// SPDX-License-Identifier: MIT
//! Build script: link the system `libsystemd` by its versioned soname.
//!
//! The logind gate (`src/logind.rs`) calls three stable sd-login ABI symbols
//! (`sd_session_is_active`, `sd_session_is_remote`, `sd_pid_get_session`). We do
//! NOT use the `libsystemd-sys` crate: it is `LGPL-2.1-or-later` (outside the
//! workspace `deny.toml` allow-list) and its build needs `libsystemd-dev`/
//! pkg-config. Instead we declare the symbols ourselves (keeping this crate MIT)
//! and dynamically link the OS's `libsystemd.so.0` directly — no unversioned `.so`
//! and no dev package required. The symbols are verified present via `nm -D`.

fn main() {
    // `-l:libsystemd.so.0` links the exact runtime soname (the GNU linker resolves
    // it from the default library search path). Applied to every final artifact
    // that links (the lib rlib itself is not linked).
    for artifact in ["bins", "tests"] {
        println!("cargo:rustc-link-arg-{artifact}=-l:libsystemd.so.0");
    }
}
