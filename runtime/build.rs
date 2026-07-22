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
    // Link the exact runtime soname (no unversioned `.so`, so no `libsystemd-dev`).
    //
    // `rustc-link-lib` rather than the former `rustc-link-arg-{bins,tests}` pair: a
    // per-artifact-kind ENUMERATION covers the kinds it names and silently misses the
    // rest — DOCTESTS are neither `bins` nor `tests`, so the first doctest to reference
    // an sd-login symbol failed to link with `undefined symbol: sd_pid_get_session`.
    // That is `docs/DEFECT_CLASSES.md` class 14 (a guard/flag covering some forms of its
    // target, not all) living in the build script. `rustc-link-lib` is the
    // authoritative-category form: it attaches to the CRATE, so every artifact that
    // links the crate — bins, tests, benches, examples AND doctests — inherits it.
    //
    // `dylib:+verbatim=` passes the filename through untouched, which is what allows the
    // versioned soname (a plain `-l systemd` would demand the unversioned dev symlink).
    println!("cargo:rustc-link-lib=dylib:+verbatim=libsystemd.so.0");

    // B1: compile the AI↔daemon general-socket wire schema (protobuf, prost).
    println!("cargo:rerun-if-changed=proto/runtime_wire.proto");
    prost_build::compile_protos(&["proto/runtime_wire.proto"], &["proto"])
        .expect("compile runtime_wire.proto");
}
