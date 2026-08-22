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

    // D0A-R9-01: build the credential-drop helper as a SELF-CONTAINED binary.
    //
    // It is handed to bwrap by fd so it needs no bind (§6 "mount exactly `fs_binds`"),
    // but a DYNAMICALLY linked binary still needs its loader and libc inside the jail —
    // the same dependency wearing different clothes. Measured: a dynamic binary in a
    // jail binding nothing dies `execvp: No such file or directory`.
    //
    // WHY A BARE `rustc` AND NOT A CARGO BIN TARGET. Static linking needs
    // `-C target-feature=+crt-static`, which is a RUSTFLAG, and cargo has no per-target
    // rustflags — setting it workspace-wide would statically link the daemon too, which
    // must stay dynamic (PAM `dlopen`s its modules). The alternative, a decoupled crate
    // with its own config, is the `shell-host` pattern; it was rejected because §13.4
    // records that decoupled crates are invisible to `--workspace` and that this exact
    // gap shipped D0-R2-03. Keeping the helper inside this crate keeps it audited.
    //
    // `-C link-arg=-static` alone is NOT a substitute: measured, it produces a binary
    // that links, reports as `ELF ... executable`, and SEGFAULTS (rc 139).
    //
    // D0A-R10-11: `--target $TARGET`, because a bare `rustc` builds for the HOST and knows
    // nothing about what cargo was asked to compile. Under `cargo build --target <foreign>`
    // the daemon is cross-compiled while this helper is not, and the host binary is copied
    // into `<target>/<triple>/<profile>/` for `installer/build.sh` to stage BESIDE the
    // foreign daemon — a root-owned 0755 file that cannot execute on the machine it ships to.
    //
    // MEASURED, not argued (2026-08-20), by driving THIS compiled build script with the
    // environment cargo sets for `--target aarch64-unknown-linux-gnu`:
    //   without `--target`: rc=0 and a 5.3MB **x86-64** `delphi-drop` in the aarch64
    //                       profile dir — silently staged beside a foreign daemon;
    //   with it:            rc=101, `rust-lld: … is incompatible with elf64-x86-64`,
    //                       and NO artifact. Loud beats wrong.
    // (A cargo-driven cross build cannot get this far on this box — `libsqlite3-sys` needs
    // a cross C toolchain first — and producing a RUNNABLE aarch64 helper additionally
    // needs an aarch64 linker + glibc, which rustup's std does not supply. What is proven
    // is the direction: no wrong-arch artifact is produced. `installer/install.sh`'s ELF
    // check is the backstop for one arriving by any other route.)
    println!("cargo:rerun-if-changed=helper/delphi-drop.rs");
    let out = std::env::var("OUT_DIR").expect("OUT_DIR");
    let target = std::env::var("TARGET").expect("TARGET is set by cargo for build scripts");
    let helper = std::path::Path::new(&out).join("delphi-drop");
    let status = std::process::Command::new(std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into()))
        .args(["--target", &target])
        .args(["-O", "-C", "target-feature=+crt-static", "--edition", "2024", "-o"])
        .arg(&helper)
        .arg("helper/delphi-drop.rs")
        .status()
        .expect("spawn rustc for the drop helper");
    assert!(status.success(), "building the drop helper for {target} failed");

    // Also place it beside the other binaries so `installer/build.sh` can name it.
    // OUT_DIR is `<target>/<profile>/build/<pkg>-<hash>/out`, so three levels up is
    // `<target>/<profile>` — derived, not guessed, and stable across hash changes.
    // Writing outside OUT_DIR is discouraged by cargo; done deliberately because the
    // alternative is the installer parsing `--message-format=json` to discover a path
    // this script already knows.
    //
    // D0A-R10-10: CHECKED, and via a temp file + rename.
    //
    // `let _ = copy(…)` meant a failed copy left the PREVIOUS build's helper sitting there,
    // and `installer/build.sh` cannot detect that: its staging assertion shas the source and
    // the destination, which are then the same stale bytes agreeing with each other. A
    // silent failure here is a stale root-owned binary installed on a machine.
    //
    // Rename rather than copy-in-place for two reasons, both real: a concurrent
    // `installer/build.sh` can otherwise stage a HALF-WRITTEN helper, and copying onto a
    // binary another process is executing fails with ETXTBSY, which as a hard error would
    // turn a rare race into a broken build.
    let profile_dir = helper
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .unwrap_or_else(|| panic!("deriving <target>/<profile> from OUT_DIR {out}"));
    let staged = profile_dir.join("delphi-drop");
    let tmp = profile_dir.join(format!("delphi-drop.tmp{}", std::process::id()));
    std::fs::copy(&helper, &tmp)
        .unwrap_or_else(|e| panic!("copying the drop helper {} -> {}: {e}", helper.display(), tmp.display()));
    std::fs::rename(&tmp, &staged)
        .unwrap_or_else(|e| panic!("renaming the drop helper {} -> {}: {e}", tmp.display(), staged.display()));

    // D0A-R9-02 step 6: EMBED THE HELPER'S DIGEST IN THE DAEMON.
    //
    // `execute.rs` opens /usr/libexec/delphi-drop by PATH, so the helper carried the same
    // inode-vs-content gap v7 closed for the tool — and it is the ONE component whose
    // substitution grants uid control, since it is what calls setresuid. Sealing its
    // snapshot at startup binds the bytes; comparing them to a digest fixed AT BUILD TIME
    // is what makes a substituted installation refuse rather than run.
    //
    // Hashed from the bytes just built, so the constant and the artifact cannot disagree.
    let helper_bytes = std::fs::read(&helper)
        .unwrap_or_else(|e| panic!("reading the built drop helper {}: {e}", helper.display()));
    let digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&helper_bytes);
        h.finalize()
    };
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    println!("cargo:rustc-env=DELPHI_DROP_DIGEST={hex}");

    // B1: compile the AI↔daemon general-socket wire schema (protobuf, prost).
    println!("cargo:rerun-if-changed=proto/runtime_wire.proto");
    prost_build::compile_protos(&["proto/runtime_wire.proto"], &["proto"])
        .expect("compile runtime_wire.proto");
}
