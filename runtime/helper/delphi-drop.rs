// SPDX-License-Identifier: MIT

//! `delphi-drop` — the credential drop between bwrap and the approved tool (D0A-R9-01).
//!
//! bwrap cannot do this itself: `--uid` requires a user namespace, and measurement
//! showed it is namespace-internal anyway (leg B — `INNER 65534` while an outside
//! observer still reads the launcher). Dropping *before* bwrap drops bwrap, which then
//! cannot build its own sandbox (leg C — `loopback: Failed RTM_NEWADDR`). So the drop
//! belongs to bwrap's **payload**, which is this.
//!
//! Usage: `delphi-drop <uid> <gid> <envfd> <program> <argv0> [args...]`
//!
//! # Why the environment arrives on a FILE DESCRIPTOR (D0A-R15-01)
//!
//! The approved `env_delta` is untrusted. It used to be applied to the `Command` that is
//! bwrap — a root process, running before the sandbox existed and before this helper lowered
//! credentials — where `LD_PRELOAD` is arbitrary root code execution and `PATH` chooses which
//! binary builds the jail. It now travels as sealed bytes nobody's loader reads, and this
//! helper applies it with `execve` AFTER `setresuid`. The first process it can influence is
//! the unprivileged tool, which is the one it was approved for.
//!
//! `argv0` is passed SEPARATELY from `program`: bwrap's `--argv0` would apply to
//! this helper, not to the tool, so without it the tool would see `argv[0]` as
//! `/proc/self/fd/N` instead of its approved name — a difference nothing in the
//! audit would show.
//!
//! # Why this binary must be STATICALLY linked
//!
//! It is handed to bwrap **by fd** (`/proc/self/fd/N`) so it needs no bind of its own —
//! adding one would violate §6's "mount exactly `fs_binds`". But a *dynamically* linked
//! binary still needs its loader and libc reachable inside the jail, which is the same
//! dependency wearing different clothes: measured, a dynamic binary in a jail binding
//! nothing fails with `execvp: No such file or directory`, and a `crt-static` one runs.
//! `runtime/tests/drop_helper_is_self_contained.rs` is the guard on that.
//!
//! # Fidelity levels supported
//!
//! One interface only — **direct syscalls** (`setgroups`/`setresgid`/`setresuid`/
//! `execv`). There is no lower-fidelity fallback and none would be acceptable: a
//! partial credential change is worse than none, so every failure is fatal here.

use std::os::unix::ffi::OsStrExt;

// Compiled by `build.rs` with a bare `rustc` invocation (see there for why), so NO
// crate dependencies are available — not even `libc`. The entry points are declared
// here and linked statically by `crt-static`.
type Char = std::ffi::c_char;
unsafe extern "C" {
    fn setgroups(size: usize, list: *const u32) -> i32;
    fn setresgid(r: u32, e: u32, s: u32) -> i32;
    fn setresuid(r: u32, e: u32, s: u32) -> i32;
    fn execve(path: *const Char, argv: *const *const Char, envp: *const *const Char) -> i32;
    fn read(fd: i32, buf: *mut core::ffi::c_void, count: usize) -> isize;
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn getgid() -> u32;
}

fn fail(what: &str) -> ! {
    eprintln!("delphi-drop: {what} failed: {}", std::io::Error::last_os_error());
    std::process::exit(127);
}

fn main() {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() < 6 {
        eprintln!("usage: delphi-drop <uid> <gid> <envfd> <program> <argv0> [args...]");
        std::process::exit(2);
    }
    let uid: u32 = args[1].to_string_lossy().parse().unwrap_or_else(|_| {
        eprintln!("delphi-drop: uid must be numeric");
        std::process::exit(2);
    });
    let gid: u32 = args[2].to_string_lossy().parse().unwrap_or_else(|_| {
        eprintln!("delphi-drop: gid must be numeric");
        std::process::exit(2);
    });
    // Never drop TO root: that would make the whole exercise a no-op, and it is the
    // shape a mis-supplied argument takes.
    if uid == 0 || gid == 0 {
        eprintln!("delphi-drop: refusing to 'drop' to uid/gid 0");
        std::process::exit(2);
    }

    // Order is load-bearing: each step requires the privilege the next one gives away.
    // SAFETY: raw credential syscalls on this process; no caller memory is touched.
    // `setgroups(0, NULL)` clears the supplementary set.
    unsafe {
        if setgroups(0, std::ptr::null()) != 0 {
            fail("setgroups");
        }
        if setresgid(gid, gid, gid) != 0 {
            fail("setresgid");
        }
        if setresuid(uid, uid, uid) != 0 {
            fail("setresuid");
        }
        // Proof, not assumption: if any id survived, exec nothing.
        if getuid() != uid || geteuid() != uid || getgid() != gid {
            eprintln!("delphi-drop: credentials did not take; refusing to exec");
            std::process::exit(127);
        }
    }

    // Read the approved environment BEFORE exec, from the sealed fd named in argv. `-` means
    // none: the tool gets an empty environment, never the daemon's.
    let envp_owned: Vec<std::ffi::CString> = if args[3] == "-" {
        Vec::new()
    } else {
        let fd: i32 = args[3].to_string_lossy().parse().unwrap_or_else(|_| {
            eprintln!("delphi-drop: envfd must be numeric or '-'");
            std::process::exit(2);
        });
        let mut blob = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            // SAFETY: reading into a stack buffer whose length is passed exactly.
            let n = unsafe { read(fd, chunk.as_mut_ptr().cast(), chunk.len()) };
            if n < 0 {
                fail("read environment fd");
            }
            if n == 0 {
                break;
            }
            blob.extend_from_slice(&chunk[..n as usize]);
        }
        blob.split(|b| *b == 0)
            .filter(|e| !e.is_empty())
            .map(|e| {
                std::ffi::CString::new(e).unwrap_or_else(|_| {
                    eprintln!("delphi-drop: environment entry contains NUL");
                    std::process::exit(2);
                })
            })
            .collect()
    };

    let prog = std::ffi::CString::new(args[4].as_bytes()).unwrap_or_else(|_| {
        eprintln!("delphi-drop: program path contains NUL");
        std::process::exit(2);
    });
    // argv[0] is the APPROVED name (args[5]), not the program path (args[4]).
    let argv: Vec<std::ffi::CString> = args[5..]
        .iter()
        .map(|a| std::ffi::CString::new(a.as_bytes()).unwrap_or_default())
        .collect();
    let mut raw: Vec<*const Char> = argv.iter().map(|a| a.as_ptr()).collect();
    raw.push(std::ptr::null());
    let mut envp: Vec<*const Char> = envp_owned.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());
    // SAFETY: `prog`, `raw` and `envp` outlive the call; both vectors are NULL-terminated.
    unsafe {
        execve(prog.as_ptr(), raw.as_ptr(), envp.as_ptr());
    }
    fail("execve");
}
