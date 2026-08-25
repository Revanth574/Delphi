// SPDX-License-Identifier: MIT
//
// D0A-R9-01 — the drop helper must run in a jail that binds NOTHING.
//
// WRITTEN BEFORE THE HELPER'S BUILD CONFIG, deliberately: the shape of the helper
// depends on this answer, so the test is the thing that forces the answer rather than
// ratifying one already chosen. Against a default (dynamically linked) build it FAILS.
//
// WHAT THE EARLIER PREMISE TEST DID NOT COVER. `a_second_kept_fd_survives_a_second_exec`
// proved an fd survives a second `execve` and can be exec'd — but its helper was a
// `#!/bin/sh` script in a jail that bound `/usr`. That is a different claim. A
// dynamically linked helper needs its loader and libc reachable inside the jail, which
// is the same `/usr` dependency wearing different clothes. Measured on this box:
//
//     static  (crt-static) in a jail binding nothing -> ran (its own exit code)
//     dynamic              in a jail binding nothing -> execvp: No such file or directory
//
// So the assertion is "binds nothing", not "binds nothing from /usr".

use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

/// Built by `runtime/build.rs` with `crt-static` into `OUT_DIR` — deliberately NOT a
/// cargo bin target, because cargo would link it dynamically and no per-target rustflag
/// exists to stop that.
const HELPER: &str = concat!(env!("OUT_DIR"), "/delphi-drop");

// D0A-R15-04: this used to accept ANY exit code, so a lane where bwrap EXISTS but cannot
// build a jail ran the test and FAILED it instead of skipping. The shared probe is the one
// production-adjacent definition of "can build a jail", and it reports the real blocker.

/// The helper, handed to bwrap by fd, in a jail with **no binds at all** — not even
/// `/usr`. Exercised via its own argument validation so the leg needs no second binary:
/// a helper that could not start could not report `2` for a bad argument count.
#[test]
fn the_shipped_helper_runs_in_a_jail_binding_nothing() {
    if let Err(why) = delphi_runtime::bwrap_can_build_a_jail() {
        eprintln!("SKIP the_shipped_helper_runs_in_a_jail_binding_nothing: measured blocker: {why}");
        return;
    }
    let f = std::fs::File::open(HELPER).expect("open the shipped helper");
    let fd = f.as_raw_fd();
    // `File::open` sets O_CLOEXEC, so the fd would NOT survive into bwrap and the test
    // would fail whatever the helper's linkage was — a red with no discriminating power.
    // Production clears it through this exact call; the test uses the same one.
    let keep = vec![fd];
    let mut cmd = Command::new("bwrap");
    cmd.args([
            "--unshare-all",
            "--die-with-parent",
            "--clearenv",
            "--proc",
            "/proc",
            "--chdir",
            "/",
            "--",
            &format!("/proc/self/fd/{fd}"),
    ]);
    // SAFETY: as the production path — `mark_cloexec_except` is async-signal-safe and
    // does not allocate.
    unsafe {
        cmd.pre_exec(move || {
            delphi_runtime::mark_cloexec_except(&keep)
                .map_err(|e| std::io::Error::other(e.to_string()))
        });
    }
    let out = cmd.output().expect("spawn bwrap");

    let err = String::from_utf8_lossy(&out.stderr);
    // A dynamically linked helper dies HERE, before any of its own code runs.
    assert!(
        !err.contains("No such file or directory"),
        "the helper did not start in an empty jail — it is not self-contained. \
         A dynamically linked binary needs its loader and libc bound, which the \
         profile cannot guarantee for an arbitrary action. stderr: {err}"
    );
    // Its OWN diagnostic, which only a running helper can produce.
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected the helper's own usage exit; stderr: {err}"
    );
    assert!(err.contains("usage: delphi-drop"), "stderr: {err}");
}

/// The helper must never "drop" to root — that is what a mis-supplied argument looks
/// like, and it would make the whole mechanism a silent no-op.
/// Each id is checked INDEPENDENTLY, so weakening `||` to `&&` bites (D0A-R10-09).
#[test]
fn dropping_to_root_is_refused_for_either_id() {
    for (uid, gid) in [("0", "0"), ("0", "997"), ("997", "0")] {
        let out = Command::new(HELPER)
            .args([uid, gid, "-", "/bin/true", "true"])
            .output()
            .expect("spawn helper");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "uid={uid} gid={gid}: {err}");
        assert!(err.contains("refusing"), "uid={uid} gid={gid}: {err}");
    }
}

#[test]
fn dropping_to_root_is_refused() {
    let out = Command::new(HELPER)
        // FIVE args: uid, gid, the env fd (`-` = none), the program, and argv0 — which the
        // helper takes explicitly. With fewer it exits through USAGE and never reaches the
        // root check this test names (D0A-R10-09).
        .args(["0", "0", "-", "/bin/true", "true"])
        .output()
        .expect("spawn helper");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refusing"),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}
