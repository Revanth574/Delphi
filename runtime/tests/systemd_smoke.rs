// SPDX-License-Identifier: MIT

//! Live-systemd smoke-test — the production deploy mechanism actually produces
//! the anchor property (Increment 1a, closing the documented-vs-real gap).
//!
//! The kernel-equivalence test in `anchor.rs` proves "GIVEN a root-owned `0711`
//! directory, the anchor holds". This test proves the *other half*: that the
//! **shipped `delphi-runtimed@.service`**, started on **real systemd**, actually
//! produces that directory (`root:root 0711`) and that the daemon binds the
//! socket (`root:<session-gid> 0660`). It verifies the assumption the equivalence
//! relies on, against the real unit rather than against `man systemd.exec`.
//!
//! Privileged AND systemd-only: EUID-gated (skips when not root) and skipped when
//! the host is not booted with systemd. It installs the real unit + the built
//! binary, `systemctl start`s an instance for a throwaway user, asserts the live
//! ownership/modes, and tears everything down. Part of the mandatory 1d gate; run
//! in the WSL2-root lane (`--test-threads=1`).

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use nix::unistd::{geteuid, User};

/// The shipped unit file (the exact artifact, not a test variant).
const UNIT_SRC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/systemd/delphi-runtimed@.service");
/// The freshly-built daemon binary cargo points us at.
const BIN_SRC: &str = env!("CARGO_BIN_EXE_delphi-runtimed");
/// Where the shipped unit's `ExecStart=` expects the binary.
const INSTALLED_BIN: &str = "/usr/libexec/delphi-runtimed";
const INSTALLED_UNIT: &str = "/etc/systemd/system/delphi-runtimed@.service";
/// FIXED-name backup of a displaced operator binary. Fixed (not pid-suffixed) so there is
/// never more than one and never any "which one is the real binary" ambiguity: if it exists,
/// a prior run was interrupted inside its backup→restore window and this IS the operator's
/// real binary. `restore_stale_backup` heals that before this run touches anything.
const BIN_BACKUP: &str = "/usr/libexec/delphi-runtimed.smoke-bak";

fn systemd_booted() -> bool {
    Path::new("/run/systemd/system").exists()
}

fn sh(program: &str, args: &[&str]) -> std::process::Output {
    Command::new(program)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn `{program}`: {e}"))
}

/// Best-effort teardown that runs even if an assertion panics.
struct Teardown {
    user: String,
    instance: String,
    /// True when this run RENAMED an operator binary aside to `BIN_BACKUP` (restore it on
    /// drop). False when it PROVISIONED `INSTALLED_BIN` where none existed (just remove our
    /// copy). The word `provisioned` also lets the fixture-hygiene audit see the ownership
    /// gate on this fixture.
    bin_provisioned: bool,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        let _ = sh("systemctl", &["stop", &self.instance]);
        // The /etc unit path is TEST-OWNED (the installer ships the unit to
        // /usr/lib/systemd/system/), so removing it destroys no operator artifact — see the
        // path list in fixture_hygiene.rs.
        let _ = std::fs::remove_file(INSTALLED_UNIT);
        // Remove OUR fresh binary copy, then restore the operator's if we displaced one. Both
        // steps are best-effort; a SIGKILL between them leaves the operator's real binary at
        // BIN_BACKUP, which the NEXT run's `restore_stale_backup` heals (fixed-name backup).
        let _ = std::fs::remove_file(INSTALLED_BIN);
        if !self.bin_provisioned
            && let Err(e) = std::fs::rename(BIN_BACKUP, INSTALLED_BIN)
        {
            eprintln!(
                "WARN: could not restore operator daemon binary {INSTALLED_BIN} from \
                 {BIN_BACKUP}: {e} — the real binary is at {BIN_BACKUP}; re-run this test \
                 or installer/install.sh to restore it"
            );
        }
        let _ = sh("systemctl", &["daemon-reload"]);
        let _ = sh("userdel", &[&self.user]);
        let _ = std::fs::remove_dir_all(format!("/run/delphi/{}", self.user));
    }
}

/// CRASH-SAFETY — self-heal a prior run SIGKILLed inside its backup→restore window.
///
/// The backup→restore dance means that between the backup rename and the restore rename,
/// `INSTALLED_BIN` is the TEST's binary (or absent) while the operator's real binary sits at
/// the FIXED `BIN_BACKUP`. A kill there would otherwise leave the WRONG binary silently at the
/// production path — a presence check passes; only an md5 comparison after a completed run
/// catches it. That is worse than the loud deletion this fixture replaced, so it must not be
/// left to chance. This runs BEFORE this run's own backup: if `BIN_BACKUP` exists, the prior
/// run did not finish, so restore it (atomic rename), OVERWRITING whatever wrong binary sits
/// at `INSTALLED_BIN`. Fixed backup name ⇒ at most one, no ambiguity. systemd_smoke is
/// root + serial-only, so the fixed name cannot collide with a concurrent run (which would
/// already collide on `INSTALLED_BIN` itself). Edge: if the operator REINSTALLED between the
/// interruption and now, this restores the slightly-older-but-valid backup — still strictly
/// better than a silent wrong binary.
fn restore_stale_backup() {
    if Path::new(BIN_BACKUP).exists() {
        match std::fs::rename(BIN_BACKUP, INSTALLED_BIN) {
            Ok(()) => eprintln!(
                "systemd_smoke: healed a prior interrupted run — restored {INSTALLED_BIN} \
                 from the stale {BIN_BACKUP}"
            ),
            Err(e) => eprintln!(
                "WARN: stale {BIN_BACKUP} present (prior interrupted run) but restore failed: \
                 {e} — the real binary is at {BIN_BACKUP}"
            ),
        }
    }
}

fn assert_owner_mode(path: &Path, uid: u32, gid: u32, mode: u32, what: &str) {
    let m = std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("{what}: cannot stat {}: {e}", path.display()));
    assert_eq!(m.uid(), uid, "{what}: owner uid must be {uid}, got {}", m.uid());
    assert_eq!(m.gid(), gid, "{what}: group gid must be {gid}, got {}", m.gid());
    assert_eq!(
        m.mode() & 0o777,
        mode,
        "{what}: mode must be {mode:o}, got {:o}",
        m.mode() & 0o777
    );
}

/// THE LIVE SMOKE-TEST: install the shipped unit, start it on real systemd, and
/// assert the production mechanism produces the root-owned anchor + group socket.
#[test]
fn shipped_unit_produces_root_owned_anchor_on_systemd() {
    if geteuid().as_raw() != 0 {
        eprintln!(
            "SKIP shipped_unit_produces_root_owned_anchor_on_systemd: requires root. \
             Run the privileged lane:\n  wsl -u root -- env -C /mnt/c/dev/Delphi \\\n    \
             /home/raven/.cargo/bin/cargo test -p delphi-runtime --test systemd_smoke \\\n    \
             -- --test-threads=1 --nocapture"
        );
        return;
    }
    if !systemd_booted() {
        eprintln!("SKIP shipped_unit_produces_root_owned_anchor_on_systemd: host is not booted with systemd");
        return;
    }

    let user = format!("dsmoke{}", std::process::id() % 100_000);
    let instance = format!("delphi-runtimed@{user}.service");

    // Clean any leftover user from a previous aborted run, then create a fresh
    // unprivileged, no-home, no-login throwaway.
    let _ = sh("userdel", &[&user]);
    let added = sh("useradd", &["-M", "-s", "/usr/sbin/nologin", &user]);
    assert!(
        added.status.success(),
        "useradd {user} failed: {}",
        String::from_utf8_lossy(&added.stderr)
    );

    std::fs::create_dir_all("/usr/libexec").expect("ensure /usr/libexec");

    // CRASH-SAFETY FIRST: heal any prior run killed inside its backup→restore window before
    // this run reads or moves anything (else this run could back up the WRONG binary).
    restore_stale_backup();

    // Class 16/17 — an installer may already own INSTALLED_BIN. Displace it (rename aside to
    // the FIXED BIN_BACKUP) so the smoke test still runs against the FRESH build, and arm the
    // teardown to RESTORE it, never delete it. Only when nothing was present do we
    // provision-and-remove. The prior version unconditionally copied over and then
    // remove_file'd this path, deleting the operator's installed daemon binary mid-run — the
    // exact Class-16 shape, one path over from the PAM stack, that fixture_hygiene.rs now
    // guards for every operator-owned path.
    let bin_provisioned = if Path::new(INSTALLED_BIN).exists() {
        std::fs::rename(INSTALLED_BIN, BIN_BACKUP).expect("back up operator daemon binary");
        false
    } else {
        true
    };

    let _guard = Teardown { user: user.clone(), instance: instance.clone(), bin_provisioned };

    // Install the SHIPPED unit + the built binary at the unit's ExecStart path.
    std::fs::copy(BIN_SRC, INSTALLED_BIN).expect("install daemon binary");
    std::fs::set_permissions(INSTALLED_BIN, std::fs::Permissions::from_mode(0o755))
        .expect("chmod daemon binary");
    std::fs::copy(UNIT_SRC, INSTALLED_UNIT).expect("install unit file");
    assert!(
        sh("systemctl", &["daemon-reload"]).status.success(),
        "systemctl daemon-reload failed"
    );

    // Start the instance for the throwaway user.
    let started = sh("systemctl", &["start", &instance]);
    assert!(
        started.status.success(),
        "systemctl start {instance} failed: {}\n--- status ---\n{}",
        String::from_utf8_lossy(&started.stderr),
        String::from_utf8_lossy(&sh("systemctl", &["status", &instance, "--no-pager"]).stdout)
    );

    let session_gid = User::from_name(&user)
        .expect("getpwnam")
        .expect("session user exists")
        .gid
        .as_raw();

    let dir = PathBuf::from(format!("/run/delphi/{user}"));
    let socket = dir.join("approve.sock");

    // The daemon binds the socket shortly after exec — poll briefly.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }

    // ASSERT the live production mechanism produced exactly the anchor property:
    // systemd's RuntimeDirectory= → root-owned 0711 directory ...
    assert_owner_mode(&dir, 0, 0, 0o711, "RuntimeDirectory (systemd)");
    // ... and the daemon's bind → root:<session-gid> 0660 socket.
    assert_owner_mode(&socket, 0, session_gid, 0o660, "approval socket (daemon bind)");
}
