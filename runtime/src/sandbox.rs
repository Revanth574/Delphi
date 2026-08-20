// SPDX-License-Identifier: MIT

//! The default-deny sandbox profile, derived from the approved scope (Increment 1d).
//!
//! "sandbox = approval" has **two** parts, and only the first is covered by the
//! action digest:
//!
//! 1. **the scope is approved** — `fs_binds`/`net_policy` are fields of the
//!    canonical [`PendingAction`](crate::action::PendingAction), so the digest (and
//!    the token pinned to it) bind them. The foundation covers this.
//! 2. **the bwrap args faithfully ENFORCE the approved scope** — the translation
//!    scope→args is correct AND complete: enforced == approved, no broader (no
//!    extra bind, no `--bind` where `--ro-bind`, no net where none), no narrower.
//!    The digest does **not** cover this (it binds the scope *field*, not the
//!    `bwrap` *args*), so it is the property [`SandboxProfile`]'s tests bite — the
//!    divergence discipline applied to the sandbox derivation.
//!
//! Reentry containment (F5 / R3-02): the jail binds **only** the approved scope, so
//! the daemon's approval socket (outside that scope) is not in the jail's mount
//! namespace and the tool cannot connect back to self-approve. The `--clearenv`
//! and the caller's `close_range` (1b `fdsec`) remove the env/fd paths back.
//!
//! Network is honest at the **type** level (`docs/TRUST_MODEL.md` §6, F5):
//! [`NetPolicy`](crate::action::NetPolicy) has only `None`/`Full` — it cannot
//! *express* a host allowlist, so there is no unenforceable scope to derive from.

use crate::action::{BindMode, NetPolicy, PendingAction};

/// The bwrap arguments (before the trailing `-- <command>`) that set up the jail
/// for one approved action. Derived from the canonical object's scope.
pub struct SandboxProfile {
    args: Vec<String>,
}

/// Lexically normalise without touching the filesystem: fold `.` away and pop on
/// `..`, so `/run/delphi/../delphi/x` cannot spell its way past a prefix compare.
fn lexical_normalize(path: &std::path::Path) -> std::path::PathBuf {
    use std::path::Component;
    let mut out = std::path::PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Refuse an `fs_bind` that names the daemon's own runtime directory (D0A-R9-10).
///
/// **Why this is defence in depth and not the barrier** — the asymmetry is the whole
/// justification for shipping it with the uid drop, so it is stated where it is
/// enforced rather than only in `docs/CONFORMANCE_REGISTER.md`:
///
/// * While the action runs as **root**, mode bits stop nothing (root overrides DAC),
///   so *this check is the sole barrier* between the tool and the approval socket.
/// * Once the action runs as the dedicated tool uid, the socket's `0660
///   root:<session-gid>` and the anchor's `0711` already stop it, and `SO_PEERCRED`
///   stops it again. Two mechanisms, neither of them this one.
///
/// So the uid drop is the enabling change; this makes a single point of failure into
/// a third line. It does **not** close D0A-R9-03: a symlink swapped *after* this
/// check still redirects the bind, which is that finding's TOCTOU.
///
/// # Examples
///
/// ```
/// use std::path::{Path, PathBuf};
/// use delphi_runtime::sandbox::refuse_denied_bind;
///
/// let base = Path::new("/run/delphi");
/// assert!(refuse_denied_bind(Path::new("/home/alice/src"), base).is_ok());
/// assert!(refuse_denied_bind(Path::new("/run/delphi/alice"), base).is_err());
/// // Traversal cannot spell its way out.
/// assert!(refuse_denied_bind(Path::new("/run/delphi/../delphi/alice"), base).is_err());
/// ```
///
/// # Errors
///
/// [`RuntimeError::DeniedBind`] if `path` resolves inside `base`.
#[must_use = "a refused bind must abort the execution, not be discarded"]
pub fn refuse_denied_bind(
    path: &std::path::Path,
    base: &std::path::Path,
) -> Result<(), crate::RuntimeError> {
    let base_n = lexical_normalize(base);
    // Both forms are checked: the lexical one always, and the symlink-resolved one
    // when the path exists. Neither subsumes the other — canonicalize sees through a
    // symlink but fails on a not-yet-created path, and the lexical form is the only
    // one available then.
    let candidates = [
        Some(lexical_normalize(path)),
        std::fs::canonicalize(path).ok().map(|p| lexical_normalize(&p)),
    ];
    for candidate in candidates.into_iter().flatten() {
        // THREE relations, not one (D0A-R10-04). Rejecting only `candidate inside base`
        // admitted every ANCESTOR — binding `/run`, or `/`, mounts `/run/delphi` and its
        // socket into the jail just as surely as naming it directly. `base.starts_with`
        // is the containment leg. `/run/delphi/..` folds to `/run` and is caught by it,
        // which is the third spelling this predicate has now missed twice.
        if candidate == base_n
            || candidate.starts_with(&base_n)
            || base_n.starts_with(&candidate)
        {
            return Err(crate::RuntimeError::DeniedBind {
                path: candidate,
                base: base_n,
            });
        }
    }
    Ok(())
}

/// Refuse a bind whose destination path does not exist (D0A-R10-01).
///
/// bwrap creates a missing destination path, and when that path lies inside an
/// enclosing bind the creation goes **through the mount into the host filesystem** —
/// measured: `--bind OUTER OUTER --bind SRC OUTER/x/y` leaves `x/y` on the host.
///
/// The profile always emits `source == dest`, so destinations exist by construction and
/// this cannot currently fire. That is exactly why it is here: **the invariant is what
/// protects, and it was undocumented and unenforced.** A future remapping bind would
/// open the hole with nothing to catch it.
///
/// # Errors
///
/// [`RuntimeError::BindWouldCreateOnHost`] if a bind path does not exist.
pub fn refuse_host_creating_bind(
    binds: &[(std::path::PathBuf, BindMode)],
) -> Result<(), crate::RuntimeError> {
    for (path, _) in binds {
        if !path.exists() {
            return Err(crate::RuntimeError::BindWouldCreateOnHost { path: path.clone() });
        }
    }
    Ok(())
}

/// Directories that must exist, traversable, before the binds are applied.
///
/// **Why this is production logic and not a convenience** (`docs/DEFECT_CLASSES.md`
/// class 40): bwrap auto-creates a bind's missing parents as **`0700` owned by the
/// sandbox uid**. While the tool kept bwrap's own uid that was invisible; once the
/// payload drops to a different uid it cannot traverse them, and every bind under a
/// not-yet-existing parent becomes unreachable.
///
/// Two exclusions:
///
/// * **the bind path itself** — bwrap creates that mountpoint;
/// * **any ancestor lying inside another bind.**
///
/// **CORRECTED (D0A-R10-01): the second exclusion does NOT prevent a host write.** It
/// stops *this code* emitting `--dir` there; bwrap still creates that ancestor while
/// installing the inner bind, and — measured — that creation lands in the **host**
/// filesystem through the enclosing mount. What actually prevents it is the profile's
/// `source == dest` invariant, which [`refuse_host_creating_bind`] now enforces rather
/// than leaving accidental.
fn ancestor_dirs(binds: &[(std::path::PathBuf, BindMode)]) -> Vec<String> {
    use std::collections::BTreeSet;
    let norm: Vec<std::path::PathBuf> =
        binds.iter().map(|(p, _)| lexical_normalize(p)).collect();
    let mut wanted: BTreeSet<std::path::PathBuf> = BTreeSet::new();
    for b in &norm {
        let mut cur = b.parent();
        while let Some(a) = cur {
            if a.parent().is_none() {
                break; // `/` always exists
            }
            wanted.insert(a.to_path_buf());
            cur = a.parent();
        }
    }
    wanted.retain(|a| !norm.iter().any(|b| a == b || a.starts_with(b)));
    // `BTreeSet<PathBuf>` orders component-wise, so a prefix precedes what it
    // contains — parent-first, which is what bwrap's in-order application needs.
    wanted.into_iter().map(|p| p.to_string_lossy().into_owned()).collect()
}

impl SandboxProfile {
    /// Derive the default-deny profile from `action`'s approved scope.
    ///
    /// Default-deny base: every namespace EXCEPT user (D0A-R9-01),
    /// `--die-with-parent`, `--new-session` (detach the controlling tty),
    /// `--clearenv`. Then exactly the approved `fs_binds` (`--ro-bind`/`--bind`),
    /// the `env_delta`, `--chdir`, and `--share-net` **only** for `NetPolicy::Full`.
    #[must_use]
    pub fn derive(action: &PendingAction) -> Self {
        let mut args = vec![
            // E (D0A-R9-01): every namespace EXCEPT user. `--unshare-all` implies
            // `--unshare-user-try`, and bwrap's own userns maps sandbox_uid ->
            // parent_uid — measured identity-transparent (leg A: INNER 0 /
            // SO_PEERCRED 0), so it supplied isolation, never identity. Worse, it
            // maps exactly ONE uid, so nothing inside can drop to another (leg D:
            // setresuid EINVAL). Dropping it is what lets the payload reach a real
            // host uid. §6 mandates no user namespace — only `--unshare-net`.
            "--unshare-ipc".to_string(),
            "--unshare-pid".to_string(),
            "--unshare-uts".to_string(),
            "--unshare-cgroup-try".to_string(),
            "--die-with-parent".to_string(),
            "--new-session".to_string(),
            "--clearenv".to_string(),
            // Jail infrastructure (not scope): a private /proc is REQUIRED for the
            // `/proc/self/fd/N` swap-proof exec (R3-04); a minimal /dev for basic
            // device access. Neither exposes a path back to the daemon.
            "--proc".to_string(),
            "/proc".to_string(),
            "--dev".to_string(),
            "/dev".to_string(),
        ];
        // Emitted BOTH ways now that there is no `--unshare-all` to counteract:
        // `--unshare-net` for `None`, `--share-net` for `Full`. Explicit in each
        // direction rather than one being the absence of the other.
        match action.net_policy {
            NetPolicy::None => args.push("--unshare-net".to_string()),
            NetPolicy::Full => args.push("--share-net".to_string()),
        }
        // Ancestors BEFORE the binds: bwrap applies arguments in order (class 40).
        for dir in ancestor_dirs(&action.fs_binds) {
            args.push("--perms".to_string());
            args.push("0755".to_string());
            args.push("--dir".to_string());
            args.push(dir);
        }
        // PARENT-FIRST (D0A-R10-05). bwrap applies setup operations sequentially, so a
        // parent emitted after a nested child mounts OVER it and the child's mode is
        // silently lost — `child=ro, parent=rw` leaves the child WRITABLE through the
        // parent while an argv-level scope check still sees both flags. Sorting
        // component-wise puts a prefix before what it contains.
        let mut ordered: Vec<&(std::path::PathBuf, BindMode)> = action.fs_binds.iter().collect();
        ordered.sort_by_key(|b| lexical_normalize(&b.0));
        for (path, mode) in ordered {
            let flag = match mode {
                BindMode::ReadOnly => "--ro-bind",
                BindMode::ReadWrite => "--bind",
            };
            let p = path.to_string_lossy().into_owned();
            args.push(flag.to_string());
            args.push(p.clone());
            args.push(p);
        }
        for (k, v) in &action.env_delta {
            args.push("--setenv".to_string());
            args.push(k.clone());
            args.push(v.clone());
        }
        args.push("--chdir".to_string());
        args.push(action.cwd.to_string_lossy().into_owned());
        Self { args }
    }

    /// The derived bwrap arguments (before the trailing `-- <command>`).
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

#[cfg(test)]
mod tests {
    use super::{refuse_denied_bind, refuse_host_creating_bind};
    use std::path::Path;

    const BASE: &str = "/run/delphi";

    /// Emitted `--perms MODE --dir PATH` triples, in order.
    fn emitted_dirs(args: &[String]) -> Vec<String> {
        emitted_dir_perms(args).into_iter().map(|(_, p)| p).collect()
    }

    /// The same triples, keeping the MODE — which nothing asserted until D0A-R10's
    /// mutation audit measured `0755 -> 0700` surviving the entire suite.
    fn emitted_dir_perms(args: &[String]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 3 < args.len() {
            if args[i] == "--perms" && args[i + 2] == "--dir" {
                out.push((args[i + 1].clone(), args[i + 3].clone()));
            }
            i += 1;
        }
        out
    }

    fn index_of(args: &[String], needle: &str) -> Option<usize> {
        args.iter().position(|a| a == needle)
    }

    /// D0A-R9-01 / class 40 — the profile must create every bind's ancestors with a
    /// traversable mode. bwrap otherwise auto-creates them `0700` owned by the SANDBOX
    /// uid, which a dropped payload cannot traverse.
    ///
    /// This is the case an implementation gets right for the paths it thought of.
    #[test]
    fn every_ancestor_of_every_bind_is_created_traversable() {
        let a = action_with(
            vec![
                (PathBuf::from("/run/delphi-x/sess"), BindMode::ReadOnly),
                (PathBuf::from("/opt/vendor/tool/bin"), BindMode::ReadWrite),
            ],
            NetPolicy::None,
        );
        let args = SandboxProfile::derive(&a).args().to_vec();
        let dirs = emitted_dirs(&args);
        for want in ["/run", "/run/delphi-x", "/opt", "/opt/vendor", "/opt/vendor/tool"] {
            assert!(dirs.iter().any(|d| d == want), "missing ancestor `{want}`; got {dirs:?}");
        }
        // THE MODE THIS TEST'S NAME CLAIMS. Until D0A-R10 it asserted only that the
        // ancestors were emitted, so `--perms 0755 -> 0700` — bwrap's own default, the
        // exact value class 40 exists to override — passed the whole suite (measured by
        // scratch/d0a-mutation-audit.sh). A name that promises `traversable` while the
        // assertion checks presence is the R9-01 shape: cited for more than it observes.
        for (mode, dir) in emitted_dir_perms(&args) {
            assert_eq!(mode, "0755", "ancestor `{dir}` is emitted with mode {mode}, not 0755");
        }
        // The bind target itself is bwrap's mountpoint — creating it would be wrong.
        assert!(!dirs.iter().any(|d| d == "/run/delphi-x/sess"), "must not --dir the bind itself");
        // Parent-first, and before the bind that needs it: bwrap applies args in order.
        let (p, c) = (index_of(&args, "/run").unwrap(), index_of(&args, "/run/delphi-x").unwrap());
        assert!(p < c, "ancestors must be emitted parent-first");
        let bind_at = args.iter().position(|x| x == "--ro-bind").unwrap();
        assert!(c < bind_at, "ancestors must precede the bind that needs them");
    }

    /// Shared ancestors are emitted ONCE. A repeat is not merely noise: bwrap applies
    /// each in order, so a second `--dir` over an existing path re-applies the mode.
    #[test]
    fn shared_ancestors_are_not_emitted_twice() {
        let a = action_with(
            vec![
                (PathBuf::from("/srv/data/one"), BindMode::ReadOnly),
                (PathBuf::from("/srv/data/two"), BindMode::ReadOnly),
            ],
            NetPolicy::None,
        );
        let dirs = emitted_dirs(SandboxProfile::derive(&a).args());
        assert_eq!(dirs.iter().filter(|d| *d == "/srv").count(), 1, "got {dirs:?}");
        assert_eq!(dirs.iter().filter(|d| *d == "/srv/data").count(), 1, "got {dirs:?}");
    }

    /// THE DANGEROUS ONE. If `/opt` is itself bound, `/opt/vendor` lives INSIDE that
    /// bind — and `--dir` there creates the directory in the HOST filesystem through
    /// the mount. An ancestor that falls inside another bind must NOT be emitted.
    #[test]
    fn an_ancestor_inside_another_bind_is_never_created() {
        let a = action_with(
            vec![
                (PathBuf::from("/opt"), BindMode::ReadOnly),
                (PathBuf::from("/opt/vendor/tool"), BindMode::ReadOnly),
            ],
            NetPolicy::None,
        );
        let dirs = emitted_dirs(SandboxProfile::derive(&a).args());
        assert!(
            !dirs.iter().any(|d| d == "/opt/vendor"),
            "creating a dir inside a bind writes through to the HOST; got {dirs:?}"
        );
    }

    /// D0A-R10-04 — an ANCESTOR bind mounts the denied base in just as effectively.
    #[test]
    fn a_bind_containing_the_runtime_directory_is_refused() {
        for p in ["/run", "/", "/run/delphi/..", "/run/./delphi/../.."] {
            assert!(
                refuse_denied_bind(Path::new(p), Path::new(BASE)).is_err(),
                "binding `{p}` places {BASE} inside the jail"
            );
        }
        // Positive control: a sibling that contains nothing of the base is still fine.
        assert!(refuse_denied_bind(Path::new("/run/user/1000"), Path::new(BASE)).is_ok());
    }

    /// D0A-R10-05 — proven by ATTEMPTING THE WRITE, not by reading flags.
    ///
    /// The argv-level scope test sees `--ro-bind CHILD` and `--bind PARENT` and passes
    /// either way; the mount topology is where the property lives (class 41).
    #[test]
    fn a_read_only_child_stays_read_only_when_its_parent_is_bound_after_it() {
        if std::process::Command::new("bwrap").arg("--version").output().is_err() {
            eprintln!("SKIP a_read_only_child_stays_read_only_when_its_parent_is_bound_after_it: measured blocker: bwrap not executable");
            return;
        }
        let root = std::env::temp_dir().join(format!("delphi-r1005-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("ro")).unwrap();
        let target = root.join("ro/witness");
        std::fs::write(&target, b"original").unwrap();

        // REVERSED proposal order: the read-only child FIRST, its writable parent after.
        let a = action_with(
            vec![
                (root.join("ro"), BindMode::ReadOnly),
                (root.clone(), BindMode::ReadWrite),
            ],
            NetPolicy::None,
        );
        let mut args = SandboxProfile::derive(&a).args().to_vec();
        args.extend(["--ro-bind".into(), "/usr".into(), "/usr".into()]);
        args.extend(["--symlink".into(), "usr/bin".into(), "/bin".into()]);
        args.extend(["--symlink".into(), "usr/lib".into(), "/lib".into()]);
        args.extend(["--symlink".into(), "usr/lib64".into(), "/lib64".into()]);
        args.extend([
            "--".into(),
            "/bin/sh".into(),
            "-c".into(),
            format!("echo TAMPERED > {}", target.display()),
        ]);
        let out = std::process::Command::new("bwrap").args(&args).output().unwrap();
        eprintln!(
            "[R10-05] write attempt rc={:?} stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "original",
            "D0A-R10-05: the read-only child was written through its parent bind"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// D0A-R10-01 — observed on the FILESYSTEM, not in the emitted args.
    ///
    /// The previous ancestor tests assert on `--perms/--dir` strings: an argv-level
    /// observation of a filesystem-level effect. That is why they could not see this
    /// at all — filtering an ancestor stops *Delphi* emitting `--dir`, and bwrap
    /// creates it anyway while installing the inner bind, **through the enclosing
    /// mount, in the host filesystem** (measured: `--bind OUTER OUTER --bind SRC
    /// OUTER/x/y` leaves `x/y` on the host).
    ///
    /// This asserts the host is unchanged after a real bwrap run.
    #[test]
    fn a_nested_bind_does_not_create_anything_in_the_host() {
        if std::process::Command::new("bwrap").arg("--version").output().is_err() {
            eprintln!("SKIP a_nested_bind_does_not_create_anything_in_the_host: measured blocker: bwrap not executable");
            return;
        }
        let root = std::env::temp_dir().join(format!("delphi-r1001-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("vendor/tool")).unwrap();
        std::fs::write(root.join("vendor/tool/f"), b"x").unwrap();

        let before = tree(&root);
        let a = action_with(
            vec![
                (root.clone(), BindMode::ReadWrite),
                (root.join("vendor/tool"), BindMode::ReadOnly),
            ],
            NetPolicy::None,
        );
        // The profile is what production emits, run for real.
        let mut args = SandboxProfile::derive(&a).args().to_vec();
        args.extend(["--ro-bind".into(), "/usr".into(), "/usr".into()]);
        args.extend(["--symlink".into(), "usr/bin".into(), "/bin".into()]);
        args.extend(["--symlink".into(), "usr/lib".into(), "/lib".into()]);
        args.extend(["--symlink".into(), "usr/lib64".into(), "/lib64".into()]);
        args.extend(["--".into(), "/bin/true".into()]);
        let out = std::process::Command::new("bwrap").args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "bwrap must build this jail, or the test proves nothing: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            tree(&root),
            before,
            "D0A-R10-01: the host tree changed — bwrap created a path through a bind"
        );
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// CLASS 40 AT THE LAYER THE PROPERTY LIVES IN — the mode bwrap actually applied,
    /// read from inside the jail, not the mode we emitted.
    ///
    /// The argv assertion above catches a changed constant. It cannot catch bwrap
    /// declining to honour `--perms`, applying it to the wrong operation, or a later
    /// argument re-creating the directory with a different mode — all of which are how
    /// the payload would find an untraversable ancestor despite a correct-looking
    /// profile. `0700` is bwrap's own default and therefore the value this must exclude.
    #[test]
    fn a_created_ancestor_is_0755_inside_a_real_jail() {
        if std::process::Command::new("bwrap").arg("--version").output().is_err() {
            eprintln!("SKIP a_created_ancestor_is_0755_inside_a_real_jail: measured blocker: bwrap not executable");
            return;
        }
        let root = std::env::temp_dir().join(format!("delphi-r10perm-{}", std::process::id()));
        let leaf = root.join("deep/tool");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&leaf).unwrap();

        let a = action_with(vec![(leaf.clone(), BindMode::ReadOnly)], NetPolicy::None);
        let mut args = SandboxProfile::derive(&a).args().to_vec();
        args.extend(["--ro-bind".into(), "/usr".into(), "/usr".into()]);
        args.extend(["--symlink".into(), "usr/bin".into(), "/bin".into()]);
        args.extend(["--symlink".into(), "usr/lib".into(), "/lib".into()]);
        args.extend(["--symlink".into(), "usr/lib64".into(), "/lib64".into()]);
        let ancestor = root.join("deep");
        args.extend([
            "--".into(),
            "/bin/sh".into(),
            "-c".into(),
            format!("stat -c %a {}", ancestor.display()),
        ]);
        let out = std::process::Command::new("bwrap").args(&args).output().unwrap();
        assert!(
            out.status.success(),
            "bwrap must build this jail, or the test proves nothing: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let mode = String::from_utf8_lossy(&out.stdout).trim().to_string();
        println!("  in-jail mode of {}: {mode}", ancestor.display());
        assert_eq!(mode, "755", "the ancestor bwrap created is not traversable by a dropped uid");
        std::fs::remove_dir_all(&root).unwrap();
    }

    fn tree(root: &std::path::Path) -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(d) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                out.push(e.path().to_string_lossy().into_owned());
                if e.path().is_dir() {
                    stack.push(e.path());
                }
            }
        }
        out.sort();
        out
    }

    /// The invariant that ACTUALLY protects, enforced rather than assumed.
    #[test]
    fn a_bind_whose_path_does_not_exist_is_refused() {
        let missing = std::path::PathBuf::from("/nonexistent-delphi-r1001/x/y");
        assert!(refuse_host_creating_bind(&[(missing, BindMode::ReadOnly)]).is_err());
        // Positive control: an existing path is admitted.
        assert!(refuse_host_creating_bind(&[(std::path::PathBuf::from("/usr"), BindMode::ReadOnly)]).is_ok());
    }

    /// D0A-R9-10. Every shape that names the daemon's runtime directory, including
    /// the ones a lexical prefix compare alone would miss (class 14 — a guard must
    /// cover all FORMS of the thing it guards).
    #[test]
    fn every_spelling_of_the_runtime_directory_is_refused() {
        for p in [
            "/run/delphi",
            "/run/delphi/alice",
            "/run/delphi/alice/approve.sock",
            "/run/delphi/../delphi/alice",
            // THE DISCRIMINATING ONE. The case above starts with the prefix
            // component-wise even UNFOLDED, so it proves nothing about normalization
            // — found by weaken (b), which did not bite until these were added.
            // These escape the prefix and re-enter, so only folding refuses them.
            "/tmp/../run/delphi/alice",
            "/run/user/../delphi/alice",
            "/run/./delphi/alice",
            "/run/delphi/alice/../alice",
        ] {
            assert!(
                refuse_denied_bind(Path::new(p), Path::new(BASE)).is_err(),
                "must refuse `{p}`"
            );
        }
    }

    /// POSITIVE CONTROL (class 35): without this, "the runtime dir is refused" cannot
    /// be told apart from "everything is refused".
    #[test]
    fn ordinary_paths_are_allowed() {
        for p in ["/home/alice/src", "/usr", "/run/user/1000", "/run/delphi-other"] {
            assert!(
                refuse_denied_bind(Path::new(p), Path::new(BASE)).is_ok(),
                "must allow `{p}`"
            );
        }
    }

    /// `/run/delphi-other` is the one a naive `starts_with` on the STRING admits as a
    /// prefix match and wrongly refuses; component-wise `starts_with` does not.
    #[test]
    fn a_sibling_sharing_a_string_prefix_is_not_refused() {
        assert!(refuse_denied_bind(Path::new("/run/delphi-other/x"), Path::new(BASE)).is_ok());
    }

    /// A symlink INTO the runtime directory is resolved and refused. This is the
    /// canonicalize leg; it does not close D0A-R9-03, whose swap happens after it.
    #[test]
    fn a_symlink_into_the_runtime_directory_is_resolved_and_refused() {
        let dir = std::env::temp_dir().join(format!("delphi-denylist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real");
        std::fs::create_dir_all(&target).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        // Base at the symlink's TARGET: the link's own path is outside it lexically,
        // so only the resolved form can refuse this.
        assert!(refuse_denied_bind(&link, &target).is_err(), "resolved form must refuse");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    use crate::action::RequiredTier;

    fn action_with(binds: Vec<(PathBuf, BindMode)>, net: NetPolicy) -> PendingAction {
        PendingAction {
            pending_id: "act-1".into(),
            preview_version: 1,
            executable_fd: std::fs::File::open("/dev/null").unwrap().into(),
            executable_digest: [0xAB; 32],
            argv: vec!["tool".into()],
            cwd: PathBuf::from("/tmp"),
            env_delta: vec![],
            fs_binds: binds,
            net_policy: net,
            timeout: Duration::from_secs(30),
            required_tier: RequiredTier::Biometric,
            script: None,
        }
    }

    /// Extract the (flag, src, dst) bind triples from a bwrap arg list.
    fn binds(args: &[String]) -> Vec<(String, String, String)> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < args.len() {
            if (args[i] == "--ro-bind" || args[i] == "--bind") && i + 2 < args.len() {
                out.push((args[i].clone(), args[i + 1].clone(), args[i + 2].clone()));
                i += 3;
            } else {
                i += 1;
            }
        }
        out
    }

    /// THE FAITHFULNESS CHECK: the args enforce EXACTLY `action`'s scope — every
    /// approved bind present with the right mode (complete), nothing beyond it (not
    /// broader), and the net policy matched. Used on both the real derivation and a
    /// broadening variant.
    fn args_enforce_scope(args: &[String], action: &PendingAction) -> bool {
        let got = binds(args);
        if got.len() != action.fs_binds.len() {
            return false; // a bind beyond (or short of) the approved scope
        }
        for (path, mode) in &action.fs_binds {
            let want_flag = match mode {
                BindMode::ReadOnly => "--ro-bind",
                BindMode::ReadWrite => "--bind",
            };
            let p = path.to_string_lossy();
            if !got.iter().any(|(f, s, d)| f == want_flag && *s == *p && *d == *p) {
                return false; // missing, or rw-where-ro
            }
        }
        let has_share_net = args.iter().any(|a| a == "--share-net");
        let has_unshare_net = args.iter().any(|a| a == "--unshare-net");
        match action.net_policy {
            // D0A-R10: both directions. `!--share-net` alone was sufficient only while
            // `--unshare-all` implied the unshare; under E the absence of BOTH flags
            // means bwrap's default, which SHARES the host network.
            NetPolicy::None if has_share_net || !has_unshare_net => return false,
            NetPolicy::Full if !has_share_net || has_unshare_net => return false,
            _ => {}
        }
        // §6 "env is scrubbed to `env_delta`" starts with dropping the daemon's own
        // environment. Nothing asserted this: removing `--clearenv` passed the whole
        // suite (D0A-R9-08 recorded the gap; the mutation audit measured it).
        if !args.iter().any(|a| a == "--clearenv") {
            return false;
        }
        // Default-deny base present. STRONGER than the old `--unshare-all` check:
        // every namespace is named, and `--unshare-user` must be ABSENT — its
        // presence would put the tool back in a one-uid namespace it cannot drop
        // out of (D0A-R9-01, leg D).
        if args.iter().any(|a| a == "--unshare-user" || a == "--unshare-all") {
            return false;
        }
        ["--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup-try"]
            .iter()
            .all(|want| args.iter().any(|a| a == want))
    }

    /// A broadening derivation (the RED variant): emits `--bind` where the scope
    /// says `--ro-bind`. Same scope, lossy translation.
    fn broadened(action: &PendingAction) -> Vec<String> {
        SandboxProfile::derive(action)
            .args()
            .iter()
            .map(|a| if a == "--ro-bind" { "--bind".to_string() } else { a.clone() })
            .collect()
    }

    /// CORRECT: the derivation enforces exactly the approved scope (ro stays ro, rw
    /// stays rw, net none has no --share-net, no extra binds).
    #[test]
    fn derivation_enforces_exactly_the_approved_scope() {
        let action = action_with(
            vec![
                (PathBuf::from("/data"), BindMode::ReadOnly),
                (PathBuf::from("/out"), BindMode::ReadWrite),
            ],
            NetPolicy::None,
        );
        assert!(
            args_enforce_scope(SandboxProfile::derive(&action).args(), &action),
            "the real derivation must enforce exactly the approved scope"
        );
    }

    /// RED-proof (same check, derivation the only variable): a broadening
    /// derivation (rw where ro) diverges — enforced exceeds approved.
    #[test]
    fn red_proof_broadening_derivation_diverges_from_approved() {
        let action = action_with(vec![(PathBuf::from("/data"), BindMode::ReadOnly)], NetPolicy::None);
        assert!(
            !args_enforce_scope(&broadened(&action), &action),
            "RED-proof: a derivation that emits --bind where the scope says --ro-bind enforces \
             a BROADER sandbox than approved — enforced != approved. The digest binds the scope \
             field; this test binds the enforcement."
        );
    }

    /// net=full is the only way to get `--share-net`; net=none never emits it.
    ///
    /// **BOTH DIRECTIONS, because the negative alone stopped being sufficient when E
    /// landed (D0A-R10).** This asserted only `!--share-net` for `None`, which was
    /// enough while `--unshare-all` supplied the unshare implicitly. E replaced that
    /// with an explicit list, so `NetPolicy::None` now depends on emitting
    /// `--unshare-net` — and bwrap's default is a SHARED network, so deleting that arm
    /// gives an approved-no-network action the host's network. Measured: the deletion
    /// passed the entire suite (scratch/d0a-mutation-audit.sh). The test did not change;
    /// what its assertion was sufficient to prove did.
    #[test]
    fn net_policy_maps_faithfully_and_cannot_express_an_allowlist() {
        let none = SandboxProfile::derive(&action_with(vec![], NetPolicy::None));
        assert!(!none.args().iter().any(|a| a == "--share-net"));
        assert!(
            none.args().iter().any(|a| a == "--unshare-net"),
            "NetPolicy::None must UNSHARE the network; bwrap shares it by default. got {:?}",
            none.args()
        );
        let full = SandboxProfile::derive(&action_with(vec![], NetPolicy::Full));
        assert!(full.args().iter().any(|a| a == "--share-net"));
        assert!(
            !full.args().iter().any(|a| a == "--unshare-net"),
            "NetPolicy::Full must not also unshare the network"
        );
        // NetPolicy has only None/Full — there is no allowlist variant to derive an
        // unenforceable scope from (F5 honesty at the type level).
    }
}
