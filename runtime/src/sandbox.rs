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
        if candidate == base_n || candidate.starts_with(&base_n) {
            return Err(crate::RuntimeError::DeniedBind {
                path: candidate,
                base: base_n,
            });
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
/// Two exclusions, both load-bearing:
///
/// * **the bind path itself** — bwrap creates that mountpoint;
/// * **any ancestor lying inside another bind** — `--dir` there would create the
///   directory *through* the mount, in the **host** filesystem.
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
        for (path, mode) in &action.fs_binds {
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
    use super::refuse_denied_bind;
    use std::path::Path;

    const BASE: &str = "/run/delphi";

    /// Emitted `--perms MODE --dir PATH` triples, in order.
    fn emitted_dirs(args: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        while i + 3 < args.len() {
            if args[i] == "--perms" && args[i + 2] == "--dir" {
                out.push(args[i + 3].clone());
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
        match action.net_policy {
            NetPolicy::None if has_share_net => return false, // net where none
            NetPolicy::Full if !has_share_net => return false, // none where net
            _ => {}
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
    #[test]
    fn net_policy_maps_faithfully_and_cannot_express_an_allowlist() {
        let none = SandboxProfile::derive(&action_with(vec![], NetPolicy::None));
        assert!(!none.args().iter().any(|a| a == "--share-net"));
        let full = SandboxProfile::derive(&action_with(vec![], NetPolicy::Full));
        assert!(full.args().iter().any(|a| a == "--share-net"));
        // NetPolicy has only None/Full — there is no allowlist variant to derive an
        // unenforceable scope from (F5 honesty at the type level).
    }
}
