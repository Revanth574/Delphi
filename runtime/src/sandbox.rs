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

impl SandboxProfile {
    /// Derive the default-deny profile from `action`'s approved scope.
    ///
    /// Default-deny base: `--unshare-all` (all namespaces, incl. net),
    /// `--die-with-parent`, `--new-session` (detach the controlling tty),
    /// `--clearenv`. Then exactly the approved `fs_binds` (`--ro-bind`/`--bind`),
    /// the `env_delta`, `--chdir`, and `--share-net` **only** for `NetPolicy::Full`.
    #[must_use]
    pub fn derive(action: &PendingAction) -> Self {
        let mut args = vec![
            "--unshare-all".to_string(),
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
        if matches!(action.net_policy, NetPolicy::Full) {
            args.push("--share-net".to_string());
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
        args.iter().any(|a| a == "--unshare-all") // default-deny base present
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
