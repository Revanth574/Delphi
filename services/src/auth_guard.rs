// SPDX-License-Identifier: MIT

//! Per-method authorization guard for the D-Bus boundary (services-sweep SVC-2,
//! Stage 2).
//!
//! [`AuthGuard::enforce`] is the single seam every `#[zbus::interface]` method
//! calls on its first line — the SVC-2 analog of SVC-6's `ensure_within`. It
//! resolves the caller's identity from the message header (SVC-2 Decision 2:
//! unique-name only, no credential round-trip for general methods), runs the
//! bus-free [`authorize`] policy, records the decision to the fortress audit
//! log, and returns:
//!
//! - `Ok(())` for [`AuthOutcome::Authorized`] — proceed.
//! - `Ok(())` for [`AuthOutcome::ConfirmationRequired`] — proceed (the shell
//!   owns the confirmation UI; see the proceed-and-audit note on
//!   [`AuthGuard::enforce`]).
//! - `Err(AccessDenied)` for [`AuthOutcome::AuthorizationDenied`] — the method
//!   does NOT execute (unmapped method, or unrecognized caller under the
//!   deployed deny policy).
//!
//! The cloud-send path (SVC-1-R1-1-01) gets a SEPARATE async seam in Stage 3 —
//! it needs the credential round-trip and the same-caller-binding token check,
//! and so will hold the [`CallerResolver`](crate::caller_resolver::CallerResolver).
//! This general guard is the Stage-2 deliverable rolled across every method.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use fortress::audit::{AuditLog, AuditResult};
use fortress::permissions::PermissionTier;
use zbus::message::Header;

use crate::auth::{
    authorize, authorize_cloud_send, AuthOutcome, AuthPolicy, CallerIdentity, CloudSendConfirmations,
    MethodPolicy,
};
use crate::caller_resolver::identity_from_header;

/// The shared SVC-2 authorization guard: the caller-identity policy, the tier
/// catalogue, and the fortress audit sink. One instance is shared (`Arc`)
/// across every D-Bus service.
pub struct AuthGuard {
    policy: AuthPolicy,
    methods: MethodPolicy,
    audit: Arc<Mutex<AuditLog>>,
}

impl AuthGuard {
    /// Build a guard from a caller-identity [`AuthPolicy`] and a shared audit
    /// log. The tier catalogue is the canonical [`MethodPolicy`].
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth::AuthPolicy;
    /// use delphi_services::auth_guard::AuthGuard;
    /// use fortress::audit::AuditLog;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let guard = AuthGuard::new(
    ///     AuthPolicy::dev(),
    ///     Arc::new(Mutex::new(AuditLog::in_memory())),
    /// );
    /// let _ = guard;
    /// ```
    #[must_use]
    pub fn new(policy: AuthPolicy, audit: Arc<Mutex<AuditLog>>) -> Self {
        Self {
            policy,
            methods: MethodPolicy::from_table(),
            audit,
        }
    }

    /// Build a dev guard with an in-memory audit log — the v0.4 wiring/test
    /// convenience (log-and-allow policy, no on-disk audit). Lets callers above
    /// `fortress` (e.g. shell-bridge) construct a guard without importing
    /// [`AuditLog`]. Production wiring uses [`new`](Self::new) with the deployed
    /// policy and a persistent audit log.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::auth_guard::AuthGuard;
    /// let guard = AuthGuard::dev_in_memory();
    /// let _ = guard;
    /// ```
    #[must_use]
    pub fn dev_in_memory() -> Self {
        Self::new(AuthPolicy::dev(), Arc::new(Mutex::new(AuditLog::in_memory())))
    }

    /// Enforce SVC-2 authorization for a general (non-cloud-send) method, given
    /// its `action` string and the message `header`. Call on the FIRST line of
    /// every `#[zbus::interface]` method, before any domain state access
    /// (mirrors SVC-6's `ensure_within`).
    ///
    /// # Proceed-and-audit, and the destructive-tier gap
    ///
    /// `Authorized` and `ConfirmationRequired` both PROCEED; only
    /// `AuthorizationDenied` blocks. Per the SVC-2 design (Codex Q4) the D-Bus
    /// check authorizes *whether* the caller may attempt the action at its tier;
    /// the actual confirmation/biometric UI lives in the shell, which
    /// confirms-then-calls.
    ///
    /// **Destructive (Biometric-tier) operations proceed on caller
    /// authorization; human confirmation is enforced by the shell UI, not
    /// structurally at the D-Bus boundary. Structural confirmation-token
    /// enforcement for the destructive tier (mirroring the cloud-send
    /// same-caller-bound token model) is a future hardening, not implemented in
    /// v0.4. The standard session bus is not the security boundary in dev; in
    /// deployment, caller-identity gating plus the shell's confirmation flow are
    /// the enforcement.** (Flagged for the SVC-2 Codex review alongside the Q9
    /// recheck skip and SVC-1-R1-1-01.)
    ///
    /// # Errors
    ///
    /// Returns [`zbus::fdo::Error::AccessDenied`] when the caller is not
    /// authorized to attempt the action (unmapped method, or unrecognized caller
    /// under the deployed deny policy).
    pub fn enforce(&self, action: &'static str, header: &Header<'_>) -> zbus::fdo::Result<()> {
        let caller = identity_from_header(header);
        let outcome = authorize(action, &caller, &self.policy, &self.methods);
        self.record(action, &caller, &outcome);
        match outcome {
            AuthOutcome::Authorized | AuthOutcome::ConfirmationRequired { .. } => Ok(()),
            AuthOutcome::AuthorizationDenied { reason } => {
                Err(zbus::fdo::Error::AccessDenied(reason.to_string()))
            }
        }
    }

    /// Enforce SVC-1-R1-1-01 **same-caller binding** for *completing* a cloud
    /// send — the separate async-resolved seam this module's header promised,
    /// distinct from [`enforce`](Self::enforce)'s general tier gate. The caller
    /// must already be resolved (the cloud-send path does the credential
    /// round-trip via [`CallerResolver`](crate::caller_resolver::CallerResolver)
    /// before calling this); this method is the sync policy + audit step.
    ///
    /// `fingerprint` identifies the pending confirmation (a hash of the
    /// confirmation token — never the raw token). `confirmations` is the
    /// registry the issuing call populated via
    /// [`CloudSendConfirmations::issue`]. `now` is injected for deterministic
    /// TTL testing (live callers pass [`Instant::now`]).
    ///
    /// Delegates the decision to [`authorize_cloud_send`] (same-caller binding
    /// enforced in dev AND deployed; deployed additionally requires the
    /// authenticated shell and degrades-to-deny on missing creds), records it to
    /// the fortress audit chain, and maps:
    ///
    /// - `Authorized` → `Ok(())` (proceed to the actual send).
    /// - `AuthorizationDenied` → `Err(AccessDenied)` (the send does NOT happen —
    ///   a different caller echoing another's confirmation, an expired binding,
    ///   or deployed creds unavailable).
    ///
    /// # Errors
    ///
    /// Returns [`zbus::fdo::Error::AccessDenied`] when the completer is not the
    /// caller the confirmation was bound to (or the binding expired, or — under
    /// the deployed policy — the caller is not the authenticated shell).
    pub fn enforce_cloud_send(
        &self,
        caller: &CallerIdentity,
        fingerprint: &str,
        now: Instant,
        confirmations: &CloudSendConfirmations,
    ) -> zbus::fdo::Result<()> {
        let outcome = authorize_cloud_send(caller, fingerprint, now, confirmations, &self.policy);
        self.record("inference.cloud_send", caller, &outcome);
        match outcome {
            AuthOutcome::Authorized | AuthOutcome::ConfirmationRequired { .. } => Ok(()),
            AuthOutcome::AuthorizationDenied { reason } => {
                Err(zbus::fdo::Error::AccessDenied(reason.to_string()))
            }
        }
    }

    /// Record the decision to the fortress audit chain. `module` is the
    /// authenticated caller's unique bus name; `target` is empty — the action
    /// string already names the operation and we never log caller payloads
    /// (SVC-4 leak discipline).
    fn record(&self, action: &str, caller: &CallerIdentity, outcome: &AuthOutcome) {
        let (tier, result) = match outcome {
            AuthOutcome::Authorized => (PermissionTier::Autonomous, AuditResult::Allowed),
            AuthOutcome::ConfirmationRequired { tier, .. } => (*tier, AuditResult::Pending),
            AuthOutcome::AuthorizationDenied { .. } => (
                self.methods.tier_of(action).unwrap_or(PermissionTier::Confirm),
                AuditResult::Denied,
            ),
        };
        let mut log = self.audit.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        log.log_action(&caller.unique_name, action, "", tier, result);
    }
}

/// Shared completeness-test helpers (SVC-2 Decision 3). Reusable across every
/// service's completeness test so the mechanism is identical everywhere.
#[cfg(test)]
pub(crate) mod completeness {
    use crate::auth::METHOD_POLICY;

    /// Build a bus-free method-call message carrying `sender` as its unique bus
    /// name, for guard testing: `header_msg(":1.5").header()` yields a `Header`
    /// with that sender. The path/member are placeholders — the guard keys on
    /// the action string passed to `enforce`, not the header's member. Shared so
    /// every service's behavioral completeness test constructs headers
    /// identically.
    pub(crate) fn header_msg(sender: &str) -> zbus::message::Message {
        zbus::message::Message::method_call("/org/delphi/Probe", "Probe")
            .expect("valid path/member")
            .sender(sender)
            .expect("valid unique sender name")
            .build(&())
            .expect("empty body builds")
    }

    /// Extract D-Bus method names from an interface's introspection XML.
    pub(crate) fn method_names(introspection_xml: &str) -> Vec<String> {
        introspection_xml
            .split("<method name=\"")
            .skip(1)
            .filter_map(|s| s.split('"').next().map(str::to_string))
            .collect()
    }

    /// Convert a D-Bus PascalCase method name to its snake_case action suffix
    /// (zbus maps the Rust `get_recent` to the D-Bus `GetRecent`).
    pub(crate) fn pascal_to_snake(name: &str) -> String {
        let mut out = String::new();
        for (i, c) in name.char_indices() {
            if c.is_ascii_uppercase() {
                if i > 0 {
                    out.push('_');
                }
                out.push(c.to_ascii_lowercase());
            } else {
                out.push(c);
            }
        }
        out
    }

    /// AUTO half (Decision 3a): assert every method exposed by `introspection_xml`
    /// is classified in [`METHOD_POLICY`] under `iface` (e.g. `"timeline"`). A
    /// new method added without a tier-table entry fails here automatically.
    pub(crate) fn assert_all_methods_classified(iface: &str, introspection_xml: &str) {
        let names = method_names(introspection_xml);
        assert!(
            !names.is_empty(),
            "introspection produced no methods for {iface} — parser or XML format changed"
        );
        for name in names {
            let action = format!("{iface}.{}", pascal_to_snake(&name));
            assert!(
                METHOD_POLICY.iter().any(|(a, _)| *a == action),
                "D-Bus method {name} (action {action}) is not classified in METHOD_POLICY — \
                 every SVC-2-guarded method must have a tier (SVC-2 completeness)"
            );
        }
    }

    /// CROSS-CHECK (Decision 3, completeness-of-the-completeness-test): assert the
    /// behavioral half (b) exercised EVERY method the interface exposes.
    /// `exercised` is the set of D-Bus method names (PascalCase, as introspected)
    /// that the behavioral test invoked.
    ///
    /// Half (b) is hand-written (one denial assertion per method), so without
    /// this its coverage depends on the author remembering each method — a
    /// classified-but-unguarded method the author forgot to add to (b) would
    /// slip through. This welds (b)'s coverage to (a)'s auto-enumeration: if
    /// introspection lists a method `exercised` omits, the behavioral half is
    /// itself incomplete → FAIL loudly. Stale entries (listed but no longer
    /// introspected — e.g. a renamed method) also fail.
    pub(crate) fn assert_behavioral_covers_all(
        iface: &str,
        introspection_xml: &str,
        exercised: &[&str],
    ) {
        use std::collections::BTreeSet;
        let introspected: BTreeSet<String> = method_names(introspection_xml).into_iter().collect();
        let covered: BTreeSet<String> = exercised.iter().map(|s| (*s).to_string()).collect();

        let missing: Vec<&String> = introspected.difference(&covered).collect();
        assert!(
            missing.is_empty(),
            "behavioral completeness for {iface}: introspected methods NOT exercised by the \
             behavioral guard test: {missing:?} — add a denial assertion for each (SVC-2)"
        );
        let stale: Vec<&String> = covered.difference(&introspected).collect();
        assert!(
            stale.is_empty(),
            "behavioral test for {iface} lists methods not in introspection \
             (renamed/removed?): {stale:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::completeness::{method_names, pascal_to_snake};

    #[test]
    fn pascal_to_snake_maps_dbus_names() {
        assert_eq!(pascal_to_snake("GetRecent"), "get_recent");
        assert_eq!(pascal_to_snake("Undo"), "undo");
        assert_eq!(pascal_to_snake("Count"), "count");
        assert_eq!(pascal_to_snake("CreateFromTemplate"), "create_from_template");
    }

    #[test]
    fn method_names_parses_introspection_xml() {
        let xml = r#"<interface name="org.delphi.Timeline">
  <method name="GetRecent"><arg type="u"/></method>
  <method name="Undo"><arg type="s"/></method>
</interface>"#;
        assert_eq!(method_names(xml), vec!["GetRecent".to_string(), "Undo".to_string()]);
    }

    /// SVC-1-R1-1-01: the guard wrapper maps the same-caller-binding decision to
    /// the wire result. The deep policy matrix (TTL, deployed shell, degrade-to-
    /// deny) lives in `auth.rs`'s `authorize_cloud_send` tests; this asserts the
    /// `enforce_cloud_send` wrapper authorizes the issuing caller and returns
    /// `AccessDenied` for a different caller echoing the binding. Bus-free.
    #[test]
    fn enforce_cloud_send_binds_to_issuing_caller() {
        use super::AuthGuard;
        use crate::auth::{CallerIdentity, CloudSendConfirmations};
        use std::time::Instant;

        let guard = AuthGuard::dev_in_memory();
        let mut reg = CloudSendConfirmations::default();
        let a = CallerIdentity::from_unique_name(":1.10");
        let b = CallerIdentity::from_unique_name(":1.11");
        reg.issue("fp-token-hash", &a);

        // The issuing caller completes → authorized.
        assert!(guard
            .enforce_cloud_send(&a, "fp-token-hash", Instant::now(), &reg)
            .is_ok());
        // A different caller echoing A's confirmation → AccessDenied (the closure).
        assert!(matches!(
            guard
                .enforce_cloud_send(&b, "fp-token-hash", Instant::now(), &reg)
                .unwrap_err(),
            zbus::fdo::Error::AccessDenied(_)
        ));
        // An unbound fingerprint → AccessDenied (nothing was issued for it).
        assert!(matches!(
            guard
                .enforce_cloud_send(&a, "never-issued", Instant::now(), &reg)
                .unwrap_err(),
            zbus::fdo::Error::AccessDenied(_)
        ));
    }
}
