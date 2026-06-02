// SPDX-License-Identifier: MIT

//! D-Bus ActionTimeline interface.
//!
//! Exposes the 24-hour undo timeline over D-Bus. The shell can list
//! recent actions and trigger undo operations.
//!
//! Interface: `org.delphi.Timeline`
//!
//! # SVC-2 authorization (first guarded service)
//!
//! Every method calls [`AuthGuard::enforce`](crate::auth_guard::AuthGuard::enforce)
//! on its first line, before any domain state access — the SVC-2 analog of
//! SVC-6's `ensure_within`. The `#[zbus(header)]` special argument injects the
//! message header (the caller's unique bus name) with no wire-signature change.
//! `get_recent`/`count` are `Autonomous` (proceed); `undo` is `Biometric`
//! (destructive) and proceeds with audit under the documented proceed-and-audit
//! posture (see `AuthGuard::enforce`).

use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::message::Header;

use die_orchestrator::timeline::Timeline;

use crate::auth_guard::AuthGuard;

/// D-Bus object path for the Timeline interface.
pub const PATH: &str = "/org/delphi/Timeline";

/// Timeline D-Bus service.
///
/// Wraps the orchestrator `Timeline` and exposes it over D-Bus.
/// Uses `std::sync::Mutex` instead of `tokio::sync::RwLock` because
/// `rusqlite::Connection` is `!Send`. SQLite operations are fast
/// enough that blocking is acceptable.
///
/// # Examples
///
/// ```
/// use delphi_services::timeline::TimelineService;
/// use delphi_services::auth::AuthPolicy;
/// use delphi_services::auth_guard::AuthGuard;
/// use die_orchestrator::timeline::Timeline;
/// use fortress::audit::AuditLog;
/// use std::sync::{Arc, Mutex};
///
/// let tl = Arc::new(Mutex::new(Timeline::in_memory().unwrap()));
/// let guard = Arc::new(AuthGuard::new(
///     AuthPolicy::dev(),
///     Arc::new(Mutex::new(AuditLog::in_memory())),
/// ));
/// let svc = TimelineService::new(tl, guard);
/// ```
pub struct TimelineService {
    timeline: Arc<Mutex<Timeline>>,
    /// Shared SVC-2 authorization guard (caller-identity policy + tier catalogue
    /// + audit). Every method enforces through it before touching the timeline.
    guard: Arc<AuthGuard>,
}

impl TimelineService {
    /// Create a new timeline service guarded by the shared [`AuthGuard`].
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::timeline::TimelineService;
    /// use delphi_services::auth::AuthPolicy;
    /// use delphi_services::auth_guard::AuthGuard;
    /// use die_orchestrator::timeline::Timeline;
    /// use fortress::audit::AuditLog;
    /// use std::sync::{Arc, Mutex};
    ///
    /// let svc = TimelineService::new(
    ///     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
    ///     Arc::new(AuthGuard::new(
    ///         AuthPolicy::dev(),
    ///         Arc::new(Mutex::new(AuditLog::in_memory())),
    ///     )),
    /// );
    /// ```
    #[must_use]
    pub fn new(timeline: Arc<Mutex<Timeline>>, guard: Arc<AuthGuard>) -> Self {
        Self { timeline, guard }
    }
}

#[zbus::interface(name = "org.delphi.Timeline")]
impl TimelineService {
    /// Get the most recent actions.
    ///
    /// Returns a JSON array of action records.
    async fn get_recent(
        &self,
        #[zbus(header)] header: Header<'_>,
        limit: u32,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("timeline.get_recent", &header)?;

        let tl = self.timeline.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let records = tl
            .list_recent(limit)
            .map_err(|e| crate::error::opaque("timeline operation failed", e))?;

        let json: Vec<serde_json::Value> = records
            .iter()
            .map(|r| {
                serde_json::json!({
                    "action_id": r.action_id,
                    "description": r.description,
                    "timestamp": r.timestamp,
                    "reversible": r.reversible,
                    "expires_at": r.expires_at,
                    "status": r.status.as_str(),
                })
            })
            .collect();

        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization failed: {e}")))
    }

    /// Undo an action by ID.
    ///
    /// Returns the undo command that was executed.
    async fn undo(
        &self,
        #[zbus(header)] header: Header<'_>,
        action_id: String,
    ) -> zbus::fdo::Result<String> {
        // SVC-2: authorize first (timeline.undo is the destructive Biometric
        // tier — proceed-and-audit; see AuthGuard::enforce), then cap the input.
        self.guard.enforce("timeline.undo", &header)?;
        crate::limits::ensure_within(&action_id, crate::limits::MAX_STRING_BYTES, "action_id")?;
        info!(action_id = %action_id, "D-Bus undo request");

        let tl = self.timeline.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        tl.undo_action(&action_id)
            .map_err(|e| crate::error::opaque("timeline operation failed", e))
    }

    /// Get the total action count.
    async fn count(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<u32> {
        self.guard.enforce("timeline.count", &header)?;

        let tl = self.timeline.lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let count = tl
            .count()
            .map_err(|e| crate::error::opaque("timeline operation failed", e))?;
        Ok(count as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fortress::audit::AuditLog;
    use zbus::message::Message;

    use crate::auth::AuthPolicy;

    /// Build a guarded TimelineService with the given caller-identity policy.
    fn mk_svc(policy: AuthPolicy) -> TimelineService {
        let tl = Arc::new(Mutex::new(Timeline::in_memory().unwrap()));
        let guard = Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(AuditLog::in_memory())),
        ));
        TimelineService::new(tl, guard)
    }

    /// A bus-free method-call message carrying `sender` as its unique name, so
    /// `msg.header()` yields a `Header` with that sender for guard testing.
    fn msg(sender: &str) -> Message {
        Message::method_call("/org/delphi/Timeline", "Probe")
            .unwrap()
            .sender(sender)
            .unwrap()
            .build(&())
            .unwrap()
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
    }

    #[test]
    fn service_creation() {
        let _svc = mk_svc(AuthPolicy::dev());
    }

    #[tokio::test]
    async fn get_recent_empty() {
        // Dev policy: an unrecognized caller is logged-and-allowed, so an
        // Autonomous method proceeds.
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        let json = svc.get_recent(m.header(), 10).await.unwrap();
        assert_eq!(json, "[]");
    }

    #[tokio::test]
    async fn count_starts_at_zero() {
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        let count = svc.count(m.header()).await.unwrap();
        assert_eq!(count, 0);
    }

    /// SVC-6-R2-3: undo's `action_id` is capped at the boundary. The SVC-2 guard
    /// (dev: proceed-and-audit for the Biometric tier) runs first, then the cap
    /// rejects the oversize input.
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        assert!(matches!(
            svc.undo(m.header(), oversize).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    // ── SVC-2 completeness (Decision 3) ──

    /// (a) AUTO: every method this interface exposes is classified in
    /// METHOD_POLICY. Introspect the live interface (bus-free) and check each
    /// method name against the tier catalogue. A new method added without a
    /// policy entry fails here automatically.
    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let svc = mk_svc(AuthPolicy::dev());
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        crate::auth_guard::completeness::assert_all_methods_classified("timeline", &xml);
    }

    /// (b) BEHAVIORAL: every method, invoked under the DEPLOYED deny policy by an
    /// unrecognized caller, must return `AccessDenied` — proving the guard is
    /// wired (a method missing the `enforce` call would execute instead). The
    /// `exercised` set is cross-checked against introspection
    /// ([`assert_behavioral_covers_all`]) so a method this hand-written list
    /// forgets fails loudly rather than slipping through.
    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc(AuthPolicy::deployed()); // no shell recorded → all unrecognized
        let m = msg(":1.999");
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("GetRecent");
        assert!(
            matches!(
                svc.get_recent(m.header(), 10).await.unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "get_recent must be guarded"
        );
        exercised.push("Undo");
        assert!(
            matches!(
                svc.undo(m.header(), "act-1".to_string()).await.unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "undo must be guarded"
        );
        exercised.push("Count");
        assert!(
            matches!(
                svc.count(m.header()).await.unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "count must be guarded"
        );

        // Cross-check: the behavioral set equals the introspected set.
        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        crate::auth_guard::completeness::assert_behavioral_covers_all("timeline", &xml, &exercised);
    }

    /// The destructive (Biometric) tier proceeds under proceed-and-audit in dev:
    /// `undo` is authorized-to-attempt (ConfirmationRequired), so the guard lets
    /// it through to the domain logic (here: a missing action returns a domain
    /// error, NOT AccessDenied — proving it executed past the guard).
    #[tokio::test]
    async fn undo_biometric_proceeds_under_proceed_and_audit() {
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        let err = svc.undo(m.header(), "missing-action".to_string()).await.unwrap_err();
        // Not AccessDenied: the guard proceeded (proceed-and-audit) and the
        // domain rejected the unknown action id.
        assert!(
            !matches!(err, zbus::fdo::Error::AccessDenied(_)),
            "Biometric-tier undo must proceed-and-audit in dev, not be access-denied"
        );
    }
}
