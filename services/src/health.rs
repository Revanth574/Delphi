// SPDX-License-Identifier: MIT

//! D-Bus Health interface — capability #13 (predictive crisis prevention).
//!
//! Exposes the orchestrator's [`CrisisMonitor`] over D-Bus.
//!
//! Interface: `org.delphi.Health`
//!
//! SVC-2: every method enforces authorization via the shared [`AuthGuard`] on
//! its first line. The five read/check methods are Autonomous;
//! `add_watched_repo`/`remove_watched_repo`/`add_expected_network_destination`
//! are Confirm. (The two `#[zbus(signal)]` declarations carry no guard.)
//!
//! # Fidelity provenance (Iron Law #13)
//!
//! Every finding carries a [`Fidelity`] tag preserved verbatim in JSON under
//! each finding's `"fidelity"` key.
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because the underlying
//! [`GoalStore`] is `!Send` across await points — see CLAUDE.md Section 3 rule 6.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;

use die_orchestrator::goals::GoalStore;
use die_orchestrator::health::{HealthFinding, Severity};
use die_orchestrator::risk::{CrisisMonitor, GoalRiskMonitor, check_all_with_goals};

use crate::auth_guard::AuthGuard;

/// D-Bus object path for the Health interface.
pub const PATH: &str = "/org/delphi/Health";

/// Health D-Bus service.
///
/// # Examples
///
/// ```
/// use delphi_services::health::HealthService;
/// use delphi_services::auth_guard::AuthGuard;
/// use die_orchestrator::risk::CrisisMonitor;
/// use die_orchestrator::goals::GoalStore;
/// use std::sync::{Arc, Mutex};
///
/// let svc = HealthService::new(
///     Arc::new(Mutex::new(CrisisMonitor::new())),
///     Arc::new(Mutex::new(GoalStore::in_memory().unwrap())),
///     Arc::new(AuthGuard::dev_in_memory()),
/// );
/// ```
pub struct HealthService {
    monitor: Arc<Mutex<CrisisMonitor>>,
    goals: Arc<Mutex<GoalStore>>,
    goal_monitor: GoalRiskMonitor,
    guard: Arc<AuthGuard>,
}

impl HealthService {
    #[must_use]
    pub fn new(
        monitor: Arc<Mutex<CrisisMonitor>>,
        goals: Arc<Mutex<GoalStore>>,
        guard: Arc<AuthGuard>,
    ) -> Self {
        Self {
            monitor,
            goals,
            goal_monitor: GoalRiskMonitor::new(),
            guard,
        }
    }
}

#[zbus::interface(name = "org.delphi.Health")]
impl HealthService {
    /// Run all monitors (cheap + subprocess) and return findings as a JSON array.
    async fn check_all(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        self.guard.enforce("health.check_all", &header)?;
        info!("D-Bus check_all");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let goals = self
            .goals
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("goals lock poisoned: {e}")))?;
        let findings = check_all_with_goals(&mut monitor, &self.goal_monitor, &goals);
        serialize_findings(&findings)
    }

    /// Run only the cheap monitors (no subprocess shell-outs).
    async fn check_quick(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        self.guard.enforce("health.check_quick", &header)?;
        info!("D-Bus check_quick");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let findings = monitor.check_quick();
        serialize_findings(&findings)
    }

    /// Disk-only findings (SMART probe).
    async fn get_disk_health(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        self.guard.enforce("health.get_disk_health", &header)?;
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let findings = monitor.disk.check();
        serialize_findings(&findings)
    }

    /// Project-only findings (git + goal deadlines).
    async fn get_project_risk(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        self.guard.enforce("health.get_project_risk", &header)?;
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let goals = self
            .goals
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("goals lock poisoned: {e}")))?;
        let mut findings = monitor.git.check_paths(&monitor.watch_paths);
        findings.extend(self.goal_monitor.check(&goals));
        serialize_findings(&findings)
    }

    /// Security-only findings (network + USB).
    async fn get_security_risk(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        self.guard.enforce("health.get_security_risk", &header)?;
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let mut findings = monitor.network.check();
        findings.extend(monitor.usb.check());
        serialize_findings(&findings)
    }

    /// Register a git repo for monitoring. Returns `true` if newly added.
    async fn add_watched_repo(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: String,
    ) -> zbus::fdo::Result<bool> {
        self.guard.enforce("health.add_watched_repo", &header)?;
        crate::limits::ensure_within(&path, crate::limits::MAX_STRING_BYTES, "path")?;
        info!(path = %path, "D-Bus add_watched_repo");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let p = PathBuf::from(&path);
        let was_present = monitor.watch_paths.contains(&p);
        monitor.watch_repo(p);
        Ok(!was_present)
    }

    /// Stop monitoring a git repo. Returns `true` if the path was removed.
    async fn remove_watched_repo(
        &self,
        #[zbus(header)] header: Header<'_>,
        path: String,
    ) -> zbus::fdo::Result<bool> {
        self.guard.enforce("health.remove_watched_repo", &header)?;
        crate::limits::ensure_within(&path, crate::limits::MAX_STRING_BYTES, "path")?;
        info!(path = %path, "D-Bus remove_watched_repo");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        Ok(monitor.unwatch_repo(std::path::Path::new(&path)))
    }

    /// Add a network destination to the allowed list.
    async fn add_expected_network_destination(
        &self,
        #[zbus(header)] header: Header<'_>,
        host: String,
        purpose: String,
    ) -> zbus::fdo::Result<bool> {
        self.guard
            .enforce("health.add_expected_network_destination", &header)?;
        crate::limits::ensure_within(&host, crate::limits::MAX_STRING_BYTES, "host")?;
        crate::limits::ensure_within(&purpose, crate::limits::MAX_STRING_BYTES, "purpose")?;
        info!(host = %host, purpose = %purpose, "D-Bus add_expected_network_destination");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        monitor.network.add_expected(&host, &purpose);
        Ok(true)
    }

    // ── signals (declared only; emission deferred to daemon) ────────

    /// Emitted when a new finding crosses one of the monitors.
    #[zbus(signal)]
    async fn health_finding_detected(
        signal_emitter: &SignalEmitter<'_>,
        component: &str,
        severity: &str,
        message: &str,
    ) -> zbus::Result<()>;

    /// Emitted when a baseline accumulates enough samples to be trusted.
    #[zbus(signal)]
    async fn baseline_established(
        signal_emitter: &SignalEmitter<'_>,
        component: &str,
        sample_count: u32,
    ) -> zbus::Result<()>;
}

// ────────────────────────────────────────────────────────────────────
// JSON helpers
// ────────────────────────────────────────────────────────────────────

fn serialize_findings(findings: &[HealthFinding]) -> zbus::fdo::Result<String> {
    let arr: Vec<serde_json::Value> = findings.iter().map(finding_to_json).collect();
    serde_json::to_string(&arr)
        .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
}

fn finding_to_json(f: &HealthFinding) -> serde_json::Value {
    serde_json::json!({
        "component": f.component,
        "severity": severity_str(f.severity),
        "message": f.message,
        "recommendation": f.recommendation,
        "fidelity": f.fidelity.as_str(),
        "detected_at": f.detected_at.to_rfc3339(),
        "baseline_context": f.baseline_context,
    })
}

fn severity_str(s: Severity) -> &'static str {
    s.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;
    use die_orchestrator::environment::Fidelity;
    use die_orchestrator::health::{HealthFinding, Severity};

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    fn guard(policy: AuthPolicy) -> Arc<AuthGuard> {
        Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(fortress::audit::AuditLog::in_memory())),
        ))
    }

    fn mk_svc() -> HealthService {
        mk_svc_with(AuthPolicy::dev())
    }

    fn mk_svc_with(policy: AuthPolicy) -> HealthService {
        let monitor = CrisisMonitor::new();
        let store = GoalStore::in_memory().unwrap();
        HealthService::new(
            Arc::new(Mutex::new(monitor)),
            Arc::new(Mutex::new(store)),
            guard(policy),
        )
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
        assert!(PATH.ends_with("Health"));
    }

    #[test]
    fn service_creation() {
        let _ = mk_svc();
    }

    #[test]
    fn finding_to_json_includes_fidelity_provenance() {
        let f = HealthFinding::now(
            "disk:/dev/sda",
            Severity::Warning,
            "msg",
            "rec",
            Fidelity::Subprocess,
        );
        let v = finding_to_json(&f);
        assert_eq!(v["component"], "disk:/dev/sda");
        assert_eq!(v["severity"], "warning");
        assert_eq!(v["fidelity"], "subprocess");
        assert!(v["detected_at"].is_string());
    }

    #[test]
    fn serialize_findings_empty_yields_empty_array() {
        let s = serialize_findings(&[]).unwrap();
        assert_eq!(s, "[]");
    }

    #[test]
    fn serialize_findings_preserves_order() {
        let a = HealthFinding::now("a", Severity::Info, "m", "r", Fidelity::Direct);
        let b = HealthFinding::now("b", Severity::Critical, "m", "r", Fidelity::Direct);
        let s = serialize_findings(&[a, b]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v[0]["component"], "a");
        assert_eq!(v[1]["component"], "b");
        assert_eq!(v[1]["severity"], "critical");
    }

    #[tokio::test]
    async fn check_quick_returns_array() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let s = svc.check_quick(m.header()).await.unwrap();
        assert!(s.starts_with('['));
        assert!(s.ends_with(']'));
    }

    #[tokio::test]
    async fn check_all_returns_array() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let s = svc.check_all(m.header()).await.unwrap();
        assert!(s.starts_with('['));
    }

    #[tokio::test]
    async fn get_disk_health_returns_array() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let s = svc.get_disk_health(m.header()).await.unwrap();
        assert!(s.starts_with('['));
    }

    #[tokio::test]
    async fn get_project_risk_returns_array() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let s = svc.get_project_risk(m.header()).await.unwrap();
        assert!(s.starts_with('['));
    }

    #[tokio::test]
    async fn get_security_risk_returns_array() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let s = svc.get_security_risk(m.header()).await.unwrap();
        assert!(s.starts_with('['));
    }

    #[tokio::test]
    async fn add_watched_repo_returns_true_first_time() {
        let svc = mk_svc();
        let m = msg(":1.5");
        assert!(svc.add_watched_repo(m.header(), "/repo1".to_string()).await.unwrap());
        let m = msg(":1.5");
        assert!(!svc.add_watched_repo(m.header(), "/repo1".to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn remove_watched_repo_returns_true_on_existing() {
        let svc = mk_svc();
        let m = msg(":1.5");
        svc.add_watched_repo(m.header(), "/repo1".to_string()).await.unwrap();
        let m = msg(":1.5");
        assert!(svc.remove_watched_repo(m.header(), "/repo1".to_string()).await.unwrap());
        let m = msg(":1.5");
        assert!(!svc.remove_watched_repo(m.header(), "/repo1".to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn add_expected_network_destination_returns_true() {
        let svc = mk_svc();
        let m = msg(":1.5");
        let ok = svc
            .add_expected_network_destination(m.header(), "1.2.3.4".to_string(), "test".to_string())
            .await
            .unwrap();
        assert!(ok);
    }

    #[tokio::test]
    async fn project_risk_includes_overdue_goal() {
        let svc = mk_svc();
        {
            let store = svc.goals.lock().unwrap();
            let id = store
                .create_goal("Late", "x", die_orchestrator::goals::Priority::High, None)
                .unwrap();
            let past = chrono::Utc::now() - chrono::Duration::days(5);
            let patch = die_orchestrator::goals::GoalPatch {
                deadline: Some(Some(past)),
                ..Default::default()
            };
            store.update_goal(id, patch).unwrap();
        }
        let m = msg(":1.5");
        let s = svc.get_project_risk(m.header()).await.unwrap();
        assert!(s.contains(r#""severity":"critical""#));
        assert!(s.contains("passed"));
    }

    #[tokio::test]
    async fn project_risk_skips_far_future_goal() {
        let svc = mk_svc();
        {
            let store = svc.goals.lock().unwrap();
            let id = store
                .create_goal("Way out", "x", die_orchestrator::goals::Priority::Low, None)
                .unwrap();
            let far = chrono::Utc::now() + chrono::Duration::days(60);
            let patch = die_orchestrator::goals::GoalPatch {
                deadline: Some(Some(far)),
                ..Default::default()
            };
            store.update_goal(id, patch).unwrap();
        }
        let m = msg(":1.5");
        let s = svc.get_project_risk(m.header()).await.unwrap();
        assert!(!s.contains(r#""severity":"critical""#));
        assert!(!s.contains(r#""severity":"warning""#));
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter is capped at the boundary
    /// (after the SVC-2 guard).
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc();
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);

        let m = msg(":1.5");
        assert!(matches!(
            svc.add_watched_repo(m.header(), oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.remove_watched_repo(m.header(), oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.add_expected_network_destination(m.header(), oversize.clone(), "p".to_string())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.add_expected_network_destination(m.header(), "1.2.3.4".to_string(), oversize.clone())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    // ── SVC-2 completeness (Decision 3) ──

    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let svc = mk_svc();
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_all_methods_classified("health", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc_with(AuthPolicy::deployed());
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("CheckAll");
        let m = msg(":1.999");
        assert!(matches!(svc.check_all(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("CheckQuick");
        let m = msg(":1.999");
        assert!(matches!(svc.check_quick(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetDiskHealth");
        let m = msg(":1.999");
        assert!(matches!(svc.get_disk_health(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetProjectRisk");
        let m = msg(":1.999");
        assert!(matches!(svc.get_project_risk(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetSecurityRisk");
        let m = msg(":1.999");
        assert!(matches!(svc.get_security_risk(m.header()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("AddWatchedRepo");
        let m = msg(":1.999");
        assert!(matches!(svc.add_watched_repo(m.header(), "/r".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("RemoveWatchedRepo");
        let m = msg(":1.999");
        assert!(matches!(svc.remove_watched_repo(m.header(), "/r".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("AddExpectedNetworkDestination");
        let m = msg(":1.999");
        assert!(matches!(
            svc.add_expected_network_destination(m.header(), "h".to_string(), "p".to_string()).await.unwrap_err(),
            zbus::fdo::Error::AccessDenied(_)
        ));

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("health", &xml, &exercised);
    }
}
