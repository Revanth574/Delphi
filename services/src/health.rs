// SPDX-License-Identifier: MIT

//! D-Bus Health interface — capability #13 (predictive crisis prevention).
//!
//! Exposes the orchestrator's [`CrisisMonitor`] over D-Bus. The shell uses
//! this to surface findings in the action timeline, the brain uses it to
//! adjust scheduling decisions when the system is under stress, and the
//! learning engine uses it to correlate user activity with crash/leak
//! events for future warnings.
//!
//! Interface: `org.delphi.Health`
//!
//! # Fidelity provenance (Iron Law #13)
//!
//! Every finding carries a [`Fidelity`] tag. Consumers can filter out
//! `Fidelity::Unavailable` findings or weight `Fidelity::Subprocess`
//! lower than `Fidelity::Direct`. JSON encoding preserves the provenance
//! verbatim under each finding's `"fidelity"` key.
//!
//! # Signal emission
//!
//! Both signals (`HealthFindingDetected`, `BaselineEstablished`) are
//! **declared** here for D-Bus introspection. **Emission** is done by
//! the orchestrator daemon, which polls [`check_all`](EnvironmentService::check_all)
//! on an interval, diffs against the previous result, and uses a
//! `SignalEmitter` to broadcast new findings. This mirrors the pattern
//! established in `goals.rs` and `environment.rs`.
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because the underlying
//! [`GoalStore`] is `!Send` across await points — see CLAUDE.md
//! Section 3 "D-Bus Service Pattern" rule 6.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::object_server::SignalEmitter;

use die_orchestrator::goals::GoalStore;
use die_orchestrator::health::{HealthFinding, Severity};
use die_orchestrator::risk::{
    CrisisMonitor, GoalRiskMonitor, check_all_with_goals,
};

/// D-Bus object path for the Health interface.
pub const PATH: &str = "/org/delphi/Health";

/// Health D-Bus service.
///
/// Wraps a [`CrisisMonitor`] plus a borrowed handle to the [`GoalStore`]
/// (so deadline-vs-progress findings can be produced alongside the rest).
/// Both are held in `Arc<Mutex<...>>` so async D-Bus methods can lock
/// briefly to read state or mutate watch lists.
///
/// # Examples
///
/// ```
/// use delphi_services::health::HealthService;
/// use die_orchestrator::risk::CrisisMonitor;
/// use die_orchestrator::goals::GoalStore;
/// use std::sync::{Arc, Mutex};
///
/// let monitor = CrisisMonitor::new();
/// let store = GoalStore::in_memory().unwrap();
/// let svc = HealthService::new(
///     Arc::new(Mutex::new(monitor)),
///     Arc::new(Mutex::new(store)),
/// );
/// ```
pub struct HealthService {
    monitor: Arc<Mutex<CrisisMonitor>>,
    goals: Arc<Mutex<GoalStore>>,
    goal_monitor: GoalRiskMonitor,
}

impl HealthService {
    #[must_use]
    pub fn new(monitor: Arc<Mutex<CrisisMonitor>>, goals: Arc<Mutex<GoalStore>>) -> Self {
        Self {
            monitor,
            goals,
            goal_monitor: GoalRiskMonitor::new(),
        }
    }
}

#[zbus::interface(name = "org.delphi.Health")]
impl HealthService {
    /// Run all monitors (cheap + subprocess) and return findings as a JSON array.
    async fn check_all(&self) -> zbus::fdo::Result<String> {
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
    async fn check_quick(&self) -> zbus::fdo::Result<String> {
        info!("D-Bus check_quick");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let findings = monitor.check_quick();
        serialize_findings(&findings)
    }

    /// Disk-only findings (SMART probe).
    async fn get_disk_health(&self) -> zbus::fdo::Result<String> {
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let findings = monitor.disk.check();
        serialize_findings(&findings)
    }

    /// Project-only findings (git + goal deadlines).
    async fn get_project_risk(&self) -> zbus::fdo::Result<String> {
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
    async fn get_security_risk(&self) -> zbus::fdo::Result<String> {
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        let mut findings = monitor.network.check();
        findings.extend(monitor.usb.check());
        serialize_findings(&findings)
    }

    /// Register a git repo for monitoring. Returns `true` if newly added,
    /// `false` if already present.
    async fn add_watched_repo(&self, path: String) -> zbus::fdo::Result<bool> {
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
    async fn remove_watched_repo(&self, path: String) -> zbus::fdo::Result<bool> {
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
        host: String,
        purpose: String,
    ) -> zbus::fdo::Result<bool> {
        info!(host = %host, purpose = %purpose, "D-Bus add_expected_network_destination");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("monitor lock poisoned: {e}")))?;
        monitor.network.add_expected(&host, &purpose);
        Ok(true)
    }

    // ── signals (declared only; emission deferred to daemon) ────────

    /// Emitted when a new finding crosses one of the monitors. The daemon
    /// diffs successive `check_all` results to decide what's "new."
    #[zbus(signal)]
    async fn health_finding_detected(
        signal_emitter: &SignalEmitter<'_>,
        component: &str,
        severity: &str,
        message: &str,
    ) -> zbus::Result<()>;

    /// Emitted when a baseline accumulates enough samples to be trusted
    /// for anomaly detection (see `BASELINE_SUFFICIENT_THRESHOLD`).
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

    fn mk_svc() -> HealthService {
        let monitor = CrisisMonitor::new();
        let store = GoalStore::in_memory().unwrap();
        HealthService::new(Arc::new(Mutex::new(monitor)), Arc::new(Mutex::new(store)))
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

    // ── JSON shape ──────────────────────────────────────────────────

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

    // ── Live-method round trips ─────────────────────────────────────

    #[tokio::test]
    async fn check_quick_returns_array() {
        let svc = mk_svc();
        let s = svc.check_quick().await.unwrap();
        assert!(s.starts_with('['));
        assert!(s.ends_with(']'));
        // Quick check on this dev box: USB empty, no leaks, network may
        // include unknown destinations — so just verify shape, not contents.
    }

    #[tokio::test]
    async fn check_all_returns_array() {
        let svc = mk_svc();
        let s = svc.check_all().await.unwrap();
        assert!(s.starts_with('['));
        // No goals in store, so no goal findings to merge.
    }

    #[tokio::test]
    async fn get_disk_health_returns_array() {
        let svc = mk_svc();
        let s = svc.get_disk_health().await.unwrap();
        assert!(s.starts_with('['));
    }

    #[tokio::test]
    async fn get_project_risk_returns_array() {
        let svc = mk_svc();
        let s = svc.get_project_risk().await.unwrap();
        assert!(s.starts_with('['));
    }

    #[tokio::test]
    async fn get_security_risk_returns_array() {
        let svc = mk_svc();
        let s = svc.get_security_risk().await.unwrap();
        assert!(s.starts_with('['));
    }

    // ── Watch list mutations ────────────────────────────────────────

    #[tokio::test]
    async fn add_watched_repo_returns_true_first_time() {
        let svc = mk_svc();
        assert!(svc.add_watched_repo("/repo1".to_string()).await.unwrap());
        assert!(!svc.add_watched_repo("/repo1".to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn remove_watched_repo_returns_true_on_existing() {
        let svc = mk_svc();
        svc.add_watched_repo("/repo1".to_string()).await.unwrap();
        assert!(svc.remove_watched_repo("/repo1".to_string()).await.unwrap());
        assert!(!svc.remove_watched_repo("/repo1".to_string()).await.unwrap());
    }

    #[tokio::test]
    async fn add_expected_network_destination_returns_true() {
        let svc = mk_svc();
        let ok = svc
            .add_expected_network_destination("1.2.3.4".to_string(), "test".to_string())
            .await
            .unwrap();
        assert!(ok);
    }

    // ── Goal-deadline integration via project risk ──────────────────

    #[tokio::test]
    async fn project_risk_includes_overdue_goal() {
        let svc = mk_svc();
        // Create a goal whose deadline is already in the past
        {
            let store = svc.goals.lock().unwrap();
            let id = store
                .create_goal(
                    "Late",
                    "x",
                    die_orchestrator::goals::Priority::High,
                    None,
                )
                .unwrap();
            let past = chrono::Utc::now() - chrono::Duration::days(5);
            let patch = die_orchestrator::goals::GoalPatch {
                deadline: Some(Some(past)),
                ..Default::default()
            };
            store.update_goal(id, patch).unwrap();
        }
        let s = svc.get_project_risk().await.unwrap();
        // An overdue goal must produce a Critical finding referencing it.
        assert!(s.contains(r#""severity":"critical""#));
        assert!(s.contains("passed"));
    }

    #[tokio::test]
    async fn project_risk_skips_far_future_goal() {
        let svc = mk_svc();
        {
            let store = svc.goals.lock().unwrap();
            let id = store
                .create_goal(
                    "Way out",
                    "x",
                    die_orchestrator::goals::Priority::Low,
                    None,
                )
                .unwrap();
            let far = chrono::Utc::now() + chrono::Duration::days(60);
            let patch = die_orchestrator::goals::GoalPatch {
                deadline: Some(Some(far)),
                ..Default::default()
            };
            store.update_goal(id, patch).unwrap();
        }
        let s = svc.get_project_risk().await.unwrap();
        // No deadline-related finding should be emitted.
        assert!(!s.contains(r#""severity":"critical""#));
        assert!(!s.contains(r#""severity":"warning""#));
    }
}
