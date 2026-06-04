// SPDX-License-Identifier: MIT

//! D-Bus Environment interface — capability #12.
//!
//! Exposes the orchestrator's [`EnvironmentMonitor`] over D-Bus. The
//! shell, the learning engine, and the orchestrator's brain all
//! consume the published state to make policy decisions.
//!
//! Interface: `org.delphi.Environment`
//!
//! SVC-2: every method enforces authorization via the shared [`AuthGuard`] on
//! its first line. The six `get_*` readers are Autonomous;
//! `set_location_label`/`remove_location_label` are Confirm. (The six
//! `#[zbus(signal)]` declarations are not inbound methods and carry no guard.)
//!
//! # Fidelity provenance (Iron Law #13)
//!
//! Every reading carries a [`Fidelity`] tag preserved verbatim in the JSON
//! under each domain object's `"fidelity"` key.
//!
//! # Signal emission
//!
//! The state-change signals are **declared** here for introspection; emission
//! is the orchestrator daemon's responsibility (it polls, diffs, and emits via
//! a [`SignalEmitter`]). The wrapper stays unit-testable without a live bus.
//!
//! Uses `std::sync::Mutex` (not `tokio::sync`) because the underlying sensor may
//! hold `!Send` types — see CLAUDE.md Section 3 rule 6.

use std::sync::{Arc, Mutex};

use tracing::info;
use zbus::message::Header;
use zbus::object_server::SignalEmitter;

use die_orchestrator::environment::{
    ActivityObservations, BatteryInfo, EnvironmentMonitor, EnvironmentState, Fidelity,
    LocationContext, MemoryInfo, ThermalInfo, TimeContext,
};

use crate::auth_guard::AuthGuard;

/// D-Bus object path for the Environment interface.
pub const PATH: &str = "/org/delphi/Environment";

/// Environment D-Bus service.
///
/// Wraps an [`EnvironmentMonitor`] in `Arc<Mutex<...>>` so D-Bus async methods
/// can lock it briefly. The Mutex is `std::sync::Mutex` because the underlying
/// sensor may not be `Send` across await points.
///
/// # Examples
///
/// ```
/// use delphi_services::environment::EnvironmentService;
/// use delphi_services::auth_guard::AuthGuard;
/// use die_orchestrator::environment::EnvironmentMonitor;
/// use std::sync::{Arc, Mutex};
///
/// let monitor = EnvironmentMonitor::new_linux();
/// let svc = EnvironmentService::new(Arc::new(Mutex::new(monitor)), Arc::new(AuthGuard::dev_in_memory()));
/// ```
pub struct EnvironmentService {
    monitor: Arc<Mutex<EnvironmentMonitor>>,
    guard: Arc<AuthGuard>,
}

impl EnvironmentService {
    /// Create a new environment service guarded by the shared [`AuthGuard`].
    #[must_use]
    pub fn new(monitor: Arc<Mutex<EnvironmentMonitor>>, guard: Arc<AuthGuard>) -> Self {
        Self { monitor, guard }
    }
}

#[zbus::interface(name = "org.delphi.Environment")]
impl EnvironmentService {
    /// Capture the full environment state. Returns a JSON-encoded
    /// [`EnvironmentState`].
    async fn get_state(
        &self,
        #[zbus(header)] header: Header<'_>,
        activity_obs_json: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("environment.get_state", &header)?;
        let obs = parse_activity_observations(&activity_obs_json)?;
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let state = monitor
            .snapshot(&obs)
            .map_err(|e| crate::error::opaque("environment read failed", e))?;
        serde_json::to_string(&environment_state_to_json(&state))
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Get just the battery sub-snapshot (empty string when no battery present).
    async fn get_battery(
        &self,
        #[zbus(header)] header: Header<'_>,
        activity_obs_json: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("environment.get_battery", &header)?;
        let obs = parse_activity_observations(&activity_obs_json)?;
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let state = monitor
            .snapshot(&obs)
            .map_err(|e| crate::error::opaque("environment read failed", e))?;
        match state.battery {
            Some(b) => serde_json::to_string(&battery_to_json(&b))
                .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}"))),
            None => Ok(String::new()),
        }
    }

    /// Get just the thermal sub-snapshot.
    async fn get_thermal(
        &self,
        #[zbus(header)] header: Header<'_>,
        activity_obs_json: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("environment.get_thermal", &header)?;
        let obs = parse_activity_observations(&activity_obs_json)?;
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let state = monitor
            .snapshot(&obs)
            .map_err(|e| crate::error::opaque("environment read failed", e))?;
        serde_json::to_string(&thermal_to_json(&state.thermal))
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Get just the memory sub-snapshot.
    async fn get_memory(
        &self,
        #[zbus(header)] header: Header<'_>,
        activity_obs_json: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("environment.get_memory", &header)?;
        let obs = parse_activity_observations(&activity_obs_json)?;
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let state = monitor
            .snapshot(&obs)
            .map_err(|e| crate::error::opaque("environment read failed", e))?;
        serde_json::to_string(&memory_to_json(&state.memory))
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Get just the time-context sub-snapshot.
    async fn get_time_context(
        &self,
        #[zbus(header)] header: Header<'_>,
        activity_obs_json: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("environment.get_time_context", &header)?;
        let obs = parse_activity_observations(&activity_obs_json)?;
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let state = monitor
            .snapshot(&obs)
            .map_err(|e| crate::error::opaque("environment read failed", e))?;
        serde_json::to_string(&time_context_to_json(&state.time))
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Get just the location sub-snapshot.
    async fn get_location(
        &self,
        #[zbus(header)] header: Header<'_>,
        activity_obs_json: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("environment.get_location", &header)?;
        let obs = parse_activity_observations(&activity_obs_json)?;
        let monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        let state = monitor
            .snapshot(&obs)
            .map_err(|e| crate::error::opaque("environment read failed", e))?;
        serde_json::to_string(&location_to_json(&state.location))
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Set a label in the location map. `key` must be `"ssid:<name>"` or
    /// `"wired:true"`. Returns `true` on success.
    async fn set_location_label(
        &self,
        #[zbus(header)] header: Header<'_>,
        key: String,
        label: String,
    ) -> zbus::fdo::Result<bool> {
        self.guard.enforce("environment.set_location_label", &header)?;
        // SVC-6-R2-3: cap BEFORE info!()/validation/store.
        crate::limits::ensure_within(&key, crate::limits::MAX_STRING_BYTES, "key")?;
        crate::limits::ensure_within(&label, crate::limits::MAX_STRING_BYTES, "label")?;
        info!(key = %key, label = %label, "D-Bus set_location_label");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        // SVC-7: the domain validates the key/label grammar.
        Ok(monitor.location_map_mut().set_label(&key, &label))
    }

    /// Remove a label from the location map. Returns `true` if the key existed.
    async fn remove_location_label(
        &self,
        #[zbus(header)] header: Header<'_>,
        key: String,
    ) -> zbus::fdo::Result<bool> {
        self.guard.enforce("environment.remove_location_label", &header)?;
        crate::limits::ensure_within(&key, crate::limits::MAX_STRING_BYTES, "key")?;
        info!(key = %key, "D-Bus remove_location_label");
        let mut monitor = self
            .monitor
            .lock()
            .map_err(|e| zbus::fdo::Error::Failed(format!("lock poisoned: {e}")))?;
        Ok(monitor.location_map_mut().remove_label(&key))
    }

    // ── signals (declared only; emission handled by the orchestrator daemon) ──

    /// Emitted when battery percent crosses below a configured low-power threshold.
    #[zbus(signal)]
    async fn battery_low(signal_emitter: &SignalEmitter<'_>, percent: u8) -> zbus::Result<()>;

    /// Emitted when CPU temperature crosses the throttling threshold.
    #[zbus(signal)]
    async fn thermal_warning(
        signal_emitter: &SignalEmitter<'_>,
        temp_celsius: f64,
        fidelity: &str,
    ) -> zbus::Result<()>;

    /// Emitted when memory pressure transitions to High or Critical.
    #[zbus(signal)]
    async fn memory_pressure_high(
        signal_emitter: &SignalEmitter<'_>,
        level: &str,
        fidelity: &str,
    ) -> zbus::Result<()>;

    /// Emitted when the time band transitions (e.g. Morning → Midday).
    #[zbus(signal)]
    async fn time_band_changed(
        signal_emitter: &SignalEmitter<'_>,
        new_band: &str,
    ) -> zbus::Result<()>;

    /// Emitted when the resolved location label changes.
    #[zbus(signal)]
    async fn location_changed(
        signal_emitter: &SignalEmitter<'_>,
        new_label: &str,
    ) -> zbus::Result<()>;

    /// Emitted when the classified activity state changes.
    #[zbus(signal)]
    async fn activity_state_changed(
        signal_emitter: &SignalEmitter<'_>,
        new_state: &str,
    ) -> zbus::Result<()>;
}

// ────────────────────────────────────────────────────────────────────
// JSON helpers
// ────────────────────────────────────────────────────────────────────

fn fidelity_str(f: Fidelity) -> &'static str {
    f.as_str()
}

fn battery_to_json(b: &BatteryInfo) -> serde_json::Value {
    serde_json::json!({
        "percent": b.percent,
        "state": b.state.as_str(),
        "time_remaining_sec": b.time_remaining_sec,
        "fidelity": fidelity_str(b.fidelity),
    })
}

fn thermal_to_json(t: &ThermalInfo) -> serde_json::Value {
    serde_json::json!({
        "cpu_temp_celsius": t.cpu_temp_celsius,
        "throttling": t.throttling,
        "fidelity": fidelity_str(t.fidelity),
    })
}

fn memory_to_json(m: &MemoryInfo) -> serde_json::Value {
    serde_json::json!({
        "total_kb": m.total_kb,
        "available_kb": m.available_kb,
        "pressure_level": m.pressure_level.as_str(),
        "psi_some_avg10": m.psi_some_avg10,
        "fidelity": fidelity_str(m.fidelity),
    })
}

fn time_context_to_json(t: &TimeContext) -> serde_json::Value {
    serde_json::json!({
        "band": t.band.as_str(),
        "is_weekend": t.is_weekend,
        "local_datetime": t.local_datetime.to_rfc3339(),
    })
}

fn location_to_json(l: &LocationContext) -> serde_json::Value {
    serde_json::json!({
        "label": l.label,
        "wifi_ssid": l.wifi_ssid,
        "on_wired": l.on_wired,
        "fidelity": fidelity_str(l.fidelity),
    })
}

fn environment_state_to_json(s: &EnvironmentState) -> serde_json::Value {
    serde_json::json!({
        "captured_at": s.captured_at.to_rfc3339(),
        "battery": s.battery.as_ref().map(battery_to_json),
        "thermal": thermal_to_json(&s.thermal),
        "memory": memory_to_json(&s.memory),
        "disk_usage_percent": s.disk_usage_percent,
        "disk_fidelity": fidelity_str(s.disk_fidelity),
        "time": time_context_to_json(&s.time),
        "location": location_to_json(&s.location),
        "activity": s.activity.as_str(),
    })
}

/// Parse [`ActivityObservations`] from a JSON object string. Accepts the empty
/// string as a sentinel for the zeroed default.
fn parse_activity_observations(json: &str) -> zbus::fdo::Result<ActivityObservations> {
    if json.is_empty() {
        return Ok(ActivityObservations::default());
    }
    crate::limits::ensure_within(json, crate::limits::MAX_STRING_BYTES, "activity_obs_json")?;
    serde_json::from_str(json).map_err(|e| {
        zbus::fdo::Error::InvalidArgs(format!("invalid activity observations JSON: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use die_orchestrator::environment::{
        ActivityState, EnvironmentSensor, MemoryInfo, PowerState, PressureLevel, ThermalInfo,
    };

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    struct StubSensor {
        battery: Option<BatteryInfo>,
        thermal: ThermalInfo,
        memory: MemoryInfo,
        wifi: (Option<String>, Fidelity),
        wired: bool,
    }

    impl StubSensor {
        fn rich() -> Self {
            Self {
                battery: Some(BatteryInfo {
                    percent: 75,
                    state: PowerState::Battery,
                    time_remaining_sec: Some(7200),
                    fidelity: Fidelity::Direct,
                }),
                thermal: ThermalInfo {
                    cpu_temp_celsius: Some(55.0),
                    throttling: false,
                    fidelity: Fidelity::Direct,
                },
                memory: MemoryInfo {
                    total_kb: 16_000_000,
                    available_kb: 8_000_000,
                    pressure_level: PressureLevel::Normal,
                    psi_some_avg10: Some(0.0),
                    fidelity: Fidelity::Direct,
                },
                wifi: (Some("home-net".to_string()), Fidelity::Subprocess),
                wired: false,
            }
        }

        fn no_battery() -> Self {
            let mut s = Self::rich();
            s.battery = None;
            s
        }
    }

    impl EnvironmentSensor for StubSensor {
        fn read_battery(&self) -> Result<Option<BatteryInfo>, die_orchestrator::OrchestratorError> {
            Ok(self.battery.clone())
        }
        fn read_thermal(&self) -> Result<ThermalInfo, die_orchestrator::OrchestratorError> {
            Ok(self.thermal.clone())
        }
        fn read_memory(&self) -> Result<MemoryInfo, die_orchestrator::OrchestratorError> {
            Ok(self.memory.clone())
        }
        fn read_disk_usage(
            &self,
        ) -> Result<(Option<u8>, Fidelity), die_orchestrator::OrchestratorError> {
            Ok((Some(42), Fidelity::Subprocess))
        }
        fn read_wifi_ssid(
            &self,
        ) -> Result<(Option<String>, Fidelity), die_orchestrator::OrchestratorError> {
            Ok(self.wifi.clone())
        }
        fn read_on_wired(&self) -> Result<bool, die_orchestrator::OrchestratorError> {
            Ok(self.wired)
        }
    }

    fn guard(policy: AuthPolicy) -> Arc<AuthGuard> {
        Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(fortress::audit::AuditLog::in_memory())),
        ))
    }

    fn mk_svc_rich() -> EnvironmentService {
        let monitor = EnvironmentMonitor::with_sensor(Box::new(StubSensor::rich()));
        EnvironmentService::new(Arc::new(Mutex::new(monitor)), guard(AuthPolicy::dev()))
    }

    fn mk_svc_no_battery() -> EnvironmentService {
        let monitor = EnvironmentMonitor::with_sensor(Box::new(StubSensor::no_battery()));
        EnvironmentService::new(Arc::new(Mutex::new(monitor)), guard(AuthPolicy::dev()))
    }

    fn mk_svc_deployed() -> EnvironmentService {
        let monitor = EnvironmentMonitor::with_sensor(Box::new(StubSensor::rich()));
        EnvironmentService::new(Arc::new(Mutex::new(monitor)), guard(AuthPolicy::deployed()))
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
        assert!(PATH.ends_with("Environment"));
    }

    #[test]
    fn service_creation() {
        let _ = mk_svc_rich();
    }

    #[tokio::test]
    async fn get_state_returns_full_json_shape() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let json = svc.get_state(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""captured_at":"#));
        assert!(json.contains(r#""thermal":"#));
        assert!(json.contains(r#""memory":"#));
        assert!(json.contains(r#""location":"#));
        assert!(json.contains(r#""activity":"#));
        assert!(json.contains(r#""disk_usage_percent":42"#));
        assert!(json.contains(r#""disk_fidelity":"subprocess""#));
    }

    #[tokio::test]
    async fn get_state_handles_default_observations() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let json = svc.get_state(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""activity":"unknown""#));
    }

    #[tokio::test]
    async fn get_state_uses_provided_observations() {
        let svc = mk_svc_rich();
        let obs = ActivityObservations {
            keystrokes_last_minute: 60,
            active_window_switches_last_minute: 2,
            ..Default::default()
        };
        let m = msg(":1.5");
        let json = svc
            .get_state(m.header(), serde_json::to_string(&obs).unwrap())
            .await
            .unwrap();
        assert!(json.contains(r#""activity":"deep_work""#));
    }

    #[tokio::test]
    async fn get_state_rejects_malformed_observations_json() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let err = svc.get_state(m.header(), "not-json".to_string()).await.unwrap_err();
        assert!(err.to_string().to_lowercase().contains("invalid"));
    }

    #[tokio::test]
    async fn get_battery_returns_json_when_present() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let json = svc.get_battery(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""percent":75"#));
        assert!(json.contains(r#""state":"battery""#));
        assert!(json.contains(r#""time_remaining_sec":7200"#));
        assert!(json.contains(r#""fidelity":"direct""#));
    }

    #[tokio::test]
    async fn get_battery_returns_empty_string_when_absent() {
        let svc = mk_svc_no_battery();
        let m = msg(":1.5");
        let json = svc.get_battery(m.header(), String::new()).await.unwrap();
        assert!(json.is_empty());
    }

    #[tokio::test]
    async fn get_thermal_returns_fidelity_tagged_json() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let json = svc.get_thermal(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""cpu_temp_celsius":55.0"#));
        assert!(json.contains(r#""throttling":false"#));
        assert!(json.contains(r#""fidelity":"direct""#));
    }

    #[tokio::test]
    async fn get_memory_returns_pressure_level_string() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let json = svc.get_memory(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""pressure_level":"normal""#));
        assert!(json.contains(r#""total_kb":16000000"#));
        assert!(json.contains(r#""psi_some_avg10":0.0"#));
        assert!(json.contains(r#""fidelity":"direct""#));
    }

    #[tokio::test]
    async fn get_time_context_returns_band_and_weekend_flag() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let json = svc.get_time_context(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""band":"#));
        assert!(json.contains(r#""is_weekend":"#));
        assert!(json.contains(r#""local_datetime":"#));
    }

    #[tokio::test]
    async fn get_location_returns_ssid_and_fidelity() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let json = svc.get_location(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""wifi_ssid":"home-net""#));
        assert!(json.contains(r#""fidelity":"subprocess""#));
        assert!(json.contains(r#""on_wired":false"#));
    }

    #[tokio::test]
    async fn set_location_label_persists_across_calls() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let ok = svc
            .set_location_label(m.header(), "ssid:home-net".to_string(), "home".to_string())
            .await
            .unwrap();
        assert!(ok);
        let m = msg(":1.5");
        let json = svc.get_location(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""label":"home""#));
    }

    #[tokio::test]
    async fn set_location_label_rejects_invalid_key() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let ok = svc
            .set_location_label(m.header(), "evil:key".to_string(), "x".to_string())
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn remove_location_label_returns_true_on_existing_key() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        svc.set_location_label(m.header(), "ssid:home-net".to_string(), "home".to_string())
            .await
            .unwrap();
        let m = msg(":1.5");
        let removed = svc
            .remove_location_label(m.header(), "ssid:home-net".to_string())
            .await
            .unwrap();
        assert!(removed);
        let m = msg(":1.5");
        let json = svc.get_location(m.header(), String::new()).await.unwrap();
        assert!(json.contains(r#""label":null"#));
    }

    #[tokio::test]
    async fn remove_location_label_returns_false_on_missing_key() {
        let svc = mk_svc_rich();
        let m = msg(":1.5");
        let removed = svc
            .remove_location_label(m.header(), "ssid:never-set".to_string())
            .await
            .unwrap();
        assert!(!removed);
    }

    #[tokio::test]
    async fn get_state_reports_idle_when_observations_say_idle() {
        let svc = mk_svc_rich();
        let obs = ActivityObservations {
            seconds_since_last_input: 9_999,
            ..Default::default()
        };
        let m = msg(":1.5");
        let json = svc
            .get_state(m.header(), serde_json::to_string(&obs).unwrap())
            .await
            .unwrap();
        assert!(json.contains(&format!(r#""activity":"{}""#, ActivityState::Idle.as_str())));
    }

    #[tokio::test]
    async fn get_state_reports_meeting_when_microphone_in_use() {
        let svc = mk_svc_rich();
        let obs = ActivityObservations {
            microphone_in_use: true,
            ..Default::default()
        };
        let m = msg(":1.5");
        let json = svc
            .get_state(m.header(), serde_json::to_string(&obs).unwrap())
            .await
            .unwrap();
        assert!(json.contains(r#""activity":"meeting""#));
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter is capped at the boundary
    /// (after the SVC-2 guard).
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc_rich();
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);

        for getter in ["state", "battery", "thermal", "memory", "time", "location"] {
            let m = msg(":1.5");
            let err = match getter {
                "state" => svc.get_state(m.header(), oversize.clone()).await,
                "battery" => svc.get_battery(m.header(), oversize.clone()).await,
                "thermal" => svc.get_thermal(m.header(), oversize.clone()).await,
                "memory" => svc.get_memory(m.header(), oversize.clone()).await,
                "time" => svc.get_time_context(m.header(), oversize.clone()).await,
                _ => svc.get_location(m.header(), oversize.clone()).await,
            };
            assert!(matches!(err.unwrap_err(), zbus::fdo::Error::InvalidArgs(_)), "{getter}");
        }
        let m = msg(":1.5");
        assert!(matches!(
            svc.set_location_label(m.header(), oversize.clone(), "label".to_string())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.set_location_label(m.header(), "ssid:home".to_string(), oversize.clone())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.remove_location_label(m.header(), oversize).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    // ── SVC-2 completeness (Decision 3) ──

    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let svc = mk_svc_rich();
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_all_methods_classified("environment", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc_deployed();
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("GetState");
        let m = msg(":1.999");
        assert!(matches!(svc.get_state(m.header(), String::new()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetBattery");
        let m = msg(":1.999");
        assert!(matches!(svc.get_battery(m.header(), String::new()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetThermal");
        let m = msg(":1.999");
        assert!(matches!(svc.get_thermal(m.header(), String::new()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetMemory");
        let m = msg(":1.999");
        assert!(matches!(svc.get_memory(m.header(), String::new()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetTimeContext");
        let m = msg(":1.999");
        assert!(matches!(svc.get_time_context(m.header(), String::new()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("GetLocation");
        let m = msg(":1.999");
        assert!(matches!(svc.get_location(m.header(), String::new()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("SetLocationLabel");
        let m = msg(":1.999");
        assert!(matches!(svc.set_location_label(m.header(), "ssid:x".to_string(), "l".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));
        exercised.push("RemoveLocationLabel");
        let m = msg(":1.999");
        assert!(matches!(svc.remove_location_label(m.header(), "ssid:x".to_string()).await.unwrap_err(), zbus::fdo::Error::AccessDenied(_)));

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("environment", &xml, &exercised);
    }
}
