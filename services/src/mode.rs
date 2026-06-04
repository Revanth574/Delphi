// SPDX-License-Identifier: MIT

//! D-Bus Mode interface.
//!
//! Manages per-window UI modes (Direct, Assisted, Autonomous, Focus).
//! The shell queries and sets modes via this interface.
//!
//! Interface: `org.delphi.Mode`
//!
//! # SVC-2 authorization
//!
//! Every method enforces authorization via the shared [`AuthGuard`] on its first
//! line (`mode.get_mode`/`mode.list_modes` are Autonomous; `mode.set_mode` is
//! Confirm). The `#[zbus(header)]` special argument injects the caller's unique
//! bus name with no wire-signature change.
//!
//! # Focus-mode → learning-engine arming (SVC-5-R2-1)
//!
//! Focus mode is a security-relevant state: while *any* window is in `Focus`
//! the learning engine MUST be paused — `list_suggestions` empty, `accept`
//! rejected. Round 1 shipped a [`LearningFacade`] gate that enforced these
//! invariants when armed, but nothing ARMED it: `set_mode` wrote `"Focus"`
//! into the mode map and returned, the facade stayed un-armed, and a user
//! who enabled Focus mode believed learning was suppressed when it was not
//! (Codex Round 2 SVC-5-R2-1, P1).
//!
//! The fix wires the gate from the only places that can change a window's
//! mode — this D-Bus `set_mode` AND the WebSocket bridge's `handle_mode_set`
//! — by calling [`apply_focus_from_modes`] inside each transport's
//! mode-map critical section. The helper recomputes "any window in Focus"
//! from the just-written mode map and synchronously arms the facade.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use die_orchestrator::learning::LearningFacade;
use tokio::sync::RwLock;
use tracing::info;
use zbus::message::Header;

use crate::auth_guard::AuthGuard;

/// D-Bus object path for the Mode interface.
pub const PATH: &str = "/org/delphi/Mode";

/// Valid mode names.
const VALID_MODES: &[&str] = &["Direct", "Assisted", "Autonomous", "Focus"];

/// Mode D-Bus service.
///
/// Tracks the UI mode for each window by ID and, on every mode change,
/// recomputes whether any window is in `Focus` and arms the shared
/// [`LearningFacade`] accordingly.
///
/// # Examples
///
/// ```
/// use delphi_services::mode::ModeService;
/// use delphi_services::auth_guard::AuthGuard;
/// use die_orchestrator::learning::LearningFacade;
/// use std::sync::{Arc, Mutex};
/// use tokio::sync::RwLock;
/// use std::collections::HashMap;
///
/// let modes = Arc::new(RwLock::new(HashMap::new()));
/// let learning = Arc::new(Mutex::new(LearningFacade::in_memory().unwrap()));
/// let svc = ModeService::new(modes, learning, Arc::new(AuthGuard::dev_in_memory()));
/// ```
pub struct ModeService {
    /// Map of `window_id → mode name`.
    modes: Arc<RwLock<HashMap<String, String>>>,
    /// Shared learning facade. Mode changes arm/disarm Focus on it
    /// (SVC-5-R2-1). Held as `Arc<std::sync::Mutex<...>>` — `std::Mutex`
    /// because the facade embeds a `!Send` `rusqlite::Connection`; no
    /// method holds this lock across an `.await`.
    learning: Arc<StdMutex<LearningFacade>>,
    /// Shared SVC-2 authorization guard.
    guard: Arc<AuthGuard>,
}

impl ModeService {
    /// Create a new mode service that arms `learning` on every mode change and
    /// authorizes every method through the shared [`AuthGuard`].
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::mode::ModeService;
    /// use delphi_services::auth_guard::AuthGuard;
    /// use die_orchestrator::learning::LearningFacade;
    /// use std::sync::{Arc, Mutex};
    /// use tokio::sync::RwLock;
    /// use std::collections::HashMap;
    ///
    /// let svc = ModeService::new(
    ///     Arc::new(RwLock::new(HashMap::new())),
    ///     Arc::new(Mutex::new(LearningFacade::in_memory().unwrap())),
    ///     Arc::new(AuthGuard::dev_in_memory()),
    /// );
    /// ```
    #[must_use]
    pub fn new(
        modes: Arc<RwLock<HashMap<String, String>>>,
        learning: Arc<StdMutex<LearningFacade>>,
        guard: Arc<AuthGuard>,
    ) -> Self {
        Self {
            modes,
            learning,
            guard,
        }
    }
}

#[zbus::interface(name = "org.delphi.Mode")]
impl ModeService {
    /// Get the current mode for a window.
    ///
    /// Returns "Direct" if the window has no mode set.
    async fn get_mode(
        &self,
        #[zbus(header)] header: Header<'_>,
        window_id: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("mode.get_mode", &header)?;
        // SVC-6-R2-3: cap window_id before using it as a HashMap key.
        crate::limits::ensure_within(
            &window_id,
            crate::limits::MAX_STRING_BYTES,
            "window_id",
        )?;
        let modes = self.modes.read().await;
        Ok(modes
            .get(&window_id)
            .cloned()
            .unwrap_or_else(|| "Direct".to_string()))
    }

    /// Set the mode for a window.
    ///
    /// Valid modes: Direct, Assisted, Autonomous, Focus. On every successful
    /// update the [`LearningFacade`] is armed/disarmed via
    /// [`apply_focus_from_modes`] inside the same mode-map critical section
    /// (SVC-5-R2-1), so a Focus transition immediately suppresses learning
    /// observation and rejects suggestion-accept attempts.
    ///
    /// Declared `pub` so cross-crate integration tests (notably the
    /// shell-bridge `focus_arms_facade_through_both_transports` test) can
    /// drive the D-Bus path directly without spinning up a real
    /// `zbus::Connection` — they then assert the facade was armed.
    pub async fn set_mode(
        &self,
        #[zbus(header)] header: Header<'_>,
        window_id: String,
        mode: String,
    ) -> zbus::fdo::Result<()> {
        // SVC-2: authorize first (mode.set_mode is the Confirm tier — proceed-
        // and-audit; the shell owns the confirmation UI).
        self.guard.enforce("mode.set_mode", &header)?;
        // SVC-6-R2-3: cap every String param BEFORE any validation, log, or
        // mode-map mutation. A multi-MiB `mode` would still be rejected by
        // the VALID_MODES list-equality check (the equality fast-paths on
        // length), but capping first keeps the policy uniform across all
        // methods and avoids any DoS amplification on the bus.
        crate::limits::ensure_within(
            &window_id,
            crate::limits::MAX_STRING_BYTES,
            "window_id",
        )?;
        crate::limits::ensure_within(&mode, crate::limits::MAX_STRING_BYTES, "mode")?;
        if !VALID_MODES.contains(&mode.as_str()) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "invalid mode '{mode}'. Valid: {VALID_MODES:?}"
            )));
        }

        info!(window_id = %window_id, mode = %mode, "D-Bus mode change");

        let mut modes = self.modes.write().await;
        modes.insert(window_id, mode);
        // SVC-5-R2-1: arm the facade inside the same critical section that
        // updated the mode map, so a concurrent set_mode cannot race with
        // the arming and leave the facade in a state inconsistent with the
        // most recently written mode.
        apply_focus_from_modes(&modes, &self.learning)
            .map_err(zbus::fdo::Error::Failed)?;
        Ok(())
    }

    /// List all windows with their current modes.
    ///
    /// Returns a JSON object `{window_id: mode}`.
    async fn list_modes(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<String> {
        self.guard.enforce("mode.list_modes", &header)?;
        let modes = self.modes.read().await;
        serde_json::to_string(&*modes)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization failed: {e}")))
    }
}

/// Recompute the global Focus state from a `(window_id → mode)` snapshot and
/// arm the [`LearningFacade`] accordingly: any window in `"Focus"` → engine
/// paused; otherwise → engine resumed (SVC-5-R2-1).
///
/// **Lock-ordering contract.** Call this *while holding* the caller's
/// mode-map lock (so the mode update and the facade arming form one critical
/// section the next `set_mode` cannot race). This function then acquires the
/// facade's `std::sync::Mutex` synchronously — it never `.await`s while
/// either lock is held. The strict order is therefore:
///
/// 1. caller acquires the mode-map lock (tokio `RwLock`, with `.await`)
/// 2. caller updates the mode-map and calls this function
/// 3. this function acquires the facade `std::sync::Mutex` synchronously
/// 4. this function calls `enter_focus` / `leave_focus` on the facade
/// 5. all locks drop at scope exit
///
/// Inverting (facade → mode-map) would deadlock; holding the std `Mutex`
/// across an `.await` would make any enclosing async future `!Send`. Neither
/// happens here.
///
/// Returns `Err(message)` only if the facade `Mutex` was poisoned by a
/// panicking thread — callers map that to a generic transport `Failed`
/// rather than `AccessDenied`, since a poisoned lock is an internal bug,
/// not an access decision.
///
/// # Examples
///
/// ```
/// use delphi_services::mode::apply_focus_from_modes;
/// use die_orchestrator::learning::LearningFacade;
/// use std::collections::HashMap;
/// use std::sync::Mutex;
///
/// let facade = Mutex::new(LearningFacade::in_memory().unwrap());
/// let mut modes = HashMap::new();
/// modes.insert("win-1".to_string(), "Focus".to_string());
/// apply_focus_from_modes(&modes, &facade).unwrap();
/// assert!(facade.lock().unwrap().focus_active(), "any-window-in-Focus must arm the facade");
/// ```
pub fn apply_focus_from_modes(
    modes: &HashMap<String, String>,
    facade: &StdMutex<LearningFacade>,
) -> Result<(), String> {
    let any_focus = modes.values().any(|m| m == "Focus");
    let mut facade = facade
        .lock()
        .map_err(|e| format!("learning facade lock poisoned: {e}"))?;
    if any_focus {
        facade.enter_focus();
    } else {
        facade.leave_focus();
    }
    Ok(())
}

/// Check if a mode string is valid.
///
/// # Examples
///
/// ```
/// use delphi_services::mode::is_valid_mode;
///
/// assert!(is_valid_mode("Direct"));
/// assert!(is_valid_mode("Focus"));
/// assert!(!is_valid_mode("invalid"));
/// ```
#[must_use]
pub fn is_valid_mode(mode: &str) -> bool {
    VALID_MODES.contains(&mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    use fortress::audit::AuditLog;

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    fn mk_facade() -> Arc<StdMutex<LearningFacade>> {
        Arc::new(StdMutex::new(LearningFacade::in_memory().unwrap()))
    }

    fn mk_guard(policy: AuthPolicy) -> Arc<AuthGuard> {
        Arc::new(AuthGuard::new(
            policy,
            Arc::new(StdMutex::new(AuditLog::in_memory())),
        ))
    }

    fn mk_svc(policy: AuthPolicy) -> ModeService {
        ModeService::new(
            Arc::new(RwLock::new(HashMap::new())),
            mk_facade(),
            mk_guard(policy),
        )
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
    }

    #[test]
    fn valid_modes() {
        assert!(is_valid_mode("Direct"));
        assert!(is_valid_mode("Assisted"));
        assert!(is_valid_mode("Autonomous"));
        assert!(is_valid_mode("Focus"));
    }

    #[test]
    fn invalid_modes() {
        assert!(!is_valid_mode("direct"));
        assert!(!is_valid_mode(""));
        assert!(!is_valid_mode("SuperMode"));
    }

    #[tokio::test]
    async fn get_default_mode() {
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        let mode = svc.get_mode(m.header(), "win-1".to_string()).await.unwrap();
        assert_eq!(mode, "Direct");
    }

    #[tokio::test]
    async fn set_and_get_mode() {
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        svc.set_mode(m.header(), "win-1".to_string(), "Assisted".to_string())
            .await
            .unwrap();
        let m = msg(":1.5");
        let mode = svc.get_mode(m.header(), "win-1".to_string()).await.unwrap();
        assert_eq!(mode, "Assisted");
    }

    #[tokio::test]
    async fn set_invalid_mode_fails() {
        let svc = mk_svc(AuthPolicy::dev());
        let m = msg(":1.5");
        let result = svc
            .set_mode(m.header(), "win-1".to_string(), "BadMode".to_string())
            .await;
        assert!(result.is_err());
    }

    // ── SVC-5-R2-1: mode-set arms the learning facade ──
    //
    // These tests are the RED→GREEN proof. Each `assert!(...focus_active())`
    // would fail against pre-round-2 code (where set_mode does only
    // `modes.insert`). The SVC-2 guard (dev: proceed-and-audit) lets set_mode
    // through to the focus-arming critical section.

    #[tokio::test]
    async fn set_mode_focus_arms_facade() {
        let modes = Arc::new(RwLock::new(HashMap::new()));
        let facade = mk_facade();
        let svc = ModeService::new(modes, facade.clone(), mk_guard(AuthPolicy::dev()));

        assert!(!facade.lock().unwrap().focus_active());

        let m = msg(":1.5");
        svc.set_mode(m.header(), "win-1".to_string(), "Focus".to_string())
            .await
            .unwrap();

        assert!(
            facade.lock().unwrap().focus_active(),
            "ModeService::set_mode(\"Focus\") must arm the facade (SVC-5-R2-1)"
        );
    }

    #[tokio::test]
    async fn set_mode_back_to_non_focus_disarms_facade() {
        let modes = Arc::new(RwLock::new(HashMap::new()));
        let facade = mk_facade();
        let svc = ModeService::new(modes, facade.clone(), mk_guard(AuthPolicy::dev()));

        let m = msg(":1.5");
        svc.set_mode(m.header(), "win-1".to_string(), "Focus".to_string())
            .await
            .unwrap();
        assert!(facade.lock().unwrap().focus_active());

        let m = msg(":1.5");
        svc.set_mode(m.header(), "win-1".to_string(), "Direct".to_string())
            .await
            .unwrap();
        assert!(
            !facade.lock().unwrap().focus_active(),
            "leaving the last Focus window must disarm the facade"
        );
    }

    #[tokio::test]
    async fn any_window_in_focus_arms_facade() {
        let modes = Arc::new(RwLock::new(HashMap::new()));
        let facade = mk_facade();
        let svc = ModeService::new(modes, facade.clone(), mk_guard(AuthPolicy::dev()));

        let m = msg(":1.5");
        svc.set_mode(m.header(), "win-1".to_string(), "Direct".to_string())
            .await
            .unwrap();
        let m = msg(":1.5");
        svc.set_mode(m.header(), "win-2".to_string(), "Focus".to_string())
            .await
            .unwrap();
        assert!(facade.lock().unwrap().focus_active());

        let m = msg(":1.5");
        svc.set_mode(m.header(), "win-2".to_string(), "Assisted".to_string())
            .await
            .unwrap();
        assert!(!facade.lock().unwrap().focus_active());
    }

    /// SVC-6-R2-3: every D-Bus `String` parameter is capped at
    /// `MAX_STRING_BYTES` *before* any logging, validation, or storage (and
    /// after the SVC-2 guard).
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc(AuthPolicy::dev());
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);

        let m = msg(":1.5");
        assert!(matches!(
            svc.get_mode(m.header(), oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.set_mode(m.header(), oversize.clone(), "Direct".to_string()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.set_mode(m.header(), "win-1".to_string(), oversize.clone()).await.unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    #[test]
    fn apply_focus_from_modes_idempotent() {
        let facade = StdMutex::new(LearningFacade::in_memory().unwrap());
        let mut modes = HashMap::new();
        modes.insert("a".to_string(), "Focus".to_string());

        apply_focus_from_modes(&modes, &facade).unwrap();
        apply_focus_from_modes(&modes, &facade).unwrap();
        assert!(facade.lock().unwrap().focus_active());

        modes.insert("a".to_string(), "Direct".to_string());
        apply_focus_from_modes(&modes, &facade).unwrap();
        apply_focus_from_modes(&modes, &facade).unwrap();
        assert!(!facade.lock().unwrap().focus_active());
    }

    // ── SVC-2 completeness (Decision 3) ──

    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let svc = mk_svc(AuthPolicy::dev());
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_all_methods_classified("mode", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc(AuthPolicy::deployed());
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("GetMode");
        let m = msg(":1.999");
        assert!(
            matches!(
                svc.get_mode(m.header(), "win-1".to_string()).await.unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "get_mode must be guarded"
        );
        exercised.push("SetMode");
        let m = msg(":1.999");
        assert!(
            matches!(
                svc.set_mode(m.header(), "win-1".to_string(), "Direct".to_string())
                    .await
                    .unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "set_mode must be guarded"
        );
        exercised.push("ListModes");
        let m = msg(":1.999");
        assert!(
            matches!(
                svc.list_modes(m.header()).await.unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "list_modes must be guarded"
        );

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("mode", &xml, &exercised);
    }
}
