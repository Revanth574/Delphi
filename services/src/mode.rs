// SPDX-License-Identifier: MIT

//! D-Bus Mode interface.
//!
//! Manages per-window UI modes (Direct, Assisted, Autonomous, Focus).
//! The shell queries and sets modes via this interface.
//!
//! Interface: `org.delphi.Mode`

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

/// D-Bus object path for the Mode interface.
pub const PATH: &str = "/org/delphi/Mode";

/// Valid mode names.
const VALID_MODES: &[&str] = &["Direct", "Assisted", "Autonomous", "Focus"];

/// Mode D-Bus service.
///
/// Tracks the UI mode for each window by ID.
///
/// # Examples
///
/// ```
/// use delphi_services::mode::ModeService;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
/// use std::collections::HashMap;
///
/// let modes = Arc::new(RwLock::new(HashMap::new()));
/// let svc = ModeService::new(modes);
/// ```
pub struct ModeService {
    /// Map of window_id → mode name.
    modes: Arc<RwLock<HashMap<String, String>>>,
}

impl ModeService {
    /// Create a new mode service.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::mode::ModeService;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    /// use std::collections::HashMap;
    ///
    /// let svc = ModeService::new(Arc::new(RwLock::new(HashMap::new())));
    /// ```
    #[must_use]
    pub fn new(modes: Arc<RwLock<HashMap<String, String>>>) -> Self {
        Self { modes }
    }
}

#[zbus::interface(name = "org.delphi.Mode")]
impl ModeService {
    /// Get the current mode for a window.
    ///
    /// Returns "Direct" if the window has no mode set.
    async fn get_mode(&self, window_id: String) -> zbus::fdo::Result<String> {
        let modes = self.modes.read().await;
        Ok(modes
            .get(&window_id)
            .cloned()
            .unwrap_or_else(|| "Direct".to_string()))
    }

    /// Set the mode for a window.
    ///
    /// Valid modes: Direct, Assisted, Autonomous, Focus.
    async fn set_mode(
        &self,
        window_id: String,
        mode: String,
    ) -> zbus::fdo::Result<()> {
        if !VALID_MODES.contains(&mode.as_str()) {
            return Err(zbus::fdo::Error::InvalidArgs(format!(
                "invalid mode '{mode}'. Valid: {VALID_MODES:?}"
            )));
        }

        info!(window_id = %window_id, mode = %mode, "D-Bus mode change");

        let mut modes = self.modes.write().await;
        modes.insert(window_id, mode);
        Ok(())
    }

    /// List all windows with their current modes.
    ///
    /// Returns a JSON object `{window_id: mode}`.
    async fn list_modes(&self) -> zbus::fdo::Result<String> {
        let modes = self.modes.read().await;
        serde_json::to_string(&*modes)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialization failed: {e}")))
    }
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
        let modes = Arc::new(RwLock::new(HashMap::new()));
        let svc = ModeService::new(modes);
        let mode = svc.get_mode("win-1".to_string()).await.unwrap();
        assert_eq!(mode, "Direct");
    }

    #[tokio::test]
    async fn set_and_get_mode() {
        let modes = Arc::new(RwLock::new(HashMap::new()));
        let svc = ModeService::new(modes);

        svc.set_mode("win-1".to_string(), "Assisted".to_string())
            .await
            .unwrap();

        let mode = svc.get_mode("win-1".to_string()).await.unwrap();
        assert_eq!(mode, "Assisted");
    }

    #[tokio::test]
    async fn set_invalid_mode_fails() {
        let modes = Arc::new(RwLock::new(HashMap::new()));
        let svc = ModeService::new(modes);

        let result = svc
            .set_mode("win-1".to_string(), "BadMode".to_string())
            .await;
        assert!(result.is_err());
    }
}
