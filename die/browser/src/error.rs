// SPDX-License-Identifier: MIT

//! Browser engine error types.
//!
//! Uses `thiserror` for typed errors per CLAUDE.md rules
//! (library crate = `thiserror`).

use thiserror::Error;

/// Errors that can occur during browser operations.
///
/// # Examples
///
/// ```
/// use die_browser::BrowserError;
///
/// let err = BrowserError::Timeout { seconds: 30 };
/// assert!(err.to_string().contains("30"));
/// ```
#[derive(Debug, Error)]
pub enum BrowserError {
    /// The browser process failed to start.
    #[error("failed to spawn browser process: {reason}")]
    SpawnFailed {
        /// Why the spawn failed.
        reason: String,
    },

    /// A command timed out waiting for a response.
    #[error("browser command timed out after {seconds}s")]
    Timeout {
        /// Timeout duration in seconds.
        seconds: u64,
    },

    /// Navigation to a URL failed.
    #[error("navigation failed: {url} — {reason}")]
    NavigationFailed {
        /// The URL that failed to load.
        url: String,
        /// Why navigation failed.
        reason: String,
    },

    /// Content extraction failed.
    #[error("extraction failed: {reason}")]
    ExtractionFailed {
        /// Why extraction failed.
        reason: String,
    },

    /// JavaScript evaluation failed.
    #[error("JS evaluation failed: {reason}")]
    EvalFailed {
        /// Why the JS eval failed.
        reason: String,
    },

    /// The browser process exited unexpectedly.
    #[error("browser process exited unexpectedly (code: {code:?})")]
    ProcessExited {
        /// Exit code, if available.
        code: Option<i32>,
    },

    /// Communication with the browser process failed.
    #[error("IPC error: {reason}")]
    IpcError {
        /// Why IPC failed.
        reason: String,
    },

    /// Invalid command or response format.
    #[error("protocol error: {reason}")]
    ProtocolError {
        /// Why the protocol was violated.
        reason: String,
    },

    /// Screenshot capture failed.
    #[error("screenshot failed: {reason}")]
    ScreenshotFailed {
        /// Why the screenshot failed.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_message() {
        let err = BrowserError::Timeout { seconds: 30 };
        assert!(err.to_string().contains("30"));
        assert!(err.to_string().contains("timed out"));
    }

    #[test]
    fn spawn_failed_message() {
        let err = BrowserError::SpawnFailed {
            reason: "not installed".to_string(),
        };
        assert!(err.to_string().contains("not installed"));
    }

    #[test]
    fn navigation_failed_message() {
        let err = BrowserError::NavigationFailed {
            url: "https://example.com".to_string(),
            reason: "DNS resolution failed".to_string(),
        };
        assert!(err.to_string().contains("example.com"));
        assert!(err.to_string().contains("DNS"));
    }

    #[test]
    fn process_exited_with_code() {
        let err = BrowserError::ProcessExited { code: Some(1) };
        assert!(err.to_string().contains("1"));
    }

    #[test]
    fn process_exited_no_code() {
        let err = BrowserError::ProcessExited { code: None };
        assert!(err.to_string().contains("None"));
    }

    #[test]
    fn ipc_error_message() {
        let err = BrowserError::IpcError {
            reason: "pipe broken".to_string(),
        };
        assert!(err.to_string().contains("pipe broken"));
    }

    #[test]
    fn extraction_error_message() {
        let err = BrowserError::ExtractionFailed {
            reason: "selector not found".to_string(),
        };
        assert!(err.to_string().contains("selector not found"));
    }

    #[test]
    fn eval_error_message() {
        let err = BrowserError::EvalFailed {
            reason: "ReferenceError".to_string(),
        };
        assert!(err.to_string().contains("ReferenceError"));
    }

    #[test]
    fn screenshot_error_message() {
        let err = BrowserError::ScreenshotFailed {
            reason: "page not loaded".to_string(),
        };
        assert!(err.to_string().contains("page not loaded"));
    }
}
