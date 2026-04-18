// SPDX-License-Identifier: MIT

//! Browser command and result types.
//!
//! Defines the JSON protocol used between the Rust engine and the
//! Playwright Node.js child process. Commands are serialized to JSON
//! and sent via stdin; results come back via stdout.

use serde::{Deserialize, Serialize};

/// A command sent to the browser process.
///
/// Each variant maps to a Playwright action. The command is serialized
/// to JSON and written to the child process's stdin.
///
/// # Examples
///
/// ```
/// use die_browser::BrowserCommand;
///
/// let cmd = BrowserCommand::Navigate {
///     url: "https://example.com".to_string(),
///     wait_until: "domcontentloaded".to_string(),
/// };
/// let json = serde_json::to_string(&cmd).unwrap();
/// assert!(json.contains("Navigate"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum BrowserCommand {
    /// Navigate to a URL.
    Navigate {
        /// Target URL.
        url: String,
        /// Wait condition: "load", "domcontentloaded", "networkidle".
        wait_until: String,
    },

    /// Extract content from the current page.
    Extract {
        /// What to extract.
        target: ExtractTarget,
        /// Optional CSS selector to scope extraction.
        selector: Option<String>,
    },

    /// Take a screenshot of the current page.
    Screenshot {
        /// Output format.
        format: ScreenshotFormat,
        /// Whether to capture full page or just viewport.
        full_page: bool,
    },

    /// Click an element on the page.
    Click {
        /// CSS selector of the element to click.
        selector: String,
    },

    /// Type text into an input element.
    TypeText {
        /// CSS selector of the input element.
        selector: String,
        /// Text to type.
        text: String,
    },

    /// Evaluate JavaScript in the page context.
    Evaluate {
        /// JavaScript expression to evaluate.
        expression: String,
    },

    /// Wait for an element to appear.
    WaitForSelector {
        /// CSS selector to wait for.
        selector: String,
        /// Maximum wait time in milliseconds.
        timeout_ms: u64,
    },

    /// Get the current page URL.
    GetUrl,

    /// Get the page title.
    GetTitle,

    /// Go back in browser history.
    GoBack,

    /// Go forward in browser history.
    GoForward,

    /// Close the browser and exit the process.
    Close,
}

/// What content to extract from the page.
///
/// # Examples
///
/// ```
/// use die_browser::ExtractTarget;
///
/// let target = ExtractTarget::Text;
/// let json = serde_json::to_string(&target).unwrap();
/// assert!(json.contains("Text"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtractTarget {
    /// Extract visible text content.
    Text,
    /// Extract raw HTML.
    Html,
    /// Extract all links as `(text, href)` pairs.
    Links,
    /// Extract structured data (tables, lists) as JSON.
    Structured,
}

/// Screenshot output format.
///
/// # Examples
///
/// ```
/// use die_browser::ScreenshotFormat;
///
/// let fmt = ScreenshotFormat::Png;
/// let json = serde_json::to_string(&fmt).unwrap();
/// assert!(json.contains("Png"));
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScreenshotFormat {
    /// PNG image (lossless).
    Png,
    /// JPEG image (lossy, smaller).
    Jpeg,
}

/// A result returned from the browser process.
///
/// Deserialized from the JSON output on the child process's stdout.
///
/// # Examples
///
/// ```
/// use die_browser::BrowserResult;
///
/// let json = r#"{"success": true, "data": "Hello, world!", "error": null}"#;
/// let result: BrowserResult = serde_json::from_str(json).unwrap();
/// assert!(result.success);
/// assert_eq!(result.data.unwrap(), "Hello, world!");
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserResult {
    /// Whether the command succeeded.
    pub success: bool,
    /// Result data (type depends on the command).
    pub data: Option<serde_json::Value>,
    /// Error message if the command failed.
    pub error: Option<String>,
}

impl BrowserResult {
    /// Create a success result with data.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_browser::BrowserResult;
    ///
    /// let r = BrowserResult::ok(serde_json::json!("done"));
    /// assert!(r.success);
    /// ```
    #[must_use]
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    /// Create a failure result with an error message.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_browser::BrowserResult;
    ///
    /// let r = BrowserResult::fail("page not found");
    /// assert!(!r.success);
    /// ```
    #[must_use]
    pub fn fail(error: &str) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_navigate() {
        let cmd = BrowserCommand::Navigate {
            url: "https://example.com".to_string(),
            wait_until: "load".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("Navigate"));
        assert!(json.contains("example.com"));
        assert!(json.contains("load"));
    }

    #[test]
    fn serialize_extract_text() {
        let cmd = BrowserCommand::Extract {
            target: ExtractTarget::Text,
            selector: Some("main".to_string()),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("Extract"));
        assert!(json.contains("Text"));
        assert!(json.contains("main"));
    }

    #[test]
    fn serialize_extract_links() {
        let cmd = BrowserCommand::Extract {
            target: ExtractTarget::Links,
            selector: None,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("Links"));
    }

    #[test]
    fn serialize_screenshot() {
        let cmd = BrowserCommand::Screenshot {
            format: ScreenshotFormat::Png,
            full_page: true,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("Png"));
        assert!(json.contains("true"));
    }

    #[test]
    fn serialize_click() {
        let cmd = BrowserCommand::Click {
            selector: "#submit-btn".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("#submit-btn"));
    }

    #[test]
    fn serialize_type_text() {
        let cmd = BrowserCommand::TypeText {
            selector: "input[name=email]".to_string(),
            text: "user@example.com".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("user@example.com"));
    }

    #[test]
    fn serialize_evaluate() {
        let cmd = BrowserCommand::Evaluate {
            expression: "document.title".to_string(),
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("document.title"));
    }

    #[test]
    fn serialize_wait_for_selector() {
        let cmd = BrowserCommand::WaitForSelector {
            selector: ".loaded".to_string(),
            timeout_ms: 5000,
        };
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains(".loaded"));
        assert!(json.contains("5000"));
    }

    #[test]
    fn serialize_get_url() {
        let cmd = BrowserCommand::GetUrl;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("GetUrl"));
    }

    #[test]
    fn serialize_close() {
        let cmd = BrowserCommand::Close;
        let json = serde_json::to_string(&cmd).unwrap();
        assert!(json.contains("Close"));
    }

    #[test]
    fn deserialize_success_result() {
        let json = r#"{"success": true, "data": "Hello!", "error": null}"#;
        let result: BrowserResult = serde_json::from_str(json).unwrap();
        assert!(result.success);
        assert_eq!(result.data.unwrap(), "Hello!");
        assert!(result.error.is_none());
    }

    #[test]
    fn deserialize_error_result() {
        let json = r#"{"success": false, "data": null, "error": "not found"}"#;
        let result: BrowserResult = serde_json::from_str(json).unwrap();
        assert!(!result.success);
        assert!(result.data.is_none());
        assert_eq!(result.error.unwrap(), "not found");
    }

    #[test]
    fn result_ok_constructor() {
        let r = BrowserResult::ok(serde_json::json!(42));
        assert!(r.success);
        assert_eq!(r.data.unwrap(), 42);
        assert!(r.error.is_none());
    }

    #[test]
    fn result_fail_constructor() {
        let r = BrowserResult::fail("timeout");
        assert!(!r.success);
        assert!(r.data.is_none());
        assert_eq!(r.error.unwrap(), "timeout");
    }

    #[test]
    fn extract_target_variants() {
        for target in [
            ExtractTarget::Text,
            ExtractTarget::Html,
            ExtractTarget::Links,
            ExtractTarget::Structured,
        ] {
            let json = serde_json::to_string(&target).unwrap();
            let back: ExtractTarget = serde_json::from_str(&json).unwrap();
            // Roundtrip should work
            assert_eq!(json, serde_json::to_string(&back).unwrap());
        }
    }

    #[test]
    fn screenshot_format_variants() {
        for fmt in [ScreenshotFormat::Png, ScreenshotFormat::Jpeg] {
            let json = serde_json::to_string(&fmt).unwrap();
            let back: ScreenshotFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(json, serde_json::to_string(&back).unwrap());
        }
    }
}
