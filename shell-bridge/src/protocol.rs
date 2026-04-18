// SPDX-License-Identifier: MIT

//! WebSocket protocol messages.
//!
//! Defines the JSON-RPC-like request/response format used between
//! the React shell and the bridge server.

use serde::{Deserialize, Serialize};

/// A request from the shell to the bridge.
///
/// # Examples
///
/// ```
/// use shell_bridge::protocol::Request;
///
/// let json = r#"{"id": 1, "method": "inference.query", "params": {"prompt": "Hi", "max_tokens": 100}}"#;
/// let req: Request = serde_json::from_str(json).unwrap();
/// assert_eq!(req.method, "inference.query");
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    /// Request ID (echoed in response).
    pub id: u64,
    /// Method name (e.g., "inference.query", "file_search.search").
    pub method: String,
    /// Method parameters as JSON value.
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A successful response from the bridge.
///
/// # Examples
///
/// ```
/// use shell_bridge::protocol::Response;
///
/// let resp = Response::ok(1, serde_json::json!({"output": "Hello!"}));
/// let json = serde_json::to_string(&resp).unwrap();
/// assert!(json.contains("Hello!"));
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct Response {
    /// Echoed request ID.
    pub id: u64,
    /// Result payload (None on error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error payload (None on success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorPayload>,
}

impl Response {
    /// Create a success response.
    ///
    /// # Examples
    ///
    /// ```
    /// use shell_bridge::protocol::Response;
    ///
    /// let r = Response::ok(1, serde_json::json!("hello"));
    /// assert!(r.error.is_none());
    /// ```
    #[must_use]
    pub fn ok(id: u64, result: serde_json::Value) -> Self {
        Self {
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response.
    ///
    /// # Examples
    ///
    /// ```
    /// use shell_bridge::protocol::Response;
    ///
    /// let r = Response::err(1, -1, "something went wrong");
    /// assert!(r.result.is_none());
    /// assert!(r.error.is_some());
    /// ```
    #[must_use]
    pub fn err(id: u64, code: i32, message: &str) -> Self {
        Self {
            id,
            result: None,
            error: Some(ErrorPayload {
                code,
                message: message.to_string(),
            }),
        }
    }
}

/// Error payload in a response.
///
/// # Examples
///
/// ```
/// use shell_bridge::protocol::ErrorPayload;
///
/// let err = ErrorPayload { code: -1, message: "not found".to_string() };
/// assert_eq!(err.code, -1);
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct ErrorPayload {
    /// Error code.
    pub code: i32,
    /// Human-readable error message.
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request() {
        let json = r#"{"id": 42, "method": "inference.query", "params": {"prompt": "test"}}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.id, 42);
        assert_eq!(req.method, "inference.query");
    }

    #[test]
    fn parse_request_without_params() {
        let json = r#"{"id": 1, "method": "inference.status"}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert!(req.params.is_null());
    }

    #[test]
    fn response_ok_serializes() {
        let resp = Response::ok(1, serde_json::json!({"text": "hello"}));
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("hello"));
        assert!(!json.contains("error"));
    }

    #[test]
    fn response_err_serializes() {
        let resp = Response::err(5, -1, "failed");
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("failed"));
        assert!(!json.contains("result"));
    }

    #[test]
    fn roundtrip_ok_response() {
        let resp = Response::ok(10, serde_json::json!(42));
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["id"], 10);
        assert_eq!(parsed["result"], 42);
    }
}
