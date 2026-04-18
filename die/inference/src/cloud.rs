// SPDX-License-Identifier: MIT

//! Cloud inference client for Tier 2/3 routing.
//!
//! Provides an async HTTP client for the Anthropic Messages API.
//! All cloud calls go through this module — no direct API calls
//! from other modules (per CLAUDE.md Section 10, Rule 4).
//!
//! # Security
//!
//! API keys are retrieved from the Fortress credential vault at
//! runtime. They are never stored in config files, environment
//! variables, or source code.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::error::InferenceError;

/// Default request timeout for cloud API calls.
const DEFAULT_TIMEOUT_SECS: u64 = 60;

/// Maximum retry count with exponential backoff.
const MAX_RETRIES: u32 = 3;

/// Anthropic API endpoint.
const ANTHROPIC_API_URL: &str = "https://api.anthropic.com/v1/messages";

/// Anthropic API version header.
const ANTHROPIC_VERSION: &str = "2023-06-01";

/// Supported cloud model identifiers.
///
/// # Examples
///
/// ```
/// use die_inference::cloud::CloudModel;
///
/// let model = CloudModel::ClaudeSonnet;
/// assert_eq!(model.api_model_id(), "claude-sonnet-4-20250514");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudModel {
    /// Claude Sonnet (Tier 2) — balanced speed/quality.
    ClaudeSonnet,
    /// Claude Opus (Tier 3) — maximum capability.
    ClaudeOpus,
}

impl CloudModel {
    /// Get the API model identifier string.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::cloud::CloudModel;
    ///
    /// assert!(CloudModel::ClaudeOpus.api_model_id().contains("opus"));
    /// ```
    #[must_use]
    pub fn api_model_id(self) -> &'static str {
        match self {
            Self::ClaudeSonnet => "claude-sonnet-4-20250514",
            Self::ClaudeOpus => "claude-opus-4-20250514",
        }
    }

    /// Get the human-readable name.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::cloud::CloudModel;
    ///
    /// assert_eq!(CloudModel::ClaudeSonnet.display_name(), "Claude Sonnet");
    /// ```
    #[must_use]
    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeSonnet => "Claude Sonnet",
            Self::ClaudeOpus => "Claude Opus",
        }
    }
}

/// Cloud inference client.
///
/// Wraps `reqwest` with Anthropic API authentication and retry logic.
///
/// # Examples
///
/// ```
/// use die_inference::cloud::CloudClient;
///
/// let client = CloudClient::new("sk-test-key".to_string());
/// assert!(client.is_available());
/// ```
#[derive(Debug, Clone)]
pub struct CloudClient {
    /// The reqwest HTTP client (reused across requests).
    client: reqwest::Client,
    /// Anthropic API key (from Fortress vault).
    api_key: String,
    /// Request timeout.
    timeout: Duration,
}

impl CloudClient {
    /// Create a new cloud client with an API key.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::cloud::CloudClient;
    ///
    /// let client = CloudClient::new("sk-ant-test".to_string());
    /// ```
    #[must_use]
    pub fn new(api_key: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .build()
            .unwrap_or_default();

        Self {
            client,
            api_key,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        }
    }

    /// Check whether the cloud client has a valid API key configured.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::cloud::CloudClient;
    ///
    /// let client = CloudClient::new("sk-valid-key".to_string());
    /// assert!(client.is_available());
    ///
    /// let empty = CloudClient::new(String::new());
    /// assert!(!empty.is_available());
    /// ```
    #[must_use]
    pub fn is_available(&self) -> bool {
        !self.api_key.is_empty()
    }

    /// Send a completion request to the Anthropic API.
    ///
    /// Implements retry logic with exponential backoff (max 3 retries)
    /// per CLAUDE.md Section 4 (network operations must have retries).
    ///
    /// # Errors
    ///
    /// Returns `InferenceError::CloudApi` on API errors,
    /// `InferenceError::Timeout` on timeout.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_inference::cloud::{CloudClient, CloudModel};
    ///
    /// # async fn example() -> Result<(), die_inference::InferenceError> {
    /// let client = CloudClient::new("sk-ant-key".to_string());
    /// let response = client.complete("Hello!", 256, CloudModel::ClaudeSonnet).await?;
    /// println!("{}", response.text);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn complete(
        &self,
        prompt: &str,
        max_tokens: u32,
        model: CloudModel,
    ) -> Result<CloudResponse, InferenceError> {
        if !self.is_available() {
            return Err(InferenceError::CloudApi(
                "no API key configured. Store one with: \
                 delphi fortress set anthropic-api-key <your-key>"
                    .to_string(),
            ));
        }

        let request_body = AnthropicRequest {
            model: model.api_model_id().to_string(),
            max_tokens,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: prompt.to_string(),
            }],
        };

        let mut last_error = None;

        for attempt in 0..MAX_RETRIES {
            if attempt > 0 {
                let backoff = Duration::from_millis(500 * 2u64.pow(attempt - 1));
                info!(
                    attempt,
                    backoff_ms = backoff.as_millis() as u64,
                    "retrying cloud API call"
                );
                tokio::time::sleep(backoff).await;
            }

            match self.send_request(&request_body).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!(
                        attempt,
                        error = %e,
                        "cloud API call failed"
                    );
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or(InferenceError::CloudApi(
            "all retry attempts exhausted".to_string(),
        )))
    }

    /// Send a single request (no retries — called by `complete`).
    async fn send_request(
        &self,
        body: &AnthropicRequest,
    ) -> Result<CloudResponse, InferenceError> {
        let start = std::time::Instant::now();

        let response = self
            .client
            .post(ANTHROPIC_API_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .timeout(self.timeout)
            .json(body)
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    InferenceError::Timeout(self.timeout.as_millis() as u64)
                } else {
                    InferenceError::CloudApi(format!("request failed: {e}"))
                }
            })?;

        let status = response.status();
        if !status.is_success() {
            let error_body = response.text().await.unwrap_or_default();
            return Err(InferenceError::CloudApi(format!(
                "API returned {status}: {error_body}"
            )));
        }

        let api_response: AnthropicResponse = response
            .json()
            .await
            .map_err(|e| InferenceError::CloudApi(format!(
                "failed to parse API response: {e}"
            )))?;

        let text = api_response
            .content
            .into_iter()
            .filter(|c| c.content_type == "text")
            .map(|c| c.text)
            .collect::<Vec<_>>()
            .join("");

        let latency_ms = start.elapsed().as_millis() as u64;

        debug!(
            model = body.model,
            latency_ms,
            output_len = text.len(),
            "cloud response received"
        );

        Ok(CloudResponse {
            text,
            model: body.model.clone(),
            latency_ms,
        })
    }
}

/// Response from a cloud completion.
///
/// # Examples
///
/// ```
/// use die_inference::cloud::CloudResponse;
///
/// let resp = CloudResponse {
///     text: "Hello!".to_string(),
///     model: "claude-sonnet-4-20250514".to_string(),
///     latency_ms: 500,
/// };
/// assert!(!resp.text.is_empty());
/// ```
#[derive(Debug, Clone)]
pub struct CloudResponse {
    /// The generated text.
    pub text: String,
    /// The model that generated it.
    pub model: String,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u64,
}

// ─── Anthropic API wire types ───────────────────────────────────────

#[derive(Debug, Serialize)]
struct AnthropicRequest {
    model: String,
    max_tokens: u32,
    messages: Vec<AnthropicMessage>,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    content: Vec<AnthropicContentBlock>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    content_type: String,
    text: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloud_model_ids_are_correct() {
        assert!(CloudModel::ClaudeSonnet.api_model_id().contains("sonnet"));
        assert!(CloudModel::ClaudeOpus.api_model_id().contains("opus"));
    }

    #[test]
    fn cloud_model_display_names() {
        assert_eq!(CloudModel::ClaudeSonnet.display_name(), "Claude Sonnet");
        assert_eq!(CloudModel::ClaudeOpus.display_name(), "Claude Opus");
    }

    #[test]
    fn client_available_with_key() {
        let client = CloudClient::new("sk-test-key".to_string());
        assert!(client.is_available());
    }

    #[test]
    fn client_unavailable_without_key() {
        let client = CloudClient::new(String::new());
        assert!(!client.is_available());
    }

    #[tokio::test]
    async fn complete_fails_without_key() {
        let client = CloudClient::new(String::new());
        let result = client
            .complete("test", 100, CloudModel::ClaudeSonnet)
            .await;
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("no API key"));
    }

    #[test]
    fn cloud_response_fields() {
        let resp = CloudResponse {
            text: "Generated text".to_string(),
            model: "claude-sonnet-4-20250514".to_string(),
            latency_ms: 350,
        };
        assert_eq!(resp.latency_ms, 350);
        assert!(resp.model.contains("sonnet"));
    }

    #[test]
    fn anthropic_request_serializes() {
        let req = AnthropicRequest {
            model: "claude-sonnet-4-20250514".to_string(),
            max_tokens: 256,
            messages: vec![AnthropicMessage {
                role: "user".to_string(),
                content: "Hello".to_string(),
            }],
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("claude-sonnet"));
        assert!(json.contains("256"));
    }
}
