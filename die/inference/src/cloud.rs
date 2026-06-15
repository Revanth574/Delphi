// SPDX-License-Identifier: MIT

//! Cloud inference client for Tier 2/3 routing.
//!
//! Provides an async HTTP client for the Anthropic Messages API.
//! All cloud calls go through this module — no direct API calls
//! from other modules (per CLAUDE.md Section 10, Rule 4).
//!
//! # Security
//!
//! The API key is provided to [`CloudClient::new`] by the caller (today
//! `Router::set_cloud_api_key`, ultimately the services layer) and held as a
//! redacted `ApiKey` newtype that never renders the secret in `Debug`/`Display`
//! (INF-1). It is never written to config files, environment variables, or
//! source code. Fortress-vault-backed retrieval is a forward-requirement — the
//! `fortress::Vault` is not yet wired as the key source (FORT-Q5 / INF-3).

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::egress::SanitizedPrompt;
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

/// A secret API key whose raw value cannot leak through formatting.
///
/// The footgun this closes (INF-1 — the SVC-1-R1-1-02 class, already fixed for
/// [`ConfirmationTokenWire`](crate::token::ConfirmationTokenWire)): a bare
/// secret `String` can be `Debug`-printed anywhere it flows — into a `{:?}` of
/// any enclosing struct, a `tracing` field, or a stray `dbg!`. Wrapping the
/// secret in this newtype makes redaction a property of the **type**: both
/// [`Debug`](fmt::Debug) and [`Display`](fmt::Display) render `[REDACTED]`, so
/// the value stays hidden wherever an `ApiKey` travels.
///
/// The raw secret is reachable **only** through [`expose`](Self::expose). That
/// name is deliberate: `git grep '.expose()'` enumerates every site that reads
/// the secret in the clear, so the extraction surface is auditable by
/// construction. There is no other accessor and no public field.
struct ApiKey(String);

impl ApiKey {
    /// Wrap a raw secret key.
    fn new(key: String) -> Self {
        Self(key)
    }

    /// Expose the raw secret for a legitimate in-the-clear use (the Anthropic
    /// `x-api-key` auth header, and the configured/empty check).
    ///
    /// Named to mark the extraction: every `.expose()` call is a site where the
    /// secret leaves the redacted wrapper. Keep these to the minimum and grep
    /// for them to audit the surface.
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ApiKey {
    /// Redacts: never renders the secret. Keeps the type name so a `{:?}` is
    /// still structurally informative without disclosing the value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiKey([REDACTED])")
    }
}

impl fmt::Display for ApiKey {
    /// Redacts: never renders the secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
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
#[derive(Debug)]
pub struct CloudClient {
    /// The reqwest HTTP client (reused across requests).
    client: reqwest::Client,
    /// Anthropic API key — a redacting [`ApiKey`] newtype, so the derived
    /// `Debug` on this struct (or anything that holds it) can never disclose
    /// the secret (INF-1). `Clone` was dropped: nothing clones a `CloudClient`.
    api_key: ApiKey,
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
            api_key: ApiKey::new(api_key),
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
        // `.expose()` is one of the two sanctioned secret-extraction sites
        // (the other is the auth header in `send_request`); we only read its
        // emptiness here, never log or format the value.
        !self.api_key.expose().is_empty()
    }

    /// Send a completion request to the Anthropic API.
    ///
    /// **SVC-1: capability-gated and crate-internal.** This method is the raw
    /// cloud-egress mechanic. It is `pub(crate)` and accepts a
    /// [`SanitizedPrompt`] — never a raw `&str` — so it cannot be reached with
    /// un-sanitized text. The only caller is
    /// [`CloudEgressGateway`](crate::egress::CloudEgressGateway), which mints
    /// the capability immediately after a ZKQP `sanitize`. External crates
    /// must go through the gateway; there is no public raw-prompt overload.
    ///
    /// Implements retry logic with exponential backoff (max 3 retries)
    /// per CLAUDE.md Section 4 (network operations must have retries).
    ///
    /// # Errors
    ///
    /// Returns `InferenceError::CloudApi` on API errors,
    /// `InferenceError::Timeout` on timeout.
    pub(crate) async fn complete(
        &self,
        prompt: &SanitizedPrompt,
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
                // SVC-1: the only text that crosses the network is the
                // sanitized capability's payload.
                content: prompt.as_str().to_string(),
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
            // `.expose()` — the one place the secret is sent in the clear.
            .header("x-api-key", self.api_key.expose())
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

    /// INF-1 (latent-structural footgun): `CloudClient` derived `Debug` over a
    /// raw `api_key: String`, so a `{:?}` of the client — or of any struct that
    /// holds one — would print the live key. RED pre-fix: the secret appears
    /// verbatim in the Debug output. Post-fix: the redacting `ApiKey` newtype
    /// hides it. This is the core proof of the fix.
    #[test]
    fn cloud_client_debug_does_not_leak_api_key_inf_1() {
        let secret = "sk-ant-SUPER-SECRET-key-zzz";
        let client = CloudClient::new(secret.to_string());
        let dbg = format!("{client:?}");
        assert!(!dbg.contains(secret), "CloudClient Debug leaked the API key: {dbg}");
        assert!(dbg.contains("REDACTED"), "the api_key field should render redacted: {dbg}");
    }

    /// Redaction is a property of the TYPE, not of one struct: a bare `ApiKey`
    /// must hide its secret under BOTH `Debug` and `Display`, so it stays
    /// redacted wherever it flows (into a tracing field, an enclosing `{:?}`,
    /// a `dbg!`). This is what makes the fix close the class, not one site.
    #[test]
    fn api_key_type_redacts_in_debug_and_display_inf_1() {
        let secret = "sk-ant-SUPER-SECRET-key-zzz";
        let key = ApiKey::new(secret.to_string());
        let dbg = format!("{key:?}");
        let disp = format!("{key}");
        assert!(!dbg.contains(secret), "ApiKey Debug leaked the secret: {dbg}");
        assert!(!disp.contains(secret), "ApiKey Display leaked the secret: {disp}");
        assert!(dbg.contains("REDACTED"), "Debug should mark redaction: {dbg}");
        assert!(disp.contains("REDACTED"), "Display should mark redaction: {disp}");
    }

    /// Redaction must not break auth: the real secret still reaches the header
    /// via the named `.expose()` accessor, and the configured/empty check still
    /// works end-to-end through `is_available`. Guards against over-redaction
    /// (e.g. `.expose()` returning the placeholder) silently breaking cloud auth.
    #[test]
    fn api_key_remains_functional_via_expose_inf_1() {
        let secret = "sk-ant-SUPER-SECRET-key-zzz";
        let key = ApiKey::new(secret.to_string());
        assert_eq!(key.expose(), secret, "expose() must return the exact secret");
        assert!(!key.expose().is_empty());
        assert!(ApiKey::new(String::new()).expose().is_empty());
        // End-to-end through the is_available() path (which reads via expose):
        assert!(CloudClient::new(secret.to_string()).is_available());
        assert!(!CloudClient::new(String::new()).is_available());
    }

    // SVC-1: the "no API key -> CloudApi error on send" behavior moved to
    // `egress::tests::clean_query_without_key_errors_on_send`. `complete` now
    // requires a `SanitizedPrompt` (private to the egress module), so it can
    // only be exercised through the gateway.

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
