// SPDX-License-Identifier: MIT

//! D-Bus Inference interface.
//!
//! Exposes AI query routing over D-Bus so the shell can send
//! natural language prompts and receive responses with tier/model info.
//!
//! Interface: `org.delphi.Inference`

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;

use die_inference::router::Router;
use die_inference::{InferenceRequest, RouteOutcome};

/// D-Bus object path for the Inference interface.
pub const PATH: &str = "/org/delphi/Inference";

/// Inference D-Bus service.
///
/// Wraps the inference `Router` and exposes it over D-Bus.
///
/// # Examples
///
/// ```
/// use delphi_services::inference::InferenceService;
/// use die_inference::router::Router;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// let router = Arc::new(RwLock::new(Router::new()));
/// let svc = InferenceService::new(router);
/// ```
pub struct InferenceService {
    router: Arc<RwLock<Router>>,
}

impl InferenceService {
    /// Create a new inference service backed by the given router.
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::inference::InferenceService;
    /// use die_inference::router::Router;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// let svc = InferenceService::new(Arc::new(RwLock::new(Router::new())));
    /// ```
    #[must_use]
    pub fn new(router: Arc<RwLock<Router>>) -> Self {
        Self { router }
    }
}

#[zbus::interface(name = "org.delphi.Inference")]
impl InferenceService {
    /// Query the AI with a prompt.
    ///
    /// Returns a JSON object discriminated by `status` (SVC-1):
    ///
    /// - `{"status":"completed","output":..,"tier":..,"model_id":..}` —
    ///   normal response (local, or cloud with PII placeholders restored).
    /// - `{"status":"confirmation_required","privacy_score":N,"sanitized_preview":..,"token":".."}`
    ///   — a cloud query whose ZKQP privacy score is too high to send without
    ///   explicit user confirmation. Nothing was sent. The shell shows the
    ///   preview and, on acceptance, re-calls `query` echoing the `token` back
    ///   as `cloud_confirmation_token`.
    ///
    /// `cloud_confirmation_token` carries that explicit consent (SVC-1-R1-1):
    /// the opaque, HMAC-bound token string from a prior `confirmation_required`
    /// response. The empty string means "no token presented". A forged or
    /// stale token simply fails verification and re-pauses; it never sends
    /// unsanitized text — ZKQP applies regardless; a valid token only
    /// overrides the privacy-score *pause* (Iron Law #1). Replacing the old
    /// `cloud_confirmed: bool` closes the caller-forgeable-consent bypass.
    ///
    /// **Wire-contract change (SVC-1):** returns the JSON union above and
    /// takes a `cloud_confirmation_token` string parameter.
    async fn query(
        &self,
        prompt: String,
        max_tokens: u32,
        sensitive: bool,
        cloud_confirmation_token: String,
    ) -> zbus::fdo::Result<String> {
        crate::limits::ensure_within(&prompt, crate::limits::MAX_STRING_BYTES, "prompt")?;
        crate::limits::ensure_within(
            &cloud_confirmation_token,
            crate::limits::MAX_STRING_BYTES,
            "cloud_confirmation_token",
        )?;
        info!(
            prompt_len = prompt.len(),
            max_tokens,
            sensitive,
            has_token = !cloud_confirmation_token.is_empty(),
            "D-Bus inference query"
        );

        let router = self.router.read().await;
        let req = InferenceRequest {
            input: prompt,
            max_tokens,
            sensitive,
            // Empty string -> None (no confirmation presented).
            cloud_confirmation_token: if cloud_confirmation_token.is_empty() {
                None
            } else {
                Some(cloud_confirmation_token)
            },
        };

        let outcome = router
            .route(req)
            .await
            .map_err(|e| crate::error::opaque("inference query failed", e))?;
        let json = match outcome {
            RouteOutcome::Completed(resp) => serde_json::json!({
                "status": "completed",
                "output": resp.output,
                "tier": format!("{:?}", resp.tier),
                "model_id": resp.model_id,
            }),
            RouteOutcome::CloudConfirmationRequired(c) => serde_json::json!({
                "status": "confirmation_required",
                "privacy_score": c.privacy_score,
                "sanitized_preview": c.sanitized_preview,
                "token": c.token,
            }),
        };
        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Check which backends are available.
    ///
    /// Returns `(has_local, has_cloud)`.
    async fn status(&self) -> zbus::fdo::Result<(bool, bool)> {
        let router = self.router.read().await;
        Ok((router.has_local_model(), router.has_cloud()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
    }

    #[test]
    fn service_creation() {
        let router = Arc::new(RwLock::new(Router::new()));
        let _svc = InferenceService::new(router);
    }

    /// SVC-6-R2-3: every `String` param of `query` is capped at the boundary
    /// BEFORE info!()/routing. Covers `prompt` and (SVC-1-R1-1) the new
    /// `cloud_confirmation_token`.
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = InferenceService::new(Arc::new(RwLock::new(Router::new())));
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        // prompt
        assert!(matches!(
            svc.query(oversize.clone(), 16, false, String::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        // cloud_confirmation_token
        assert!(matches!(
            svc.query("hi".to_string(), 16, false, oversize)
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }
}
