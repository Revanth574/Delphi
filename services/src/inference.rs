// SPDX-License-Identifier: MIT

//! D-Bus Inference interface.
//!
//! Exposes AI query routing over D-Bus so the shell can send
//! natural language prompts and receive responses with tier/model info.
//!
//! Interface: `org.delphi.Inference`
//!
//! SVC-2: `query` and `status` enforce authorization via the shared
//! [`AuthGuard`] on their first line. (The cloud-send *subaction* within `query`
//! — its same-caller-binding consent check, SVC-1-R1-1-01 — is the separate
//! Stage-3 seam, distinct from this general tier gate.)

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::info;
use zbus::message::Header;

use die_inference::router::Router;
use die_inference::{ConfirmationTokenWire, InferenceRequest, RouteOutcome};

use crate::auth_guard::AuthGuard;

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
/// use delphi_services::auth::AuthPolicy;
/// use delphi_services::auth_guard::AuthGuard;
/// use die_inference::router::Router;
/// use fortress::audit::AuditLog;
/// use std::sync::{Arc, Mutex};
/// use tokio::sync::RwLock;
///
/// let router = Arc::new(RwLock::new(Router::new()));
/// let guard = Arc::new(AuthGuard::new(
///     AuthPolicy::dev(),
///     Arc::new(Mutex::new(AuditLog::in_memory())),
/// ));
/// let svc = InferenceService::new(router, guard);
/// ```
pub struct InferenceService {
    router: Arc<RwLock<Router>>,
    guard: Arc<AuthGuard>,
}

impl InferenceService {
    /// Create a new inference service backed by the given router, guarded by the
    /// shared [`AuthGuard`].
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::inference::InferenceService;
    /// use delphi_services::auth::AuthPolicy;
    /// use delphi_services::auth_guard::AuthGuard;
    /// use die_inference::router::Router;
    /// use fortress::audit::AuditLog;
    /// use std::sync::{Arc, Mutex};
    /// use tokio::sync::RwLock;
    ///
    /// let svc = InferenceService::new(
    ///     Arc::new(RwLock::new(Router::new())),
    ///     Arc::new(AuthGuard::new(
    ///         AuthPolicy::dev(),
    ///         Arc::new(Mutex::new(AuditLog::in_memory())),
    ///     )),
    /// );
    /// ```
    #[must_use]
    pub fn new(router: Arc<RwLock<Router>>, guard: Arc<AuthGuard>) -> Self {
        Self { router, guard }
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
    /// overrides the privacy-score *pause* (Iron Law #1).
    ///
    /// **Wire-contract change (SVC-1):** returns the JSON union above and
    /// takes a `cloud_confirmation_token` string parameter.
    async fn query(
        &self,
        #[zbus(header)] header: Header<'_>,
        prompt: String,
        max_tokens: u32,
        sensitive: bool,
        cloud_confirmation_token: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("inference.query", &header)?;
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
            // Empty string -> None (no confirmation presented). Wrap into the
            // redacted-Debug newtype (SVC-1-R1-1-02) at the boundary.
            cloud_confirmation_token: if cloud_confirmation_token.is_empty() {
                None
            } else {
                Some(ConfirmationTokenWire::new(cloud_confirmation_token))
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
                // Explicit transport read of the redacted-Debug newtype.
                "token": c.token.as_str(),
            }),
        };
        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
    }

    /// Check which backends are available.
    ///
    /// Returns `(has_local, has_cloud)`.
    async fn status(&self, #[zbus(header)] header: Header<'_>) -> zbus::fdo::Result<(bool, bool)> {
        self.guard.enforce("inference.status", &header)?;
        let router = self.router.read().await;
        Ok((router.has_local_model(), router.has_cloud()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fortress::audit::AuditLog;
    use std::sync::Mutex;

    use crate::auth::AuthPolicy;
    use crate::auth_guard::completeness::{
        assert_all_methods_classified, assert_behavioral_covers_all, header_msg as msg,
    };

    fn mk_svc(policy: AuthPolicy) -> InferenceService {
        let router = Arc::new(RwLock::new(Router::new()));
        let guard = Arc::new(AuthGuard::new(
            policy,
            Arc::new(Mutex::new(AuditLog::in_memory())),
        ));
        InferenceService::new(router, guard)
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
    }

    #[test]
    fn service_creation() {
        let _svc = mk_svc(AuthPolicy::dev());
    }

    /// SVC-6-R2-3: every `String` param of `query` is capped at the boundary
    /// (after the SVC-2 guard). Covers `prompt` and `cloud_confirmation_token`.
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc(AuthPolicy::dev());
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        let m = msg(":1.5");
        assert!(matches!(
            svc.query(m.header(), oversize.clone(), 16, false, String::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        let m = msg(":1.5");
        assert!(matches!(
            svc.query(m.header(), "hi".to_string(), 16, false, oversize)
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    // ── SVC-2 completeness (Decision 3) ──

    #[test]
    fn svc2_every_method_is_classified() {
        use zbus::object_server::Interface;
        let svc = mk_svc(AuthPolicy::dev());
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_all_methods_classified("inference", &xml);
    }

    #[tokio::test]
    async fn svc2_every_method_denies_unrecognized_caller_when_deployed() {
        let svc = mk_svc(AuthPolicy::deployed());
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("Query");
        let m = msg(":1.999");
        assert!(
            matches!(
                svc.query(m.header(), "hi".to_string(), 16, false, String::new())
                    .await
                    .unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "query must be guarded"
        );
        exercised.push("Status");
        let m = msg(":1.999");
        assert!(
            matches!(
                svc.status(m.header()).await.unwrap_err(),
                zbus::fdo::Error::AccessDenied(_)
            ),
            "status must be guarded"
        );

        use zbus::object_server::Interface;
        let mut xml = String::new();
        svc.introspect_to_writer(&mut xml, 0);
        assert_behavioral_covers_all("inference", &xml, &exercised);
    }
}
