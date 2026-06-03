// SPDX-License-Identifier: MIT

//! D-Bus Inference interface.
//!
//! Exposes AI query routing over D-Bus so the shell can send
//! natural language prompts and receive responses with tier/model info.
//!
//! Interface: `org.delphi.Inference`
//!
//! SVC-2: `query` and `status` enforce authorization via the shared
//! [`AuthGuard`] on their first line (the general tier gate). The cloud-send
//! *subaction* within `query` — its same-caller-binding consent check,
//! SVC-1-R1-1-01 — is the Stage-3 seam wired here: `query` additionally
//! resolves the caller's credentials (`#[zbus(connection)]`), binds a pending
//! cloud-send confirmation to its issuing caller, and rejects a completion
//! echoed by any other caller. The bus-free core is [`query_authorized`], so
//! the binding is unit-testable without a live bus; the real-bus end-to-end
//! closure is the Stage-3 Piece-3 integration test.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::RwLock;
use tracing::info;
use zbus::message::Header;

use die_inference::router::Router;
use die_inference::{ConfirmationTokenWire, InferenceRequest, RouteOutcome};

use crate::auth::{CallerIdentity, CloudSendConfirmations};
use crate::auth_guard::AuthGuard;
use crate::caller_resolver::CallerResolver;

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
/// use delphi_services::auth::{AuthPolicy, CloudSendConfirmations};
/// use delphi_services::auth_guard::AuthGuard;
/// use delphi_services::caller_resolver::CallerResolver;
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
/// let svc = InferenceService::new(
///     router,
///     guard,
///     Arc::new(CallerResolver::new()),
///     Arc::new(Mutex::new(CloudSendConfirmations::default())),
/// );
/// ```
pub struct InferenceService {
    router: Arc<RwLock<Router>>,
    guard: Arc<AuthGuard>,
    /// Resolves caller credentials (uid via the connection) for the deployed
    /// cloud-send shell check. The unique name (same-caller binding basis) comes
    /// from the message header; this adds uid/pid best-effort, cached.
    resolver: Arc<CallerResolver>,
    /// Pending cloud-send confirmations, each bound to the unique bus name of the
    /// caller that requested it (SVC-1-R1-1-01). Shared mutable state so a
    /// confirmation issued on one `query` call is visible to the completing call.
    cloud_confirmations: Arc<Mutex<CloudSendConfirmations>>,
}

impl InferenceService {
    /// Create a new inference service backed by the given router, guarded by the
    /// shared [`AuthGuard`], with a [`CallerResolver`] (cloud-send credential
    /// resolution) and a shared [`CloudSendConfirmations`] registry (same-caller
    /// binding).
    ///
    /// # Examples
    ///
    /// ```
    /// use delphi_services::inference::InferenceService;
    /// use delphi_services::auth::{AuthPolicy, CloudSendConfirmations};
    /// use delphi_services::auth_guard::AuthGuard;
    /// use delphi_services::caller_resolver::CallerResolver;
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
    ///     Arc::new(CallerResolver::new()),
    ///     Arc::new(Mutex::new(CloudSendConfirmations::default())),
    /// );
    /// ```
    #[must_use]
    pub fn new(
        router: Arc<RwLock<Router>>,
        guard: Arc<AuthGuard>,
        resolver: Arc<CallerResolver>,
        cloud_confirmations: Arc<Mutex<CloudSendConfirmations>>,
    ) -> Self {
        Self {
            router,
            guard,
            resolver,
            cloud_confirmations,
        }
    }

    /// Bus-free core of [`query`](Self::query): everything after the general
    /// tier gate and caller resolution, given an already-resolved
    /// [`CallerIdentity`]. Lives in a non-`#[zbus::interface]` block so it is NOT
    /// exposed on the bus and CAN be unit-tested without a live `Connection`.
    ///
    /// The SVC-1-R1-1-01 same-caller binding is enforced here in two places:
    ///
    /// - **Completing** (a token is presented): the caller must be the one the
    ///   confirmation was bound to ([`AuthGuard::enforce_cloud_send`]), checked
    ///   BEFORE `route()` so an unauthorized completer never reaches the gateway
    ///   send.
    /// - **Requesting** (`route()` returns `CloudConfirmationRequired`): the
    ///   pending confirmation is bound to this caller via
    ///   [`CloudSendConfirmations::issue`], so only they can complete it.
    ///
    /// The registry key is a SHA-256 [`token_fingerprint`] of the confirmation
    /// token, never the raw token (SVC-1-R1-1-02).
    ///
    /// # Errors
    ///
    /// - [`zbus::fdo::Error::InvalidArgs`] if a string parameter exceeds its cap.
    /// - [`zbus::fdo::Error::AccessDenied`] if a presented confirmation is not
    ///   bound to this caller (the R1-1-01 closure).
    /// - [`zbus::fdo::Error::Failed`] if routing or serialization fails.
    async fn query_authorized(
        &self,
        caller: &CallerIdentity,
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
            caller = %caller.unique_name,
            "D-Bus inference query"
        );

        // SVC-1-R1-1-01 (completing): a presented token may only be redeemed by
        // the caller it was issued to. Gate BEFORE route() so a rejected
        // completer never reaches the gateway send. The lock is released before
        // the `?` and before any await (no std Mutex held across `.await`).
        if !cloud_confirmation_token.is_empty() {
            let fingerprint = token_fingerprint(&cloud_confirmation_token);
            let decision = {
                let confirmations = self
                    .cloud_confirmations
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                self.guard
                    .enforce_cloud_send(caller, &fingerprint, Instant::now(), &confirmations)
            };
            decision?;
        }

        let router = self.router.read().await;
        let req = InferenceRequest {
            input: prompt,
            max_tokens,
            sensitive,
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
            RouteOutcome::CloudConfirmationRequired(c) => {
                // SVC-1-R1-1-01 (requesting): bind this pending confirmation to
                // the caller that asked for it, so only they can complete it.
                let fingerprint = token_fingerprint(c.token.as_str());
                {
                    let mut confirmations = self
                        .cloud_confirmations
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    confirmations.issue(fingerprint, caller);
                }
                serde_json::json!({
                    "status": "confirmation_required",
                    "privacy_score": c.privacy_score,
                    "sanitized_preview": c.sanitized_preview,
                    // Explicit transport read of the redacted-Debug newtype.
                    "token": c.token.as_str(),
                })
            }
        };
        serde_json::to_string(&json)
            .map_err(|e| zbus::fdo::Error::Failed(format!("serialize: {e}")))
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
    /// **SVC-1-R1-1-01 same-caller binding (Stage 3):** a confirmation is bound
    /// to the unique bus name of the caller that requested it; a completion
    /// echoed by any *other* caller is rejected with `AccessDenied`, BEFORE the
    /// cloud send. The caller's credentials are resolved from the message header
    /// (unique name) plus the connection (uid, for the deployed shell check) —
    /// hence the `#[zbus(connection)]` special argument. The D-Bus wire
    /// signature is unchanged: `header`/`connection` are zbus special arguments,
    /// not method parameters.
    ///
    /// # Errors
    ///
    /// [`zbus::fdo::Error::AccessDenied`] for an unauthorized caller (general
    /// tier gate) or a cloud-send completion echoed by a non-issuing caller;
    /// [`zbus::fdo::Error::InvalidArgs`] for an oversize parameter;
    /// [`zbus::fdo::Error::Failed`] on routing/serialization failure.
    async fn query(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &zbus::Connection,
        prompt: String,
        max_tokens: u32,
        sensitive: bool,
        cloud_confirmation_token: String,
    ) -> zbus::fdo::Result<String> {
        self.guard.enforce("inference.query", &header)?;
        // SVC-1-R1-1-01: resolve the caller — unique name from the header (the
        // binding basis, always available) plus uid via the connection creds
        // (the deployed shell check). Cached by unique name, so the credential
        // round-trip happens only on the first call from a given caller.
        let caller = self.resolver.resolve(&header, conn).await;
        self.query_authorized(&caller, prompt, max_tokens, sensitive, cloud_confirmation_token)
            .await
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

/// SHA-256 hex fingerprint of a cloud-confirmation token. Used as the
/// [`CloudSendConfirmations`] registry key so the registry binds an operation to
/// its issuing caller WITHOUT storing the raw token (which the registry's
/// derived `Debug` would otherwise leak — SVC-1-R1-1-02). The 64-char hex digest
/// is stable for a given token within and across process runs (SHA-256 is
/// keyless), so the issuing call and the completing call derive the same key.
fn token_fingerprint(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(token.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use fortress::audit::AuditLog;

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
        InferenceService::new(
            router,
            guard,
            Arc::new(CallerResolver::new()),
            Arc::new(Mutex::new(CloudSendConfirmations::default())),
        )
    }

    /// A real session-bus connection for the few tests that must call the D-Bus
    /// `query`/`status` methods directly (they take `#[zbus(connection)]`). WSL2
    /// provides a session bus at `/run/user/<uid>/bus`; a bus-less CI must wrap
    /// the suite with `dbus-run-session`. The connection is unused on the guard-
    /// denial path these tests exercise (the general gate rejects before any
    /// credential resolution); it only needs to be a valid `Connection` value.
    async fn test_session_connection() -> zbus::Connection {
        zbus::Connection::session().await.expect(
            "a D-Bus session bus is required for inference D-Bus method tests \
             (WSL2 provides one; in CI run under `dbus-run-session`)",
        )
    }

    #[test]
    fn path_is_valid() {
        assert!(PATH.starts_with("/org/delphi"));
    }

    #[test]
    fn service_creation() {
        let _svc = mk_svc(AuthPolicy::dev());
    }

    /// SHA-256 fingerprint is stable for a token, distinct across tokens, and
    /// never embeds the raw token (the registry-leak guard, SVC-1-R1-1-02).
    #[test]
    fn token_fingerprint_is_stable_and_distinct() {
        let a = token_fingerprint("token-one");
        assert_eq!(a, token_fingerprint("token-one"), "fingerprint must be stable");
        assert_ne!(
            a,
            token_fingerprint("token-two"),
            "distinct tokens must produce distinct fingerprints"
        );
        assert_eq!(a.len(), 64, "SHA-256 hex digest is 64 chars");
        assert!(!a.contains("token-one"), "fingerprint must not embed the token");
    }

    /// SVC-6-R2-3: every `String` param of `query` is capped at the boundary
    /// (after the SVC-2 guard). Exercised bus-free through `query_authorized`,
    /// which holds the caps. Covers `prompt` and `cloud_confirmation_token`.
    #[tokio::test]
    async fn every_string_param_rejects_oversize() {
        let svc = mk_svc(AuthPolicy::dev());
        let caller = CallerIdentity::from_unique_name(":1.5");
        let oversize = "x".repeat(crate::limits::MAX_STRING_BYTES + 1);
        assert!(matches!(
            svc.query_authorized(&caller, oversize.clone(), 16, false, String::new())
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
        assert!(matches!(
            svc.query_authorized(&caller, "hi".to_string(), 16, false, oversize)
                .await
                .unwrap_err(),
            zbus::fdo::Error::InvalidArgs(_)
        ));
    }

    /// SVC-1-R1-1-01 at the service layer (bus-free): caller A's pending
    /// cloud-send confirmation cannot be completed by caller B echoing A's
    /// token. The gate denies BEFORE `route()`, so no send occurs. The real-bus
    /// end-to-end proof (RED against pre-SVC-2) is the Piece-3 live test; this
    /// exercises the same gate via `query_authorized` with pre-resolved
    /// identities and a manually-issued binding (simulating A's call 1).
    #[tokio::test]
    async fn cloud_send_token_bound_to_issuing_caller_blocks_other_caller() {
        let svc = mk_svc(AuthPolicy::dev());
        let caller_a = CallerIdentity::from_unique_name(":1.10");
        let caller_b = CallerIdentity::from_unique_name(":1.11");
        let token = "issued-to-A";

        // Call 1 (A requests): the confirmation is bound to A.
        {
            let mut reg = svc
                .cloud_confirmations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            reg.issue(token_fingerprint(token), &caller_a);
        }

        // Call 2 (B echoes A's token): denied at the gate, before route().
        let err = svc
            .query_authorized(&caller_b, "hi".to_string(), 16, false, token.to_string())
            .await
            .unwrap_err();
        assert!(
            matches!(err, zbus::fdo::Error::AccessDenied(_)),
            "caller B echoing A's cloud-send token must be denied (R1-1-01); got {err:?}"
        );
    }

    /// Complement of the closure: the issuing caller A passes the same-caller
    /// gate. `route()` then fails for lack of a configured backend in this unit
    /// context — but crucially NOT with `AccessDenied`, proving the gate admitted
    /// A and the send was attempted. The full success path is the Piece-3 live
    /// test (real gateway).
    #[tokio::test]
    async fn cloud_send_token_passes_gate_for_issuing_caller() {
        let svc = mk_svc(AuthPolicy::dev());
        let caller_a = CallerIdentity::from_unique_name(":1.10");
        let token = "issued-to-A";
        {
            let mut reg = svc
                .cloud_confirmations
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            reg.issue(token_fingerprint(token), &caller_a);
        }
        let result = svc
            .query_authorized(&caller_a, "hi".to_string(), 16, false, token.to_string())
            .await;
        if let Err(zbus::fdo::Error::AccessDenied(msg)) = &result {
            panic!("issuing caller A was wrongly denied at the cloud-send gate: {msg}");
        }
    }

    /// A token presented with no prior issue (forged, or for a different
    /// operation) is denied at the gate — the registry has no binding for its
    /// fingerprint. Closes the "any echoed token completes a send" hole.
    #[tokio::test]
    async fn cloud_send_unbound_token_is_denied() {
        let svc = mk_svc(AuthPolicy::dev());
        let caller = CallerIdentity::from_unique_name(":1.10");
        let err = svc
            .query_authorized(&caller, "hi".to_string(), 16, false, "never-issued".to_string())
            .await
            .unwrap_err();
        assert!(matches!(err, zbus::fdo::Error::AccessDenied(_)));
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
        let conn = test_session_connection().await;
        let mut exercised: Vec<&str> = Vec::new();

        exercised.push("Query");
        let m = msg(":1.999");
        assert!(
            matches!(
                svc.query(m.header(), &conn, "hi".to_string(), 16, false, String::new())
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
