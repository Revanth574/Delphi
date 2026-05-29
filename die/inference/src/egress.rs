// SPDX-License-Identifier: MIT

//! Cloud egress gateway — the single, structurally-enforced door to cloud
//! inference (services-sweep SVC-1).
//!
//! # Why this module exists
//!
//! Before SVC-1, [`crate::router::Router`] called `CloudClient::complete`
//! with the **raw** user prompt, and the only privacy control was the
//! caller-set `sensitive` bool. ZKQP ([`fortress::zkqp::QuerySanitizer`])
//! existed but was wired into nothing — any code path (and `die-inference`
//! is a *library*, callable outside the D-Bus services, e.g. directly from
//! `die-orchestrator::brain`) could transmit un-sanitized text to the cloud.
//! That violates CLAUDE.md §10.4 ("ALL cloud API calls must go through the
//! ZKQP proxy") and ZKQP rule 5 ("ALWAYS active for Tier 3 — no disable
//! option").
//!
//! # The structural guarantee (capability pattern, mirrors SVC-8)
//!
//! 1. [`CloudClient::complete`](crate::cloud::CloudClient::complete) is
//!    `pub(crate)` and accepts a [`SanitizedPrompt`], never a raw `&str`.
//! 2. [`SanitizedPrompt`]'s field and constructor are private to THIS
//!    module — the only code that can mint one is [`CloudEgressGateway`],
//!    and it does so only from the output of a ZKQP `sanitize` call.
//! 3. [`CloudEgressGateway::complete`] is the only public path to cloud
//!    egress. It sanitizes first, pauses on a high privacy score, mints the
//!    capability from the sanitized text, sends, and restores the response
//!    (consuming the PII mapping immediately).
//!
//! Therefore no code — current or future, D-Bus or library — can reach the
//! cloud without sanitization, and the compiler/`pub(crate)` visibility
//! enforces it rather than a call-site convention. Audit by grep: the only
//! caller of `CloudClient::complete` is this module; the only constructor of
//! `SanitizedPrompt` is this module.
//!
//! # Both halves are structural — send (sanitize) AND receive (restore)
//!
//! [`fortress::zkqp::SanitizationResult`] carries the PII->placeholder
//! mapping with no `Debug`/`Clone` and a `restore(self)` that consumes it.
//! The gateway owns the result as a local across the cloud `.await`, restores
//! the response immediately, and drops it — the mapping never lands on a
//! long-lived struct, never logs, and cannot outlive the single request.

use fortress::zkqp::QuerySanitizer;
use tracing::{info, warn};

use crate::cloud::{CloudClient, CloudModel, CloudResponse};
use crate::error::InferenceError;

/// A prompt that has passed ZKQP sanitization and is cleared for cloud
/// transmission (SVC-1 capability token).
///
/// The inner text and the constructor are private to the `egress` module, so
/// possession of a `SanitizedPrompt` is **proof** the text was produced by a
/// ZKQP `sanitize` call routed through [`CloudEgressGateway`]. No other code
/// — even elsewhere in `die-inference` — can fabricate one, so
/// [`CloudClient::complete`](crate::cloud::CloudClient::complete) (which
/// requires `&SanitizedPrompt`) cannot be reached with un-sanitized text.
pub struct SanitizedPrompt(String);

impl SanitizedPrompt {
    /// Mint a capability from already-sanitized text. Private to the module:
    /// only [`CloudEgressGateway::complete`] calls it, immediately after a
    /// ZKQP `sanitize`. Kept `fn` (not `pub`) so no external — or even other
    /// in-crate — code can construct the token from arbitrary text.
    fn from_sanitized(text: String) -> Self {
        Self(text)
    }

    /// The sanitized text to place on the wire. `pub(crate)` so
    /// [`CloudClient`](crate::cloud::CloudClient) can read it to build the
    /// request body; reading is harmless — the capability protection is on
    /// *construction*, not access.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// The single public door to cloud inference (SVC-1). Owns the
/// [`CloudClient`] (HTTP mechanics) and the [`QuerySanitizer`] (ZKQP), so the
/// only way to reach the cloud is through a method that sanitizes first.
pub struct CloudEgressGateway {
    client: CloudClient,
    sanitizer: QuerySanitizer,
}

/// The result of an egress attempt.
#[derive(Debug)]
pub enum EgressOutcome {
    /// The cloud responded; `response.text` has had placeholders restored to
    /// the original PII values.
    Completed(CloudResponse),
    /// The query's privacy score is too high to send without explicit user
    /// confirmation (CLAUDE.md ZKQP rule 4). Nothing was sent; the PII
    /// mapping has already been dropped.
    ConfirmationRequired {
        /// The ZKQP privacy score (0-100).
        privacy_score: u32,
        /// The sanitized query for the user to review (PII already replaced).
        sanitized_preview: String,
    },
}

impl CloudEgressGateway {
    /// Build a gateway with an API key (constructs the [`CloudClient`]) and a
    /// default [`QuerySanitizer`].
    #[must_use]
    pub fn new(api_key: String) -> Self {
        Self {
            client: CloudClient::new(api_key),
            sanitizer: QuerySanitizer::new(),
        }
    }

    /// Whether the underlying cloud client has an API key configured.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.client.is_available()
    }

    /// Sanitize `raw_prompt`, send it to the cloud (unless a high privacy
    /// score requires confirmation the caller has not yet given), and restore
    /// PII placeholders in the response — the ONLY public cloud-egress path.
    ///
    /// - If the privacy score is too high and `confirmed == false`, returns
    ///   [`EgressOutcome::ConfirmationRequired`] WITHOUT sending; the PII
    ///   mapping is dropped at function exit and never spans the user round
    ///   trip. On the user's accept, the caller re-issues with
    ///   `confirmed == true`, which re-sanitizes deterministically and sends.
    /// - Otherwise sends the sanitized text via the capability-gated
    ///   [`CloudClient::complete`](crate::cloud::CloudClient::complete) and
    ///   returns [`EgressOutcome::Completed`] with the response de-sanitized.
    ///
    /// # Errors
    ///
    /// Propagates [`InferenceError`] from the cloud client (timeout, API
    /// error, missing key).
    pub async fn complete(
        &self,
        raw_prompt: &str,
        max_tokens: u32,
        model: CloudModel,
        confirmed: bool,
    ) -> Result<EgressOutcome, InferenceError> {
        // Step 1: ZKQP sanitize. `result` owns the PII mapping; it is a local
        // held across the `.await` below, restored immediately, then dropped.
        let result = self.sanitizer.sanitize(raw_prompt);

        // Step 2: privacy-score pause. If too risky and the user has not
        // explicitly consented, return WITHOUT sending. `result` (and its
        // mapping) drops here — it never spans the user confirmation round
        // trip; the confirmed retry re-sanitizes deterministically.
        if result.requires_confirmation() && !confirmed {
            warn!(
                score = result.score().total,
                "ZKQP: cloud query paused — privacy score requires user confirmation"
            );
            return Ok(EgressOutcome::ConfirmationRequired {
                privacy_score: result.score().total,
                sanitized_preview: result.sanitized_text().to_string(),
            });
        }

        // Step 3: mint the capability from the sanitized text and send. This
        // is the ONLY construction of a SanitizedPrompt in the codebase.
        let sanitized = SanitizedPrompt::from_sanitized(result.sanitized_text().to_string());
        if result.pii_count() > 0 {
            info!(
                pii_count = result.pii_count(),
                score = result.score().total,
                "ZKQP: sending sanitized query to cloud"
            );
        }
        let cloud_resp = self.client.complete(&sanitized, max_tokens, model).await?;

        // Step 4: restore placeholders -> PII in the response. `restore`
        // consumes `result`, so the mapping is gone the instant this returns.
        let restored = result.restore(&cloud_resp.text);
        Ok(EgressOutcome::Completed(CloudResponse {
            text: restored,
            model: cloud_resp.model,
            latency_ms: cloud_resp.latency_ms,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_unavailable_without_key() {
        let gw = CloudEgressGateway::new(String::new());
        assert!(!gw.is_available());
    }

    #[test]
    fn gateway_available_with_key() {
        let gw = CloudEgressGateway::new("sk-test".to_string());
        assert!(gw.is_available());
    }

    /// SVC-1: a high-privacy-score query without confirmation must PAUSE
    /// (return ConfirmationRequired) and NOT attempt to send. We use an empty
    /// API key: if the gateway tried to send, `complete` would surface a
    /// CloudApi "no API key" error; instead it returns ConfirmationRequired
    /// BEFORE reaching the client, proving the pause short-circuits egress.
    #[tokio::test]
    async fn high_score_query_pauses_before_send() {
        let gw = CloudEgressGateway::new(String::new());
        // Email weight is 20 and the confirmation threshold is STRICTLY > 80
        // (4 emails = 80 is still "safe"), so 5 distinct emails = 100 > 80
        // deterministically triggers the pause without relying on the weights
        // of other PII types.
        let risky = "Mail a@a.com b@b.com c@c.com d@d.com e@e.com for the rollout";
        let outcome = gw
            .complete(risky, 64, CloudModel::ClaudeSonnet, false)
            .await
            .expect("pause is an Ok outcome, not an error");
        match outcome {
            EgressOutcome::ConfirmationRequired {
                privacy_score,
                sanitized_preview,
            } => {
                assert!(privacy_score > 80, "score {privacy_score} should exceed 80");
                // The preview is already sanitized — no raw PII in it.
                assert!(!sanitized_preview.contains("a@a.com"));
                assert!(!sanitized_preview.contains("e@e.com"));
            }
            EgressOutcome::Completed(_) => {
                panic!("a high-score query must pause, not send")
            }
        }
    }

    /// SVC-1: explicit confirmation (`confirmed = true`) overrides the pause
    /// — the same high-score query then proceeds to send (and, with an empty
    /// key, errors on send rather than pausing). Proves `cloud_confirmed`
    /// honors the user's explicit decision (Iron Law #1) without ever
    /// skipping sanitization.
    #[tokio::test]
    async fn confirmed_high_score_query_proceeds_to_send() {
        let gw = CloudEgressGateway::new(String::new());
        let risky = "Mail a@a.com b@b.com c@c.com d@d.com e@e.com for the rollout";
        let err = gw
            .complete(risky, 64, CloudModel::ClaudeSonnet, true)
            .await
            .expect_err("confirmed + empty key must attempt send and error");
        assert!(err.to_string().contains("no API key"), "got: {err}");
    }

    /// SVC-1 (moved from cloud.rs): a clean (no-PII) query does NOT pause, so
    /// the gateway proceeds to send — and with an empty API key the cloud
    /// client surfaces the "no API key" CloudApi error. This proves the
    /// non-paused path actually reaches the capability-gated send.
    #[tokio::test]
    async fn clean_query_without_key_errors_on_send() {
        let gw = CloudEgressGateway::new(String::new());
        let outcome = gw
            .complete("What is 2 + 2?", 64, CloudModel::ClaudeSonnet, false)
            .await;
        let err = outcome.expect_err("empty key must error on send").to_string();
        assert!(err.contains("no API key"), "got: {err}");
    }

    /// SVC-1 (c): the only text a `SanitizedPrompt` can carry is ZKQP-sanitized
    /// — it is minted exclusively from `SanitizationResult::sanitized_text()`,
    /// so raw PII can never reach `CloudClient::complete` (which requires the
    /// capability). This reproduces the gateway's mint step and asserts the
    /// capability's payload has the email replaced by a placeholder. RED
    /// against pre-SVC-1 code (neither `SanitizedPrompt` nor the mint existed).
    #[test]
    fn sanitized_prompt_carries_no_raw_pii() {
        let sanitizer = QuerySanitizer::new();
        let result = sanitizer.sanitize("Email a@b.com about the plan");
        assert!(result.pii_count() > 0, "email must be detected");
        // The gateway mints the capability from the sanitized text — the SOLE
        // construction path. Whatever ends up in the capability is what
        // reaches the wire.
        let prompt = SanitizedPrompt::from_sanitized(result.sanitized_text().to_string());
        assert!(
            !prompt.as_str().contains("a@b.com"),
            "raw PII must never reach the cloud egress capability"
        );
        assert!(
            prompt.as_str().contains("[EMAIL_"),
            "the capability must carry the placeholder, not the original"
        );
    }
}
