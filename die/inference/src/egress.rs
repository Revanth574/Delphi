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

use std::sync::atomic::{AtomicBool, Ordering};

use fortress::zkqp::QuerySanitizer;
use hmac::Mac;
use rand::RngCore;
use tracing::{info, warn};

use crate::cloud::{CloudClient, CloudModel, CloudResponse};
use crate::error::InferenceError;
use crate::token::{self, ConfirmationToken, ConfirmationTokenWire};

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
    /// Ephemeral per-gateway HMAC key for [`ConfirmationToken`]s (SVC-1-R1-1).
    /// Generated once at construction, never exposed. Only this gateway can
    /// mint or verify a token, so a caller cannot forge consent. Rotating it
    /// (gateway reconstruction) simply invalidates any outstanding token.
    token_key: [u8; 32],
    /// SVC-2 Piece 2: session-level "data may leave this device" consent,
    /// enforced STRUCTURALLY here — [`complete`](Self::complete) refuses to send
    /// while this is `false`, returning [`EgressOutcome::DestinationConsentRequired`]
    /// instead. Independent of the privacy score (it covers low-score sends the
    /// privacy pause does not gate) and of the same-caller token binding
    /// (SVC-1-R1-1-01, which gates *which caller* may redeem a token). Default
    /// `false`: a fresh gateway (a new session) refuses cloud egress until the
    /// user grants it via [`grant_destination_consent`](Self::grant_destination_consent).
    /// A gateway is the only thing that can flip it, so a caller skipping the
    /// shell dialog still cannot reach the send.
    destination_consent: AtomicBool,
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
        /// Opaque [`ConfirmationToken`] wire form (SVC-1-R1-1), carried as a
        /// [`ConfirmationTokenWire`] with redacted `Debug` (SVC-1-R1-1-02) so a
        /// `{:?}` on this outcome can't persist the live token. The caller
        /// echoes it back to approve sending; it is HMAC-bound to this exact
        /// sanitized prompt / model / max_tokens and expires shortly.
        token_wire: ConfirmationTokenWire,
    },
    /// SVC-2 Piece 2: the session has not granted destination consent ("data may
    /// leave this device"), so the gateway STRUCTURALLY refused to send —
    /// nothing was transmitted, regardless of the privacy score. Distinct from
    /// [`ConfirmationRequired`](Self::ConfirmationRequired) (which is about
    /// *content* sensitivity once egress is already permitted). Carries the
    /// sanitized preview and a fresh token so the shell can present a single
    /// "allow cloud + here's what would be sent" dialog; on grant the caller
    /// re-issues with [`grant_destination_consent`](CloudEgressGateway::grant_destination_consent)
    /// set and the same token (which also satisfies the privacy pause if the
    /// score is high). The token's `Debug` is redacted exactly as above.
    DestinationConsentRequired {
        /// The ZKQP privacy score (0-100) of the would-be send, for the dialog.
        privacy_score: u32,
        /// The sanitized query the user is being shown (PII already replaced).
        sanitized_preview: String,
        /// Opaque token (SVC-1-R1-1) bound to this sanitized prompt; reused on
        /// the granted retry so one user acceptance both grants destination
        /// consent and (for a high-score query) clears the privacy pause.
        token_wire: ConfirmationTokenWire,
    },
}

impl CloudEgressGateway {
    /// Build a gateway with an API key (constructs the [`CloudClient`]) and a
    /// default [`QuerySanitizer`].
    #[must_use]
    pub fn new(api_key: String) -> Self {
        let mut token_key = [0u8; 32];
        rand::rng().fill_bytes(&mut token_key);
        Self {
            client: CloudClient::new(api_key),
            sanitizer: QuerySanitizer::new(),
            token_key,
            // Closed by default: a new session refuses cloud egress until the
            // user explicitly grants destination consent (SVC-2 Piece 2).
            destination_consent: AtomicBool::new(false),
        }
    }

    /// Grant session-level destination consent — "data may leave this device
    /// this session" (SVC-2 Piece 2). After this, [`complete`](Self::complete)
    /// stops short-circuiting with [`EgressOutcome::DestinationConsentRequired`]
    /// and proceeds to the privacy-score pause / send. Idempotent. The grant is
    /// per-gateway, so it lasts the gateway's (session's) lifetime and resets
    /// when the gateway is reconstructed.
    pub fn grant_destination_consent(&self) {
        self.destination_consent.store(true, Ordering::SeqCst);
    }

    /// Whether session destination consent has been granted. For diagnostics
    /// and tests; the enforcement is in [`complete`](Self::complete), not here.
    #[must_use]
    pub fn is_destination_consented(&self) -> bool {
        self.destination_consent.load(Ordering::SeqCst)
    }

    /// Whether the underlying cloud client has an API key configured.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.client.is_available()
    }

    /// Sanitize `raw_prompt`, send it to the cloud (unless a high privacy
    /// score requires confirmation the caller has not yet supplied a valid
    /// token for), and restore PII placeholders in the response — the ONLY
    /// public cloud-egress path.
    ///
    /// `confirmation_token_wire` is the opaque wire string the caller echoes
    /// back from a prior [`EgressOutcome::ConfirmationRequired`] (SVC-1-R1-1).
    ///
    /// - If the privacy score is too high and no VALID token is presented,
    ///   returns [`EgressOutcome::ConfirmationRequired`] WITHOUT sending,
    ///   carrying a freshly-issued token bound to this sanitized prompt. The
    ///   PII mapping is dropped at function exit and never spans the user
    ///   round trip. A token verifies only if the gateway issued it for this
    ///   exact sanitized prompt / model / max_tokens and it has not expired;
    ///   an edited prompt or a forged/expired token fails and re-pauses.
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
        confirmation_token_wire: Option<&str>,
    ) -> Result<EgressOutcome, InferenceError> {
        // Step 1: ZKQP sanitize. `result` owns the PII mapping; it is a local
        // held across the `.await` below, restored immediately, then dropped.
        let result = self.sanitizer.sanitize(raw_prompt);

        // Step 2 (SVC-2 Piece 2): structural destination-consent gate. The
        // gateway refuses to send until the session has granted "data may leave
        // this device" — enforced HERE, at the single egress door, not in a
        // shell dialog a caller could skip. It is independent of the privacy
        // score (covers low-score sends the pause below does not gate) and of
        // the same-caller token binding (SVC-1-R1-1-01). We mint a token bound
        // to this sanitized prompt and carry it (plus the preview) so the shell
        // can show one "allow cloud + here's what would be sent" dialog; on the
        // granted retry the same token also clears the Step-3 pause for a
        // high-score query. `result` (and its PII mapping) drops here on this
        // path — it never spans the user round trip.
        if !self.destination_consent.load(Ordering::SeqCst) {
            let fresh = self.issue_token(result.sanitized_text(), model, max_tokens);
            warn!(
                score = result.score().total,
                "cloud egress refused: session destination consent not granted"
            );
            return Ok(EgressOutcome::DestinationConsentRequired {
                privacy_score: result.score().total,
                sanitized_preview: result.sanitized_text().to_string(),
                token_wire: ConfirmationTokenWire::new(fresh.to_wire()),
            });
        }

        // Step 3: privacy-score pause. If too risky, require a VALID token
        // bound to THIS sanitized prompt. A bool can be forged by any caller
        // (Codex SVC-1-R1-1); an HMAC token cannot. Verify against the freshly
        // re-sanitized text — an edited prompt, a forged token, or an expired
        // token all fail and re-pause. `result` (and its mapping) drops here
        // on the pause path; it never spans the user confirmation round trip.
        if result.requires_confirmation() {
            let approved = confirmation_token_wire
                .and_then(ConfirmationToken::from_wire)
                .is_some_and(|t| {
                    self.verify_token(&t, result.sanitized_text(), model, max_tokens)
                });
            if !approved {
                let fresh = self.issue_token(result.sanitized_text(), model, max_tokens);
                warn!(
                    score = result.score().total,
                    "ZKQP: cloud query paused — privacy score requires user confirmation"
                );
                return Ok(EgressOutcome::ConfirmationRequired {
                    privacy_score: result.score().total,
                    sanitized_preview: result.sanitized_text().to_string(),
                    token_wire: ConfirmationTokenWire::new(fresh.to_wire()),
                });
            }
        }

        // Step 4: mint the capability from the sanitized text and send. This
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

        // Step 5: restore placeholders -> PII in the response. `restore`
        // consumes `result`, so the mapping is gone the instant this returns.
        let restored = result.restore(&cloud_resp.text);
        Ok(EgressOutcome::Completed(CloudResponse {
            text: restored,
            model: cloud_resp.model,
            latency_ms: cloud_resp.latency_ms,
        }))
    }

    /// Mint a [`ConfirmationToken`] bound to `(sanitized_prompt, model,
    /// max_tokens)` and the current time, MAC'd with the gateway's ephemeral
    /// key (SVC-1-R1-1). The SOLE trusted minting path — only the gateway has
    /// the key, so only the gateway can produce a token that
    /// [`verify_token`](Self::verify_token) will accept.
    fn issue_token(
        &self,
        sanitized_prompt: &str,
        model: CloudModel,
        max_tokens: u32,
    ) -> ConfirmationToken {
        let issued_at = token::now_unix();
        let mac = token::build_mac(&self.token_key, sanitized_prompt, model, max_tokens, issued_at)
            .finalize()
            .into_bytes();
        ConfirmationToken::from_parts(issued_at, token::hex_encode(&mac))
    }

    /// Verify a [`ConfirmationToken`] against the freshly re-sanitized prompt
    /// (SVC-1-R1-1): the HMAC must match (constant-time, via the hmac crate's
    /// `verify_slice`) AND the token must be within its TTL. Any mismatch —
    /// forged token, a different/edited prompt, or expiry — returns `false`,
    /// causing the caller to re-pause with a fresh token.
    ///
    /// `pub(crate)` so the router-level test surface can exercise it; the
    /// security rests on the private `token_key`, not on this method's
    /// visibility.
    pub(crate) fn verify_token(
        &self,
        token: &ConfirmationToken,
        sanitized_prompt: &str,
        model: CloudModel,
        max_tokens: u32,
    ) -> bool {
        if !token::within_ttl(token.issued_at_unix(), token::now_unix()) {
            return false;
        }
        let Some(expected) = token::hex_decode(token.mac_hex()) else {
            return false;
        };
        token::build_mac(
            &self.token_key,
            sanitized_prompt,
            model,
            max_tokens,
            token.issued_at_unix(),
        )
        .verify_slice(&expected)
        .is_ok()
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
        // SVC-2 Piece 2: grant destination consent so this exercises the
        // privacy pause (Step 3), not the destination gate (Step 2) that now
        // precedes it.
        gw.grant_destination_consent();
        // Email weight is 20 and the confirmation threshold is STRICTLY > 80
        // (4 emails = 80 is still "safe"), so 5 distinct emails = 100 > 80
        // deterministically triggers the pause without relying on the weights
        // of other PII types.
        let risky = "Mail a@a.com b@b.com c@c.com d@d.com e@e.com for the rollout";
        let outcome = gw
            .complete(risky, 64, CloudModel::ClaudeSonnet, None)
            .await
            .expect("pause is an Ok outcome, not an error");
        match outcome {
            EgressOutcome::ConfirmationRequired {
                privacy_score,
                sanitized_preview,
                token_wire,
            } => {
                assert!(privacy_score > 80, "score {privacy_score} should exceed 80");
                // The preview is already sanitized — no raw PII in it.
                assert!(!sanitized_preview.contains("a@a.com"));
                assert!(!sanitized_preview.contains("e@e.com"));
                // A token bound to this prompt is supplied for the retry.
                assert!(!token_wire.as_str().is_empty());
            }
            EgressOutcome::Completed(_) => {
                panic!("a high-score query must pause, not send")
            }
            EgressOutcome::DestinationConsentRequired { .. } => {
                panic!("destination consent was granted — the gate must not fire")
            }
        }
    }

    /// SVC-1-R1-1: the confirmation gate is a CAPABILITY, not a bool. A
    /// caller cannot skip the pause on the first call — there is no token to
    /// present (`None`), and a fabricated token fails verification. Only the
    /// gateway-issued token (obtained from a prior pause) authorizes the send.
    /// This is the full pause -> token -> retry -> send cycle, AND the
    /// input-change rejection (a token bound to prompt A does not authorize a
    /// different prompt B). RED against the pre-fix `confirmed: bool` (which
    /// any caller could set true on the first call).
    #[tokio::test]
    async fn confirmation_requires_a_valid_gateway_issued_token() {
        let gw = CloudEgressGateway::new(String::new());
        // SVC-2 Piece 2: this test isolates the SVC-1 token capability (Step 3),
        // so grant destination consent up front to pass the Step-2 gate.
        gw.grant_destination_consent();
        let prompt_a = "Mail a@a.com b@b.com c@c.com d@d.com e@e.com for the rollout";

        // First call, no token -> pause, carrying a token bound to prompt A.
        let token_a = match gw
            .complete(prompt_a, 64, CloudModel::ClaudeSonnet, None)
            .await
            .unwrap()
        {
            EgressOutcome::ConfirmationRequired { token_wire, .. } => token_wire,
            EgressOutcome::Completed(_) => panic!("first call must pause"),
            EgressOutcome::DestinationConsentRequired { .. } => {
                panic!("destination consent granted — Step-2 gate must not fire")
            }
        };

        // A FORGED token (valid shape, wrong MAC) must NOT authorize: re-pause.
        let forged = format!("{}:{}", token::now_unix(), "ab".repeat(32));
        match gw
            .complete(prompt_a, 64, CloudModel::ClaudeSonnet, Some(&forged))
            .await
            .unwrap()
        {
            EgressOutcome::ConfirmationRequired { .. } => {}
            EgressOutcome::Completed(_) => panic!("a forged token must not authorize send"),
            EgressOutcome::DestinationConsentRequired { .. } => {
                panic!("destination consent granted — Step-2 gate must not fire")
            }
        }

        // The GENUINE token for prompt A authorizes the send (errors only on
        // the empty key, proving it reached the capability-gated client).
        let err = gw
            .complete(prompt_a, 64, CloudModel::ClaudeSonnet, Some(token_a.as_str()))
            .await
            .expect_err("valid token + empty key must attempt send and error");
        assert!(err.to_string().contains("no API key"), "got: {err}");

        // Prompt A's token must NOT authorize a prompt whose SANITIZED text
        // differs (the HMAC binds to the sanitized payload, SVC-1-R1-1). NB:
        // the binding is to the *sanitized* text, so swapping PII values alone
        // (a@a.com -> z@z.com) yields the SAME placeholders and SAME token —
        // which is correct (the cloud receives exactly the approved payload).
        // Invalidation triggers on an edit to the non-PII structure, which is
        // what a user "editing the query" changes. So prompt_b alters the
        // surrounding words, changing the sanitized text.
        let prompt_b = "URGENT please notify a@a.com b@b.com c@c.com d@d.com e@e.com today";
        match gw
            .complete(prompt_b, 64, CloudModel::ClaudeSonnet, Some(token_a.as_str()))
            .await
            .unwrap()
        {
            EgressOutcome::ConfirmationRequired { .. } => {}
            EgressOutcome::Completed(_) => {
                panic!("a token bound to prompt A's sanitized text must not authorize a differently-sanitized prompt")
            }
            EgressOutcome::DestinationConsentRequired { .. } => {
                panic!("destination consent granted — Step-2 gate must not fire")
            }
        }
    }

    /// SVC-1-R1-1 (c): an EXPIRED but otherwise-valid token is rejected. We
    /// mint a correctly-MAC'd token with an old `issued_at` using the
    /// gateway's own key (same-module test access) — proving the TTL check is
    /// independent of MAC validity. A fresh token for the same inputs verifies.
    #[test]
    fn expired_token_is_rejected() {
        let gw = CloudEgressGateway::new(String::new());
        let sanitized = "[EMAIL_001] [EMAIL_002]";
        let model = CloudModel::ClaudeSonnet;

        let old = token::now_unix().saturating_sub(token::TOKEN_TTL_SECS + 5);
        let mac_old = token::build_mac(&gw.token_key, sanitized, model, 64, old)
            .finalize()
            .into_bytes();
        let expired = ConfirmationToken::from_parts(old, token::hex_encode(&mac_old));
        assert!(
            !gw.verify_token(&expired, sanitized, model, 64),
            "an expired token must be rejected even with a valid MAC"
        );

        let now = token::now_unix();
        let mac_now = token::build_mac(&gw.token_key, sanitized, model, 64, now)
            .finalize()
            .into_bytes();
        let fresh = ConfirmationToken::from_parts(now, token::hex_encode(&mac_now));
        assert!(
            gw.verify_token(&fresh, sanitized, model, 64),
            "a fresh, correctly-bound token must verify"
        );
    }

    /// SVC-1 (moved from cloud.rs): a clean (no-PII) query does NOT pause, so
    /// the gateway proceeds to send — and with an empty API key the cloud
    /// client surfaces the "no API key" CloudApi error. This proves the
    /// non-paused path actually reaches the capability-gated send.
    #[tokio::test]
    async fn clean_query_without_key_errors_on_send() {
        let gw = CloudEgressGateway::new(String::new());
        // SVC-2 Piece 2: grant destination consent so a clean (low-score) query
        // reaches the send rather than the Step-2 destination gate.
        gw.grant_destination_consent();
        let outcome = gw
            .complete("What is 2 + 2?", 64, CloudModel::ClaudeSonnet, None)
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

    /// SVC-2 Piece 2: the structural destination-consent gate. A fresh gateway
    /// REFUSES egress — even a clean, low-score query that would otherwise send
    /// straight out — returning `DestinationConsentRequired` and reaching no
    /// client. With an empty key, a send attempt would surface "no API key", so
    /// the ABSENCE of that error proves nothing was transmitted. After grant,
    /// the same clean query proceeds to the capability-gated send (surfacing
    /// "no API key"). This is the egress refusal mirroring how the SVC-1 pause
    /// and the SVC-1-R1-1-01 binding short-circuit before the send.
    #[tokio::test]
    async fn destination_consent_gate_refuses_send_until_granted() {
        let gw = CloudEgressGateway::new(String::new());
        assert!(!gw.is_destination_consented(), "closed by default");
        // Closed by default: even a clean, low-score query is refused at egress.
        match gw
            .complete("What is 2 + 2?", 64, CloudModel::ClaudeSonnet, None)
            .await
            .expect("a refusal is an Ok outcome, not an error — nothing was sent")
        {
            EgressOutcome::DestinationConsentRequired { token_wire, .. } => {
                assert!(
                    !token_wire.as_str().is_empty(),
                    "carries a token bound to the content for the granted retry"
                );
            }
            other => panic!("a fresh gateway must refuse cloud egress; got {other:?}"),
        }

        // After grant, the clean query reaches the capability-gated send.
        gw.grant_destination_consent();
        assert!(gw.is_destination_consented());
        let err = gw
            .complete("What is 2 + 2?", 64, CloudModel::ClaudeSonnet, None)
            .await
            .expect_err("granted + empty key must attempt the send and error");
        assert!(err.to_string().contains("no API key"), "got: {err}");
    }

    /// SVC-2 Piece 2: the destination gate (Step 2) precedes the privacy pause
    /// (Step 3). A high-PII query on a fresh gateway yields
    /// `DestinationConsentRequired`, NOT `ConfirmationRequired` — "may data
    /// leave at all" is asked before "is this content sensitive". The refusal
    /// still carries the sanitized preview (no raw PII) so the shell can combine
    /// both consents into one dialog.
    #[tokio::test]
    async fn destination_gate_precedes_privacy_pause() {
        let gw = CloudEgressGateway::new(String::new());
        let risky = "Mail a@a.com b@b.com c@c.com d@d.com e@e.com for the rollout";
        match gw
            .complete(risky, 64, CloudModel::ClaudeSonnet, None)
            .await
            .expect("refusal is an Ok outcome")
        {
            EgressOutcome::DestinationConsentRequired {
                privacy_score,
                sanitized_preview,
                ..
            } => {
                assert!(privacy_score > 80, "carries the would-be score {privacy_score}");
                assert!(!sanitized_preview.contains("a@a.com"), "preview is sanitized");
            }
            EgressOutcome::ConfirmationRequired { .. } => {
                panic!("the destination gate must precede the privacy pause")
            }
            EgressOutcome::Completed(_) => panic!("nothing must be sent without consent"),
        }
    }
}
