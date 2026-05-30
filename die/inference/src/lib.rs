// SPDX-License-Identifier: MIT

//! # DIE Inference
//!
//! Three-tier inference manager for the Delphi Intelligence Engine.
//!
//! Routes inference requests across three tiers:
//! - **Tier 1 (Local):** Small on-device models (Qwen3 7B / Llama 3.1 8B, 4-bit GGUF)
//! - **Tier 2 (Local/Cloud):** Medium models (Qwen3 30B / DeepSeek-V3-Lite / Claude Sonnet)
//! - **Tier 3 (Cloud + ZKQP):** Large cloud models (Claude Opus / GPT-5.4 / Gemini 3.1 Pro)
//!
//! The router selects the cheapest capable model per task. Requests
//! containing sensitive data are forced to local routing.
//!
//! # Dependencies
//!
//! Depends on [`fortress`] for secure credential storage (cloud API keys).
//! Does **not** depend on any module above it in the hierarchy.

pub mod cloud;
pub mod egress;
pub mod error;
pub mod hardware;
pub mod model;
pub mod router;
pub mod token;

pub use error::InferenceError;
pub use token::{ConfirmationToken, ConfirmationTokenWire};

/// An inference request to be routed to the appropriate tier.
///
/// # Examples
///
/// ```
/// use die_inference::InferenceRequest;
///
/// let req = InferenceRequest {
///     input: "Summarize this document".to_string(),
///     max_tokens: 512,
///     sensitive: false,
///     cloud_confirmation_token: None,
/// };
/// assert!(!req.sensitive);
/// ```
#[derive(Debug, Clone)]
pub struct InferenceRequest {
    /// The prompt or input text.
    pub input: String,
    /// Maximum tokens to generate.
    pub max_tokens: u32,
    /// Whether this request contains sensitive data (forces local routing).
    ///
    /// This is the ROUTING signal (Iron Law #1 — explicit caller intent):
    /// `true` means "never leaves the device." It governs *whether* a query
    /// may reach the cloud at all. It is **independent** of ZKQP protection
    /// — ZKQP sanitization is applied structurally to anything that does go
    /// to cloud, regardless of this flag (SVC-1).
    pub sensitive: bool,
    /// Opaque confirmation token carrying the user's explicit consent to send
    /// a high-privacy-score query's *sanitized* version to the cloud
    /// (SVC-1-R1-1). `None` by default: a high-privacy-score query pauses with
    /// [`RouteOutcome::CloudConfirmationRequired`] (which supplies a token)
    /// instead of sending. After the user reviews the sanitized preview and
    /// accepts, the caller re-issues with this set to the token's wire string.
    ///
    /// This is the opaque **wire form** of a [`ConfirmationToken`], carried as
    /// a [`ConfirmationTokenWire`] — a `String` newtype with a redacted `Debug`
    /// (SVC-1-R1-1-02) so this request (and every boundary type it flows
    /// through) stays `Debug`/`Clone` without a stray `{:?}` ever persisting
    /// the live token. Forgery resistance is the token's HMAC, NOT this field's
    /// type: a fabricated string fails the gateway's
    /// [`verify_token`](crate::egress::CloudEgressGateway::verify_token) and is
    /// treated as "no confirmation" (the query pauses again). It never causes
    /// unsanitized text to be sent — ZKQP applies regardless; a valid token
    /// only overrides the *pause* (Iron Law #1).
    pub cloud_confirmation_token: Option<ConfirmationTokenWire>,
}

/// The outcome of routing an inference request (SVC-1).
///
/// The cloud path can pause for user confirmation when ZKQP judges a query's
/// privacy score too high, so routing no longer always yields a response —
/// it yields either a completed response or a confirmation request. This
/// typed outcome propagates the pause to the caller (router -> service ->
/// shell) rather than swallowing it mid-pipeline.
#[derive(Debug, Clone)]
pub enum RouteOutcome {
    /// The request completed (local, or cloud with the response de-sanitized).
    Completed(InferenceResponse),
    /// The cloud query was sanitized but its privacy score is high enough to
    /// require explicit user confirmation before sending (CLAUDE.md ZKQP
    /// rule 4). Nothing was sent; no PII mapping is retained. The caller
    /// shows the preview and, on acceptance, re-issues with
    /// [`InferenceRequest::cloud_confirmation_token`] set to the carried
    /// [`CloudConfirmation::token`] wire string (SVC-1-R1-1).
    CloudConfirmationRequired(CloudConfirmation),
}

/// Details of a paused cloud query awaiting user confirmation (SVC-1).
///
/// Carries only non-sensitive decision data: the privacy score and the
/// already-sanitized preview (PII replaced with placeholders). It deliberately
/// does NOT carry the PII->placeholder mapping — that mapping never outlives
/// the single send/restore cycle and never spans user think-time.
#[derive(Debug, Clone)]
pub struct CloudConfirmation {
    /// The ZKQP privacy score (0-100) that triggered the pause.
    pub privacy_score: u32,
    /// The sanitized query the user is being asked to approve sending. Safe
    /// to display: PII is already replaced with placeholders.
    pub sanitized_preview: String,
    /// Opaque confirmation-token wire form (SVC-1-R1-1), carried as a
    /// [`ConfirmationTokenWire`] with redacted `Debug` (SVC-1-R1-1-02). The
    /// caller echoes it back as
    /// [`InferenceRequest::cloud_confirmation_token`] on the confirmed retry.
    /// It is HMAC-bound to this exact sanitized prompt / model / max_tokens and
    /// expires shortly, so it cannot be reused for a different query or
    /// replayed later.
    pub token: ConfirmationTokenWire,
}

/// The response from an inference operation.
///
/// # Examples
///
/// ```
/// use die_inference::{InferenceResponse, InferenceTier};
///
/// let resp = InferenceResponse {
///     output: "Here is the summary...".to_string(),
///     tier: InferenceTier::Local,
///     model_id: "qwen3-7b-q4".to_string(),
/// };
/// assert_eq!(resp.tier, InferenceTier::Local);
/// ```
#[derive(Debug, Clone)]
pub struct InferenceResponse {
    /// The generated text.
    pub output: String,
    /// Which tier handled the request.
    pub tier: InferenceTier,
    /// Identifier of the model that produced the response.
    pub model_id: String,
}

/// Which inference tier handled a request.
///
/// # Examples
///
/// ```
/// use die_inference::InferenceTier;
///
/// let tier = InferenceTier::Local;
/// assert_eq!(format!("{tier:?}"), "Local");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InferenceTier {
    /// Tier 1: On-device small model.
    Local,
    /// Tier 2: On-device medium model or cloud fallback.
    Hybrid,
    /// Tier 3: Cloud model with ZKQP privacy.
    Cloud,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inference_request_can_be_sensitive() {
        let req = InferenceRequest {
            input: "my password is hunter2".to_string(),
            max_tokens: 100,
            sensitive: true,
            cloud_confirmation_token: None,
        };
        assert!(req.sensitive);
    }

    #[test]
    fn inference_tier_equality() {
        assert_eq!(InferenceTier::Local, InferenceTier::Local);
        assert_ne!(InferenceTier::Local, InferenceTier::Cloud);
    }

    #[test]
    fn cloud_confirmation_debug_redacts_token() {
        // SVC-1-R1-1-02: a transitively-carrying boundary type must not leak
        // the token via its derived Debug. RED against the pre-fix
        // `token: String` (whose Debug printed the MAC verbatim inside the
        // CloudConfirmation dump).
        let mac = "cd".repeat(32);
        let confirmation = CloudConfirmation {
            privacy_score: 90,
            sanitized_preview: "[EMAIL_001]".to_string(),
            token: ConfirmationTokenWire::new(format!("1700000000:{mac}")),
        };
        let debug = format!("{confirmation:?}");
        assert!(
            !debug.contains(&mac),
            "CloudConfirmation Debug leaked the token MAC: {debug}"
        );
        assert!(
            debug.contains("<redacted>"),
            "token should render redacted inside CloudConfirmation Debug: {debug}"
        );
        // Non-secret decision data is still visible for diagnostics.
        assert!(debug.contains("90"));
        assert!(debug.contains("[EMAIL_001]"));
    }
}
