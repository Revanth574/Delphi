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

pub use error::InferenceError;

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
///     cloud_confirmed: false,
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
    /// Explicit user consent to send the *sanitized* query to the cloud even
    /// when its privacy score is high enough to normally require confirmation
    /// (SVC-1). `false` by default: a high-privacy-score query pauses with
    /// [`RouteOutcome::CloudConfirmationRequired`] instead of sending. After
    /// the user reviews the sanitized preview and accepts, the caller
    /// re-issues with `cloud_confirmed = true`. This never sends unsanitized
    /// text — ZKQP still applies; it only overrides the *pause*, honoring the
    /// user's explicit decision (Iron Law #1).
    pub cloud_confirmed: bool,
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
    /// `cloud_confirmed = true`.
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
            cloud_confirmed: false,
        };
        assert!(req.sensitive);
    }

    #[test]
    fn inference_tier_equality() {
        assert_eq!(InferenceTier::Local, InferenceTier::Local);
        assert_ne!(InferenceTier::Local, InferenceTier::Cloud);
    }
}
