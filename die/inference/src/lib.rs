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
    pub sensitive: bool,
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
        };
        assert!(req.sensitive);
    }

    #[test]
    fn inference_tier_equality() {
        assert_eq!(InferenceTier::Local, InferenceTier::Local);
        assert_ne!(InferenceTier::Local, InferenceTier::Cloud);
    }
}
