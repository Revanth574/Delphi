// SPDX-License-Identifier: MIT

//! Inference routing logic.
//!
//! The router decides whether to send a request to local inference,
//! cloud inference, or a hybrid of both. Sensitive requests are always
//! routed locally. The cheapest capable model is selected per task.
//!
//! # Routing Rules
//!
//! 1. If `request.sensitive == true` → force Tier 1 (local)
//! 2. If local model is loaded and capable → Tier 1
//! 3. If local medium model available → Tier 2 (local)
//! 4. If cloud credentials available → Tier 2/3 (cloud)
//! 5. If nothing available → `InferenceError::NoBackend`

use crate::error::InferenceError;
use crate::{InferenceRequest, InferenceResponse};

/// The inference router that selects the appropriate tier for each request.
///
/// # Examples
///
/// ```
/// use die_inference::router::Router;
///
/// let router = Router::new();
/// // Router is created — actual routing requires model backends.
/// ```
pub struct Router {
    _local_available: bool,
    _cloud_available: bool,
}

impl Router {
    /// Create a new inference router.
    ///
    /// Initially, no backends are available. Backends are registered
    /// after model loading and credential verification.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::router::Router;
    /// let router = Router::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            _local_available: false,
            _cloud_available: false,
        }
    }

    /// Route an inference request to the appropriate tier.
    ///
    /// # Errors
    ///
    /// Returns `InferenceError::NoBackend` if no tier can handle the request.
    /// Returns `InferenceError::Credential` if cloud routing is needed but
    /// credentials are missing.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_inference::{InferenceRequest, router::Router};
    ///
    /// # async fn example() {
    /// let router = Router::new();
    /// let req = InferenceRequest {
    ///     input: "Hello".to_string(),
    ///     max_tokens: 100,
    ///     sensitive: false,
    /// };
    /// // No backends registered yet, so this returns NoBackend.
    /// let result = router.route(req).await;
    /// assert!(result.is_err());
    /// # }
    /// ```
    pub async fn route(&self, req: InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        if req.sensitive {
            tracing::info!("sensitive request — forcing local tier");
        }

        tracing::debug!(
            input_len = req.input.len(),
            max_tokens = req.max_tokens,
            sensitive = req.sensitive,
            "routing inference request"
        );

        // No backends registered yet — return descriptive error.
        Err(InferenceError::NoBackend)
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn route_returns_no_backend_when_empty() {
        let router = Router::new();
        let req = InferenceRequest {
            input: "test".to_string(),
            max_tokens: 50,
            sensitive: false,
        };
        let err = router.route(req).await.unwrap_err();
        assert!(matches!(err, InferenceError::NoBackend));
    }

    #[tokio::test]
    async fn sensitive_request_does_not_panic() {
        let router = Router::new();
        let req = InferenceRequest {
            input: "secret data".to_string(),
            max_tokens: 50,
            sensitive: true,
        };
        // Should not panic even with no backends.
        let _ = router.route(req).await;
    }
}
