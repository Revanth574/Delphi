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
use die_inference::InferenceRequest;

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
    /// Returns `(response_text, tier, model_id)`.
    async fn query(
        &self,
        prompt: String,
        max_tokens: u32,
        sensitive: bool,
    ) -> zbus::fdo::Result<(String, String, String)> {
        info!(
            prompt_len = prompt.len(),
            max_tokens,
            sensitive,
            "D-Bus inference query"
        );

        let router = self.router.read().await;
        let req = InferenceRequest {
            input: prompt,
            max_tokens,
            sensitive,
        };

        match router.route(req).await {
            Ok(resp) => Ok((resp.output, format!("{:?}", resp.tier), resp.model_id)),
            Err(e) => Err(zbus::fdo::Error::Failed(e.to_string())),
        }
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
}
