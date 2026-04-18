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
//! 3. If cloud credentials available → Tier 2/3 (cloud)
//! 4. If nothing available → `InferenceError::NoBackend`
//!
//! # Cascading Failure
//!
//! Per CLAUDE.md Section 8: model loading errors cascade:
//! local → cloud → "AI temporarily unavailable."

use std::path::Path;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::cloud::{CloudClient, CloudModel, CloudResponse};
use crate::error::InferenceError;
use crate::hardware::{self, HardwareProfile, ModelRecommendation};
use crate::model::{self, GenerationResult, LocalModel};
use crate::{InferenceRequest, InferenceResponse, InferenceTier};

/// The inference router that selects the appropriate tier for each request.
///
/// Owns the local model (if loaded) and cloud client (if configured).
/// Thread-safe via `Arc<RwLock>` on the local model (generation is
/// not `Send` so we hold a read lock for the duration).
///
/// # Examples
///
/// ```
/// use die_inference::router::Router;
///
/// let router = Router::new();
/// assert!(!router.has_local_model());
/// assert!(!router.has_cloud());
/// ```
pub struct Router {
    /// Local model (Tier 1). Protected by RwLock for concurrent reads.
    local_model: Arc<RwLock<Option<LocalModel>>>,

    /// Cloud client (Tier 2/3).
    cloud_client: Option<CloudClient>,

    /// Detected hardware profile.
    hardware: HardwareProfile,

    /// Model recommendation based on hardware.
    recommendation: ModelRecommendation,
}

impl Router {
    /// Create a new inference router with no backends.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::router::Router;
    /// let router = Router::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let hardware = hardware::detect();
        let recommendation = hardware::recommend_model(&hardware);

        info!(
            max_params_b = recommendation.max_params_b,
            gpu_layers = recommendation.gpu_layers,
            description = %recommendation.description,
            "router initialized with hardware recommendation"
        );

        Self {
            local_model: Arc::new(RwLock::new(None)),
            cloud_client: None,
            hardware,
            recommendation,
        }
    }

    /// Check if a local model is loaded.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::router::Router;
    ///
    /// let router = Router::new();
    /// assert!(!router.has_local_model());
    /// ```
    #[must_use]
    pub fn has_local_model(&self) -> bool {
        // Try-lock for non-async check.
        self.local_model
            .try_read()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }

    /// Check if cloud API is configured.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::router::Router;
    ///
    /// let router = Router::new();
    /// assert!(!router.has_cloud());
    /// ```
    #[must_use]
    pub fn has_cloud(&self) -> bool {
        self.cloud_client
            .as_ref()
            .is_some_and(CloudClient::is_available)
    }

    /// Get the hardware profile.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::router::Router;
    ///
    /// let router = Router::new();
    /// assert!(router.hardware().cpu_cores > 0);
    /// ```
    #[must_use]
    pub fn hardware(&self) -> &HardwareProfile {
        &self.hardware
    }

    /// Get the model recommendation.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::router::Router;
    ///
    /// let router = Router::new();
    /// assert!(router.recommendation().max_params_b > 0);
    /// ```
    #[must_use]
    pub fn recommendation(&self) -> &ModelRecommendation {
        &self.recommendation
    }

    /// Load a local model from a GGUF file path.
    ///
    /// Uses the hardware recommendation for context size and GPU layers.
    ///
    /// # Errors
    ///
    /// Returns `InferenceError::ModelLoad` if the model file is invalid.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_inference::router::Router;
    /// use std::path::Path;
    ///
    /// # async fn example() -> Result<(), die_inference::InferenceError> {
    /// let mut router = Router::new();
    /// router.load_local_model(Path::new("model.gguf")).await?;
    /// assert!(router.has_local_model());
    /// # Ok(())
    /// # }
    /// ```
    pub async fn load_local_model(&mut self, path: &Path) -> Result<(), InferenceError> {
        let context_size = self.recommendation.context_size;
        let gpu_layers = self.recommendation.gpu_layers;

        info!(
            path = %path.display(),
            context_size,
            gpu_layers,
            "loading local model"
        );

        let loaded = LocalModel::load(path, context_size, gpu_layers)?;
        let mut guard = self.local_model.write().await;
        *guard = Some(loaded);

        info!("local model loaded and registered with router");
        Ok(())
    }

    /// Auto-discover and load the best local model.
    ///
    /// Scans the default model directory for GGUF files and loads the
    /// largest one that fits the hardware recommendation.
    ///
    /// # Errors
    ///
    /// Returns `InferenceError::ModelLoad` if no models are found or
    /// the best candidate fails to load.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use die_inference::router::Router;
    ///
    /// # async fn example() -> Result<(), die_inference::InferenceError> {
    /// let mut router = Router::new();
    /// router.auto_load_local_model().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn auto_load_local_model(&mut self) -> Result<(), InferenceError> {
        let models = model::discover_models(None);

        if models.is_empty() {
            return Err(InferenceError::ModelLoad(
                model::no_model_error_message(),
            ));
        }

        // Pick the first (largest) model that fits.
        let chosen = &models[0];
        info!(
            filename = %chosen.filename,
            size_mb = chosen.size_mb,
            "auto-selected model"
        );

        self.load_local_model(&chosen.path).await
    }

    /// Configure the cloud client with an API key.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_inference::router::Router;
    ///
    /// let mut router = Router::new();
    /// router.set_cloud_api_key("sk-ant-test-key".to_string());
    /// assert!(router.has_cloud());
    /// ```
    pub fn set_cloud_api_key(&mut self, api_key: String) {
        info!("cloud client configured");
        self.cloud_client = Some(CloudClient::new(api_key));
    }

    /// Route an inference request to the appropriate tier.
    ///
    /// Implements the cascading logic:
    /// 1. Sensitive → local only
    /// 2. Local available → use local
    /// 3. Cloud available → use cloud
    /// 4. Nothing → NoBackend error
    ///
    /// # Errors
    ///
    /// Returns `InferenceError::NoBackend` if no tier can handle the request.
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
    /// let result = router.route(req).await;
    /// # }
    /// ```
    pub async fn route(&self, req: InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        debug!(
            input_len = req.input.len(),
            max_tokens = req.max_tokens,
            sensitive = req.sensitive,
            "routing inference request"
        );

        // Step 1: Try local model.
        match self.try_local(&req).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                if req.sensitive {
                    // Sensitive data must stay local — do not cascade to cloud.
                    warn!("sensitive request failed locally: {e}");
                    return Err(e);
                }
                debug!("local inference unavailable: {e}, trying cloud");
            }
        }

        // Step 2: Try cloud.
        match self.try_cloud(&req).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                debug!("cloud inference unavailable: {e}");
            }
        }

        // Step 3: All tiers exhausted.
        Err(InferenceError::NoBackend)
    }

    /// Attempt local inference.
    async fn try_local(&self, req: &InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        let guard = self.local_model.read().await;
        let local = guard
            .as_ref()
            .ok_or(InferenceError::ModelLoad(
                "no local model loaded".to_string(),
            ))?;

        info!("routing to local model (Tier 1)");

        let result: GenerationResult = local.generate(
            &req.input,
            req.max_tokens,
            30, // 30-second timeout.
        )?;

        Ok(InferenceResponse {
            output: result.text,
            tier: InferenceTier::Local,
            model_id: result.model_name,
        })
    }

    /// Attempt cloud inference.
    async fn try_cloud(&self, req: &InferenceRequest) -> Result<InferenceResponse, InferenceError> {
        let client = self
            .cloud_client
            .as_ref()
            .ok_or(InferenceError::CloudApi(
                "no cloud client configured".to_string(),
            ))?;

        if !client.is_available() {
            return Err(InferenceError::CloudApi(
                "cloud client has no API key".to_string(),
            ));
        }

        // Choose model based on request complexity.
        let model = select_cloud_model(req);
        let tier = match model {
            CloudModel::ClaudeSonnet => InferenceTier::Hybrid,
            CloudModel::ClaudeOpus => InferenceTier::Cloud,
        };

        info!(
            model = model.display_name(),
            tier = ?tier,
            "routing to cloud"
        );

        let response: CloudResponse = client
            .complete(&req.input, req.max_tokens, model)
            .await?;

        Ok(InferenceResponse {
            output: response.text,
            tier,
            model_id: response.model,
        })
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

/// Select a cloud model based on request complexity.
///
/// Simple heuristic: short prompts (<500 chars) use Sonnet (cheaper),
/// longer prompts use Opus (more capable).
///
/// # Examples
///
/// ```
/// use die_inference::router::select_cloud_model;
/// use die_inference::InferenceRequest;
/// use die_inference::cloud::CloudModel;
///
/// let short = InferenceRequest {
///     input: "Hello".to_string(),
///     max_tokens: 100,
///     sensitive: false,
/// };
/// assert_eq!(select_cloud_model(&short), CloudModel::ClaudeSonnet);
/// ```
#[must_use]
pub fn select_cloud_model(req: &InferenceRequest) -> CloudModel {
    if req.input.len() > 500 || req.max_tokens > 1024 {
        CloudModel::ClaudeOpus
    } else {
        CloudModel::ClaudeSonnet
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
    async fn sensitive_request_does_not_cascade_to_cloud() {
        let mut router = Router::new();
        router.set_cloud_api_key("sk-test".to_string());

        let req = InferenceRequest {
            input: "secret data".to_string(),
            max_tokens: 50,
            sensitive: true,
        };

        // Should fail with ModelLoad (no local model), NOT try cloud.
        let err = router.route(req).await.unwrap_err();
        assert!(
            matches!(err, InferenceError::ModelLoad(_)),
            "expected ModelLoad, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn non_sensitive_tries_cloud_after_local_fails() {
        let mut router = Router::new();
        router.set_cloud_api_key(String::new()); // Invalid key.

        let req = InferenceRequest {
            input: "test".to_string(),
            max_tokens: 50,
            sensitive: false,
        };

        // Local fails (no model) → cloud fails (empty key) → NoBackend.
        let err = router.route(req).await.unwrap_err();
        assert!(matches!(err, InferenceError::NoBackend));
    }

    #[test]
    fn router_default_has_no_backends() {
        let router = Router::default();
        assert!(!router.has_local_model());
        assert!(!router.has_cloud());
    }

    #[test]
    fn set_cloud_key_enables_cloud() {
        let mut router = Router::new();
        assert!(!router.has_cloud());

        router.set_cloud_api_key("sk-ant-key".to_string());
        assert!(router.has_cloud());
    }

    #[test]
    fn hardware_is_detected() {
        let router = Router::new();
        assert!(router.hardware().cpu_cores > 0);
    }

    #[test]
    fn recommendation_is_valid() {
        let router = Router::new();
        assert!(router.recommendation().max_params_b > 0);
    }

    #[test]
    fn select_cloud_model_short_prompt() {
        let req = InferenceRequest {
            input: "Hi".to_string(),
            max_tokens: 100,
            sensitive: false,
        };
        assert_eq!(select_cloud_model(&req), CloudModel::ClaudeSonnet);
    }

    #[test]
    fn select_cloud_model_long_prompt() {
        let req = InferenceRequest {
            input: "x".repeat(600),
            max_tokens: 100,
            sensitive: false,
        };
        assert_eq!(select_cloud_model(&req), CloudModel::ClaudeOpus);
    }

    #[test]
    fn select_cloud_model_high_tokens() {
        let req = InferenceRequest {
            input: "short".to_string(),
            max_tokens: 2000,
            sensitive: false,
        };
        assert_eq!(select_cloud_model(&req), CloudModel::ClaudeOpus);
    }
}
