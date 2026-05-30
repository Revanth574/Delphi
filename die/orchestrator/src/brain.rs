// SPDX-License-Identifier: MIT

//! Web-augmented inference brain.
//!
//! The brain coordinates between the inference router (LLM) and the
//! browser engine (web access) to answer queries that require
//! real-time information from the internet.
//!
//! # Flow
//!
//! ```text
//! User query → classify(needs_web?) → if yes → browser.navigate → extract → augment prompt
//!                                   → if no  → direct inference
//!                                   → merge results → respond
//! ```
//!
//! # Intent Classification
//!
//! The brain uses keyword heuristics to classify whether a query
//! likely needs web access. In later phases, this will be replaced
//! by a trained intent classifier.

use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{info, warn};

use die_browser::engine::{BrowserConfig, BrowserEngine};
use die_inference::router::Router;
use die_inference::{CloudConfirmation, InferenceRequest, RouteOutcome};

use crate::OrchestratorError;

/// Keywords that signal a query may need web access.
const WEB_KEYWORDS: &[&str] = &[
    "weather",
    "news",
    "latest",
    "current",
    "today",
    "price",
    "stock",
    "score",
    "live",
    "trending",
    "search for",
    "look up",
    "find online",
    "what is the",
    "who is the",
    "browse",
    "website",
    "download",
    "open the page",
];

/// Confidence threshold for web-augmented responses.
const WEB_AUGMENT_MARKER: &str = "[web-augmented]";

/// Result of a brain query — may include web context.
///
/// # Examples
///
/// ```
/// use die_orchestrator::brain::BrainResponse;
///
/// let resp = BrainResponse {
///     output: "The answer is 42.".to_string(),
///     tier: "Local".to_string(),
///     model_id: "qwen3-7b".to_string(),
///     web_augmented: false,
///     web_url: None,
///     cloud_confirmation: None,
/// };
/// assert!(!resp.web_augmented);
/// ```
#[derive(Debug, Clone)]
pub struct BrainResponse {
    /// The LLM's response text. Empty when `cloud_confirmation` is `Some`
    /// (the query paused before producing a response).
    pub output: String,
    /// Which inference tier was used. `"ConfirmationRequired"` when the
    /// cloud query paused for user confirmation (SVC-1).
    pub tier: String,
    /// Which model produced the response. Empty when paused.
    pub model_id: String,
    /// Whether web data was included in the context.
    pub web_augmented: bool,
    /// The URL fetched for augmentation, if any.
    pub web_url: Option<String>,
    /// `Some` when the cloud query's ZKQP privacy score required user
    /// confirmation before sending (SVC-1). Carries the score, the sanitized
    /// preview, and an opaque confirmation token (SVC-1-R1-1); nothing was
    /// sent. The caller shows the preview and, on acceptance, re-issues `query`
    /// with `cloud_confirmation_token` set to the `CloudConfirmation`'s `token`
    /// wire string. `None` for completed (local or sent-and-restored)
    /// responses.
    pub cloud_confirmation: Option<CloudConfirmation>,
}

/// The orchestrator brain — coordinates LLM + web for queries.
///
/// # Examples
///
/// ```
/// use die_orchestrator::brain::Brain;
/// use die_inference::router::Router;
/// use std::sync::Arc;
/// use tokio::sync::RwLock;
///
/// let brain = Brain::new(Arc::new(RwLock::new(Router::new())));
/// assert!(!brain.has_browser());
/// ```
pub struct Brain {
    /// Inference router for LLM queries.
    router: Arc<RwLock<Router>>,
    /// Browser engine for web access (lazy-initialized).
    browser: Option<Arc<BrowserEngine>>,
}

impl Brain {
    /// Create a new brain with an inference router.
    ///
    /// The browser engine is not started by default. Call
    /// [`enable_browser`] to activate web-augmented inference.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::brain::Brain;
    /// use die_inference::router::Router;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// let brain = Brain::new(Arc::new(RwLock::new(Router::new())));
    /// ```
    #[must_use]
    pub fn new(router: Arc<RwLock<Router>>) -> Self {
        Self {
            router,
            browser: None,
        }
    }

    /// Enable the browser engine with the given configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::brain::Brain;
    /// use die_inference::router::Router;
    /// use die_browser::engine::BrowserConfig;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// let mut brain = Brain::new(Arc::new(RwLock::new(Router::new())));
    /// brain.enable_browser(BrowserConfig::default());
    /// assert!(brain.has_browser());
    /// ```
    pub fn enable_browser(&mut self, config: BrowserConfig) {
        self.browser = Some(Arc::new(BrowserEngine::new(config)));
        info!("browser engine enabled for web-augmented inference");
    }

    /// Whether the browser engine is configured.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::brain::Brain;
    /// use die_inference::router::Router;
    /// use std::sync::Arc;
    /// use tokio::sync::RwLock;
    ///
    /// let brain = Brain::new(Arc::new(RwLock::new(Router::new())));
    /// assert!(!brain.has_browser());
    /// ```
    #[must_use]
    pub fn has_browser(&self) -> bool {
        self.browser.is_some()
    }

    /// Classify whether a query likely needs web access.
    ///
    /// Uses keyword heuristics. Returns `true` if the query contains
    /// web-related keywords AND the browser is enabled.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_orchestrator::brain::needs_web;
    ///
    /// assert!(needs_web("What's the weather in Tokyo?"));
    /// assert!(needs_web("latest news about AI"));
    /// assert!(!needs_web("What is 2 + 2?"));
    /// assert!(!needs_web("Write a function to sort a list"));
    /// ```
    #[must_use]
    pub fn needs_web_access(&self, query: &str) -> bool {
        if self.browser.is_none() {
            return false;
        }
        needs_web(query)
    }

    /// Process a query — using web augmentation if needed.
    ///
    /// 1. Classify: does the query need web data?
    /// 2. If yes and browser is available: fetch web context
    /// 3. Augment the prompt with web context
    /// 4. Route through inference engine
    /// 5. Return combined result
    ///
    /// # Errors
    ///
    /// Returns an error if inference fails entirely (no backends
    /// available). Browser failures degrade gracefully to
    /// inference-only.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_orchestrator::brain::Brain;
    /// # use die_inference::router::Router;
    /// # use std::sync::Arc;
    /// # use tokio::sync::RwLock;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let brain = Brain::new(Arc::new(RwLock::new(Router::new())));
    /// let response = brain.query("What is Rust?", 256, false, None).await;
    /// # });
    /// ```
    pub async fn query(
        &self,
        input: &str,
        max_tokens: u32,
        sensitive: bool,
        cloud_confirmation_token: Option<String>,
    ) -> Result<BrainResponse, OrchestratorError> {
        let needs_web = self.needs_web_access(input);
        let mut web_context: Option<String> = None;
        let mut web_url: Option<String> = None;

        // Attempt web augmentation if needed
        if needs_web {
            match self.fetch_web_context(input).await {
                Ok((context, url)) => {
                    info!(url = %url, "web context fetched");
                    web_context = Some(context);
                    web_url = Some(url);
                }
                Err(e) => {
                    // Graceful degradation — log but continue without web
                    warn!(error = %e, "web augmentation failed, falling back to inference-only");
                }
            }
        }

        // Build the prompt — augmented or plain
        let prompt = match &web_context {
            Some(context) => format!(
                "{WEB_AUGMENT_MARKER}\n\
                 The following web content may be relevant to the user's query:\n\
                 ---\n\
                 {context}\n\
                 ---\n\n\
                 User query: {input}"
            ),
            None => input.to_string(),
        };

        // Route through inference
        let router = self.router.read().await;
        // SVC-1-R1-1: the confirmation token must be bound to the FULL prompt
        // that is actually routed (including any web-augmentation context). If
        // the brain re-augments with different context on a retry, the token
        // issued for the previous augmented prompt will not verify against the
        // new sanitized text — the gateway re-pauses with a fresh token. The
        // brain therefore simply forwards the caller's token; it never caches
        // or rebinds one across differing augmented prompts.
        let req = InferenceRequest {
            input: prompt,
            max_tokens,
            sensitive,
            cloud_confirmation_token,
        };

        // SVC-1: a cloud query may pause for ZKQP confirmation. Surface that
        // as a typed BrainResponse (output empty, cloud_confirmation set)
        // rather than swallowing it as a completed response or an error.
        match router.route(req).await? {
            RouteOutcome::Completed(resp) => Ok(BrainResponse {
                output: resp.output,
                tier: format!("{:?}", resp.tier),
                model_id: resp.model_id,
                web_augmented: web_context.is_some(),
                web_url,
                cloud_confirmation: None,
            }),
            RouteOutcome::CloudConfirmationRequired(c) => Ok(BrainResponse {
                output: String::new(),
                tier: "ConfirmationRequired".to_string(),
                model_id: String::new(),
                web_augmented: web_context.is_some(),
                web_url,
                cloud_confirmation: Some(c),
            }),
        }
    }

    /// Fetch web context for a query using the browser engine.
    ///
    /// Constructs a search URL, navigates to it, and extracts text.
    async fn fetch_web_context(
        &self,
        query: &str,
    ) -> Result<(String, String), OrchestratorError> {
        let browser = self.browser.as_ref().ok_or_else(|| {
            OrchestratorError::Planning("browser not enabled".to_string())
        })?;

        // Start the browser if not running
        if !browser.is_running() {
            browser.start().await?;
        }

        // Build a search URL (DuckDuckGo — privacy-respecting)
        let encoded_query = query.replace(' ', "+");
        let url = format!("https://lite.duckduckgo.com/lite/?q={encoded_query}");

        // Navigate
        browser.navigate(&url).await?;

        // Extract text
        let result = browser.extract_text(None).await?;

        let text = result
            .data
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();

        // Truncate to avoid overwhelming the LLM context
        let truncated = truncate_context(&text, 2000);

        Ok((truncated, url))
    }
}

/// Classify whether a query likely needs web access.
///
/// Pure function — useful for testing without a Brain instance.
///
/// # Examples
///
/// ```
/// use die_orchestrator::brain::needs_web;
///
/// assert!(needs_web("What's the latest news?"));
/// assert!(!needs_web("Sort this array"));
/// ```
#[must_use]
pub fn needs_web(query: &str) -> bool {
    let lower = query.to_lowercase();
    WEB_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Truncate text to a maximum character count at a word boundary.
///
/// # Examples
///
/// ```
/// use die_orchestrator::brain::truncate_context;
///
/// let text = "Hello world this is a test";
/// assert_eq!(truncate_context(text, 11), "Hello world");
/// assert_eq!(truncate_context(text, 1000), text);
/// ```
#[must_use]
pub fn truncate_context(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        return text.to_string();
    }

    // If the character at the cut point is a space (or we're at end),
    // the cut is already at a word boundary — keep the full slice.
    if text.as_bytes().get(max_chars).is_none_or(|&b| b == b' ') {
        return text[..max_chars].to_string();
    }

    // Otherwise, find the last space before the limit to avoid mid-word cuts.
    match text[..max_chars].rfind(' ') {
        Some(pos) => text[..pos].to_string(),
        None => text[..max_chars].to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_web_detects_weather() {
        assert!(needs_web("What's the weather in NYC?"));
    }

    #[test]
    fn needs_web_detects_news() {
        assert!(needs_web("Show me the latest news"));
    }

    #[test]
    fn needs_web_detects_prices() {
        assert!(needs_web("What is the price of Bitcoin?"));
    }

    #[test]
    fn needs_web_detects_search() {
        assert!(needs_web("Search for restaurants near me"));
    }

    #[test]
    fn needs_web_detects_browse() {
        assert!(needs_web("Browse the website for details"));
    }

    #[test]
    fn needs_web_case_insensitive() {
        assert!(needs_web("WHAT IS THE LATEST NEWS?"));
        assert!(needs_web("What Is The Weather?"));
    }

    #[test]
    fn no_web_for_code_queries() {
        assert!(!needs_web("Write a function to sort a list"));
        assert!(!needs_web("How do I fix this compile error?"));
        assert!(!needs_web("Refactor the database module"));
    }

    #[test]
    fn no_web_for_math() {
        assert!(!needs_web("What is 2 + 2?"));
        assert!(!needs_web("Calculate the factorial of 10"));
    }

    #[test]
    fn truncate_short_text_unchanged() {
        assert_eq!(truncate_context("hello", 100), "hello");
    }

    #[test]
    fn truncate_at_word_boundary() {
        let text = "hello world this is long";
        assert_eq!(truncate_context(text, 11), "hello world");
    }

    #[test]
    fn truncate_no_space_in_range() {
        let text = "abcdefghij klmno";
        assert_eq!(truncate_context(text, 5), "abcde");
    }

    #[test]
    fn truncate_exact_length() {
        let text = "hello";
        assert_eq!(truncate_context(text, 5), "hello");
    }

    #[test]
    fn brain_creation() {
        let router = Arc::new(RwLock::new(Router::new()));
        let brain = Brain::new(router);
        assert!(!brain.has_browser());
    }

    #[test]
    fn brain_enable_browser() {
        let router = Arc::new(RwLock::new(Router::new()));
        let mut brain = Brain::new(router);
        brain.enable_browser(BrowserConfig::default());
        assert!(brain.has_browser());
    }

    #[test]
    fn brain_needs_web_without_browser() {
        let router = Arc::new(RwLock::new(Router::new()));
        let brain = Brain::new(router);
        // Even web-like queries return false without browser
        assert!(!brain.needs_web_access("What's the weather?"));
    }

    #[test]
    fn brain_needs_web_with_browser() {
        let router = Arc::new(RwLock::new(Router::new()));
        let mut brain = Brain::new(router);
        brain.enable_browser(BrowserConfig::default());
        assert!(brain.needs_web_access("What's the weather?"));
        assert!(!brain.needs_web_access("Sort this array"));
    }

    #[tokio::test]
    async fn brain_query_no_backends() {
        let router = Arc::new(RwLock::new(Router::new()));
        let brain = Brain::new(router);
        let result = brain.query("hello", 256, false, None).await;
        // Should fail because no inference backends
        assert!(result.is_err());
    }

    #[test]
    fn brain_response_fields() {
        let resp = BrainResponse {
            output: "test output".to_string(),
            tier: "Local".to_string(),
            model_id: "test-model".to_string(),
            web_augmented: true,
            web_url: Some("https://example.com".to_string()),
            cloud_confirmation: None,
        };
        assert!(resp.web_augmented);
        assert_eq!(resp.web_url.as_deref(), Some("https://example.com"));
        assert!(resp.cloud_confirmation.is_none());
    }

    #[test]
    fn web_augment_marker_is_detectable() {
        let prompt = format!("{WEB_AUGMENT_MARKER}\nSome context\n\nUser query: test");
        assert!(prompt.contains("[web-augmented]"));
    }
}
