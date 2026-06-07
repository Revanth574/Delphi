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
use die_inference::{
    CloudConfirmation, CloudDestinationConsent, ConfirmationTokenWire, InferenceRequest,
    RouteOutcome,
};

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
///     destination_consent: None,
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
    /// `Some` when the cloud query was refused at egress because the session
    /// has not granted destination consent ("data may leave this device" —
    /// SVC-2 Piece 2). DISTINCT from [`cloud_confirmation`](Self::cloud_confirmation):
    /// this is the prior gate of whether off-device egress is permitted at all,
    /// so a consumer must not confuse the two (a destination refusal must show
    /// the "allow cloud?" opt-in, not the content-privacy dialog). `tier` is
    /// `"DestinationConsentRequired"`. Nothing was sent. `None` otherwise.
    pub destination_consent: Option<CloudDestinationConsent>,
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
    /// # SVC-1-R1-1-01 (same-caller binding) — threat-model status
    ///
    /// This is a THIRD cloud-send entry path (alongside the D-Bus
    /// `InferenceService::query` and the shell-bridge WebSocket handler), and it
    /// forwards `cloud_confirmation_token` to the router exactly like they do.
    /// The same-caller binding that closes SVC-1-R1-1-01 lives at the D-Bus
    /// service boundary (`enforce_cloud_send`), NOT here. It is correctly OUT of
    /// this path's current threat model for one concrete reason: **`Brain` is not
    /// wired to any external entry point** — nothing in the repository constructs
    /// a `Brain` or calls `query` outside this module's own tests, so no external
    /// caller can obtain a confirmation token through the brain and no *different*
    /// caller can replay it. The two-call bypass is unreachable because the path
    /// itself is unreachable — not because "an internal caller is trusted".
    ///
    /// The SVC-2 Piece-2 destination-consent gate DOES cover this path: it is
    /// enforced at the egress gateway, the single door all three paths funnel
    /// through, so a brain cloud send is also refused until consent is granted.
    ///
    /// **Forward requirement (enforced by review today, not by code):** when the
    /// brain is wired into an external entry point, the same-caller binding — or
    /// an equivalent caller-context establishment, as `InferenceService::query`
    /// does — MUST be applied at that wiring point, because `query` forwards a
    /// `cloud_confirmation_token` to `route()` and would otherwise let a
    /// different caller replay a valid token. Recorded as the fifth item of the
    /// SVC-2 Codex review.
    ///
    /// # Prompt-injection forward requirement (ORCH-R1-01)
    ///
    /// When `web_context` is present it is **untrusted, attacker-controlled
    /// data**: any page the search surfaces can contain text crafted to read as
    /// instructions to the model ("ignore previous instructions and ..."), and
    /// today it is concatenated into the prompt with only a `---` fence and the
    /// `[web-augmented]` marker, after a plain character truncate — which is NOT
    /// sufficient injection defense. This is LATENT, not live: `Brain` is
    /// unwired (see the SVC-1-R1-1-01 note above), so no external caller can
    /// reach this path. Before the brain is wired to an external entry point,
    /// web content MUST be treated as data, not instructions:
    ///
    /// 1. Fence it with explicit non-instruction framing the model is told to
    ///    treat as quoted, untrusted data (not a bare `---`), and/or isolate it
    ///    in a separate low-trust message role.
    /// 2. Strip or score instruction-like / override phrasing before inclusion.
    /// 3. Ship hostile-injection test fixtures (pages attempting prompt override
    ///    or data exfiltration) proving web content cannot steer the model.
    ///
    /// Recorded as ORCH-R1-01 (orchestrator-sweep round 1); like the
    /// SVC-1-R1-1-01 binding, the safe state is the current unwired one and this
    /// requirement becomes mandatory at the wiring point.
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

        // Build the prompt — augmented or plain. ORCH-R1-01: `context` is
        // untrusted web data; the `---` fence + marker below is NOT sufficient
        // prompt-injection defense. See the "Prompt-injection forward
        // requirement" on `query` — it MUST be hardened (fence-as-data, strip
        // instruction-like content, hostile fixtures) before the brain is wired
        // to an external entry point. Latent today: the path is unreachable.
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
            // Wrap the raw wire string into the redacted-Debug newtype
            // (SVC-1-R1-1-02) as it enters the boundary type.
            cloud_confirmation_token: cloud_confirmation_token.map(ConfirmationTokenWire::new),
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
                destination_consent: None,
            }),
            RouteOutcome::CloudConfirmationRequired(c) => Ok(BrainResponse {
                output: String::new(),
                tier: "ConfirmationRequired".to_string(),
                model_id: String::new(),
                web_augmented: web_context.is_some(),
                web_url,
                cloud_confirmation: Some(c),
                destination_consent: None,
            }),
            // SVC-2 Piece 2: the cloud query was refused at egress for lack of
            // session destination consent. Surface it as a DISTINCT typed
            // response (its own field + tier), never as a privacy confirmation,
            // so the orchestrator/shell shows the "allow cloud?" opt-in.
            RouteOutcome::DestinationConsentRequired(c) => Ok(BrainResponse {
                output: String::new(),
                tier: "DestinationConsentRequired".to_string(),
                model_id: String::new(),
                web_augmented: web_context.is_some(),
                web_url,
                cloud_confirmation: None,
                destination_consent: Some(c),
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

        // Build a search URL (DuckDuckGo — privacy-respecting).
        let url = search_url(query);

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

    // ORCH-R1-02: `max_chars` is a BYTE budget; slicing at it directly panics
    // when it lands inside a multi-byte UTF-8 sequence. Floor to the nearest
    // char boundary at or below the budget before any slice.
    let cut = floor_char_boundary(text, max_chars);

    // If the byte at the cut is a space (or the cut is at the end), the cut is
    // already at a word boundary — keep the floored slice.
    if text.as_bytes().get(cut).is_none_or(|&b| b == b' ') {
        return text[..cut].to_string();
    }

    // Otherwise, back up to the last space before the cut to avoid mid-word cuts.
    match text[..cut].rfind(' ') {
        Some(pos) => text[..pos].to_string(),
        None => text[..cut].to_string(),
    }
}

/// Largest char-boundary byte index `<= index` in `s` — a stable-toolchain
/// equivalent of the still-unstable `str::floor_char_boundary` (ORCH-R1-02).
/// Relies only on the stable [`str::is_char_boundary`].
fn floor_char_boundary(s: &str, index: usize) -> usize {
    if index >= s.len() {
        return s.len();
    }
    let mut i = index;
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// Build the DuckDuckGo search URL for `query` (ORCH-R1-03). The query is
/// percent-encoded as a URL query-component value so reserved characters
/// (& # = ? + space and control bytes) cannot alter the URL's structure.
pub fn search_url(query: &str) -> String {
    format!(
        "https://lite.duckduckgo.com/lite/?q={}",
        percent_encode_query(query)
    )
}

/// Percent-encode `s` for use as a URL query-component value (RFC 3986): only
/// the unreserved set (ALPHA / DIGIT / `-` `_` `.` `~`) passes through; every
/// other byte becomes `%XX`. Minimal and dependency-free (ORCH-R1-03).
fn percent_encode_query(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_context_handles_utf8_boundary_orch_r1_02() {
        // max_chars is a BYTE budget; a budget landing inside a multi-byte char
        // must not panic (RED pre-fix: `text[..max_chars]` panics on the 'é' byte).
        let text = "héllo wörld";
        for budget in 0..=text.len() {
            let out = truncate_context(text, budget);
            assert!(out.len() <= budget, "result must fit the byte budget");
            assert!(text.starts_with(&out), "result must be a valid prefix: {out:?}");
        }
    }

    #[test]
    fn search_url_percent_encodes_reserved_chars_orch_r1_03() {
        // RED pre-fix: only spaces were encoded, so reserved chars passed
        // through raw and could alter the URL's query/fragment structure.
        let url = search_url("a & b=c #d");
        let q = url
            .strip_prefix("https://lite.duckduckgo.com/lite/?q=")
            .expect("search_url must target the DuckDuckGo lite endpoint");
        assert!(!q.contains('&'), "raw & must be encoded: {q}");
        assert!(!q.contains('#'), "raw # must be encoded: {q}");
        assert!(!q.contains('='), "raw = must be encoded: {q}");
        assert!(!q.contains(' '), "raw space must be encoded: {q}");
    }

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
            destination_consent: None,
        };
        assert!(resp.web_augmented);
        assert_eq!(resp.web_url.as_deref(), Some("https://example.com"));
        assert!(resp.cloud_confirmation.is_none());
        assert!(resp.destination_consent.is_none());
    }

    #[test]
    fn web_augment_marker_is_detectable() {
        let prompt = format!("{WEB_AUGMENT_MARKER}\nSome context\n\nUser query: test");
        assert!(prompt.contains("[web-augmented]"));
    }
}
