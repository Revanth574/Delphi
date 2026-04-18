// SPDX-License-Identifier: MIT

//! Browser engine — manages the Playwright child process.
//!
//! The engine spawns a Node.js script that runs Playwright in headless
//! Chromium mode. Commands are sent as JSON lines on stdin; results
//! come back as JSON lines on stdout.
//!
//! # Lifecycle
//!
//! ```text
//! BrowserEngine::new() → configure
//! engine.start()       → spawn child process
//! engine.execute(cmd)  → send command, await result
//! engine.stop()        → send Close command, wait for exit
//! ```

use std::path::PathBuf;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::command::{BrowserCommand, BrowserResult};
use crate::error::BrowserError;

/// Default command timeout (30 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default navigation timeout (60 seconds for slow pages).
const DEFAULT_NAV_TIMEOUT: Duration = Duration::from_secs(60);

/// Configuration for the browser engine.
///
/// # Examples
///
/// ```
/// use die_browser::engine::BrowserConfig;
///
/// let config = BrowserConfig::default();
/// assert!(config.headless);
/// assert_eq!(config.command_timeout.as_secs(), 30);
/// ```
#[derive(Debug, Clone)]
pub struct BrowserConfig {
    /// Run in headless mode (no visible window).
    pub headless: bool,
    /// Path to the Node.js binary.
    pub node_path: PathBuf,
    /// Path to the browser agent script.
    pub agent_script: PathBuf,
    /// Timeout for regular commands.
    pub command_timeout: Duration,
    /// Timeout for navigation commands.
    pub navigation_timeout: Duration,
    /// User agent string override.
    pub user_agent: Option<String>,
    /// Viewport width.
    pub viewport_width: u32,
    /// Viewport height.
    pub viewport_height: u32,
}

impl Default for BrowserConfig {
    /// Default configuration: headless, 1280x720 viewport.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_browser::engine::BrowserConfig;
    ///
    /// let c = BrowserConfig::default();
    /// assert_eq!(c.viewport_width, 1280);
    /// ```
    fn default() -> Self {
        Self {
            headless: true,
            node_path: PathBuf::from("node"),
            agent_script: default_agent_script_path(),
            command_timeout: DEFAULT_TIMEOUT,
            navigation_timeout: DEFAULT_NAV_TIMEOUT,
            user_agent: None,
            viewport_width: 1280,
            viewport_height: 720,
        }
    }
}

/// Resolve the default path to the browser agent script.
///
/// Looks in the Delphi data directory under `browser/agent.js`.
///
/// # Examples
///
/// ```
/// use die_browser::engine::default_agent_script_path;
///
/// let path = default_agent_script_path();
/// assert!(path.to_string_lossy().contains("browser"));
/// ```
#[must_use]
pub fn default_agent_script_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("/usr/share"))
        .join("delphi")
        .join("browser")
        .join("agent.js")
}

/// Internal state of the browser process.
struct ProcessState {
    /// The child process handle.
    child: Child,
    /// Writer to the child's stdin.
    stdin: tokio::process::ChildStdin,
    /// Buffered reader for the child's stdout.
    stdout: BufReader<tokio::process::ChildStdout>,
}

/// Headless browser engine wrapping Playwright.
///
/// Manages the lifecycle of a Playwright child process and provides
/// a typed async API for browser operations.
///
/// # Examples
///
/// ```
/// use die_browser::BrowserEngine;
/// use die_browser::engine::BrowserConfig;
///
/// let engine = BrowserEngine::new(BrowserConfig::default());
/// assert!(!engine.is_running());
/// ```
pub struct BrowserEngine {
    /// Engine configuration.
    config: BrowserConfig,
    /// Process state (None when not running).
    process: Mutex<Option<ProcessState>>,
}

impl BrowserEngine {
    /// Create a new browser engine with the given configuration.
    ///
    /// Does not start the browser process. Call [`start()`] to spawn it.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_browser::BrowserEngine;
    /// use die_browser::engine::BrowserConfig;
    ///
    /// let engine = BrowserEngine::new(BrowserConfig::default());
    /// assert!(!engine.is_running());
    /// ```
    #[must_use]
    pub fn new(config: BrowserConfig) -> Self {
        Self {
            config,
            process: Mutex::new(None),
        }
    }

    /// Whether the browser process is currently running.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_browser::BrowserEngine;
    /// use die_browser::engine::BrowserConfig;
    ///
    /// let engine = BrowserEngine::new(BrowserConfig::default());
    /// assert!(!engine.is_running());
    /// ```
    #[must_use]
    pub fn is_running(&self) -> bool {
        // Use try_lock to avoid blocking — if locked, someone is using it,
        // so the process is effectively running.
        match self.process.try_lock() {
            Ok(guard) => guard.is_some(),
            Err(_) => true,
        }
    }

    /// Get the engine configuration.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_browser::BrowserEngine;
    /// use die_browser::engine::BrowserConfig;
    ///
    /// let engine = BrowserEngine::new(BrowserConfig::default());
    /// assert!(engine.config().headless);
    /// ```
    #[must_use]
    pub fn config(&self) -> &BrowserConfig {
        &self.config
    }

    /// Start the browser process.
    ///
    /// Spawns the Node.js agent script as a child process with
    /// piped stdin/stdout for JSON line communication.
    ///
    /// # Errors
    ///
    /// Returns [`BrowserError::SpawnFailed`] if the process cannot start.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_browser::BrowserEngine;
    /// # use die_browser::engine::BrowserConfig;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let engine = BrowserEngine::new(BrowserConfig::default());
    /// engine.start().await.unwrap();
    /// assert!(engine.is_running());
    /// # });
    /// ```
    pub async fn start(&self) -> Result<(), BrowserError> {
        let mut guard = self.process.lock().await;

        if guard.is_some() {
            info!("browser engine already running");
            return Ok(());
        }

        info!(
            node = %self.config.node_path.display(),
            script = %self.config.agent_script.display(),
            headless = self.config.headless,
            "starting browser engine"
        );

        let config_json = serde_json::json!({
            "headless": self.config.headless,
            "viewport": {
                "width": self.config.viewport_width,
                "height": self.config.viewport_height,
            },
            "user_agent": self.config.user_agent,
        });

        let mut child = Command::new(&self.config.node_path)
            .arg(&self.config.agent_script)
            .arg("--config")
            .arg(config_json.to_string())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| BrowserError::SpawnFailed {
                reason: e.to_string(),
            })?;

        let stdin = child.stdin.take().ok_or(BrowserError::SpawnFailed {
            reason: "failed to capture stdin".to_string(),
        })?;

        let stdout = child.stdout.take().ok_or(BrowserError::SpawnFailed {
            reason: "failed to capture stdout".to_string(),
        })?;

        *guard = Some(ProcessState {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        });

        info!("browser engine started");
        Ok(())
    }

    /// Execute a browser command and wait for the result.
    ///
    /// Serializes the command as a JSON line, sends it to the child
    /// process, and reads the JSON line response.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The engine is not running
    /// - The command times out
    /// - IPC communication fails
    /// - The browser returns an error
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_browser::{BrowserEngine, BrowserCommand};
    /// # use die_browser::engine::BrowserConfig;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let engine = BrowserEngine::new(BrowserConfig::default());
    /// # engine.start().await.unwrap();
    /// let result = engine.execute(BrowserCommand::GetTitle).await.unwrap();
    /// println!("Page title: {:?}", result.data);
    /// # });
    /// ```
    pub async fn execute(
        &self,
        command: BrowserCommand,
    ) -> Result<BrowserResult, BrowserError> {
        let timeout = match &command {
            BrowserCommand::Navigate { .. } => self.config.navigation_timeout,
            _ => self.config.command_timeout,
        };

        let mut guard = self.process.lock().await;
        let state = guard.as_mut().ok_or(BrowserError::IpcError {
            reason: "browser engine not running".to_string(),
        })?;

        // Serialize command as a JSON line
        let mut json = serde_json::to_string(&command).map_err(|e| {
            BrowserError::ProtocolError {
                reason: format!("failed to serialize command: {e}"),
            }
        })?;
        json.push('\n');

        // Send with timeout
        let send_result =
            tokio::time::timeout(timeout, state.stdin.write_all(json.as_bytes())).await;

        match send_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(BrowserError::IpcError {
                    reason: format!("stdin write failed: {e}"),
                });
            }
            Err(_) => {
                return Err(BrowserError::Timeout {
                    seconds: timeout.as_secs(),
                });
            }
        }

        // Flush stdin
        if let Err(e) = state.stdin.flush().await {
            return Err(BrowserError::IpcError {
                reason: format!("stdin flush failed: {e}"),
            });
        }

        // Read response line with timeout
        let mut line = String::new();
        let read_result =
            tokio::time::timeout(timeout, state.stdout.read_line(&mut line)).await;

        match read_result {
            Ok(Ok(0)) => Err(BrowserError::ProcessExited { code: None }),
            Ok(Ok(_)) => {
                let result: BrowserResult =
                    serde_json::from_str(line.trim()).map_err(|e| {
                        BrowserError::ProtocolError {
                            reason: format!("invalid response JSON: {e}"),
                        }
                    })?;
                Ok(result)
            }
            Ok(Err(e)) => Err(BrowserError::IpcError {
                reason: format!("stdout read failed: {e}"),
            }),
            Err(_) => Err(BrowserError::Timeout {
                seconds: timeout.as_secs(),
            }),
        }
    }

    /// Navigate to a URL.
    ///
    /// Convenience wrapper around [`execute`] with a Navigate command.
    ///
    /// # Errors
    ///
    /// Returns an error if navigation fails or the engine is not running.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_browser::BrowserEngine;
    /// # use die_browser::engine::BrowserConfig;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let engine = BrowserEngine::new(BrowserConfig::default());
    /// # engine.start().await.unwrap();
    /// engine.navigate("https://example.com").await.unwrap();
    /// # });
    /// ```
    pub async fn navigate(&self, url: &str) -> Result<BrowserResult, BrowserError> {
        self.execute(BrowserCommand::Navigate {
            url: url.to_string(),
            wait_until: "domcontentloaded".to_string(),
        })
        .await
    }

    /// Extract text content from the current page.
    ///
    /// # Errors
    ///
    /// Returns an error if extraction fails or the engine is not running.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_browser::BrowserEngine;
    /// # use die_browser::engine::BrowserConfig;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let engine = BrowserEngine::new(BrowserConfig::default());
    /// # engine.start().await.unwrap();
    /// let text = engine.extract_text(None).await.unwrap();
    /// # });
    /// ```
    pub async fn extract_text(
        &self,
        selector: Option<&str>,
    ) -> Result<BrowserResult, BrowserError> {
        self.execute(BrowserCommand::Extract {
            target: crate::command::ExtractTarget::Text,
            selector: selector.map(String::from),
        })
        .await
    }

    /// Take a PNG screenshot of the current page.
    ///
    /// # Errors
    ///
    /// Returns an error if the screenshot fails or the engine is not running.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_browser::BrowserEngine;
    /// # use die_browser::engine::BrowserConfig;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let engine = BrowserEngine::new(BrowserConfig::default());
    /// # engine.start().await.unwrap();
    /// let screenshot = engine.screenshot(false).await.unwrap();
    /// # });
    /// ```
    pub async fn screenshot(
        &self,
        full_page: bool,
    ) -> Result<BrowserResult, BrowserError> {
        self.execute(BrowserCommand::Screenshot {
            format: crate::command::ScreenshotFormat::Png,
            full_page,
        })
        .await
    }

    /// Stop the browser engine.
    ///
    /// Sends a Close command and waits for the process to exit.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine is not running or shutdown fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_browser::BrowserEngine;
    /// # use die_browser::engine::BrowserConfig;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let engine = BrowserEngine::new(BrowserConfig::default());
    /// # engine.start().await.unwrap();
    /// engine.stop().await.unwrap();
    /// assert!(!engine.is_running());
    /// # });
    /// ```
    pub async fn stop(&self) -> Result<(), BrowserError> {
        let mut guard = self.process.lock().await;
        let state = match guard.take() {
            Some(s) => s,
            None => {
                warn!("browser engine not running, nothing to stop");
                return Ok(());
            }
        };

        let ProcessState {
            mut child,
            mut stdin,
            ..
        } = state;

        // Send close command
        let close_json = serde_json::to_string(&BrowserCommand::Close)
            .unwrap_or_else(|_| r#"{"type":"Close"}"#.to_string());
        let _ = stdin.write_all(format!("{close_json}\n").as_bytes()).await;
        let _ = stdin.flush().await;

        // Wait for process to exit (with timeout)
        match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) => {
                info!(code = ?status.code(), "browser process exited");
            }
            Ok(Err(e)) => {
                error!(error = %e, "error waiting for browser process");
            }
            Err(_) => {
                warn!("browser process did not exit in 5s, killing");
                let _ = child.kill().await;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = BrowserConfig::default();
        assert!(config.headless);
        assert_eq!(config.viewport_width, 1280);
        assert_eq!(config.viewport_height, 720);
        assert_eq!(config.command_timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.navigation_timeout, DEFAULT_NAV_TIMEOUT);
        assert!(config.user_agent.is_none());
    }

    #[test]
    fn agent_script_path_contains_browser() {
        let path = default_agent_script_path();
        assert!(path.to_string_lossy().contains("browser"));
        assert!(path.to_string_lossy().contains("agent.js"));
    }

    #[test]
    fn engine_starts_not_running() {
        let engine = BrowserEngine::new(BrowserConfig::default());
        assert!(!engine.is_running());
    }

    #[test]
    fn engine_config_accessible() {
        let config = BrowserConfig {
            viewport_width: 1920,
            viewport_height: 1080,
            ..Default::default()
        };
        let engine = BrowserEngine::new(config);
        assert_eq!(engine.config().viewport_width, 1920);
        assert_eq!(engine.config().viewport_height, 1080);
    }

    #[test]
    fn custom_config() {
        let config = BrowserConfig {
            headless: false,
            node_path: PathBuf::from("/usr/bin/node"),
            agent_script: PathBuf::from("/opt/delphi/agent.js"),
            command_timeout: Duration::from_secs(10),
            navigation_timeout: Duration::from_secs(30),
            user_agent: Some("DelphiBot/1.0".to_string()),
            viewport_width: 1920,
            viewport_height: 1080,
        };

        assert!(!config.headless);
        assert_eq!(config.user_agent.as_deref(), Some("DelphiBot/1.0"));
    }

    #[tokio::test]
    async fn start_with_missing_script_fails() {
        let config = BrowserConfig {
            node_path: PathBuf::from("nonexistent-node-binary-xyz"),
            ..BrowserConfig::default()
        };
        let engine = BrowserEngine::new(config);
        let result = engine.start().await;
        assert!(result.is_err());
        assert!(!engine.is_running());
    }

    #[tokio::test]
    async fn execute_without_start_fails() {
        let engine = BrowserEngine::new(BrowserConfig::default());
        let result = engine.execute(BrowserCommand::GetTitle).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BrowserError::IpcError { reason } => {
                assert!(reason.contains("not running"));
            }
            other => panic!("expected IpcError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn stop_when_not_running_is_ok() {
        let engine = BrowserEngine::new(BrowserConfig::default());
        let result = engine.stop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn start_with_real_process() {
        // Use `cat` as a fake "browser agent" — it echoes stdin to stdout,
        // which lets us test the IPC pipeline without Playwright.
        let config = BrowserConfig {
            node_path: PathBuf::from("cat"),
            agent_script: PathBuf::new(), // cat doesn't need a script
            ..BrowserConfig::default()
        };

        let engine = BrowserEngine::new(config);

        // Start should succeed since `cat` exists on Linux
        let start_result = engine.start().await;
        if start_result.is_err() {
            // In Windows CI, `cat` might not exist — skip gracefully
            return;
        }

        assert!(engine.is_running());

        // Stop should work
        engine.stop().await.unwrap();
        assert!(!engine.is_running());
    }
}
