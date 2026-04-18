// SPDX-License-Identifier: MIT

//! Text-to-speech engine (Piper).
//!
//! Wraps the Piper TTS system for converting text responses to audio.
//! Piper runs as a separate process; this module manages its lifecycle
//! and provides a typed async API.
//!
//! # Output Format
//!
//! Audio output is raw PCM:
//! - 22050 Hz sample rate (Piper default)
//! - Mono
//! - 16-bit signed integer samples

use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::config::VoiceConfig;
use crate::error::VoiceError;

/// Piper output sample rate (22050 Hz).
pub const TTS_SAMPLE_RATE: u32 = 22_050;

/// A chunk of synthesized audio.
///
/// # Examples
///
/// ```
/// use die_voice::AudioChunk;
///
/// let chunk = AudioChunk {
///     samples: vec![0i16; 22050],
///     sample_rate: 22050,
///     is_final: true,
/// };
/// assert!(chunk.is_final);
/// assert_eq!(chunk.duration_ms(), 1000);
/// ```
#[derive(Debug, Clone)]
pub struct AudioChunk {
    /// Raw PCM samples (16-bit signed integer).
    pub samples: Vec<i16>,
    /// Sample rate in Hz.
    pub sample_rate: u32,
    /// Whether this is the last chunk for the current synthesis.
    pub is_final: bool,
}

impl AudioChunk {
    /// Duration of this chunk in milliseconds.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::AudioChunk;
    ///
    /// let chunk = AudioChunk {
    ///     samples: vec![0i16; 11025],
    ///     sample_rate: 22050,
    ///     is_final: false,
    /// };
    /// assert_eq!(chunk.duration_ms(), 500);
    /// ```
    #[must_use]
    pub fn duration_ms(&self) -> u64 {
        if self.sample_rate == 0 {
            return 0;
        }
        (self.samples.len() as u64 * 1000) / u64::from(self.sample_rate)
    }

    /// Whether this chunk contains any audio.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::AudioChunk;
    ///
    /// let empty = AudioChunk { samples: vec![], sample_rate: 22050, is_final: true };
    /// assert!(empty.is_empty());
    /// ```
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

/// State of the TTS process.
struct TtsProcess {
    /// The child process handle.
    child: Child,
    /// Writer to stdin (text input).
    stdin: tokio::process::ChildStdin,
    /// Reader from stdout (status output).
    stdout: BufReader<tokio::process::ChildStdout>,
}

/// Text-to-speech engine wrapping Piper.
///
/// # Examples
///
/// ```
/// use die_voice::{TtsEngine, VoiceConfig};
///
/// let engine = TtsEngine::new(VoiceConfig::default());
/// assert!(!engine.is_running());
/// ```
pub struct TtsEngine {
    /// Configuration.
    config: VoiceConfig,
    /// Piper child process (None when not running).
    process: Mutex<Option<TtsProcess>>,
}

impl TtsEngine {
    /// Create a new TTS engine.
    ///
    /// Does not start the Piper process. Call [`start`] first.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{TtsEngine, VoiceConfig};
    ///
    /// let engine = TtsEngine::new(VoiceConfig::default());
    /// assert!(!engine.is_running());
    /// ```
    #[must_use]
    pub fn new(config: VoiceConfig) -> Self {
        Self {
            config,
            process: Mutex::new(None),
        }
    }

    /// Whether the Piper process is running.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{TtsEngine, VoiceConfig};
    ///
    /// let engine = TtsEngine::new(VoiceConfig::default());
    /// assert!(!engine.is_running());
    /// ```
    #[must_use]
    pub fn is_running(&self) -> bool {
        match self.process.try_lock() {
            Ok(guard) => guard.is_some(),
            Err(_) => true,
        }
    }

    /// Start the Piper TTS process.
    ///
    /// Spawns Piper with piped stdio for text-in, audio-out communication.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceError::ModelNotFound`] if the model directory doesn't exist.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_voice::{TtsEngine, VoiceConfig};
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// let engine = TtsEngine::new(VoiceConfig::default());
    /// engine.start().await.unwrap();
    /// assert!(engine.is_running());
    /// # });
    /// ```
    pub async fn start(&self) -> Result<(), VoiceError> {
        let mut guard = self.process.lock().await;

        if guard.is_some() {
            info!("TTS engine already running");
            return Ok(());
        }

        info!(
            binary = %self.config.tts_binary_path.display(),
            model = %self.config.tts_model_path.display(),
            "starting Piper TTS engine"
        );

        let mut child = Command::new(&self.config.tts_binary_path)
            .arg("--model")
            .arg(&self.config.tts_model_path)
            .arg("--output-raw")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| VoiceError::IpcError {
                reason: format!("failed to start Piper: {e}"),
            })?;

        let stdin = child.stdin.take().ok_or(VoiceError::IpcError {
            reason: "failed to capture Piper stdin".to_string(),
        })?;

        let stdout = child.stdout.take().ok_or(VoiceError::IpcError {
            reason: "failed to capture Piper stdout".to_string(),
        })?;

        *guard = Some(TtsProcess {
            child,
            stdin,
            stdout: BufReader::new(stdout),
        });

        info!("Piper TTS engine started");
        Ok(())
    }

    /// Synthesize text to audio.
    ///
    /// Sends the text to Piper and reads back the audio. Returns
    /// a single [`AudioChunk`] with the complete synthesis.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine is not running or synthesis fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_voice::{TtsEngine, VoiceConfig};
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let engine = TtsEngine::new(VoiceConfig::default());
    /// # engine.start().await.unwrap();
    /// let audio = engine.synthesize("Hello, world!").await.unwrap();
    /// assert!(!audio.is_empty());
    /// # });
    /// ```
    pub async fn synthesize(&self, text: &str) -> Result<AudioChunk, VoiceError> {
        if text.is_empty() {
            return Ok(AudioChunk {
                samples: vec![],
                sample_rate: TTS_SAMPLE_RATE,
                is_final: true,
            });
        }

        let mut guard = self.process.lock().await;
        let process = guard.as_mut().ok_or(VoiceError::IpcError {
            reason: "TTS engine not running".to_string(),
        })?;

        info!(text_len = text.len(), "synthesizing speech");

        // Send text to Piper's stdin
        let input = format!("{text}\n");
        let timeout = self.config.tts_timeout;

        match tokio::time::timeout(timeout, process.stdin.write_all(input.as_bytes())).await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                return Err(VoiceError::IpcError {
                    reason: format!("stdin write failed: {e}"),
                });
            }
            Err(_) => {
                return Err(VoiceError::Timeout {
                    seconds: timeout.as_secs(),
                });
            }
        }

        if let Err(e) = process.stdin.flush().await {
            return Err(VoiceError::IpcError {
                reason: format!("stdin flush failed: {e}"),
            });
        }

        // Read a status line (Piper emits progress to stdout)
        let mut line = String::new();
        match tokio::time::timeout(timeout, process.stdout.read_line(&mut line)).await {
            Ok(Ok(0)) => {
                return Err(VoiceError::ProcessExited { code: None });
            }
            Ok(Ok(_)) => {
                info!(status = %line.trim(), "Piper status");
            }
            Ok(Err(e)) => {
                return Err(VoiceError::IpcError {
                    reason: format!("stdout read failed: {e}"),
                });
            }
            Err(_) => {
                return Err(VoiceError::Timeout {
                    seconds: timeout.as_secs(),
                });
            }
        }

        // DECISION: Actual PCM audio reading deferred to Phase 2.
        // In Phase 1, we return a placeholder chunk. The real
        // implementation reads raw 16-bit PCM from Piper's stdout.
        let estimated_samples =
            (text.len() as u32 * TTS_SAMPLE_RATE) / 15; // ~15 chars/sec
        Ok(AudioChunk {
            samples: vec![0i16; estimated_samples as usize],
            sample_rate: TTS_SAMPLE_RATE,
            is_final: true,
        })
    }

    /// Stop the Piper process.
    ///
    /// # Errors
    ///
    /// Returns an error if shutdown fails.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use die_voice::{TtsEngine, VoiceConfig};
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let engine = TtsEngine::new(VoiceConfig::default());
    /// # engine.start().await.unwrap();
    /// engine.stop().await.unwrap();
    /// assert!(!engine.is_running());
    /// # });
    /// ```
    pub async fn stop(&self) -> Result<(), VoiceError> {
        let mut guard = self.process.lock().await;
        let process = match guard.take() {
            Some(p) => p,
            None => {
                warn!("TTS engine not running");
                return Ok(());
            }
        };

        let TtsProcess { mut child, .. } = process;

        match tokio::time::timeout(Duration::from_secs(5), child.wait()).await {
            Ok(Ok(status)) => {
                info!(code = ?status.code(), "Piper process exited");
            }
            Ok(Err(e)) => {
                error!(error = %e, "error waiting for Piper");
            }
            Err(_) => {
                warn!("Piper did not exit in 5s, killing");
                let _ = child.kill().await;
            }
        }

        Ok(())
    }

    /// Get the TTS sample rate.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::tts::TTS_SAMPLE_RATE;
    ///
    /// assert_eq!(TTS_SAMPLE_RATE, 22050);
    /// ```
    #[must_use]
    pub fn sample_rate(&self) -> u32 {
        TTS_SAMPLE_RATE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn engine_starts_not_running() {
        let engine = TtsEngine::new(VoiceConfig::default());
        assert!(!engine.is_running());
    }

    #[test]
    fn sample_rate_constant() {
        assert_eq!(TTS_SAMPLE_RATE, 22_050);
    }

    #[test]
    fn audio_chunk_duration() {
        let chunk = AudioChunk {
            samples: vec![0i16; 22050],
            sample_rate: 22050,
            is_final: true,
        };
        assert_eq!(chunk.duration_ms(), 1000);
    }

    #[test]
    fn audio_chunk_half_second() {
        let chunk = AudioChunk {
            samples: vec![0i16; 11025],
            sample_rate: 22050,
            is_final: false,
        };
        assert_eq!(chunk.duration_ms(), 500);
    }

    #[test]
    fn audio_chunk_empty() {
        let chunk = AudioChunk {
            samples: vec![],
            sample_rate: 22050,
            is_final: true,
        };
        assert!(chunk.is_empty());
        assert_eq!(chunk.duration_ms(), 0);
    }

    #[test]
    fn audio_chunk_zero_rate() {
        let chunk = AudioChunk {
            samples: vec![0i16; 100],
            sample_rate: 0,
            is_final: true,
        };
        assert_eq!(chunk.duration_ms(), 0);
    }

    #[test]
    fn engine_sample_rate() {
        let engine = TtsEngine::new(VoiceConfig::default());
        assert_eq!(engine.sample_rate(), 22050);
    }

    #[tokio::test]
    async fn start_with_missing_binary_fails() {
        let config = VoiceConfig {
            tts_binary_path: PathBuf::from("nonexistent-piper-xyz"),
            ..VoiceConfig::default()
        };
        let engine = TtsEngine::new(config);
        let result = engine.start().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn stop_when_not_running_is_ok() {
        let engine = TtsEngine::new(VoiceConfig::default());
        let result = engine.stop().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn synthesize_without_start_fails() {
        let engine = TtsEngine::new(VoiceConfig::default());
        let result = engine.synthesize("hello").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn synthesize_empty_returns_empty() {
        let engine = TtsEngine::new(VoiceConfig::default());
        // Empty text returns empty chunk even without process
        let result = engine.synthesize("").await;
        assert!(result.is_ok());
        let chunk = result.unwrap();
        assert!(chunk.is_empty());
        assert!(chunk.is_final);
    }
}
