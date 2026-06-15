// SPDX-License-Identifier: MIT

//! Speech-to-text engine (Whisper).
//!
//! Wraps the Whisper model for converting audio input to text.
//! In Phase 1, this provides the typed API and process management.
//! Full whisper-rs integration comes in Phase 2 when model files
//! are available.
//!
//! # Audio Format
//!
//! Input audio must be:
//! - 16kHz sample rate
//! - Mono (single channel)
//! - f32 PCM samples in range [-1.0, 1.0]

use std::path::PathBuf;
use std::time::Duration;

use tracing::{info, warn};

use crate::config::VoiceConfig;
use crate::error::VoiceError;

/// A transcription result from Whisper.
///
/// # Examples
///
/// ```
/// use die_voice::Transcript;
///
/// let t = Transcript {
///     text: "Hello, how are you?".to_string(),
///     language: "en".to_string(),
///     confidence: 0.95,
///     duration_ms: 2500,
/// };
/// assert!(t.confidence > 0.9);
/// ```
#[derive(Debug, Clone)]
pub struct Transcript {
    /// Recognized text.
    pub text: String,
    /// Detected language code.
    pub language: String,
    /// Confidence score (0.0–1.0).
    pub confidence: f64,
    /// Duration of the processed audio in milliseconds.
    pub duration_ms: u64,
}

/// State of the STT engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SttState {
    /// Model not loaded.
    Unloaded,
    /// Model loaded and ready.
    Ready,
    /// Currently processing audio.
    Processing,
}

/// Speech-to-text engine wrapping Whisper.
///
/// # Examples
///
/// ```
/// use die_voice::{SttEngine, VoiceConfig};
///
/// let engine = SttEngine::new(VoiceConfig::default());
/// assert_eq!(engine.state(), die_voice::stt::SttState::Unloaded);
/// ```
pub struct SttEngine {
    /// Configuration.
    config: VoiceConfig,
    /// Current engine state.
    state: SttState,
    /// Path to the loaded model (if any).
    model_path: Option<PathBuf>,
}

impl SttEngine {
    /// Create a new STT engine.
    ///
    /// Does not load the model. Call [`load_model`] first.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    ///
    /// let engine = SttEngine::new(VoiceConfig::default());
    /// assert!(!engine.is_ready());
    /// ```
    #[must_use]
    pub fn new(config: VoiceConfig) -> Self {
        Self {
            config,
            state: SttState::Unloaded,
            model_path: None,
        }
    }

    /// Get the current engine state.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    /// use die_voice::stt::SttState;
    ///
    /// let engine = SttEngine::new(VoiceConfig::default());
    /// assert_eq!(engine.state(), SttState::Unloaded);
    /// ```
    #[must_use]
    pub fn state(&self) -> SttState {
        self.state
    }

    /// Whether the engine is ready to process audio.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    ///
    /// let engine = SttEngine::new(VoiceConfig::default());
    /// assert!(!engine.is_ready());
    /// ```
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.state == SttState::Ready
    }

    /// Load the Whisper model from disk.
    ///
    /// # Errors
    ///
    /// Returns [`VoiceError::ModelNotFound`] if the model file doesn't exist.
    /// Returns [`VoiceError::ModelLoadFailed`] if loading fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    ///
    /// let mut engine = SttEngine::new(VoiceConfig::default());
    /// // Will fail because model file doesn't exist in test
    /// assert!(engine.load_model().is_err());
    /// ```
    pub fn load_model(&mut self) -> Result<(), VoiceError> {
        let model_path = &self.config.stt_model_path;

        if !model_path.exists() {
            return Err(VoiceError::ModelNotFound {
                path: model_path.display().to_string(),
            });
        }

        info!(
            path = %model_path.display(),
            language = %self.config.language,
            threads = self.config.threads,
            gpu = self.config.use_gpu,
            "loading Whisper model"
        );

        // STUB: actual whisper-rs integration is not built (whisper-rs is not a
        // dependency yet; deferred — Phase 3B+). This only validates the model
        // path exists and transitions state; transcribe() returns a placeholder
        // transcript, not real speech-to-text.

        self.model_path = Some(model_path.clone());
        self.state = SttState::Ready;
        info!("Whisper model loaded");
        Ok(())
    }

    /// Load the model from a custom path.
    ///
    /// # Errors
    ///
    /// Returns an error if the model file doesn't exist.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    ///
    /// let mut engine = SttEngine::new(VoiceConfig::default());
    /// assert!(engine.load_model_from("/nonexistent/model.bin").is_err());
    /// ```
    pub fn load_model_from(&mut self, path: &str) -> Result<(), VoiceError> {
        let model_path = PathBuf::from(path);

        if !model_path.exists() {
            return Err(VoiceError::ModelNotFound {
                path: path.to_string(),
            });
        }

        self.model_path = Some(model_path);
        self.state = SttState::Ready;
        Ok(())
    }

    /// Transcribe audio samples to text.
    ///
    /// Audio must be 16kHz mono f32 PCM samples.
    ///
    /// # Errors
    ///
    /// Returns an error if the engine is not ready or transcription fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    ///
    /// let engine = SttEngine::new(VoiceConfig::default());
    /// // Not ready — model not loaded
    /// let samples = vec![0.0f32; 16000]; // 1 second of silence
    /// assert!(engine.transcribe(&samples).is_err());
    /// ```
    pub fn transcribe(&self, samples: &[f32]) -> Result<Transcript, VoiceError> {
        if self.state != SttState::Ready {
            return Err(VoiceError::ModelLoadFailed {
                reason: "model not loaded — call load_model() first".to_string(),
            });
        }

        if samples.is_empty() {
            return Err(VoiceError::NoSpeechDetected);
        }

        let duration_ms =
            (samples.len() as u64 * 1000) / u64::from(self.config.sample_rate);

        info!(
            samples = samples.len(),
            duration_ms,
            "transcribing audio"
        );

        // STUB: returns a synthetic placeholder transcript based on audio
        // duration — NOT real transcription. Replaced when whisper-rs is
        // integrated (Phase 3B+).
        if duration_ms < 100 {
            return Err(VoiceError::NoSpeechDetected);
        }

        Ok(Transcript {
            text: format!("[STT placeholder — {duration_ms}ms of audio]"),
            language: self.config.language.clone(),
            confidence: 0.0,
            duration_ms,
        })
    }

    /// Get the configured language.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    ///
    /// let engine = SttEngine::new(VoiceConfig::default());
    /// assert_eq!(engine.language(), "en");
    /// ```
    #[must_use]
    pub fn language(&self) -> &str {
        &self.config.language
    }

    /// Estimate memory usage for the configured model.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    ///
    /// let engine = SttEngine::new(VoiceConfig::default());
    /// let mb = engine.estimated_memory_mb();
    /// assert!(mb > 0);
    /// ```
    #[must_use]
    pub fn estimated_memory_mb(&self) -> u64 {
        // Whisper base model: ~150MB, small: ~500MB, medium: ~1.5GB
        let model_name = self
            .config
            .stt_model_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("base");

        if model_name.contains("large") {
            3000
        } else if model_name.contains("medium") {
            1500
        } else if model_name.contains("small") {
            500
        } else {
            150
        }
    }

    /// Get the STT processing timeout.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    ///
    /// let engine = SttEngine::new(VoiceConfig::default());
    /// assert_eq!(engine.timeout().as_secs(), 30);
    /// ```
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.config.stt_timeout
    }

    /// Unload the model and free resources.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::{SttEngine, VoiceConfig};
    /// use die_voice::stt::SttState;
    ///
    /// let mut engine = SttEngine::new(VoiceConfig::default());
    /// engine.unload();
    /// assert_eq!(engine.state(), SttState::Unloaded);
    /// ```
    pub fn unload(&mut self) {
        if self.state != SttState::Unloaded {
            warn!("unloading Whisper model");
        }
        self.model_path = None;
        self.state = SttState::Unloaded;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_starts_unloaded() {
        let engine = SttEngine::new(VoiceConfig::default());
        assert_eq!(engine.state(), SttState::Unloaded);
        assert!(!engine.is_ready());
    }

    #[test]
    fn load_model_nonexistent_fails() {
        let mut engine = SttEngine::new(VoiceConfig::default());
        let result = engine.load_model();
        assert!(result.is_err());
    }

    #[test]
    fn load_model_from_nonexistent_fails() {
        let mut engine = SttEngine::new(VoiceConfig::default());
        let result = engine.load_model_from("/no/such/model.bin");
        assert!(result.is_err());
    }

    #[test]
    fn transcribe_without_model_fails() {
        let engine = SttEngine::new(VoiceConfig::default());
        let samples = vec![0.0f32; 16000];
        let result = engine.transcribe(&samples);
        assert!(result.is_err());
    }

    #[test]
    fn transcribe_empty_fails() {
        // Even with a model, empty audio should fail
        let engine = SttEngine::new(VoiceConfig::default());
        let result = engine.transcribe(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn language_default_is_english() {
        let engine = SttEngine::new(VoiceConfig::default());
        assert_eq!(engine.language(), "en");
    }

    #[test]
    fn estimated_memory_base_model() {
        let engine = SttEngine::new(VoiceConfig::default());
        assert_eq!(engine.estimated_memory_mb(), 150);
    }

    #[test]
    fn estimated_memory_large_model() {
        let config = VoiceConfig {
            stt_model_path: PathBuf::from("/models/whisper-large.bin"),
            ..VoiceConfig::default()
        };
        let engine = SttEngine::new(config);
        assert_eq!(engine.estimated_memory_mb(), 3000);
    }

    #[test]
    fn timeout_default() {
        let engine = SttEngine::new(VoiceConfig::default());
        assert_eq!(engine.timeout().as_secs(), 30);
    }

    #[test]
    fn unload_transitions_state() {
        let mut engine = SttEngine::new(VoiceConfig::default());
        engine.unload();
        assert_eq!(engine.state(), SttState::Unloaded);
    }

    #[test]
    fn transcript_fields() {
        let t = Transcript {
            text: "Hello world".to_string(),
            language: "en".to_string(),
            confidence: 0.95,
            duration_ms: 2000,
        };
        assert_eq!(t.text, "Hello world");
        assert_eq!(t.duration_ms, 2000);
    }

    #[test]
    fn stt_state_equality() {
        assert_eq!(SttState::Unloaded, SttState::Unloaded);
        assert_eq!(SttState::Ready, SttState::Ready);
        assert_eq!(SttState::Processing, SttState::Processing);
        assert_ne!(SttState::Unloaded, SttState::Ready);
    }
}
