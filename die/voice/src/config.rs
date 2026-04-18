// SPDX-License-Identifier: MIT

//! Voice I/O configuration.
//!
//! Configures both the STT (Whisper) and TTS (Piper) engines,
//! including model paths, audio parameters, and timeouts.

use std::path::PathBuf;
use std::time::Duration;

/// Audio sample rate for all voice processing (Whisper requires 16kHz).
pub const SAMPLE_RATE: u32 = 16_000;

/// Audio channels (mono for STT input).
pub const CHANNELS: u16 = 1;

/// Voice I/O configuration.
///
/// # Examples
///
/// ```
/// use die_voice::VoiceConfig;
///
/// let config = VoiceConfig::default();
/// assert_eq!(config.sample_rate, 16_000);
/// assert!(config.stt_model_path.to_string_lossy().contains("whisper"));
/// ```
#[derive(Debug, Clone)]
pub struct VoiceConfig {
    /// Path to the Whisper model file (GGML format).
    pub stt_model_path: PathBuf,
    /// Path to the Piper model directory.
    pub tts_model_path: PathBuf,
    /// Path to the Piper binary.
    pub tts_binary_path: PathBuf,
    /// Audio sample rate in Hz.
    pub sample_rate: u32,
    /// Number of audio channels.
    pub channels: u16,
    /// Language code for STT (e.g., "en", "es", "ja").
    pub language: String,
    /// Maximum duration for a single STT operation.
    pub stt_timeout: Duration,
    /// Maximum duration for a single TTS operation.
    pub tts_timeout: Duration,
    /// Whether to use GPU acceleration for Whisper.
    pub use_gpu: bool,
    /// Number of threads for Whisper inference.
    pub threads: u32,
}

impl Default for VoiceConfig {
    /// Default configuration targeting Whisper base model + Piper.
    ///
    /// # Examples
    ///
    /// ```
    /// use die_voice::VoiceConfig;
    ///
    /// let c = VoiceConfig::default();
    /// assert_eq!(c.language, "en");
    /// assert_eq!(c.threads, 4);
    /// ```
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("/usr/share"))
            .join("delphi");

        Self {
            stt_model_path: data_dir.join("models").join("whisper-base.bin"),
            tts_model_path: data_dir.join("models").join("piper"),
            tts_binary_path: PathBuf::from("piper"),
            sample_rate: SAMPLE_RATE,
            channels: CHANNELS,
            language: "en".to_string(),
            stt_timeout: Duration::from_secs(30),
            tts_timeout: Duration::from_secs(30),
            use_gpu: false,
            threads: 4,
        }
    }
}

/// Supported voice languages.
///
/// # Examples
///
/// ```
/// use die_voice::config::is_supported_language;
///
/// assert!(is_supported_language("en"));
/// assert!(is_supported_language("ja"));
/// assert!(!is_supported_language("klingon"));
/// ```
#[must_use]
pub fn is_supported_language(lang: &str) -> bool {
    matches!(
        lang,
        "en" | "es" | "fr" | "de" | "it" | "pt" | "nl" | "pl" | "ru"
            | "ja" | "zh" | "ko" | "ar" | "hi" | "tr" | "vi"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_values() {
        let config = VoiceConfig::default();
        assert_eq!(config.sample_rate, 16_000);
        assert_eq!(config.channels, 1);
        assert_eq!(config.language, "en");
        assert_eq!(config.threads, 4);
        assert!(!config.use_gpu);
    }

    #[test]
    fn default_model_paths_contain_expected_names() {
        let config = VoiceConfig::default();
        assert!(config.stt_model_path.to_string_lossy().contains("whisper"));
        assert!(config.tts_model_path.to_string_lossy().contains("piper"));
    }

    #[test]
    fn supported_languages() {
        assert!(is_supported_language("en"));
        assert!(is_supported_language("es"));
        assert!(is_supported_language("ja"));
        assert!(is_supported_language("zh"));
        assert!(is_supported_language("ar"));
    }

    #[test]
    fn unsupported_languages() {
        assert!(!is_supported_language("klingon"));
        assert!(!is_supported_language(""));
        assert!(!is_supported_language("xx"));
    }

    #[test]
    fn constants() {
        assert_eq!(SAMPLE_RATE, 16_000);
        assert_eq!(CHANNELS, 1);
    }

    #[test]
    fn custom_config() {
        let config = VoiceConfig {
            language: "ja".to_string(),
            use_gpu: true,
            threads: 8,
            ..VoiceConfig::default()
        };
        assert_eq!(config.language, "ja");
        assert!(config.use_gpu);
        assert_eq!(config.threads, 8);
    }
}
