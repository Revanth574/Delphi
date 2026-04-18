// SPDX-License-Identifier: MIT

//! Voice I/O error types.

use thiserror::Error;

/// Errors that can occur during voice operations.
///
/// # Examples
///
/// ```
/// use die_voice::VoiceError;
///
/// let err = VoiceError::ModelNotFound { path: "/models/whisper.bin".to_string() };
/// assert!(err.to_string().contains("whisper"));
/// ```
#[derive(Debug, Error)]
pub enum VoiceError {
    /// The voice model file was not found.
    #[error("voice model not found: {path}")]
    ModelNotFound {
        /// Path that was searched.
        path: String,
    },

    /// Failed to load a voice model.
    #[error("model load failed: {reason}")]
    ModelLoadFailed {
        /// Why loading failed.
        reason: String,
    },

    /// Audio capture or playback failed.
    #[error("audio error: {reason}")]
    AudioError {
        /// Why the audio operation failed.
        reason: String,
    },

    /// Speech recognition produced no result.
    #[error("no speech detected in audio")]
    NoSpeechDetected,

    /// TTS synthesis failed.
    #[error("synthesis failed: {reason}")]
    SynthesisFailed {
        /// Why synthesis failed.
        reason: String,
    },

    /// The voice process exited unexpectedly.
    #[error("voice process exited (code: {code:?})")]
    ProcessExited {
        /// Exit code, if available.
        code: Option<i32>,
    },

    /// Operation timed out.
    #[error("voice operation timed out after {seconds}s")]
    Timeout {
        /// Timeout duration.
        seconds: u64,
    },

    /// IPC communication failure.
    #[error("IPC error: {reason}")]
    IpcError {
        /// Why communication failed.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_not_found_message() {
        let err = VoiceError::ModelNotFound {
            path: "/models/whisper.bin".to_string(),
        };
        assert!(err.to_string().contains("whisper"));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn model_load_failed_message() {
        let err = VoiceError::ModelLoadFailed {
            reason: "invalid format".to_string(),
        };
        assert!(err.to_string().contains("invalid format"));
    }

    #[test]
    fn audio_error_message() {
        let err = VoiceError::AudioError {
            reason: "device not available".to_string(),
        };
        assert!(err.to_string().contains("device"));
    }

    #[test]
    fn no_speech_detected_message() {
        let err = VoiceError::NoSpeechDetected;
        assert!(err.to_string().contains("no speech"));
    }

    #[test]
    fn synthesis_failed_message() {
        let err = VoiceError::SynthesisFailed {
            reason: "unsupported language".to_string(),
        };
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn timeout_message() {
        let err = VoiceError::Timeout { seconds: 5 };
        assert!(err.to_string().contains("5"));
    }

    #[test]
    fn process_exited_message() {
        let err = VoiceError::ProcessExited { code: Some(1) };
        assert!(err.to_string().contains("1"));
    }

    #[test]
    fn ipc_error_message() {
        let err = VoiceError::IpcError {
            reason: "broken pipe".to_string(),
        };
        assert!(err.to_string().contains("broken pipe"));
    }
}
