// SPDX-License-Identifier: MIT

//! # Delphi Voice I/O
//!
//! Speech-to-text (STT) and text-to-speech (TTS) for the Delphi
//! Intelligence Engine. Uses Whisper for STT and Piper for TTS.
//!
//! # Architecture
//!
//! ```text
//! Microphone → AudioCapture → Whisper STT → text → Orchestrator
//!                                                        ↓
//! Speaker   ← AudioPlayback ← Piper TTS  ← text ← Inference
//! ```
//!
//! Both STT and TTS run as separate processes managed by this crate.
//! Audio is passed as raw PCM samples (16kHz, mono, f32).
//!
//! # Performance Budget
//!
//! - STT streaming latency: < 300ms (spec requirement)
//! - TTS first-byte latency: < 500ms
//! - Memory: < 500MB for both models combined

pub mod config;
pub mod error;
pub mod stt;
pub mod tts;

pub use config::VoiceConfig;
pub use error::VoiceError;
pub use stt::{SttEngine, Transcript};
pub use tts::{TtsEngine, AudioChunk};
