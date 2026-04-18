// SPDX-License-Identifier: MIT

//! Error types for the learning engine.
//!
//! Uses `thiserror` for typed errors per CLAUDE.md Section 8.
//! Learning errors must **never** crash the OS — they degrade
//! gracefully by pausing observation or returning empty suggestions.

use fortress::FortressError;

/// Errors produced by the learning engine.
///
/// # Examples
///
/// ```
/// use die_learning::LearningError;
///
/// let err = LearningError::ObserverPaused;
/// assert!(err.to_string().contains("paused"));
/// ```
#[derive(Debug, thiserror::Error)]
pub enum LearningError {
    /// The observer is paused (e.g., Focus mode active).
    #[error("learning observer is paused")]
    ObserverPaused,

    /// The event category is disabled by the user.
    #[error("event category disabled: {category}")]
    CategoryDisabled {
        /// Which category was rejected.
        category: String,
    },

    /// Pattern detection failed.
    #[error("pattern detection failed: {reason}")]
    PatternDetection {
        /// Why detection failed.
        reason: String,
    },

    /// Storage operation failed (encrypted persistence).
    #[error("learning storage failed: {reason}")]
    StorageFailed {
        /// Why storage failed.
        reason: String,
    },

    /// Security subsystem error (propagated from fortress).
    #[error("security error: {0}")]
    Security(#[from] FortressError),

    /// No patterns detected in the current event batch.
    #[error("no patterns detected in {event_count} events")]
    NoPatternsFound {
        /// How many events were analyzed.
        event_count: usize,
    },

    /// The pattern has not been observed enough times.
    #[error("insufficient observations: {observed}/{required}")]
    InsufficientObservations {
        /// Times observed.
        observed: u32,
        /// Times required.
        required: u32,
    },

    /// Serialization/deserialization error.
    #[error("serialization error: {reason}")]
    Serialization {
        /// Why serialization failed.
        reason: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observer_paused_message() {
        let err = LearningError::ObserverPaused;
        assert!(err.to_string().contains("paused"));
    }

    #[test]
    fn category_disabled_message() {
        let err = LearningError::CategoryDisabled {
            category: "file_access".to_string(),
        };
        assert!(err.to_string().contains("file_access"));
        assert!(err.to_string().contains("disabled"));
    }

    #[test]
    fn pattern_detection_message() {
        let err = LearningError::PatternDetection {
            reason: "too few events".to_string(),
        };
        assert!(err.to_string().contains("too few"));
    }

    #[test]
    fn storage_failed_message() {
        let err = LearningError::StorageFailed {
            reason: "disk full".to_string(),
        };
        assert!(err.to_string().contains("disk full"));
    }

    #[test]
    fn fortress_error_converts() {
        let fortress_err = FortressError::Encryption("key missing".to_string());
        let err: LearningError = fortress_err.into();
        assert!(err.to_string().contains("key missing"));
    }

    #[test]
    fn no_patterns_found_message() {
        let err = LearningError::NoPatternsFound { event_count: 50 };
        assert!(err.to_string().contains("50"));
    }

    #[test]
    fn insufficient_observations_message() {
        let err = LearningError::InsufficientObservations {
            observed: 2,
            required: 3,
        };
        assert!(err.to_string().contains("2/3"));
    }

    #[test]
    fn serialization_error_message() {
        let err = LearningError::Serialization {
            reason: "invalid JSON".to_string(),
        };
        assert!(err.to_string().contains("invalid JSON"));
    }
}
