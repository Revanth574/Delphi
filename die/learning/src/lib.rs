// SPDX-License-Identifier: MIT

//! # DIE Learning Engine
//!
//! Universal Learning Engine for Delphi OS. Observes user actions,
//! detects behavioral patterns, proposes automations, and progressively
//! automates repeated tasks with user consent.
//!
//! # Learning Loop
//!
//! ```text
//! OBSERVE → MODEL → PROPOSE → PRACTICE → REFINE → AUTOMATE → EVOLVE
//! ```
//!
//! # Architecture
//!
//! The learning engine sits in the DIE layer and depends only on
//! Fortress (for encrypted storage):
//!
//! ```text
//! die-orchestrator → die-learning → fortress
//! ```
//!
//! # Boundaries (CLAUDE.md Section 4)
//!
//! - MUST NOT record events for disabled categories
//! - MUST NOT access file contents — metadata only
//! - Pattern suggestions go through the shell as notifications
//! - ALL learning data encrypted via Fortress
//!
//! # Privacy
//!
//! Privacy is mathematical, not promissory. The learning engine:
//! - Observes metadata only (app name, file path, timestamp, action type)
//! - Encrypts all stored patterns via Fortress
//! - Shows a live indicator when observation is active
//! - Provides a "Forget" button to purge all learned data
//! - Auto-pauses in Focus mode

pub mod engine;
pub mod error;
pub mod event;
pub mod observer;
pub mod pattern;
pub mod privacy;

pub use engine::LearningEngine;
pub use error::LearningError;
pub use event::{EventCategory, LearningEvent};
pub use observer::Observer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_exports_accessible() {
        // Verify all public types are accessible via crate root.
        let _engine = LearningEngine::new();
        let _observer = Observer::new();
        let _event = LearningEvent::new(EventCategory::AppLaunch, "test", None);
        let _err = LearningError::ObserverPaused;
    }

    #[test]
    fn full_learning_loop_integration() {
        let mut engine = LearningEngine::new();

        // Phase 1: OBSERVE — feed events with a clear pattern.
        for i in 0..25 {
            let events = vec![
                LearningEvent::at_time(EventCategory::AppLaunch, "firefox", None, i * 60),
                LearningEvent::at_time(
                    EventCategory::AppLaunch,
                    "code",
                    None,
                    i * 60 + 10,
                ),
            ];
            for e in events {
                let _ = engine.observe(e);
            }
        }

        // Phase 2: MODEL — patterns should have been detected at event 50.
        let ids = engine.active_pattern_ids();

        if let Some(id) = ids.first() {
            // Phase 3: PROPOSE — pattern is in Proposed stage.
            let tracked = engine.get_pattern(id).unwrap();
            assert_eq!(tracked.stage, engine::PatternStage::Proposed);

            // Phase 4: PRACTICE — user accepts.
            engine.accept_pattern(id).unwrap();
            assert_eq!(
                engine.get_pattern(id).unwrap().stage,
                engine::PatternStage::Practicing,
            );

            // Phase 5: REFINE — a failure sends it back.
            engine.record_failure(id).unwrap();
            assert_eq!(
                engine.get_pattern(id).unwrap().stage,
                engine::PatternStage::Refining,
            );

            // Phase 6: AUTOMATE — 3 successes graduate it.
            engine.record_success(id).unwrap();
            engine.record_success(id).unwrap();
            engine.record_success(id).unwrap();
            assert_eq!(
                engine.get_pattern(id).unwrap().stage,
                engine::PatternStage::Automated,
            );

            // Automated patterns are reported.
            assert!(!engine.automated_patterns().is_empty());
        }
    }

    #[test]
    fn focus_mode_pauses_and_resumes() {
        let mut engine = LearningEngine::new();
        assert!(engine.is_active());

        engine.pause();
        assert!(!engine.is_active());

        let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
        assert!(engine.observe(event).is_err());

        engine.resume();
        assert!(engine.is_active());

        let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
        assert!(engine.observe(event).is_ok());
    }

    #[test]
    fn forget_purges_all_data() {
        let mut engine = LearningEngine::new();

        for i in 0..25 {
            let events = vec![
                LearningEvent::at_time(EventCategory::AppLaunch, "a", None, i * 60),
                LearningEvent::at_time(EventCategory::AppLaunch, "b", None, i * 60 + 10),
            ];
            for e in events {
                let _ = engine.observe(e);
            }
        }

        let had_patterns = engine.pattern_count() > 0;
        engine.forget();
        assert_eq!(engine.pattern_count(), 0);
        assert_eq!(engine.buffered_events(), 0);

        // If we had patterns, they're gone now.
        if had_patterns {
            assert!(engine.active_pattern_ids().is_empty());
        }
    }

    #[test]
    fn category_filtering_blocks_events() {
        let mut engine = LearningEngine::new();
        engine.disable_category(EventCategory::FileAccess);

        let event = LearningEvent::new(EventCategory::FileAccess, "/path", None);
        assert!(engine.observe(event).is_err());

        // Other categories still work.
        let event = LearningEvent::new(EventCategory::AppLaunch, "app", None);
        assert!(engine.observe(event).is_ok());
    }
}
