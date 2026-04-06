// SPDX-License-Identifier: MIT

//! # Delphi Compositor
//!
//! Wayland compositor for Delphi OS, built on [Smithay](https://smithay.github.io/).
//!
//! The compositor is a standalone component that communicates with the
//! Living Surface shell via the Wayland protocol and with the DIE
//! orchestrator via D-Bus. It has no internal workspace dependencies.
//!
//! # Architecture
//!
//! ```text
//! Living Surface (React 19) ←→ Wayland Protocol ←→ Compositor (Smithay)
//!                                                        ↕ D-Bus
//!                                                   DIE Orchestrator
//! ```
//!
//! Each window carries an independent UI mode (Direct, Assisted,
//! Autonomous, Focus) displayed as a colored dot in the title bar.

pub mod error;

pub use error::CompositorError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_type_is_accessible() {
        let err = CompositorError::BackendInit("test".to_string());
        assert!(!err.to_string().is_empty());
    }
}
