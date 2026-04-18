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
//!
//! # Modules
//!
//! - [`state`] — Central compositor state (`Delphi` struct)
//! - [`window`] — Per-window state and UI mode management
//! - [`handlers`] — Smithay protocol handler implementations
//! - [`input`] — Input event routing and compositor shortcuts
//! - [`winit_backend`] — Development backend (runs in a window)
//! - [`error`] — Error types

pub mod error;
pub mod handlers;
pub mod input;
pub mod render;
pub mod state;
pub mod window;
pub mod winit_backend;

pub use error::CompositorError;

use smithay::wayland::compositor::CompositorClientState;

/// Per-client state stored by the Wayland display.
///
/// Each connected Wayland client gets an instance of this struct,
/// which Smithay uses to track protocol state per-client.
///
/// # Examples
///
/// ```
/// use compositor::ClientState;
///
/// let state = ClientState::default();
/// // Client state is managed by Smithay internally.
/// ```
#[derive(Default)]
pub struct ClientState {
    /// Compositor protocol state for this client.
    pub compositor: CompositorClientState,
}

impl smithay::reexports::wayland_server::backend::ClientData for ClientState {
    fn initialized(&self, _client_id: smithay::reexports::wayland_server::backend::ClientId) {}
    fn disconnected(
        &self,
        _client_id: smithay::reexports::wayland_server::backend::ClientId,
        _reason: smithay::reexports::wayland_server::backend::DisconnectReason,
    ) {
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_type_is_accessible() {
        let err = CompositorError::BackendInit("test".to_string());
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn client_state_is_default() {
        let _state = ClientState::default();
    }
}
