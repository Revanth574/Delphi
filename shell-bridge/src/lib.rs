// SPDX-License-Identifier: MIT

//! # Shell Bridge
//!
//! WebSocket server that bridges the Living Surface React shell to
//! the Delphi D-Bus service layer. The shell connects via WebSocket
//! and sends JSON-RPC-like messages; the bridge translates them to
//! calls on the D-Bus services.
//!
//! # Protocol
//!
//! ```json
//! // Request (shell → bridge)
//! { "id": 1, "method": "inference.query", "params": { "prompt": "Hello", "max_tokens": 256 } }
//!
//! // Response (bridge → shell)
//! { "id": 1, "result": { "output": "Hi!", "tier": "Local", "model_id": "qwen3-7b" } }
//!
//! // Error
//! { "id": 1, "error": { "code": -1, "message": "no backend available" } }
//! ```
//!
//! # Architecture
//!
//! ```text
//! React Shell ←WebSocket:9800→ shell-bridge ──→ delphi-services (in-process)
//!                                                    ↓
//!                                     die-inference / semantic-fs / die-orchestrator
//! ```

pub mod handler;
pub mod protocol;
pub mod server;

/// Default WebSocket listen port.
pub const DEFAULT_PORT: u16 = 9800;

/// Default WebSocket listen address.
pub const DEFAULT_ADDR: &str = "127.0.0.1:9800";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_is_reasonable() {
        const { assert!(DEFAULT_PORT > 1024) };
        const { assert!(DEFAULT_PORT < 65535) };
    }

    #[test]
    fn default_addr_is_localhost() {
        assert!(DEFAULT_ADDR.starts_with("127.0.0.1"));
    }
}
