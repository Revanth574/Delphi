// SPDX-License-Identifier: MIT

//! Local development runtime spine for Delphi.
//!
//! The daemon owns the shared in-process state that the shell bridge exposes:
//! inference routing, semantic file search, window modes, the action timeline,
//! and the learning facade. This is intentionally local/dev only; production
//! packaging, systemd units, and installer integration are later units.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use die_inference::router::Router;
use die_orchestrator::learning::LearningFacade;
use die_orchestrator::timeline::Timeline;
use semantic_fs::indexer::Indexer;
use shell_bridge::handler::Handler;
use shell_bridge::server::BridgeServer;
use tokio::sync::RwLock;

/// Shared runtime state owned by `delphi-daemon`.
pub struct DaemonState {
    router: Arc<RwLock<Router>>,
    indexer: Arc<Mutex<Indexer>>,
    modes: Arc<RwLock<HashMap<String, String>>>,
    timeline: Arc<Mutex<Timeline>>,
    learning: Arc<Mutex<LearningFacade>>,
}

impl DaemonState {
    /// Build a local-dev daemon state bundle backed by in-memory stores.
    ///
    /// # Errors
    ///
    /// Returns an error if one of the in-memory stores cannot be constructed.
    pub fn dev_in_memory() -> Result<Self> {
        Ok(Self {
            router: Arc::new(RwLock::new(Router::new())),
            indexer: Arc::new(Mutex::new(Indexer::in_memory()?)),
            modes: Arc::new(RwLock::new(HashMap::new())),
            timeline: Arc::new(Mutex::new(Timeline::in_memory()?)),
            learning: Arc::new(Mutex::new(LearningFacade::in_memory()?)),
        })
    }

    /// Build a shell bridge handler over this daemon's shared state.
    #[must_use]
    pub fn handler(&self) -> Arc<Handler> {
        Arc::new(Handler::new(
            Arc::clone(&self.router),
            Arc::clone(&self.indexer),
            Arc::clone(&self.modes),
            Arc::clone(&self.timeline),
            Arc::clone(&self.learning),
        ))
    }

    /// Build a WebSocket bridge server for the provided address.
    #[must_use]
    pub fn bridge_server(&self, addr: &str) -> BridgeServer {
        BridgeServer::new(self.handler(), addr)
    }
}

/// Construct the default local-dev bridge server.
///
/// # Errors
///
/// Returns an error if local-dev state cannot be initialized.
pub fn local_dev_server(addr: &str) -> Result<BridgeServer> {
    Ok(DaemonState::dev_in_memory()?.bridge_server(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_constructs_shared_state() {
        let state = DaemonState::dev_in_memory().unwrap();
        let server = state.bridge_server("127.0.0.1:0");
        assert_eq!(server.addr(), "127.0.0.1:0");
    }
}
