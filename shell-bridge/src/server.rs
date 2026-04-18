// SPDX-License-Identifier: MIT

//! WebSocket server for the shell bridge.
//!
//! Listens on a configurable address (default `127.0.0.1:9800`) and
//! upgrades incoming TCP connections to WebSocket. Each connection
//! runs in its own tokio task, reading JSON requests, dispatching
//! them through the [`Handler`], and sending JSON responses.
//!
//! # Connection Lifecycle
//!
//! ```text
//! TCP connect → WebSocket upgrade → read loop {
//!     receive text frame → parse Request → dispatch → send Response
//! } → close
//! ```

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing::{error, info, warn};

use crate::handler::Handler;
use crate::protocol::{Request, Response};

/// WebSocket bridge server.
///
/// Wraps a shared [`Handler`] and listens for WebSocket connections
/// from the React shell. Multiple connections are served concurrently.
///
/// # Examples
///
/// ```
/// use shell_bridge::server::BridgeServer;
/// use shell_bridge::handler::Handler;
/// use die_inference::router::Router;
/// use die_orchestrator::timeline::Timeline;
/// use semantic_fs::indexer::Indexer;
/// use std::sync::{Arc, Mutex};
/// use tokio::sync::RwLock;
/// use std::collections::HashMap;
///
/// let handler = Arc::new(Handler::new(
///     Arc::new(RwLock::new(Router::new())),
///     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
///     Arc::new(RwLock::new(HashMap::new())),
///     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
///     Arc::new(RwLock::new(Vec::new())),
/// ));
///
/// let server = BridgeServer::new(handler, "127.0.0.1:9800");
/// assert_eq!(server.addr(), "127.0.0.1:9800");
/// ```
pub struct BridgeServer {
    /// Shared handler dispatching requests to backends.
    handler: Arc<Handler>,
    /// Address to bind the TCP listener to.
    addr: String,
}

impl BridgeServer {
    /// Create a new bridge server.
    ///
    /// # Examples
    ///
    /// ```
    /// use shell_bridge::server::BridgeServer;
    /// use shell_bridge::handler::Handler;
    /// use die_inference::router::Router;
    /// use die_orchestrator::timeline::Timeline;
    /// use semantic_fs::indexer::Indexer;
    /// use std::sync::{Arc, Mutex};
    /// use tokio::sync::RwLock;
    /// use std::collections::HashMap;
    ///
    /// let handler = Arc::new(Handler::new(
    ///     Arc::new(RwLock::new(Router::new())),
    ///     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
    ///     Arc::new(RwLock::new(HashMap::new())),
    ///     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
    ///     Arc::new(RwLock::new(Vec::new())),
    /// ));
    ///
    /// let server = BridgeServer::new(handler, "127.0.0.1:9800");
    /// ```
    #[must_use]
    pub fn new(handler: Arc<Handler>, addr: &str) -> Self {
        Self {
            handler,
            addr: addr.to_string(),
        }
    }

    /// Get the configured listen address.
    ///
    /// # Examples
    ///
    /// ```
    /// # use shell_bridge::server::BridgeServer;
    /// # use shell_bridge::handler::Handler;
    /// # use die_inference::router::Router;
    /// # use die_orchestrator::timeline::Timeline;
    /// # use semantic_fs::indexer::Indexer;
    /// # use std::sync::{Arc, Mutex};
    /// # use tokio::sync::RwLock;
    /// # use std::collections::HashMap;
    /// # let handler = Arc::new(Handler::new(
    /// #     Arc::new(RwLock::new(Router::new())),
    /// #     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
    /// #     Arc::new(RwLock::new(HashMap::new())),
    /// #     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
    /// #     Arc::new(RwLock::new(Vec::new())),
    /// # ));
    /// let server = BridgeServer::new(handler, "127.0.0.1:9800");
    /// assert_eq!(server.addr(), "127.0.0.1:9800");
    /// ```
    #[must_use]
    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// Run the server, accepting connections until the task is cancelled.
    ///
    /// This method binds to the configured address and enters an
    /// accept loop. Each connection is spawned as a separate task.
    /// Returns an error only if the TCP bind fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot bind to the address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use shell_bridge::server::BridgeServer;
    /// # use shell_bridge::handler::Handler;
    /// # use die_inference::router::Router;
    /// # use die_orchestrator::timeline::Timeline;
    /// # use semantic_fs::indexer::Indexer;
    /// # use std::sync::{Arc, Mutex};
    /// # use tokio::sync::RwLock;
    /// # use std::collections::HashMap;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let handler = Arc::new(Handler::new(
    /// #     Arc::new(RwLock::new(Router::new())),
    /// #     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
    /// #     Arc::new(RwLock::new(HashMap::new())),
    /// #     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
    /// #     Arc::new(RwLock::new(Vec::new())),
    /// # ));
    /// let server = BridgeServer::new(handler, "127.0.0.1:9800");
    /// server.run().await.unwrap();
    /// # });
    /// ```
    pub async fn run(&self) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!(addr = %self.addr, "shell-bridge WebSocket server listening");

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    info!(peer = %peer, "new connection");
                    let handler = Arc::clone(&self.handler);
                    tokio::spawn(handle_connection(handler, stream, peer));
                }
                Err(e) => {
                    error!(error = %e, "failed to accept connection");
                }
            }
        }
    }

    /// Run the server with a graceful shutdown signal.
    ///
    /// Accepts connections until `shutdown` resolves, then stops
    /// accepting new connections. Existing connections continue
    /// until they close naturally.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot bind to the address.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use shell_bridge::server::BridgeServer;
    /// # use shell_bridge::handler::Handler;
    /// # use die_inference::router::Router;
    /// # use die_orchestrator::timeline::Timeline;
    /// # use semantic_fs::indexer::Indexer;
    /// # use std::sync::{Arc, Mutex};
    /// # use tokio::sync::RwLock;
    /// # use std::collections::HashMap;
    /// # tokio::runtime::Runtime::new().unwrap().block_on(async {
    /// # let handler = Arc::new(Handler::new(
    /// #     Arc::new(RwLock::new(Router::new())),
    /// #     Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
    /// #     Arc::new(RwLock::new(HashMap::new())),
    /// #     Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
    /// #     Arc::new(RwLock::new(Vec::new())),
    /// # ));
    /// let server = BridgeServer::new(handler, "127.0.0.1:9800");
    /// let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    /// // In another task: tx.send(()).unwrap();
    /// server.run_until(rx).await.unwrap();
    /// # });
    /// ```
    pub async fn run_until(
        &self,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.addr).await?;
        info!(addr = %self.addr, "shell-bridge WebSocket server listening (with shutdown)");

        tokio::select! {
            _ = async {
                loop {
                    match listener.accept().await {
                        Ok((stream, peer)) => {
                            info!(peer = %peer, "new connection");
                            let handler = Arc::clone(&self.handler);
                            tokio::spawn(handle_connection(handler, stream, peer));
                        }
                        Err(e) => {
                            error!(error = %e, "failed to accept connection");
                        }
                    }
                }
            } => {}
            _ = shutdown => {
                info!("shutdown signal received, stopping accept loop");
            }
        }

        Ok(())
    }
}

/// Handle a single WebSocket connection.
///
/// Upgrades the TCP stream, then enters a read loop: parse each
/// text frame as a [`Request`], dispatch through the handler, and
/// send back the [`Response`] as JSON.
async fn handle_connection(
    handler: Arc<Handler>,
    stream: TcpStream,
    peer: SocketAddr,
) {
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            error!(peer = %peer, error = %e, "WebSocket handshake failed");
            return;
        }
    };

    info!(peer = %peer, "WebSocket connection established");
    let (mut write, mut read) = ws_stream.split();

    while let Some(msg_result) = read.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                warn!(peer = %peer, error = %e, "read error, closing");
                break;
            }
        };

        match msg {
            Message::Text(text) => {
                let response = process_text_message(&handler, &text).await;
                let json = match serde_json::to_string(&response) {
                    Ok(j) => j,
                    Err(e) => {
                        error!(error = %e, "failed to serialize response");
                        continue;
                    }
                };

                if let Err(e) = write.send(Message::Text(json.into())).await {
                    error!(peer = %peer, error = %e, "write error, closing");
                    break;
                }
            }
            Message::Ping(data) => {
                if let Err(e) = write.send(Message::Pong(data)).await {
                    warn!(peer = %peer, error = %e, "pong send failed");
                    break;
                }
            }
            Message::Close(_) => {
                info!(peer = %peer, "client sent close frame");
                break;
            }
            _ => {
                // Binary frames, pong frames — ignore
            }
        }
    }

    info!(peer = %peer, "connection closed");
}

/// Parse a text message as a [`Request`] and dispatch it.
///
/// If parsing fails, returns an error response with id 0.
async fn process_text_message(
    handler: &Handler,
    text: &str,
) -> Response {
    match serde_json::from_str::<Request>(text) {
        Ok(req) => handler.dispatch(req).await,
        Err(e) => {
            warn!(error = %e, "invalid request JSON");
            Response::err(0, -32700, &format!("parse error: {e}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use die_inference::router::Router;
    use die_orchestrator::timeline::Timeline;
    use semantic_fs::indexer::Indexer;
    use tokio::sync::RwLock;

    /// Create a test handler with empty services.
    fn test_handler() -> Arc<Handler> {
        Arc::new(Handler::new(
            Arc::new(RwLock::new(Router::new())),
            Arc::new(Mutex::new(Indexer::in_memory().unwrap())),
            Arc::new(RwLock::new(HashMap::new())),
            Arc::new(Mutex::new(Timeline::in_memory().unwrap())),
            Arc::new(RwLock::new(Vec::new())),
        ))
    }

    #[test]
    fn server_creation() {
        let handler = test_handler();
        let server = BridgeServer::new(handler, "127.0.0.1:9800");
        assert_eq!(server.addr(), "127.0.0.1:9800");
    }

    #[test]
    fn server_custom_addr() {
        let handler = test_handler();
        let server = BridgeServer::new(handler, "0.0.0.0:8080");
        assert_eq!(server.addr(), "0.0.0.0:8080");
    }

    #[tokio::test]
    async fn process_valid_json() {
        let handler = test_handler();
        let text = r#"{"id": 1, "method": "inference.status"}"#;
        let resp = process_text_message(&handler, text).await;
        assert!(resp.error.is_none());
        assert_eq!(resp.id, 1);
    }

    #[tokio::test]
    async fn process_invalid_json() {
        let handler = test_handler();
        let resp = process_text_message(&handler, "not json").await;
        assert!(resp.error.is_some());
        assert_eq!(resp.id, 0);
        assert_eq!(resp.error.unwrap().code, -32700);
    }

    #[tokio::test]
    async fn process_unknown_method() {
        let handler = test_handler();
        let text = r#"{"id": 99, "method": "bogus.call"}"#;
        let resp = process_text_message(&handler, text).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.id, 99);
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn run_until_shutdown() {
        let handler = test_handler();
        let server = BridgeServer::new(handler, "127.0.0.1:0");

        let (tx, rx) = tokio::sync::oneshot::channel::<()>();

        // Send shutdown immediately
        tx.send(()).unwrap();

        // Server should exit cleanly after receiving shutdown
        let result = server.run_until(rx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn full_websocket_roundtrip() {
        let handler = test_handler();
        // Use port 0 to get an OS-assigned port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handler_clone = Arc::clone(&handler);

        // Spawn server accept loop
        let server_handle = tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                handle_connection(handler_clone, stream, peer).await;
            }
        });

        // Connect as client
        let (mut ws_stream, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}"))
                .await
                .unwrap();

        // Send a request
        let req = r#"{"id": 1, "method": "inference.status"}"#;
        ws_stream
            .send(Message::Text(req.to_string().into()))
            .await
            .unwrap();

        // Read response
        let msg = ws_stream.next().await.unwrap().unwrap();
        let text = msg.into_text().unwrap();
        let resp: serde_json::Value = serde_json::from_str(&text).unwrap();

        assert_eq!(resp["id"], 1);
        assert!(resp["result"].is_object());
        assert_eq!(resp["result"]["has_local"], false);
        assert_eq!(resp["result"]["has_cloud"], false);

        // Close cleanly
        ws_stream.close(None).await.unwrap();
        let _ = server_handle.await;
    }

    #[tokio::test]
    async fn websocket_mode_roundtrip() {
        let handler = test_handler();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let handler_clone = Arc::clone(&handler);
        let server_handle = tokio::spawn(async move {
            if let Ok((stream, peer)) = listener.accept().await {
                handle_connection(handler_clone, stream, peer).await;
            }
        });

        let (mut ws_stream, _) =
            tokio_tungstenite::connect_async(format!("ws://{addr}"))
                .await
                .unwrap();

        // Set a mode
        let set_req = r#"{"id": 1, "method": "mode.set", "params": {"window_id": "win-1", "mode": "Focus"}}"#;
        ws_stream
            .send(Message::Text(set_req.to_string().into()))
            .await
            .unwrap();
        let msg = ws_stream.next().await.unwrap().unwrap();
        let resp: serde_json::Value =
            serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        assert_eq!(resp["result"]["mode"], "Focus");

        // Get the mode back
        let get_req = r#"{"id": 2, "method": "mode.get", "params": {"window_id": "win-1"}}"#;
        ws_stream
            .send(Message::Text(get_req.to_string().into()))
            .await
            .unwrap();
        let msg = ws_stream.next().await.unwrap().unwrap();
        let resp: serde_json::Value =
            serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        assert_eq!(resp["result"]["mode"], "Focus");

        ws_stream.close(None).await.unwrap();
        let _ = server_handle.await;
    }
}
