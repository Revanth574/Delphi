// SPDX-License-Identifier: MIT

//! `delphi-daemon` local development entry point.

use anyhow::Result;
use shell_bridge::DEFAULT_ADDR;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "delphi_daemon=info,shell_bridge=info".into()),
        )
        .init();

    let addr = std::env::var("DELPHI_DAEMON_ADDR").unwrap_or_else(|_| DEFAULT_ADDR.to_string());
    let server = delphi_daemon::local_dev_server(&addr)?;
    tracing::info!(%addr, "starting delphi-daemon local runtime");
    server.run().await?;
    Ok(())
}
