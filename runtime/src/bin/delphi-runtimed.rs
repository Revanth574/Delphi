// SPDX-License-Identifier: MIT

//! `delphi-runtimed` — the root runtime daemon entrypoint (Increment 1a).
//!
//! systemd starts this as **root** via `delphi-runtimed@.service` (no `User=`),
//! so the runtime directory it establishes is root-owned (`docs/TRUST_MODEL.md`
//! §4, R3-01). 1a does exactly one thing: establish the root anchor — the
//! root-owned `/run/delphi/<session>` directory and the group-connectable
//! approval socket inside it — then hold it. It does **not** yet service the
//! socket: the private approval channel, PAM consent, token mint, sandbox, and
//! execute are Increments 1b–1d.
//!
//! Usage: `delphi-runtimed --session <username>`

use anyhow::{bail, Context, Result};
use nix::unistd::User;

use delphi_runtime::anchor::DEFAULT_RUNTIME_BASE;
use delphi_runtime::{bind_approval_socket, ensure_runtime_dir};

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let session = parse_session_arg(std::env::args().skip(1))?;

    let user = User::from_name(&session)
        .with_context(|| format!("resolving session user `{session}`"))?
        .with_context(|| format!("no such session user `{session}`"))?;

    let dir = ensure_runtime_dir(std::path::Path::new(DEFAULT_RUNTIME_BASE), &session)
        .context("establishing the root-owned runtime directory")?;
    let (paths, _listener) = bind_approval_socket(&dir, user.gid.as_raw())
        .context("binding the approval socket")?;

    tracing::info!(
        session = %session,
        uid = user.uid.as_raw(),
        gid = user.gid.as_raw(),
        dir = %paths.dir.display(),
        socket = %paths.socket.display(),
        "anchor established (1a): root-owned dir + group-connectable socket; \
         serving is Increment 1b"
    );

    // 1a holds the anchor (keeps `_listener` alive) but does not service it yet.
    // Park indefinitely; systemd manages the lifecycle.
    loop {
        std::thread::park();
    }
}

/// Parse `--session <username>` from the argument iterator.
fn parse_session_arg(mut args: impl Iterator<Item = String>) -> Result<String> {
    match args.next().as_deref() {
        Some("--session") => args
            .next()
            .context("`--session` requires a <username> argument"),
        Some(other) => bail!("unexpected argument `{other}`; usage: delphi-runtimed --session <username>"),
        None => bail!("missing `--session <username>`; usage: delphi-runtimed --session <username>"),
    }
}
