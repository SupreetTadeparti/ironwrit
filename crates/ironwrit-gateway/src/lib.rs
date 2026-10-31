//! MCP proxy that enforces capability tokens on every tool call.
//!
//! Sits between an agent and an upstream MCP server over stdio. The agent
//! talks to the gateway as if it were the upstream; every `tools/call` is
//! checked against a [`CallPolicy`] before it is forwarded, and every
//! decision is appended to the [`Ledger`].

mod error;
mod proxy;
mod upstream;

use std::sync::Arc;

use ironwrit_ledger::Ledger;
use ironwrit_token::CallPolicy;
use rmcp::ServiceExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

pub use error::{Error, Result};
pub use upstream::Upstream;

use proxy::Gateway;

/// Serve the agent on this process's stdin/stdout until either side disconnects.
pub async fn serve_stdio<P: CallPolicy>(
    policy: P,
    ledger: Arc<Ledger>,
    upstream: Upstream,
) -> Result<()> {
    serve(policy, ledger, upstream, rmcp::transport::stdio()).await
}

/// Serve the agent on `agent` until either side disconnects.
///
/// The upstream handshake happens when the agent sends `initialize`. When the
/// session ends, the upstream's stdin is closed, the process is reaped, and a
/// final tree head is signed over everything this session logged.
pub async fn serve<P, R, W>(
    policy: P,
    ledger: Arc<Ledger>,
    upstream: Upstream,
    agent: (R, W),
) -> Result<()>
where
    P: CallPolicy,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let (upstream_io, child) = upstream.into_parts();
    let shutdown = CancellationToken::new();
    let gateway = Gateway::new(policy, ledger.clone(), upstream_io, shutdown.clone());
    let heads = tokio::spawn(sign_heads_periodically(ledger.clone(), shutdown.clone()));

    let result = match gateway.serve_with_ct(agent, shutdown.clone()).await {
        Ok(session) => {
            let reason = session.waiting().await;
            tracing::info!(?reason, "agent session ended");
            Ok(())
        }
        Err(e) => Err(Error::Agent(e.to_string())),
    };

    shutdown.cancel();
    if let Some(child) = child {
        upstream::reap(child).await;
    }
    let _ = heads.await;
    if let Err(e) = sign_head(ledger).await {
        tracing::error!(error = %e, "failed to sign the final tree head");
    }
    result
}

/// Sign a tree head every `interval` while there are new entries.
async fn sign_heads_periodically(ledger: Arc<Ledger>, shutdown: CancellationToken) {
    let interval = ledger.head_policy().interval;
    if interval.is_zero() {
        return;
    }
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = ticker.tick() => {
                if let Err(e) = sign_head(ledger.clone()).await {
                    tracing::warn!(error = %e, "failed to sign tree head");
                }
            }
        }
    }
}

async fn sign_head(ledger: Arc<Ledger>) -> Result<()> {
    let head = tokio::task::spawn_blocking(move || ledger.sign_head())
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e.to_string())))??;
    if let Some(head) = head {
        tracing::info!(size = head.size, "signed tree head");
    }
    Ok(())
}
