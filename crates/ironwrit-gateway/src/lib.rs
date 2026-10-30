//! MCP proxy that enforces capability tokens on every tool call.
//!
//! Sits between an agent and an upstream MCP server over stdio. The agent
//! talks to the gateway as if it were the upstream; every `tools/call` is
//! checked against a [`CallPolicy`] before it is forwarded.

mod error;
mod proxy;
mod upstream;

use ironwrit_token::CallPolicy;
use rmcp::ServiceExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

pub use error::{Error, Result};
pub use upstream::Upstream;

use proxy::Gateway;

/// Serve the agent on this process's stdin/stdout until either side disconnects.
pub async fn serve_stdio<P: CallPolicy>(policy: P, upstream: Upstream) -> Result<()> {
    serve(policy, upstream, rmcp::transport::stdio()).await
}

/// Serve the agent on `agent` until either side disconnects.
///
/// The upstream handshake happens when the agent sends `initialize`. When the
/// session ends, the upstream's stdin is closed and the process is reaped.
pub async fn serve<P, R, W>(policy: P, upstream: Upstream, agent: (R, W)) -> Result<()>
where
    P: CallPolicy,
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let (upstream_io, child) = upstream.into_parts();
    let shutdown = CancellationToken::new();
    let gateway = Gateway::new(policy, upstream_io, shutdown.clone());

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
    result
}
