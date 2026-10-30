use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::process::{Child, Command};

use crate::{Error, Result};

/// How long a child gets to exit on its own after its stdin closes.
const EXIT_GRACE: Duration = Duration::from_secs(3);

pub(crate) type BoxRead = Box<dyn AsyncRead + Send + Unpin>;
pub(crate) type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// The byte stream to an upstream MCP server, plus the process behind it.
///
/// The MCP handshake doesn't happen until the agent connects, so the gateway
/// can forward the agent's own client capabilities.
pub struct Upstream {
    pub(crate) reader: BoxRead,
    pub(crate) writer: BoxWrite,
    child: Option<Child>,
}

impl Upstream {
    /// Spawn `command[0]` with the remaining arguments, talking MCP over stdio.
    ///
    /// The child's stderr is inherited so its logs show up next to ours.
    pub fn spawn(command: &[String]) -> Result<Self> {
        let (program, args) = command
            .split_first()
            .ok_or_else(|| Error::Upstream("no upstream command given".into()))?;
        let spawn_error = |source| Error::Spawn {
            command: program.clone(),
            source,
        };
        // Resolve through PATH ourselves so Windows shims like `npx.cmd` work.
        let resolved = which::which(program)
            .map_err(|e| spawn_error(std::io::Error::new(std::io::ErrorKind::NotFound, e)))?;

        let mut child = Command::new(resolved)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(spawn_error)?;
        tracing::info!(command = %program, pid = child.id(), "spawned upstream");

        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            return Err(Error::Upstream("child stdio was not piped".into()));
        };
        Ok(Self {
            reader: Box::new(stdout),
            writer: Box::new(stdin),
            child: Some(child),
        })
    }

    /// Use an existing stream, e.g. an in-memory pipe in tests.
    pub fn from_io(
        reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
    ) -> Self {
        Self {
            reader: Box::new(reader),
            writer: Box::new(writer),
            child: None,
        }
    }

    pub(crate) fn into_parts(self) -> ((BoxRead, BoxWrite), Option<Child>) {
        ((self.reader, self.writer), self.child)
    }
}

/// Wait briefly for the child to exit after its stdin closed, then kill it.
pub(crate) async fn reap(mut child: Child) {
    match tokio::time::timeout(EXIT_GRACE, child.wait()).await {
        Ok(Ok(status)) => tracing::info!(%status, "upstream exited"),
        Ok(Err(e)) => tracing::warn!(error = %e, "failed to wait for upstream"),
        Err(_) => {
            tracing::warn!("upstream did not exit in time; killing it");
            if let Err(e) = child.kill().await {
                tracing::warn!(error = %e, "failed to kill upstream");
            }
        }
    }
}
