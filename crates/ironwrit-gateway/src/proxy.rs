// Roots, sampling, logging and resources/subscribe are deprecated by SEP-2577
// but still part of every protocol version the gateway speaks, so we relay them.
#![allow(deprecated)]

use std::borrow::Cow;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use ironwrit_token::{CallPolicy, Decision, ToolCall};
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext};
use rmcp::{
    ClientHandler, ErrorData as McpError, Peer, RoleClient, RoleServer, ServerHandler,
    ServiceError, ServiceExt,
};
use tokio_util::sync::CancellationToken;

use crate::upstream::{BoxRead, BoxWrite};

/// Newest protocol the gateway speaks. Later versions drop `initialize` and
/// server-to-client requests, which the relay depends on.
const MAX_PROTOCOL: ProtocolVersion = ProtocolVersion::LATEST_WITH_INITIALIZE;

/// MCP server facing the agent. Relays everything to the upstream server and
/// checks each `tools/call` against the policy first.
pub(crate) struct Gateway<P> {
    policy: P,
    /// Taken on `initialize`, when the upstream handshake happens.
    upstream_io: Mutex<Option<(BoxRead, BoxWrite)>>,
    upstream: OnceLock<Connected>,
    /// Cancelled when either side goes away, which tears down the other.
    shutdown: CancellationToken,
}

struct Connected {
    peer: Peer<RoleClient>,
    /// What we told the agent in our `initialize` response.
    info: ServerConfig,
}

impl<P: CallPolicy> Gateway<P> {
    pub(crate) fn new(
        policy: P,
        upstream_io: (BoxRead, BoxWrite),
        shutdown: CancellationToken,
    ) -> Self {
        Self {
            policy,
            upstream_io: Mutex::new(Some(upstream_io)),
            upstream: OnceLock::new(),
            shutdown,
        }
    }

    fn upstream(&self) -> Result<&Peer<RoleClient>, McpError> {
        self.upstream
            .get()
            .map(|connected| &connected.peer)
            .ok_or_else(|| McpError::internal_error("upstream not connected", None))
    }
}

impl<P: CallPolicy> ServerHandler for Gateway<P> {
    /// Connect to upstream using the agent's own client info and capabilities,
    /// then answer with the upstream's server info and capabilities.
    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        context.peer.set_peer_info(request.clone());
        let io = self
            .upstream_io
            .lock()
            .ok()
            .and_then(|mut io| io.take())
            .ok_or_else(|| McpError::invalid_request("already initialized", None))?;

        let client = UpstreamClient {
            agent: context.peer.clone(),
            info: upstream_client_config(request),
        };
        let running = client
            .serve_with_ct(io, self.shutdown.child_token())
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "upstream handshake failed");
                McpError::internal_error(format!("upstream failed to initialize: {e}"), None)
            })?;
        let upstream_info = running
            .peer()
            .peer_info()
            .ok_or_else(|| McpError::internal_error("upstream sent no server info", None))?;
        let info = agent_server_config(&upstream_info);
        tracing::info!(
            server = %info.server_info.name,
            protocol = %info.protocol_version,
            "connected to upstream"
        );

        let peer = running.peer().clone();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let reason = running.waiting().await;
            tracing::info!(?reason, "upstream connection closed");
            shutdown.cancel();
        });

        // The mutex above guarantees we get here at most once.
        let _ = self.upstream.set(Connected {
            peer,
            info: info.clone(),
        });
        Ok(info)
    }

    /// Never advertise a version newer than the upstream negotiated, or rmcp
    /// would agree to the agent's newer version on our behalf.
    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        let max = self
            .upstream
            .get()
            .map_or(&MAX_PROTOCOL, |c| &c.info.protocol_version);
        Cow::Borrowed(ProtocolVersion::known_up_to(max))
    }

    /// Report as a legacy server so modern agents fall back to `initialize`.
    async fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, McpError> {
        Err(McpError::method_not_found::<DiscoverRequestMethod>())
    }

    fn get_info(&self) -> ServerConfig {
        self.upstream
            .get()
            .map(|c| c.info.clone())
            .unwrap_or_default()
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let upstream = self.upstream()?;
        let call = ToolCall::new(
            request.name.as_ref(),
            request.arguments.clone().unwrap_or_default(),
        );
        let started = Instant::now();
        tracing::debug!(
            tool = %call.name,
            args = %serde_json::Value::Object(call.arguments.clone()),
            "tool call received"
        );

        if let Decision::Deny { reason } = self.policy.check(&call) {
            tracing::info!(
                tool = %call.name,
                decision = "deny",
                %reason,
                latency_ms = elapsed_ms(started),
                "tool call"
            );
            let denial = ContentBlock::text(format!("denied: {reason}"));
            return Ok(CallToolResult::error(vec![denial]).into());
        }

        let result = upstream.call_tool_once(request).await;
        let outcome = match &result {
            Ok(CallToolResponse::Complete(r)) if r.is_error == Some(true) => "tool_error",
            Ok(_) => "ok",
            Err(_) => "relay_error",
        };
        tracing::info!(
            tool = %call.name,
            decision = "allow",
            outcome,
            latency_ms = elapsed_ms(started),
            "tool call"
        );
        result.map_err(relay_error)
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let mut result = self
            .upstream()?
            .list_tools(request)
            .await
            .map_err(relay_error)?;
        // Hide tools the policy could never allow, so the agent doesn't plan
        // around them. Calls are still checked; this is only a courtesy.
        let before = result.tools.len();
        result
            .tools
            .retain(|tool| self.policy.could_permit(&tool.name));
        tracing::debug!(
            listed = result.tools.len(),
            hidden = before - result.tools.len(),
            "tools/list"
        );
        Ok(result)
    }

    async fn list_prompts(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        self.upstream()?
            .list_prompts(request)
            .await
            .map_err(relay_error)
    }

    async fn get_prompt(
        &self,
        request: GetPromptRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<GetPromptResponse, McpError> {
        self.upstream()?
            .get_prompt_once(request)
            .await
            .map_err(relay_error)
    }

    async fn list_resources(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        self.upstream()?
            .list_resources(request)
            .await
            .map_err(relay_error)
    }

    async fn list_resource_templates(
        &self,
        request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        self.upstream()?
            .list_resource_templates(request)
            .await
            .map_err(relay_error)
    }

    async fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResponse, McpError> {
        self.upstream()?
            .read_resource_once(request)
            .await
            .map_err(relay_error)
    }

    async fn subscribe(
        &self,
        request: SubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.upstream()?
            .subscribe(request)
            .await
            .map_err(relay_error)
    }

    async fn unsubscribe(
        &self,
        request: UnsubscribeRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.upstream()?
            .unsubscribe(request)
            .await
            .map_err(relay_error)
    }

    async fn complete(
        &self,
        request: CompleteRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CompleteResult, McpError> {
        self.upstream()?
            .complete(request)
            .await
            .map_err(relay_error)
    }

    async fn set_level(
        &self,
        request: SetLevelRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        self.upstream()?
            .set_level(request)
            .await
            .map_err(relay_error)
    }

    async fn on_roots_list_changed(&self, _context: NotificationContext<RoleServer>) {
        if let Ok(upstream) = self.upstream() {
            forwarded(upstream.notify_roots_list_changed().await);
        }
    }
}

/// MCP client facing the upstream server. Relays its requests and
/// notifications back to the agent.
struct UpstreamClient {
    agent: Peer<RoleServer>,
    info: ClientConfig,
}

impl ClientHandler for UpstreamClient {
    fn get_info(&self) -> ClientConfig {
        self.info.clone()
    }

    async fn list_roots(
        &self,
        _context: RequestContext<RoleClient>,
    ) -> Result<ListRootsResult, McpError> {
        self.agent.list_roots().await.map_err(relay_error)
    }

    async fn create_message(
        &self,
        params: CreateMessageRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<CreateMessageResult, McpError> {
        self.agent.create_message(params).await.map_err(relay_error)
    }

    async fn create_elicitation(
        &self,
        request: ElicitRequestParams,
        _context: RequestContext<RoleClient>,
    ) -> Result<ElicitResult, McpError> {
        self.agent
            .create_elicitation(request)
            .await
            .map_err(relay_error)
    }

    async fn on_progress(
        &self,
        params: ProgressNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        forwarded(self.agent.notify_progress(params).await);
    }

    async fn on_logging_message(
        &self,
        params: LoggingMessageNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        forwarded(self.agent.notify_logging_message(params).await);
    }

    async fn on_resource_updated(
        &self,
        params: ResourceUpdatedNotificationParam,
        _context: NotificationContext<RoleClient>,
    ) {
        forwarded(self.agent.notify_resource_updated(params).await);
    }

    async fn on_resource_list_changed(&self, _context: NotificationContext<RoleClient>) {
        forwarded(self.agent.notify_resource_list_changed().await);
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        forwarded(self.agent.notify_tool_list_changed().await);
    }

    async fn on_prompt_list_changed(&self, _context: NotificationContext<RoleClient>) {
        forwarded(self.agent.notify_prompt_list_changed().await);
    }
}

/// The agent's `initialize` params, cut down to what the relay supports.
fn upstream_client_config(agent: InitializeRequestParams) -> ClientConfig {
    let mut capabilities = agent.capabilities;
    // Extensions (e.g. tasks) and experimental features use methods we don't relay.
    capabilities.experimental = None;
    capabilities.extensions = None;
    let version = if ProtocolVersion::known_up_to(&MAX_PROTOCOL).contains(&agent.protocol_version) {
        agent.protocol_version
    } else {
        MAX_PROTOCOL
    };
    ClientConfig::new(capabilities, agent.client_info).with_protocol_version(version)
}

/// The upstream's `initialize` result, cut down to what the relay supports.
fn agent_server_config(upstream: &ServerPeerInfo) -> ServerConfig {
    let mut capabilities = upstream.capabilities.clone();
    capabilities.experimental = None;
    capabilities.extensions = None;
    let server_info = upstream
        .server_info
        .clone()
        .unwrap_or_else(|| Implementation::new("ironwrit", env!("CARGO_PKG_VERSION")));
    let mut info = ServerConfig::new(capabilities)
        .with_protocol_version(upstream.protocol_version.clone())
        .with_server_info(server_info);
    info.instructions = upstream.instructions.clone();
    info
}

/// Pass the other side's MCP errors through unchanged; anything else is ours.
fn relay_error(error: ServiceError) -> McpError {
    match error {
        ServiceError::McpError(error) => error,
        other => McpError::internal_error(format!("relay failed: {other}"), None),
    }
}

fn forwarded(result: Result<(), ServiceError>) {
    if let Err(e) = result {
        tracing::debug!(error = %e, "failed to forward notification");
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}
