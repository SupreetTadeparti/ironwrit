//! Round-trip tests: a mock agent talks to a mock upstream through the gateway,
//! all over in-memory pipes.

// Roots are deprecated by SEP-2577 but still relayed by the gateway.
#![allow(deprecated)]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ironwrit_gateway::Upstream;
use ironwrit_token::{AllowAll, CallPolicy, Decision, ToolCall};
use rmcp::model::*;
use rmcp::service::{NotificationContext, RequestContext, RunningService};
use rmcp::{
    ClientHandler, ErrorData as McpError, RoleClient, RoleServer, ServerHandler, ServiceExt,
};
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const PIPE_SIZE: usize = 64 * 1024;
const TIMEOUT: Duration = Duration::from_secs(10);

/// Upstream MCP server with a few tools that exercise the relay.
#[derive(Clone, Default)]
struct MockUpstream {
    calls: Arc<AtomicUsize>,
}

impl ServerHandler for MockUpstream {
    fn get_info(&self) -> ServerConfig {
        let capabilities = ServerCapabilities::builder()
            .enable_tools()
            .enable_tool_list_changed()
            .build();
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new("mock-upstream", "1.2.3"))
            .with_instructions("mock instructions")
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let schema = json!({"type": "object"});
        let schema = schema.as_object().cloned().unwrap_or_default();
        let tools = ["echo", "fail", "roots", "touch"]
            .map(|name| Tool::new(name, format!("mock {name}"), schema.clone()));
        Ok(ListToolsResult::with_all_items(tools.into()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let text = |s: String| vec![ContentBlock::text(s)];
        let result = match request.name.as_ref() {
            "echo" => {
                let args = Value::Object(request.arguments.unwrap_or_default());
                CallToolResult::success(text(args.to_string()))
            }
            "fail" => CallToolResult::error(text("it broke".into())),
            // Asks the agent for its roots, through the gateway.
            "roots" => {
                let roots = context
                    .peer
                    .list_roots()
                    .await
                    .map_err(|e| McpError::internal_error(e.to_string(), None))?;
                let uris: Vec<_> = roots.roots.into_iter().map(|r| r.uri).collect();
                CallToolResult::success(text(uris.join(",")))
            }
            "touch" => {
                let _ = context.peer.notify_tool_list_changed().await;
                CallToolResult::success(text("touched".into()))
            }
            other => {
                return Err(McpError::invalid_params(format!("no tool {other}"), None));
            }
        };
        Ok(result.into())
    }
}

/// Agent-side MCP client that exposes a root and records notifications.
struct MockAgent {
    protocol_version: ProtocolVersion,
    notifications: mpsc::UnboundedSender<&'static str>,
}

impl ClientHandler for MockAgent {
    fn get_info(&self) -> ClientConfig {
        let capabilities = ClientCapabilities::builder().enable_roots().build();
        ClientConfig::new(capabilities, Implementation::new("mock-agent", "0.0.1"))
            .with_protocol_version(self.protocol_version.clone())
    }

    async fn list_roots(
        &self,
        _context: RequestContext<RoleClient>,
    ) -> Result<ListRootsResult, McpError> {
        Ok(ListRootsResult::new(vec![Root::new("file:///docs")]))
    }

    async fn on_tool_list_changed(&self, _context: NotificationContext<RoleClient>) {
        let _ = self.notifications.send("tools/list_changed");
    }
}

/// Denies one tool by name.
struct DenyTool(&'static str);

impl CallPolicy for DenyTool {
    fn check(&self, call: &ToolCall) -> Decision {
        if call.name == self.0 {
            Decision::deny(format!("{} is not allowed", self.0))
        } else {
            Decision::Allow
        }
    }
}

struct Harness {
    agent: RunningService<RoleClient, MockAgent>,
    gateway: JoinHandle<ironwrit_gateway::Result<()>>,
    upstream_calls: Arc<AtomicUsize>,
    notifications: mpsc::UnboundedReceiver<&'static str>,
}

async fn start(policy: impl CallPolicy, protocol_version: ProtocolVersion) -> Harness {
    let upstream = MockUpstream::default();
    let upstream_calls = upstream.calls.clone();

    let (gateway_up, upstream_side) = tokio::io::duplex(PIPE_SIZE);
    tokio::spawn(async move {
        if let Ok(server) = upstream.serve(upstream_side).await {
            let _ = server.waiting().await;
        }
    });

    let (agent_side, gateway_down) = tokio::io::duplex(PIPE_SIZE);
    let (up_read, up_write) = tokio::io::split(gateway_up);
    let gateway = tokio::spawn(ironwrit_gateway::serve(
        policy,
        Upstream::from_io(up_read, up_write),
        tokio::io::split(gateway_down),
    ));

    let (tx, notifications) = mpsc::unbounded_channel();
    let agent = MockAgent {
        protocol_version,
        notifications: tx,
    };
    let agent = tokio::time::timeout(TIMEOUT, agent.serve(agent_side))
        .await
        .expect("handshake timed out")
        .expect("agent failed to initialize");

    Harness {
        agent,
        gateway,
        upstream_calls,
        notifications,
    }
}

async fn call(
    agent: &RunningService<RoleClient, MockAgent>,
    name: &str,
    args: Value,
) -> CallToolResult {
    let params = CallToolRequestParams::new(name.to_owned())
        .with_arguments(args.as_object().cloned().unwrap_or_default());
    tokio::time::timeout(TIMEOUT, agent.call_tool(params))
        .await
        .expect("call timed out")
        .expect("call failed")
}

fn text(result: &CallToolResult) -> &str {
    result
        .content
        .first()
        .and_then(|c| c.as_text())
        .map(|t| t.text.as_str())
        .unwrap_or_default()
}

#[tokio::test]
async fn initialize_relays_upstream_identity_and_capabilities() {
    let h = start(AllowAll, ProtocolVersion::LATEST_WITH_INITIALIZE).await;
    let info = h.agent.peer_info().expect("no server info");

    let server = info.server_info.as_ref().expect("no server identity");
    assert_eq!(server.name, "mock-upstream");
    assert_eq!(server.version, "1.2.3");
    assert_eq!(info.instructions.as_deref(), Some("mock instructions"));
    assert!(info.capabilities.tools.is_some());
    assert_eq!(
        info.protocol_version,
        ProtocolVersion::LATEST_WITH_INITIALIZE
    );
}

#[tokio::test]
async fn older_agent_protocol_is_passed_upstream() {
    let h = start(AllowAll, ProtocolVersion::V_2025_03_26).await;
    let info = h.agent.peer_info().expect("no server info");
    assert_eq!(info.protocol_version, ProtocolVersion::V_2025_03_26);
}

#[tokio::test]
async fn agent_newer_than_gateway_is_negotiated_down() {
    let h = start(AllowAll, ProtocolVersion::V_2026_07_28).await;
    let info = h.agent.peer_info().expect("no server info");
    assert_eq!(
        info.protocol_version,
        ProtocolVersion::LATEST_WITH_INITIALIZE
    );
}

#[tokio::test]
async fn tools_list_round_trips() {
    let h = start(AllowAll, ProtocolVersion::LATEST_WITH_INITIALIZE).await;
    let tools = h.agent.list_all_tools().await.expect("list failed");
    let names: Vec<_> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert_eq!(names, ["echo", "fail", "roots", "touch"]);
}

#[tokio::test]
async fn tool_call_round_trips() {
    let h = start(AllowAll, ProtocolVersion::LATEST_WITH_INITIALIZE).await;
    let result = call(&h.agent, "echo", json!({"message": "hi"})).await;
    assert_ne!(result.is_error, Some(true));
    assert_eq!(text(&result), r#"{"message":"hi"}"#);
}

#[tokio::test]
async fn tool_errors_pass_through() {
    let h = start(AllowAll, ProtocolVersion::LATEST_WITH_INITIALIZE).await;
    let result = call(&h.agent, "fail", json!({})).await;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(text(&result), "it broke");
}

#[tokio::test]
async fn protocol_errors_pass_through() {
    let h = start(AllowAll, ProtocolVersion::LATEST_WITH_INITIALIZE).await;
    let params = CallToolRequestParams::new("nope");
    let err = h.agent.call_tool(params).await.expect_err("should fail");
    let rmcp::ServiceError::McpError(err) = err else {
        panic!("expected an MCP error, got {err}");
    };
    assert_eq!(err.code, ErrorCode::INVALID_PARAMS);
    assert_eq!(err.message, "no tool nope");
}

#[tokio::test]
async fn denied_calls_never_reach_upstream() {
    let h = start(DenyTool("echo"), ProtocolVersion::LATEST_WITH_INITIALIZE).await;

    let denied = call(&h.agent, "echo", json!({"message": "hi"})).await;
    assert_eq!(denied.is_error, Some(true));
    assert_eq!(text(&denied), "denied: echo is not allowed");
    assert_eq!(h.upstream_calls.load(Ordering::SeqCst), 0);

    let allowed = call(&h.agent, "fail", json!({})).await;
    assert_eq!(text(&allowed), "it broke");
    assert_eq!(h.upstream_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn upstream_requests_reach_the_agent() {
    let h = start(AllowAll, ProtocolVersion::LATEST_WITH_INITIALIZE).await;
    let result = call(&h.agent, "roots", json!({})).await;
    assert_eq!(text(&result), "file:///docs");
}

#[tokio::test]
async fn upstream_notifications_reach_the_agent() {
    let mut h = start(AllowAll, ProtocolVersion::LATEST_WITH_INITIALIZE).await;
    call(&h.agent, "touch", json!({})).await;
    let got = tokio::time::timeout(TIMEOUT, h.notifications.recv())
        .await
        .expect("no notification");
    assert_eq!(got, Some("tools/list_changed"));
}

#[tokio::test]
async fn gateway_exits_when_agent_disconnects() {
    let h = start(AllowAll, ProtocolVersion::LATEST_WITH_INITIALIZE).await;
    h.agent.cancel().await.expect("cancel failed");
    let result = tokio::time::timeout(TIMEOUT, h.gateway)
        .await
        .expect("gateway did not exit")
        .expect("gateway panicked");
    assert!(result.is_ok(), "gateway failed: {result:?}");
}
