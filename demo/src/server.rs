//! Mock tool server. Deliberately naive: it does whatever it's asked, like a
//! filesystem server configured with too broad a root.

use std::io::Write;
use std::path::Path;

use rmcp::model::*;
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler, ServiceExt};
use serde_json::{Map, Value, json};

const OUTBOX: &str = "out/outbox.jsonl";

pub async fn serve() -> anyhow::Result<()> {
    let server = DemoTools.serve(rmcp::transport::stdio()).await?;
    server.waiting().await?;
    Ok(())
}

struct DemoTools;

impl ServerHandler for DemoTools {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build()).with_server_info(
            Implementation::new("ironwrit-demo-tools", env!("CARGO_PKG_VERSION")),
        )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools = vec![
            tool(
                "read_file",
                "Read a text file.",
                json!({"path": {"type": "string"}}),
                &["path"],
            ),
            tool(
                "list_directory",
                "List the entries of a directory.",
                json!({"path": {"type": "string"}}),
                &["path"],
            ),
            tool(
                "fetch",
                "Fetch a web page.",
                json!({"url": {"type": "string"}}),
                &["url"],
            ),
            tool(
                "send_email",
                "Send an email.",
                json!({
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"}
                }),
                &["to", "body"],
            ),
        ];
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let args = request.arguments.unwrap_or_default();
        let result = match request.name.as_ref() {
            "read_file" => std::fs::read_to_string(arg(&args, "path")?).map_err(|e| e.to_string()),
            "list_directory" => list_directory(arg(&args, "path")?),
            "fetch" => fetch(arg(&args, "url")?),
            "send_email" => send_email(&args),
            other => {
                return Err(McpError::invalid_params(
                    format!("unknown tool {other}"),
                    None,
                ));
            }
        };
        Ok(match result {
            Ok(text) => CallToolResult::success(vec![ContentBlock::text(text)]),
            Err(error) => CallToolResult::error(vec![ContentBlock::text(error)]),
        }
        .into())
    }
}

fn tool(
    name: &'static str,
    description: &'static str,
    properties: Value,
    required: &[&str],
) -> Tool {
    let schema = json!({"type": "object", "properties": properties, "required": required});
    Tool::new(
        name,
        description,
        schema.as_object().cloned().unwrap_or_default(),
    )
}

fn arg<'a>(args: &'a Map<String, Value>, name: &str) -> Result<&'a str, McpError> {
    args.get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| McpError::invalid_params(format!("missing string argument `{name}`"), None))
}

fn list_directory(path: &str) -> Result<String, String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .map_err(|e| e.to_string())?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    Ok(names.join("\n"))
}

/// Pages come from `web/<host>.html`; nothing touches the network.
fn fetch(url: &str) -> Result<String, String> {
    let host = url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', ':', '?', '#']).next())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if host.is_empty() || host.contains('\\') || host.starts_with('.') {
        return Err(format!("bad host in {url}"));
    }
    std::fs::read_to_string(Path::new("web").join(format!("{host}.html")))
        .map_err(|_| format!("404: nothing at {url}"))
}

/// "Sends" mail by appending it to the outbox, so the demo can show what leaked.
fn send_email(args: &Map<String, Value>) -> Result<String, String> {
    let to = args
        .get("to")
        .and_then(Value::as_str)
        .ok_or("missing `to`")?;
    let mail = json!({
        "to": to,
        "subject": args.get("subject").cloned().unwrap_or(Value::Null),
        "body": args.get("body").cloned().unwrap_or(Value::Null),
    });
    std::fs::create_dir_all("out").map_err(|e| e.to_string())?;
    let mut outbox = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(OUTBOX)
        .map_err(|e| e.to_string())?;
    writeln!(outbox, "{mail}").map_err(|e| e.to_string())?;
    Ok(format!("sent to {to}"))
}
