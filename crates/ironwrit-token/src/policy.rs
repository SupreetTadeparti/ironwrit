use serde_json::{Map, Value};

/// A `tools/call` request as the gateway sees it, before it reaches upstream.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub name: String,
    pub arguments: Map<String, Value>,
}

impl ToolCall {
    pub fn new(name: impl Into<String>, arguments: Map<String, Value>) -> Self {
        Self {
            name: name.into(),
            arguments,
        }
    }
}

/// The outcome of checking a [`ToolCall`] against a policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

impl Decision {
    pub fn deny(reason: impl Into<String>) -> Self {
        Self::Deny {
            reason: reason.into(),
        }
    }

    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }
}

/// Decides whether a tool call may be forwarded upstream.
///
/// Implementations must fail closed: if a call can't be evaluated, deny it.
pub trait CallPolicy: Send + Sync + 'static {
    fn check(&self, call: &ToolCall) -> Decision;

    /// Whether some call to `tool` might be allowed. Tools for which this is
    /// false are hidden from `tools/list`.
    fn could_permit(&self, _tool: &str) -> bool {
        true
    }
}

/// Allows every call. Used for pass-through mode until tokens are enforced.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl CallPolicy for AllowAll {
    fn check(&self, _call: &ToolCall) -> Decision {
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_allows() {
        let call = ToolCall::new("read_file", Map::new());
        assert!(AllowAll.check(&call).is_allowed());
    }

    #[test]
    fn deny_is_not_allowed() {
        assert!(!Decision::deny("nope").is_allowed());
    }
}
