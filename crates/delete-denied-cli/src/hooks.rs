use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::fmt;
use std::path::Path;

pub const MATCHER: &str = "^Bash$";
pub const STATUS_MESSAGE: &str = "DELETE-DENIED: checking shell deletion target";
pub const TIMEOUT_SECONDS: u64 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookRegistration {
    pub command: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookIdentity {
    pub key: String,
    pub hash: String,
}

/// Normalize path text returned by the Codex app-server for hook identity.
/// Windows accepts both slash spellings, but app-server emits backslashes.
pub fn normalize_hook_path(path: &Path) -> String {
    normalize_hook_path_text(&path.to_string_lossy())
}

pub fn normalize_hook_path_text(value: &str) -> String {
    if is_windows_path_text(value) {
        value.replace('/', "\\")
    } else {
        value.to_owned()
    }
}

pub fn hook_path_text_equal(left: &str, right: &str) -> bool {
    if is_windows_path_text(left) || is_windows_path_text(right) {
        normalize_hook_path_text(left).eq_ignore_ascii_case(&normalize_hook_path_text(right))
    } else {
        left == right
    }
}

pub fn hook_identity_key_equal(left: &str, right: &str) -> bool {
    hook_path_text_equal(left, right)
}

fn is_windows_path_text(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic())
        || value.starts_with('\\')
        || value.starts_with("//")
}

impl HookRegistration {
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
        }
    }
}

#[derive(Debug)]
pub enum HookConfigError {
    Malformed(serde_json::Error),
    InvalidShape(&'static str),
}

impl fmt::Display for HookConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed hooks.json: {error}"),
            Self::InvalidShape(field) => write!(f, "invalid hooks.json field shape: {field}"),
        }
    }
}

impl std::error::Error for HookConfigError {}

pub fn merge_user_hooks(
    original: Option<&str>,
    registration: &HookRegistration,
) -> Result<String, HookConfigError> {
    let mut document = parse_document(original)?;
    let hooks = hooks_object_mut(&mut document)?;
    let pre_tool_use =
        event_array_mut(hooks, true)?.ok_or(HookConfigError::InvalidShape("hooks.PreToolUse"))?;
    let mut effective_found = false;
    for group in pre_tool_use.iter_mut() {
        let group_object = group
            .as_object_mut()
            .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse[]"))?;
        let matcher = group_object
            .get("matcher")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let Some(handlers) = group_object.get_mut("hooks") else {
            continue;
        };
        let handlers = handlers
            .as_array_mut()
            .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse[].hooks"))?;
        handlers.retain(|handler| {
            if !owned_handler_matches(handler, registration) {
                return true;
            }
            if !effective_found && effective_handler_matches(&matcher, handler, registration) {
                effective_found = true;
                true
            } else {
                false
            }
        });
    }

    if !effective_found {
        let mut appended = false;
        for group in pre_tool_use.iter_mut() {
            let group_object = group
                .as_object_mut()
                .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse[]"))?;
            if group_object.get("matcher").and_then(Value::as_str) != Some(MATCHER) {
                continue;
            }
            let Some(handlers) = group_object.get_mut("hooks") else {
                continue;
            };
            let handlers = handlers
                .as_array_mut()
                .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse[].hooks"))?;
            handlers.push(canonical_registration_handler(registration));
            appended = true;
            break;
        }
        if !appended {
            pre_tool_use.push(json!({
                "matcher": MATCHER,
                "hooks": [canonical_registration_handler(registration)]
            }));
        }
    }
    render(document)
}

pub fn remove_user_hook(
    current: &str,
    registration: &HookRegistration,
) -> Result<String, HookConfigError> {
    let mut document = parse_document(Some(current))?;
    let hooks = hooks_object_mut(&mut document)?;
    let Some(pre_tool_use) = event_array_mut(hooks, false)? else {
        return render(document);
    };

    for group in pre_tool_use.iter_mut() {
        let Some(group_object) = group.as_object_mut() else {
            return Err(HookConfigError::InvalidShape("hooks.PreToolUse[]"));
        };
        let Some(handlers) = group_object.get_mut("hooks") else {
            continue;
        };
        let Some(handlers) = handlers.as_array_mut() else {
            return Err(HookConfigError::InvalidShape("hooks.PreToolUse[].hooks"));
        };
        handlers.retain(|handler| !owned_handler_matches(handler, registration));
    }
    pre_tool_use.retain(|group| {
        let Some(object) = group.as_object() else {
            return true;
        };
        let empty = object
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty);
        let only_standard_keys = object
            .keys()
            .all(|key| matches!(key.as_str(), "matcher" | "hooks"));
        !(empty && only_standard_keys)
    });
    render(document)
}

pub fn contains_user_hook(
    current: &str,
    registration: &HookRegistration,
) -> Result<bool, HookConfigError> {
    let document = parse_document(Some(current))?;
    contains_in_value(&document, registration)
}

pub fn hook_identity(
    current: &str,
    hooks_path: &Path,
    registration: &HookRegistration,
) -> Result<Option<HookIdentity>, HookConfigError> {
    let document = parse_document(Some(current))?;
    let root = document
        .as_object()
        .ok_or(HookConfigError::InvalidShape("root"))?;
    let Some(hooks) = root.get("hooks") else {
        return Ok(None);
    };
    let hooks = hooks
        .as_object()
        .ok_or(HookConfigError::InvalidShape("hooks"))?;
    let Some(groups) = hooks.get("PreToolUse") else {
        return Ok(None);
    };
    let groups = groups
        .as_array()
        .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse"))?;
    for (group_index, group) in groups.iter().enumerate() {
        let group = group
            .as_object()
            .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse[]"))?;
        let matcher = group.get("matcher").and_then(Value::as_str).unwrap_or("");
        let Some(handlers) = group.get("hooks") else {
            continue;
        };
        let handlers = handlers
            .as_array()
            .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse[].hooks"))?;
        for (handler_index, handler) in handlers.iter().enumerate() {
            if !effective_handler_matches(matcher, handler, registration) {
                continue;
            }
            let canonical = canonical_hook(matcher, handler, registration);
            let encoded = serde_json::to_vec(&canonical).map_err(HookConfigError::Malformed)?;
            let digest = Sha256::digest(encoded);
            let hash = format!(
                "sha256:{}",
                digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            );
            return Ok(Some(HookIdentity {
                key: format!(
                    "{}:pre_tool_use:{group_index}:{handler_index}",
                    normalize_hook_path(hooks_path)
                ),
                hash,
            }));
        }
    }
    Ok(None)
}

fn canonical_hook(matcher: &str, handler: &Value, registration: &HookRegistration) -> Value {
    let timeout = handler
        .get("timeout")
        .and_then(Value::as_u64)
        .unwrap_or(600)
        .max(1);
    let mut normalized_handler = Map::new();
    normalized_handler.insert("type".into(), Value::String("command".into()));
    normalized_handler.insert(
        "command".into(),
        Value::String(registration.command.clone()),
    );
    normalized_handler.insert("timeout".into(), Value::Number(timeout.into()));
    normalized_handler.insert(
        "async".into(),
        Value::Bool(
            handler
                .get("async")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        ),
    );
    if let Some(status_message) = handler.get("statusMessage") {
        if !status_message.is_null() {
            normalized_handler.insert("statusMessage".into(), status_message.clone());
        }
    }
    if let Some(additional_context_limit) = handler
        .get("additionalContextLimit")
        .and_then(Value::as_u64)
        .filter(|value| *value != 2500)
    {
        normalized_handler.insert(
            "additionalContextLimit".into(),
            Value::Number(additional_context_limit.into()),
        );
    }
    let mut normalized = Map::new();
    normalized.insert("event_name".into(), Value::String("pre_tool_use".into()));
    normalized.insert("matcher".into(), Value::String(matcher.into()));
    normalized.insert(
        "hooks".into(),
        Value::Array(vec![Value::Object(normalized_handler)]),
    );
    canonicalize(&Value::Object(normalized))
}

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort();
            let mut sorted = Map::new();
            for key in keys {
                sorted.insert(key.clone(), canonicalize(&object[key]));
            }
            Value::Object(sorted)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonicalize).collect()),
        other => other.clone(),
    }
}

fn parse_document(original: Option<&str>) -> Result<Value, HookConfigError> {
    let document = match original {
        Some(text) if !text.trim().is_empty() => {
            serde_json::from_str(text).map_err(HookConfigError::Malformed)?
        }
        _ => Value::Object(Map::new()),
    };
    if document.is_object() {
        Ok(document)
    } else {
        Err(HookConfigError::InvalidShape("root"))
    }
}

fn hooks_object_mut(document: &mut Value) -> Result<&mut Map<String, Value>, HookConfigError> {
    let root = document
        .as_object_mut()
        .ok_or(HookConfigError::InvalidShape("root"))?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()));
    hooks
        .as_object_mut()
        .ok_or(HookConfigError::InvalidShape("hooks"))
}

fn event_array_mut(
    hooks: &mut Map<String, Value>,
    create: bool,
) -> Result<Option<&mut Vec<Value>>, HookConfigError> {
    if !hooks.contains_key("PreToolUse") {
        if !create {
            return Ok(None);
        }
        hooks.insert("PreToolUse".into(), Value::Array(Vec::new()));
    }
    hooks
        .get_mut("PreToolUse")
        .and_then(Value::as_array_mut)
        .map(Some)
        .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse"))
}

fn contains_in_value(
    document: &Value,
    registration: &HookRegistration,
) -> Result<bool, HookConfigError> {
    let root = document
        .as_object()
        .ok_or(HookConfigError::InvalidShape("root"))?;
    let Some(hooks) = root.get("hooks") else {
        return Ok(false);
    };
    let hooks = hooks
        .as_object()
        .ok_or(HookConfigError::InvalidShape("hooks"))?;
    let Some(groups) = hooks.get("PreToolUse") else {
        return Ok(false);
    };
    let groups = groups
        .as_array()
        .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse"))?;
    for group in groups {
        let group = group
            .as_object()
            .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse[]"))?;
        let Some(handlers) = group.get("hooks") else {
            continue;
        };
        let handlers = handlers
            .as_array()
            .ok_or(HookConfigError::InvalidShape("hooks.PreToolUse[].hooks"))?;
        let matcher = group.get("matcher").and_then(Value::as_str).unwrap_or("");
        if handlers
            .iter()
            .any(|handler| effective_handler_matches(matcher, handler, registration))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn owned_handler_matches(handler: &Value, registration: &HookRegistration) -> bool {
    handler.get("type").and_then(Value::as_str) == Some("command")
        && handler.get("command").and_then(Value::as_str) == Some(registration.command.as_str())
}

fn effective_handler_matches(
    matcher: &str,
    handler: &Value,
    registration: &HookRegistration,
) -> bool {
    matcher == MATCHER
        && owned_handler_matches(handler, registration)
        && handler
            .get("async")
            .is_none_or(|value| value.as_bool() == Some(false))
        && handler
            .get("timeout")
            .is_none_or(|value| value.as_u64().is_some_and(|timeout| timeout > 0))
}

fn canonical_registration_handler(registration: &HookRegistration) -> Value {
    json!({
        "type": "command",
        "command": registration.command,
        "timeout": TIMEOUT_SECONDS,
        "statusMessage": STATUS_MESSAGE
    })
}

fn render(document: Value) -> Result<String, HookConfigError> {
    let mut rendered =
        serde_json::to_string_pretty(&document).map_err(HookConfigError::Malformed)?;
    rendered.push('\n');
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::{hook_identity_key_equal, hook_path_text_equal, normalize_hook_path_text};

    #[test]
    fn windows_identity_paths_normalize_slashes_and_case() {
        assert_eq!(
            normalize_hook_path_text(r"C:/Users/Alice/.codex/hooks.json"),
            r"C:\Users\Alice\.codex\hooks.json"
        );
        assert!(hook_identity_key_equal(
            r"C:/Users/Alice/.codex/hooks.json:pre_tool_use:0:0",
            r"c:\users\alice\.codex\hooks.json:pre_tool_use:0:0"
        ));
    }

    #[test]
    fn macos_identity_paths_remain_exact() {
        assert!(hook_path_text_equal(
            "/Users/alice/.codex/hooks.json",
            "/Users/alice/.codex/hooks.json"
        ));
        assert!(!hook_path_text_equal(
            "/Users/alice/.codex/hooks.json",
            "/users/alice/.codex/hooks.json"
        ));
    }
}
