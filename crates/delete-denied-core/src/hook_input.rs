use std::fmt;
use std::io::{self, Read};
use std::path::PathBuf;

use serde::Deserialize;

/// Maximum number of bytes accepted from a hook invocation on stdin.
pub const INPUT_MAX: usize = 262_144;

/// Maximum number of UTF-8 bytes accepted for a shell command.
pub const COMMAND_MAX: usize = 65_536;

/// Maximum serialized denial response size.
pub const OUTPUT_MAX: usize = 4_096;

const EXPECTED_EVENT: &str = "PreToolUse";
const EXPECTED_TOOL: &str = "Bash";

/// The subset of a Codex `PreToolUse` hook event used by the guard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookInput {
    pub cwd: PathBuf,
    pub command: String,
    pub permission_mode: Option<String>,
}

impl HookInput {
    /// Read and validate one bounded hook event without following any paths
    /// included in the event (including transcript paths).
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, HookInputError> {
        let mut limited = reader.take((INPUT_MAX + 1) as u64);
        let mut bytes = Vec::with_capacity(INPUT_MAX.min(8 * 1024));
        let read = limited.read_to_end(&mut bytes)?;
        if read > INPUT_MAX {
            return Err(HookInputError::InputTooLarge {
                max: INPUT_MAX,
                actual: read,
            });
        }

        let raw: RawHookInput = serde_json::from_slice(&bytes)?;
        if raw.hook_event_name != EXPECTED_EVENT {
            return Err(HookInputError::UnsupportedEvent {
                event: raw.hook_event_name,
            });
        }
        if raw.tool_name != EXPECTED_TOOL {
            return Err(HookInputError::UnsupportedTool {
                tool: raw.tool_name,
            });
        }

        let command_size = raw.tool_input.command.len();
        if command_size > COMMAND_MAX {
            return Err(HookInputError::CommandTooLarge {
                max: COMMAND_MAX,
                actual: command_size,
            });
        }

        Ok(Self {
            cwd: PathBuf::from(raw.cwd),
            command: raw.tool_input.command,
            permission_mode: raw.permission_mode,
        })
    }
}

#[derive(Debug, Deserialize)]
struct RawHookInput {
    hook_event_name: String,
    tool_name: String,
    cwd: String,
    #[serde(default)]
    permission_mode: Option<String>,
    tool_input: RawToolInput,
}

#[derive(Debug, Deserialize)]
struct RawToolInput {
    command: String,
}

/// Errors raised while reading or validating a hook event.
#[derive(Debug)]
pub enum HookInputError {
    Io(io::Error),
    InputTooLarge { max: usize, actual: usize },
    Json(serde_json::Error),
    UnsupportedEvent { event: String },
    UnsupportedTool { tool: String },
    CommandTooLarge { max: usize, actual: usize },
}

impl fmt::Display for HookInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "failed to read hook input: {error}"),
            Self::InputTooLarge { max, actual } => {
                write!(formatter, "hook input is {actual} bytes; maximum is {max}")
            }
            Self::Json(error) => write!(formatter, "invalid hook JSON: {error}"),
            Self::UnsupportedEvent { event } => {
                write!(formatter, "unsupported hook event: {event}")
            }
            Self::UnsupportedTool { tool } => write!(formatter, "unsupported hook tool: {tool}"),
            Self::CommandTooLarge { max, actual } => {
                write!(formatter, "command is {actual} bytes; maximum is {max}")
            }
        }
    }
}

impl std::error::Error for HookInputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::InputTooLarge { .. }
            | Self::UnsupportedEvent { .. }
            | Self::UnsupportedTool { .. }
            | Self::CommandTooLarge { .. } => None,
        }
    }
}

impl From<io::Error> for HookInputError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for HookInputError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// Structured output emitted when a `PreToolUse` call must be denied.
pub struct HookOutput;

impl HookOutput {
    /// Serialize the official Codex `PreToolUse` denial envelope.
    pub fn deny(code: &str, reason: &str) -> Result<String, OutputError> {
        let permission_decision_reason = format!("[{code}] {reason}");
        let output = serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": EXPECTED_EVENT,
                "permissionDecision": "deny",
                "permissionDecisionReason": permission_decision_reason,
            }
        });
        let serialized = serde_json::to_string(&output)?;
        if serialized.len() > OUTPUT_MAX {
            return Err(OutputError::TooLarge {
                max: OUTPUT_MAX,
                actual: serialized.len(),
            });
        }
        Ok(serialized)
    }

    /// Return the empty stdout payload used for an allow decision.
    pub fn allow_silently() -> String {
        String::new()
    }
}

/// Errors raised while producing a structured denial response.
#[derive(Debug)]
pub enum OutputError {
    Json(serde_json::Error),
    TooLarge { max: usize, actual: usize },
}

impl fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "failed to serialize denial: {error}"),
            Self::TooLarge { max, actual } => {
                write!(
                    formatter,
                    "denial output is {actual} bytes; maximum is {max}"
                )
            }
        }
    }
}

impl std::error::Error for OutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::TooLarge { .. } => None,
        }
    }
}

impl From<serde_json::Error> for OutputError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}
