use std::io::Cursor;
use std::path::Path;

use delete_denied_core::hook_input::{HookInput, HookInputError, HookOutput};

fn valid_hook_json(command: &str) -> String {
    serde_json::json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "cwd": "/Users/example/project",
        "permission_mode": "danger-full-access",
        "tool_input": {
            "command": command
        },
        "transcript_path": "/private/tmp/never-open-this.jsonl"
    })
    .to_string()
}

#[test]
fn parses_official_pre_tool_use_bash_hook_object() {
    let parsed = HookInput::from_reader(Cursor::new(valid_hook_json("rm -rf ./build")))
        .expect("valid hook JSON should parse");

    assert_eq!(parsed.cwd, Path::new("/Users/example/project"));
    assert_eq!(parsed.command, "rm -rf ./build");
    assert_eq!(
        parsed.permission_mode.as_deref(),
        Some("danger-full-access")
    );
}

#[test]
fn rejects_input_stream_over_256_kib() {
    let mut input = valid_hook_json("true").into_bytes();
    input.resize(262_145, b' ');

    let error = HookInput::from_reader(Cursor::new(input)).expect_err("oversized input must fail");
    assert!(matches!(error, HookInputError::InputTooLarge { .. }));
}

#[test]
fn rejects_command_over_64_kib() {
    let command = "x".repeat(65_537);

    let error = HookInput::from_reader(Cursor::new(valid_hook_json(&command)))
        .expect_err("oversized command must fail");
    assert!(matches!(error, HookInputError::CommandTooLarge { .. }));
}

#[test]
fn rejects_malformed_json() {
    let error =
        HookInput::from_reader(Cursor::new("{not-json")).expect_err("malformed JSON must fail");
    assert!(matches!(error, HookInputError::Json(_)));
}

#[test]
fn rejects_wrong_event_name() {
    let input = valid_hook_json("true").replace("PreToolUse", "PostToolUse");

    let error = HookInput::from_reader(Cursor::new(input)).expect_err("wrong event must fail");
    assert!(matches!(error, HookInputError::UnsupportedEvent { .. }));
}

#[test]
fn rejects_wrong_tool_name() {
    let input = valid_hook_json("true").replace("Bash", "Write");

    let error = HookInput::from_reader(Cursor::new(input)).expect_err("wrong tool must fail");
    assert!(matches!(error, HookInputError::UnsupportedTool { .. }));
}

#[test]
fn denial_output_has_official_pre_tool_use_shape() {
    let output = HookOutput::deny("DD-TEST", "protected path").expect("denial should serialize");
    let value: serde_json::Value = serde_json::from_str(&output).expect("valid JSON");

    assert_eq!(
        value,
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "[DD-TEST] protected path"
            }
        })
    );
    assert!(HookOutput::allow_silently().is_empty());
}
