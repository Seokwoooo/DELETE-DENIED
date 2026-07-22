use delete_denied_cli::hooks::{
    HookRegistration, contains_user_hook, hook_identity, merge_user_hooks, remove_user_hook,
};
use serde_json::Value;
use std::path::Path;

fn registration() -> HookRegistration {
    HookRegistration::new(
        "/Users/alice/.codex/delete-denied/bin/delete-denied-hook --policy /Users/alice/.codex/delete-denied/policy.json",
    )
}

#[test]
fn user_hook_merge_is_additive_and_idempotent() {
    let original = r#"{
  "description": "keep me",
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          { "type": "command", "command": "echo existing" }
        ]
      }
    ]
  },
  "custom": { "enabled": true }
}"#;

    let first = merge_user_hooks(Some(original), &registration()).unwrap();
    let second = merge_user_hooks(Some(&first), &registration()).unwrap();

    assert_eq!(
        serde_json::from_str::<Value>(&first).unwrap(),
        serde_json::from_str::<Value>(&second).unwrap()
    );
    assert!(contains_user_hook(&first, &registration()).unwrap());
    let value: Value = serde_json::from_str(&first).unwrap();
    assert_eq!(value["description"], "keep me");
    assert_eq!(value["custom"]["enabled"], true);
    assert_eq!(
        value["hooks"]["SessionStart"][0]["hooks"][0]["command"],
        "echo existing"
    );
}

#[test]
fn removal_deletes_only_delete_denied_handler() {
    let original = r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^Bash$",
        "hooks": [
          { "type": "command", "command": "echo existing" }
        ]
      }
    ]
  }
}"#;
    let merged = merge_user_hooks(Some(original), &registration()).unwrap();
    let removed = remove_user_hook(&merged, &registration()).unwrap();
    let value: Value = serde_json::from_str(&removed).unwrap();

    assert!(!contains_user_hook(&removed, &registration()).unwrap());
    assert_eq!(
        value["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "echo existing"
    );
}

#[test]
fn malformed_or_invalid_user_config_is_rejected() {
    assert!(merge_user_hooks(Some("{"), &registration()).is_err());
    assert!(merge_user_hooks(Some(r#"{"hooks": []}"#), &registration()).is_err());
}

#[test]
fn removal_is_not_blocked_by_optional_field_edits() {
    let merged = merge_user_hooks(None, &registration()).unwrap();
    let mut value: Value = serde_json::from_str(&merged).unwrap();
    value["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"] = 30.into();
    value["hooks"]["PreToolUse"][0]["hooks"][0]["statusMessage"] = "changed".into();
    let edited = serde_json::to_string_pretty(&value).unwrap();

    let removed = remove_user_hook(&edited, &registration()).unwrap();
    assert!(!contains_user_hook(&removed, &registration()).unwrap());
}

#[test]
fn ineffective_owned_handlers_are_not_registered_or_identified() {
    let cases = [
        r#"{"matcher":"^Write$","hooks":[{"type":"command","command":"COMMAND"}]}"#,
        r#"{"matcher":"^Bash$","hooks":[{"type":"command","command":"COMMAND","async":true}]}"#,
        r#"{"matcher":"^Bash$","hooks":[{"type":"command","command":"COMMAND","timeout":0}]}"#,
        r#"{"matcher":"^Bash$","hooks":[{"type":"command","command":"COMMAND","timeout":-1}]}"#,
        r#"{"matcher":"^Bash$","hooks":[{"type":"command","command":"COMMAND","timeout":1.5}]}"#,
        r#"{"matcher":"^Bash$","hooks":[{"type":"script","command":"COMMAND"}]}"#,
    ];
    for case in cases {
        let hooks = format!(
            r#"{{"hooks":{{"PreToolUse":[{}]}}}}"#,
            case.replace("COMMAND", &registration().command)
        );
        assert!(
            !contains_user_hook(&hooks, &registration()).unwrap(),
            "{case}"
        );
        assert!(
            hook_identity(
                &hooks,
                Path::new("/Users/alice/.codex/hooks.json"),
                &registration()
            )
            .unwrap()
            .is_none(),
            "{case}"
        );
    }
}

#[test]
fn merge_repairs_ineffective_owned_handler_without_duplicate_or_losing_unrelated_hooks() {
    let original = format!(
        r#"{{
  "description": "keep me",
  "hooks": {{
    "PreToolUse": [
      {{
        "matcher": "^Write$",
        "label": "keep group settings",
        "hooks": [
          {{ "type": "command", "command": {:?}, "async": true }},
          {{ "type": "command", "command": "echo keep" }}
        ]
      }}
    ]
  }}
}}"#,
        registration().command
    );

    let merged = merge_user_hooks(Some(&original), &registration()).unwrap();
    let value: Value = serde_json::from_str(&merged).unwrap();
    let groups = value["hooks"]["PreToolUse"].as_array().unwrap();
    let owned = groups
        .iter()
        .flat_map(|group| group["hooks"].as_array().into_iter().flatten())
        .filter(|handler| handler["command"] == registration().command)
        .collect::<Vec<_>>();
    assert_eq!(owned.len(), 1);
    assert_eq!(owned[0]["type"], "command");
    assert_eq!(owned[0]["timeout"], 5);
    assert_eq!(
        owned[0]["statusMessage"],
        "DELETE-DENIED: checking shell deletion target"
    );
    assert!(contains_user_hook(&merged, &registration()).unwrap());
    assert_eq!(value["description"], "keep me");
    assert_eq!(
        value["hooks"]["PreToolUse"][0]["label"],
        "keep group settings"
    );
    assert_eq!(
        value["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "echo keep"
    );
}

#[test]
fn removal_removes_owned_handler_even_when_matcher_and_async_are_edited() {
    let current = format!(
        r#"{{"hooks":{{"PreToolUse":[{{"matcher":"^Write$","hooks":[{{"type":"command","command":{:?},"async":true,"timeout":0,"statusMessage":null}},{{"type":"command","command":"echo keep"}}]}}]}}}}"#,
        registration().command
    );
    let removed = remove_user_hook(&current, &registration()).unwrap();
    let value: Value = serde_json::from_str(&removed).unwrap();
    assert!(!contains_user_hook(&removed, &registration()).unwrap());
    assert_eq!(
        value["hooks"]["PreToolUse"][0]["hooks"][0]["command"],
        "echo keep"
    );
}
