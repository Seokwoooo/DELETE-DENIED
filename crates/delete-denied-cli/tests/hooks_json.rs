use delete_denied_cli::hooks::{
    HookRegistration, contains_user_hook, merge_user_hooks, remove_user_hook,
};
use serde_json::Value;

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
