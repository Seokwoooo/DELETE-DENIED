use delete_denied_cli::app_server::{
    AppServerError, RpcTransport, TrustRequest, trust_hook_with_transport,
};
use delete_denied_cli::hooks::HookIdentity;
use serde_json::{Value, json};
use std::path::Path;

struct FakeTransport {
    responses: Vec<Result<Value, String>>,
    calls: Vec<(String, Value)>,
    notifications: Vec<(String, Value)>,
}

impl RpcTransport for FakeTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.calls.push((method.to_owned(), params));
        self.responses.remove(0).map_err(|error| error.to_owned())
    }

    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), String> {
        self.notifications
            .push((method.to_owned(), params.unwrap_or(Value::Null)));
        Ok(())
    }
}

fn hook(identity: &HookIdentity, trusted: bool) -> Value {
    json!({
        "source": "user",
        "sourcePath": "/Users/alice/.codex/hooks.json",
        "eventName": "preToolUse",
        "handlerType": "command",
        "command": "\"/Users/alice/.codex/delete-denied/bin/delete-denied-hook\" --policy \"/Users/alice/.codex/delete-denied/policy.json\"",
        "matcher": "^Bash$",
        "statusMessage": "DELETE-DENIED: checking shell deletion target",
        "key": identity.key,
        "currentHash": identity.hash,
        "enabled": true,
        "trustStatus": if trusted { "trusted" } else { "untrusted" }
    })
}

fn hooks_response(hook: Value) -> Value {
    json!({
        "data": [{
            "cwd": "/Users/alice",
            "hooks": [hook]
        }]
    })
}

#[test]
fn exact_hook_is_trusted_and_unrelated_state_is_preserved() {
    let identity = HookIdentity {
        key: "/Users/alice/.codex/hooks.json:pre_tool_use:0:0".into(),
        hash: "sha256:known".into(),
    };
    let mut transport = FakeTransport {
        responses: vec![
            Ok(json!({})),
            Ok(hooks_response(hook(&identity, false))),
            Ok(json!({
                "filePath": "/Users/alice/.codex/config.toml",
                "status": "ok",
                "version": 2
            })),
            Ok(hooks_response(hook(&identity, true))),
        ],
        calls: Vec::new(),
        notifications: Vec::new(),
    };
    let request = TrustRequest {
        cwd: Path::new("/Users/alice"),
        hooks_path: Path::new("/Users/alice/.codex/hooks.json"),
        config_path: Path::new("/Users/alice/.codex/config.toml"),
        identity: &identity,
        command: "\"/Users/alice/.codex/delete-denied/bin/delete-denied-hook\" --policy \"/Users/alice/.codex/delete-denied/policy.json\"",
    };

    trust_hook_with_transport(&mut transport, request).unwrap();

    assert_eq!(transport.calls[0].0, "initialize");
    assert_eq!(transport.calls[1].0, "hooks/list");
    assert_eq!(transport.calls[2].0, "config/batchWrite");
    assert_eq!(transport.calls[3].0, "hooks/list");
    assert_eq!(transport.calls[0].1["clientInfo"]["name"], "delete-denied");
    assert_eq!(transport.calls[0].1["capabilities"], Value::Null);
    assert_eq!(transport.calls[1].1["cwds"][0], "/Users/alice");
    assert_eq!(transport.notifications[0].0, "initialized");
    assert_eq!(transport.notifications[0].1, Value::Null);
    let batch = &transport.calls[2].1;
    assert_eq!(batch["filePath"], "/Users/alice/.codex/config.toml");
    assert_eq!(batch["reloadUserConfig"], true);
    assert_eq!(batch["edits"][0]["keyPath"], "hooks.state");
    assert_eq!(batch["edits"][0]["mergeStrategy"], "upsert");
    assert_eq!(
        batch["edits"][0]["value"][identity.key.as_str()]["trusted_hash"],
        identity.hash
    );
    assert_eq!(
        batch["edits"][0]["value"][identity.key.as_str()]["enabled"],
        true
    );
    assert_eq!(batch["edits"][0]["value"].as_object().unwrap().len(), 1);
}

#[test]
fn already_trusted_hook_skips_config_write() {
    let identity = HookIdentity {
        key: "/Users/alice/.codex/hooks.json:pre_tool_use:0:0".into(),
        hash: "sha256:known".into(),
    };
    let mut transport = FakeTransport {
        responses: vec![
            Ok(json!({})),
            Ok(hooks_response(hook(&identity, true))),
            Ok(hooks_response(hook(&identity, true))),
        ],
        calls: Vec::new(),
        notifications: Vec::new(),
    };
    trust_hook_with_transport(&mut transport, request(&identity)).unwrap();
    assert_eq!(
        transport
            .calls
            .iter()
            .map(|(method, _)| method.as_str())
            .collect::<Vec<_>>(),
        ["initialize", "hooks/list", "hooks/list"]
    );
}

fn request<'a>(identity: &'a HookIdentity) -> TrustRequest<'a> {
    TrustRequest {
        cwd: Path::new("/Users/alice"),
        hooks_path: Path::new("/Users/alice/.codex/hooks.json"),
        config_path: Path::new("/Users/alice/.codex/config.toml"),
        identity,
        command: "\"/Users/alice/.codex/delete-denied/bin/delete-denied-hook\" --policy \"/Users/alice/.codex/delete-denied/policy.json\"",
    }
}

#[test]
fn missing_or_ambiguous_hooks_fail_before_batch_write() {
    let identity = HookIdentity {
        key: "/Users/alice/.codex/hooks.json:pre_tool_use:0:0".into(),
        hash: "sha256:known".into(),
    };
    let mut foreign = hook(&identity, false);
    foreign["key"] = json!("/Users/alice/.codex/hooks.json:pre_tool_use:9:9");
    for hooks in [
        json!({ "hooks": [] }),
        json!({ "hooks": [foreign] }),
        json!({ "hooks": [hook(&identity, false), hook(&identity, false)] }),
    ] {
        let mut responses = vec![Ok(json!({})), Ok(hooks.clone())];
        if hooks
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        {
            responses.extend([Ok(hooks.clone()), Ok(hooks)]);
        }
        let mut transport = FakeTransport {
            responses,
            calls: Vec::new(),
            notifications: Vec::new(),
        };
        assert!(trust_hook_with_transport(&mut transport, request(&identity)).is_err());
        assert!(
            !transport
                .calls
                .iter()
                .any(|(method, _)| method == "config/batchWrite")
        );
    }
}

#[test]
fn malformed_hook_metadata_fails_before_batch_write() {
    let identity = HookIdentity {
        key: "/Users/alice/.codex/hooks.json:pre_tool_use:0:0".into(),
        hash: "sha256:known".into(),
    };
    let mut malformed = hook(&identity, false);
    malformed["statusMessage"] = Value::Null;
    let mut transport = FakeTransport {
        responses: vec![Ok(json!({})), Ok(hooks_response(malformed))],
        calls: Vec::new(),
        notifications: Vec::new(),
    };
    let result = trust_hook_with_transport(&mut transport, request(&identity));
    assert!(matches!(result, Err(AppServerError::Protocol(_))));
    assert!(
        transport
            .calls
            .iter()
            .all(|(method, _)| method != "config/batchWrite")
    );
}

#[test]
fn malformed_batch_write_result_stops_before_final_hook_check() {
    let identity = HookIdentity {
        key: "/Users/alice/.codex/hooks.json:pre_tool_use:0:0".into(),
        hash: "sha256:known".into(),
    };
    for result in [
        json!({ "filePath": "/tmp/other.toml", "status": "ok", "version": 2 }),
        json!({ "filePath": "/Users/alice/.codex/config.toml", "status": "error", "version": 2 }),
        json!({ "filePath": "/Users/alice/.codex/config.toml", "status": "ok" }),
        json!({ "filePath": "/Users/alice/.codex/config.toml", "status": "ok", "version": null }),
    ] {
        let mut transport = FakeTransport {
            responses: vec![
                Ok(json!({})),
                Ok(hooks_response(hook(&identity, false))),
                Ok(result),
            ],
            calls: Vec::new(),
            notifications: Vec::new(),
        };
        let error = trust_hook_with_transport(&mut transport, request(&identity)).unwrap_err();
        assert!(matches!(error, AppServerError::Protocol(_)));
        assert_eq!(
            transport
                .calls
                .iter()
                .filter(|(method, _)| method == "hooks/list")
                .count(),
            1
        );
    }
}

#[test]
fn transport_error_and_timeout_are_bounded_without_batch_write() {
    let identity = HookIdentity {
        key: "/Users/alice/.codex/hooks.json:pre_tool_use:0:0".into(),
        hash: "sha256:known".into(),
    };
    for error in ["rpc error", "response timed out"] {
        let mut transport = FakeTransport {
            responses: vec![Ok(json!({})), Err(error.into())],
            calls: Vec::new(),
            notifications: Vec::new(),
        };
        let result = trust_hook_with_transport(&mut transport, request(&identity));
        if error == "response timed out" {
            assert_eq!(result, Err(AppServerError::Timeout));
        } else {
            assert!(result.is_err());
        }
        assert!(
            !transport
                .calls
                .iter()
                .any(|(method, _)| method == "config/batchWrite")
        );
    }
}

#[test]
fn transiently_empty_hook_list_is_retried_before_failing_closed() {
    let identity = HookIdentity {
        key: "C:/Users/alice/.codex/hooks.json:pre_tool_use:0:0".into(),
        hash: "sha256:known".into(),
    };
    let mut transport = FakeTransport {
        responses: vec![
            Ok(json!({})),
            Ok(json!({ "data": [{ "cwd": "C:/Users/alice", "hooks": [] }] })),
            Ok(hooks_response(hook(&identity, false))),
            Ok(json!({
                "filePath": "/Users/alice/.codex/config.toml",
                "status": "ok",
                "version": 2
            })),
            Ok(hooks_response(hook(&identity, true))),
        ],
        calls: Vec::new(),
        notifications: Vec::new(),
    };

    trust_hook_with_transport(&mut transport, request(&identity)).unwrap();
    assert_eq!(
        transport
            .calls
            .iter()
            .map(|(method, _)| method.as_str())
            .collect::<Vec<_>>(),
        [
            "initialize",
            "hooks/list",
            "hooks/list",
            "config/batchWrite",
            "hooks/list"
        ]
    );
}

#[test]
fn windows_path_spelling_uses_server_identity_for_batch_write() {
    let identity = HookIdentity {
        key: "C:/Users/alice/.codex/hooks.json:pre_tool_use:0:0".into(),
        hash: "sha256:known".into(),
    };
    let mut server_hook = hook(&identity, false);
    server_hook["sourcePath"] = json!(r"C:\Users\alice\.codex\hooks.json");
    server_hook["key"] = json!(r"C:\Users\alice\.codex\hooks.json:pre_tool_use:0:0");
    server_hook["command"] = json!(
        "\"C:/Users/alice/.codex/delete-denied/bin/delete-denied-hook.exe\" --policy \"C:/Users/alice/.codex/delete-denied/policy.json\""
    );
    let trusted_server_hook = {
        let mut hook = server_hook.clone();
        hook["trustStatus"] = json!("trusted");
        hook
    };
    let mut transport = FakeTransport {
        responses: vec![
            Ok(json!({})),
            Ok(hooks_response(server_hook)),
            Ok(json!({
                "filePath": r"C:\Users\alice\.codex\config.toml",
                "status": "ok",
                "version": 2
            })),
            Ok(hooks_response(trusted_server_hook)),
        ],
        calls: Vec::new(),
        notifications: Vec::new(),
    };
    let request = TrustRequest {
        cwd: Path::new(r"C:/Users/alice"),
        hooks_path: Path::new(r"C:/Users/alice/.codex/hooks.json"),
        config_path: Path::new(r"C:/Users/alice/.codex/config.toml"),
        identity: &identity,
        command: "\"C:/Users/alice/.codex/delete-denied/bin/delete-denied-hook.exe\" --policy \"C:/Users/alice/.codex/delete-denied/policy.json\"",
    };
    trust_hook_with_transport(&mut transport, request).unwrap();
    let batch = transport
        .calls
        .iter()
        .find(|(method, _)| method == "config/batchWrite")
        .map(|(_, params)| params)
        .expect("batch write");
    assert!(
        batch["edits"][0]["value"]
            .as_object()
            .expect("hook state")
            .contains_key(r"C:\Users\alice\.codex\hooks.json:pre_tool_use:0:0")
    );
}
