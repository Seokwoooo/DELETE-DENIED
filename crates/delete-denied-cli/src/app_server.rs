use crate::hooks::{HookIdentity, STATUS_MESSAGE, hook_identity_key_equal, hook_path_text_equal};
use serde_json::{Value, json};
use std::env;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

const RPC_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const HOOK_DISCOVERY_RETRIES: usize = 3;
const HOOK_DISCOVERY_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppServerError {
    Unavailable(String),
    Protocol(String),
    Timeout,
}

impl fmt::Display for AppServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "Codex app-server unavailable: {reason}"),
            Self::Protocol(reason) => write!(f, "Codex app-server protocol error: {reason}"),
            Self::Timeout => f.write_str("Codex app-server timed out"),
        }
    }
}

impl std::error::Error for AppServerError {}

pub trait RpcTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;
    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), String>;
}

pub struct TrustRequest<'a> {
    pub cwd: &'a Path,
    pub hooks_path: &'a Path,
    pub config_path: &'a Path,
    pub identity: &'a HookIdentity,
    pub command: &'a str,
}

pub fn trust_hook(request: TrustRequest<'_>) -> Result<(), AppServerError> {
    let candidates = discover_codex_candidates()?;
    let mut last_spawn_error = None;
    for binary in candidates {
        match StdioTransport::spawn(&binary) {
            Ok(mut transport) => return trust_hook_with_transport(&mut transport, request),
            Err(error) => last_spawn_error = Some(error),
        }
    }
    Err(last_spawn_error
        .unwrap_or_else(|| AppServerError::Unavailable("codex executable not found".into())))
}

pub fn trust_hook_with_transport<T: RpcTransport>(
    transport: &mut T,
    request: TrustRequest<'_>,
) -> Result<(), AppServerError> {
    transport
        .request(
            "initialize",
            json!({
                "clientInfo": { "name": "delete-denied", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": null
            }),
        )
        .map_err(map_transport_error)?;
    transport
        .notify("initialized", None)
        .map_err(map_transport_error)?;

    let mut first = list_hooks(transport, request.cwd)?;
    let matches = loop {
        let match_count = matching_hooks(&first, &request).len();
        if match_count == 1 {
            break matching_hooks(&first, &request);
        }
        if match_count == 0
            && is_exact_missing_hook_response(&first)
            && retry_missing_hook_discovery(transport, request.cwd, &mut first)
        {
            continue;
        }
        return Err(AppServerError::Protocol(format!(
            "expected one DELETE-DENIED hook, found {}",
            match_count
        )));
    };
    let hook = matches[0];
    let server_key = hook
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| AppServerError::Protocol("DELETE-DENIED hook has no key".into()))?
        .to_owned();
    let server_hash = hook
        .get("currentHash")
        .and_then(Value::as_str)
        .ok_or_else(|| AppServerError::Protocol("DELETE-DENIED hook has no currentHash".into()))?
        .to_owned();
    let already_active = hook.get("trustStatus").and_then(Value::as_str) == Some("trusted")
        && hook.get("enabled").and_then(Value::as_bool) == Some(true);
    if !already_active {
        let write_result = transport
            .request(
                "config/batchWrite",
                json!({
                    "filePath": request.config_path,
                    "edits": [{
                        "keyPath": "hooks.state",
                        "value": {
                            server_key: {
                                "trusted_hash": server_hash,
                                "enabled": true
                            }
                        },
                        "mergeStrategy": "upsert"
                    }],
                    "reloadUserConfig": true
                }),
            )
            .map_err(map_transport_error)?;
        validate_batch_write(&write_result, request.config_path)?;
    }

    let final_hooks = list_hooks(transport, request.cwd)?;
    let matches = matching_hooks(&final_hooks, &request);
    if matches.len() != 1
        || matches[0].get("trustStatus").and_then(Value::as_str) != Some("trusted")
        || matches[0].get("enabled").and_then(Value::as_bool) != Some(true)
    {
        return Err(AppServerError::Protocol(
            "DELETE-DENIED hook was not trusted and enabled".into(),
        ));
    }
    Ok(())
}

fn list_hooks<T: RpcTransport>(transport: &mut T, cwd: &Path) -> Result<Value, AppServerError> {
    transport
        .request("hooks/list", json!({ "cwds": [cwd] }))
        .map_err(map_transport_error)
}

fn retry_missing_hook_discovery<T: RpcTransport>(
    transport: &mut T,
    cwd: &Path,
    response: &mut Value,
) -> bool {
    for _ in 1..HOOK_DISCOVERY_RETRIES {
        thread::sleep(HOOK_DISCOVERY_RETRY_DELAY);
        match list_hooks(transport, cwd) {
            Ok(next) => *response = next,
            Err(_) => return false,
        }
        if !is_exact_missing_hook_response(response) || !hook_items(response).next().is_none() {
            return true;
        }
    }
    false
}

fn is_exact_missing_hook_response(value: &Value) -> bool {
    if let Some(hooks) = value.get("hooks") {
        return hooks.as_array().is_some_and(Vec::is_empty);
    }
    let Some(data) = value.get("data").and_then(Value::as_array) else {
        return false;
    };
    !data.is_empty()
        && data.iter().all(|entry| {
            entry
                .get("hooks")
                .and_then(Value::as_array)
                .is_some_and(Vec::is_empty)
        })
}

fn map_transport_error(error: String) -> AppServerError {
    if error == "response timed out" {
        AppServerError::Timeout
    } else {
        AppServerError::Unavailable(error)
    }
}

fn validate_batch_write(result: &Value, config_path: &Path) -> Result<(), AppServerError> {
    let expected_path = config_path.to_string_lossy();
    if !result
        .get("filePath")
        .and_then(Value::as_str)
        .is_some_and(|actual| hook_path_text_equal(actual, expected_path.as_ref()))
    {
        return Err(AppServerError::Protocol(
            "config/batchWrite returned an unexpected file path".into(),
        ));
    }
    if !matches!(
        result.get("status").and_then(Value::as_str),
        Some("ok" | "okOverridden")
    ) {
        return Err(AppServerError::Protocol(
            "config/batchWrite did not report success".into(),
        ));
    }
    if result.get("version").is_none_or(Value::is_null) {
        return Err(AppServerError::Protocol(
            "config/batchWrite response has no version".into(),
        ));
    }
    Ok(())
}

fn matching_hooks<'a>(hooks: &'a Value, request: &TrustRequest<'_>) -> Vec<&'a Value> {
    hook_items(hooks)
        .filter(|hook| {
            hook.get("key")
                .and_then(Value::as_str)
                .is_some_and(|key| hook_identity_key_equal(key, &request.identity.key))
                && hook.get("currentHash").and_then(Value::as_str)
                    == Some(request.identity.hash.as_str())
                && hook.get("command").and_then(Value::as_str) == Some(request.command)
                && hook
                    .get("sourcePath")
                    .and_then(Value::as_str)
                    .is_some_and(|path| {
                        hook_path_text_equal(path, &request.hooks_path.to_string_lossy())
                    })
                && hook.get("handlerType").and_then(Value::as_str) == Some("command")
                && hook.get("matcher").and_then(Value::as_str) == Some("^Bash$")
                && hook.get("eventName").and_then(Value::as_str) == Some("preToolUse")
                && hook.get("source").and_then(Value::as_str) == Some("user")
                && hook.get("statusMessage").and_then(Value::as_str) == Some(STATUS_MESSAGE)
                && hook.get("enabled").and_then(Value::as_bool).is_some()
                && hook.get("trustStatus").and_then(Value::as_str).is_some()
        })
        .collect()
}

fn hook_items(value: &Value) -> Box<dyn Iterator<Item = &Value> + '_> {
    if let Some(items) = value.get("hooks").and_then(Value::as_array) {
        return Box::new(items.iter());
    }
    let data = value.get("data").and_then(Value::as_array);
    let flattened = data
        .into_iter()
        .flat_map(|entries| entries.iter())
        .filter_map(|entry| entry.get("hooks"))
        .flat_map(|hooks| hooks.as_array().into_iter().flatten());
    Box::new(flattened)
}

fn discover_codex_candidates() -> Result<Vec<PathBuf>, AppServerError> {
    if let Some(path) = env::var_os("DELETE_DENIED_CODEX_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(vec![path]);
        }
        return Err(AppServerError::Unavailable(format!(
            "configured Codex executable does not exist: {}",
            path.display()
        )));
    }
    let local_app_data = env::var_os("LOCALAPPDATA").map(PathBuf::from);
    let program_files = env::var_os("ProgramFiles").map(PathBuf::from);
    let home = env::var_os("HOME").map(PathBuf::from);
    let candidates = codex_candidate_paths(
        local_app_data.as_deref(),
        program_files.as_deref(),
        home.as_deref(),
        env::var_os("PATH").as_deref(),
        cfg!(windows),
    );
    let candidates = candidates
        .into_iter()
        .filter(|candidate| candidate.is_file())
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        Err(AppServerError::Unavailable(
            "codex executable not found".into(),
        ))
    } else {
        Ok(candidates)
    }
}

fn codex_candidate_paths(
    local_app_data: Option<&Path>,
    program_files: Option<&Path>,
    home: Option<&Path>,
    path: Option<&OsStr>,
    windows: bool,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    if windows {
        if let Some(local_app_data) = local_app_data {
            candidates.push(local_app_data.join("Programs/ChatGPT/resources/codex.exe"));
            candidates.push(local_app_data.join("OpenAI/ChatGPT/resources/codex.exe"));
            candidates.extend(versioned_windows_codex_candidates(local_app_data));
        }
        if let Some(program_files) = program_files {
            candidates.push(program_files.join("ChatGPT/resources/codex.exe"));
            candidates.push(program_files.join("Codex/codex.exe"));
        }
    } else {
        candidates.push(PathBuf::from(
            "/Applications/ChatGPT.app/Contents/Resources/codex",
        ));
        if let Some(home) = home {
            candidates.push(home.join("Applications/ChatGPT.app/Contents/Resources/codex"));
        }
    }
    let executable = if windows { "codex.exe" } else { "codex" };
    if let Some(path) = path {
        candidates.extend(env::split_paths(path).map(|directory| directory.join(executable)));
    }
    if windows {
        if let Some(local_app_data) = local_app_data {
            candidates.push(local_app_data.join("Programs/Codex/codex.exe"));
        }
    }
    candidates
}

fn versioned_windows_codex_candidates(local_app_data: &Path) -> Vec<PathBuf> {
    let bin = local_app_data.join("OpenAI/Codex/bin");
    let Ok(entries) = fs::read_dir(bin) else {
        return Vec::new();
    };
    let mut candidates = entries
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            if !file_type.is_dir() {
                return None;
            }
            let candidate = entry.path().join("codex.exe");
            candidate.is_file().then_some(candidate)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        let left_modified = fs::metadata(left)
            .and_then(|metadata| metadata.modified())
            .ok();
        let right_modified = fs::metadata(right)
            .and_then(|metadata| metadata.modified())
            .ok();
        right_modified.cmp(&left_modified).then_with(|| {
            right
                .parent()
                .and_then(Path::file_name)
                .and_then(|name| name.to_str())
                .cmp(
                    &left
                        .parent()
                        .and_then(Path::file_name)
                        .and_then(|name| name.to_str()),
                )
        })
    });
    candidates
}

struct StdioTransport {
    child: Child,
    stdin: ChildStdin,
    responses: Receiver<Result<String, String>>,
    next_id: u64,
}

impl StdioTransport {
    fn spawn(binary: &Path) -> Result<Self, AppServerError> {
        let mut child = Command::new(binary)
            .args(["app-server", "--stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| AppServerError::Unavailable(error.to_string()))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| AppServerError::Unavailable("app-server stdin unavailable".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AppServerError::Unavailable("app-server stdout unavailable".into()))?;
        let (sender, responses) = mpsc::channel();
        thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let result = line.map_err(|error| error.to_string()).and_then(|line| {
                    if line.len() > MAX_RESPONSE_BYTES {
                        Err("response exceeded size limit".into())
                    } else {
                        Ok(line)
                    }
                });
                if sender.send(result).is_err() {
                    break;
                }
            }
        });
        Ok(Self {
            child,
            stdin,
            responses,
            next_id: 1,
        })
    }
}

impl RpcTransport for StdioTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        serde_json::to_writer(
            &mut self.stdin,
            &json!({ "id": id, "method": method, "params": params }),
        )
        .map_err(|error| error.to_string())?;
        self.stdin
            .write_all(b"\n")
            .map_err(|error| error.to_string())?;
        self.stdin.flush().map_err(|error| error.to_string())?;
        let deadline = Instant::now() + RPC_TIMEOUT;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err("response timed out".into());
            }
            let line = self
                .responses
                .recv_timeout(remaining)
                .map_err(|error| -> String {
                    match error {
                        RecvTimeoutError::Timeout => "response timed out".into(),
                        RecvTimeoutError::Disconnected => "app-server closed stdout".into(),
                    }
                })?
                .map_err(|error| error.to_string())?;
            let envelope: Value = serde_json::from_str(&line).map_err(|error| error.to_string())?;
            if envelope.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = envelope.get("error") {
                return Err(error.to_string());
            }
            return Ok(envelope.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    fn notify(&mut self, method: &str, params: Option<Value>) -> Result<(), String> {
        let mut envelope = json!({ "method": method });
        if let Some(params) = params {
            envelope["params"] = params;
        }
        serde_json::to_writer(&mut self.stdin, &envelope).map_err(|error| error.to_string())?;
        self.stdin
            .write_all(b"\n")
            .map_err(|error| error.to_string())?;
        self.stdin.flush().map_err(|error| error.to_string())
    }
}

impl Drop for StdioTransport {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::codex_candidate_paths;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn versioned_windows_codex_candidates_are_bounded_and_before_path() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "delete-denied-codex-discovery-{}-{unique}",
            std::process::id()
        ));
        let local_app_data = root.join("LocalAppData");
        let version_old = local_app_data.join("OpenAI/Codex/bin/1.0.0/codex.exe");
        let version_new = local_app_data.join("OpenAI/Codex/bin/2.0.0/codex.exe");
        let nested = local_app_data.join("OpenAI/Codex/bin/3.0.0/nested/codex.exe");
        let path_binary = root.join("path/codex.exe");
        for file in [&version_old, &version_new, &nested, &path_binary] {
            fs::create_dir_all(file.parent().expect("parent")).expect("directory");
            fs::write(file, b"fixture").expect("binary");
        }

        let candidates = codex_candidate_paths(
            Some(&local_app_data),
            None,
            None,
            Some(path_binary.parent().unwrap().as_os_str()),
            true,
        );
        let existing = candidates
            .into_iter()
            .filter(|candidate| candidate.is_file())
            .collect::<Vec<_>>();
        assert_eq!(existing[0], version_new);
        assert_eq!(existing[1], version_old);
        assert!(!existing.contains(&nested));
        let path_index = existing
            .iter()
            .position(|candidate| candidate == &path_binary)
            .expect("PATH candidate");
        assert!(path_index > 1);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn macos_candidate_order_remains_exact_and_path_is_after_app_candidates() {
        let candidates = codex_candidate_paths(
            None,
            None,
            Some(Path::new("/Users/alice/Library")),
            Some(OsStr::new("/opt/codex")),
            false,
        );
        assert!(
            candidates
                .iter()
                .position(|path| path == Path::new("/opt/codex/codex"))
                .is_some()
        );
    }
}
