use crate::app_server::{AppServerError, TrustRequest, trust_hook};
use crate::hooks::{
    HookConfigError, HookRegistration, contains_user_hook, hook_identity, hook_identity_key_equal,
    hook_path_text_equal, merge_user_hooks, normalize_hook_path, remove_user_hook,
};
use crate::platform::{Platform, PlatformPaths, ProtectedPath};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const STATUS_ENFORCED: &str = "Protected Paths: Enforced";
pub const STATUS_SUSPENDED: &str = "Protected Paths: Suspended";
pub const STATUS_AWAITING_TRUST: &str = "Protected Paths: Awaiting Codex trust";
pub const STATUS_INACTIVE: &str = "Protected Paths: Inactive";
pub const ACTIVATION_TRUSTED: &str = "activation: Codex trust ok";
pub const ACTIVATION_AWAITING_TRUST: &str = "activation: awaiting Codex trust";
pub const ACTIVATION_INACTIVE: &str = "activation: disabled in Codex config";
pub const TRUST_INSTRUCTION: &str = "Run `delete-denied update --trust` to trust this hook.";
pub const INACTIVE_INSTRUCTION: &str = "Run `delete-denied update --trust` to re-enable this hook.";
const SCHEMA_VERSION: u32 = 1;
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;

pub trait ArtifactSource: Send + Sync {
    fn cli_bytes(&self, platform: Platform) -> Result<Vec<u8>, LifecycleError>;
    fn hook_bytes(&self, platform: Platform) -> Result<Vec<u8>, LifecycleError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HostArtifacts;

impl ArtifactSource for HostArtifacts {
    fn cli_bytes(&self, _platform: Platform) -> Result<Vec<u8>, LifecycleError> {
        let (executable, _) = current_executable_context()?;
        read_regular_file(&executable, MAX_ARTIFACT_BYTES)
    }

    fn hook_bytes(&self, _platform: Platform) -> Result<Vec<u8>, LifecycleError> {
        let (_, parent) = current_executable_context()?;
        let name = if cfg!(windows) {
            "delete-denied-hook.exe"
        } else {
            "delete-denied-hook"
        };
        read_regular_file(&parent.join(name), MAX_ARTIFACT_BYTES)
    }
}

pub struct HostDependencies {
    pub artifacts: HostArtifacts,
}

impl Default for HostDependencies {
    fn default() -> Self {
        Self {
            artifacts: HostArtifacts,
        }
    }
}

impl HostDependencies {
    pub fn as_refs(&self) -> &dyn ArtifactSource {
        &self.artifacts
    }
}

pub struct Lifecycle<'a> {
    pub paths: PlatformPaths,
    artifacts: &'a dyn ArtifactSource,
}

impl<'a> Lifecycle<'a> {
    pub fn new(paths: PlatformPaths, artifacts: &'a dyn ArtifactSource) -> Self {
        Self { paths, artifacts }
    }

    pub fn install(&self) -> Result<LifecycleResult, LifecycleError> {
        self.install_with_trust(false)
    }

    pub fn install_with_trust(&self, trust: bool) -> Result<LifecycleResult, LifecycleError> {
        if !matches!(self.status()?, StatusReport::NotInstalled(_)) {
            return Err(LifecycleError::Unhealthy(
                "DELETE-DENIED is already installed; run update".into(),
            ));
        }
        let existing_hooks = read_optional_text(&self.paths.hooks_path.logical, MAX_CONFIG_BYTES)?;
        let registration = self.registration();
        let merged_hooks = merge_user_hooks(existing_hooks.as_deref(), &registration)?;
        let cli = self.artifacts.cli_bytes(self.paths.platform)?;
        let hook = self.artifacts.hook_bytes(self.paths.platform)?;
        let policy = policy_bytes(&self.paths)?;

        fs::create_dir_all(&self.paths.binary_dir.logical)?;
        fs::create_dir_all(&self.paths.backups_path.logical)?;
        if existing_hooks.is_some() {
            let backup = self
                .paths
                .backups_path
                .logical
                .join("hooks.json.before-install");
            if !backup.exists() {
                write_owned_file(
                    &backup,
                    existing_hooks.as_deref().unwrap_or_default().as_bytes(),
                    false,
                )?;
            }
        }

        write_owned_file(&self.paths.cli_binary_path.logical, &cli, true)?;
        write_owned_file(&self.paths.hook_binary_path.logical, &hook, true)?;
        write_owned_file(&self.paths.policy_path.logical, &policy, false)?;
        let state = State {
            schema_version: SCHEMA_VERSION,
            protection_enabled: true,
        };
        let manifest = self.build_manifest(
            &registration,
            existing_hooks.is_none(),
            &cli,
            &hook,
            &policy,
        );
        write_json(&self.paths.state_path.logical, &state)?;
        write_json(&self.paths.manifest_path.logical, &manifest)?;

        // Hook registration is the final write. If it cannot be recorded,
        // restore the original user config and remove the inactive owned files.
        if let Err(error) = write_owned_file(
            &self.paths.hooks_path.logical,
            merged_hooks.as_bytes(),
            false,
        ) {
            if let Some(original) = existing_hooks.as_deref() {
                let _ =
                    write_owned_file(&self.paths.hooks_path.logical, original.as_bytes(), false);
            } else {
                let _ = remove_file_if_exists(&self.paths.hooks_path.logical);
            }
            let _ = fs::remove_dir_all(&self.paths.data_dir.logical);
            return Err(error);
        }
        if trust {
            self.trust_activation()?;
        }
        let status = self.status()?;
        Ok(LifecycleResult {
            status: status.clone(),
            message: format!(
                "installed for the current user\n{}",
                status_message(&status)
            ),
        })
    }

    pub fn status(&self) -> Result<StatusReport, LifecycleError> {
        let Some(state_text) =
            read_optional_text(&self.paths.state_path.logical, MAX_CONFIG_BYTES)?
        else {
            return Ok(StatusReport::NotInstalled("state.json is missing".into()));
        };
        let Some(manifest_text) =
            read_optional_text(&self.paths.manifest_path.logical, MAX_CONFIG_BYTES)?
        else {
            return Ok(StatusReport::NotInstalled(
                "manifest.json is missing".into(),
            ));
        };
        let state: State = serde_json::from_str(&state_text)?;
        let manifest: InstallManifest = serde_json::from_str(&manifest_text)?;
        if state.schema_version != SCHEMA_VERSION || manifest.schema_version != SCHEMA_VERSION {
            return Ok(StatusReport::Unhealthy(
                "unsupported installation schema".into(),
            ));
        }
        if let Err(error) = self.verify_manifest(&manifest, state.protection_enabled) {
            return Ok(StatusReport::Unhealthy(error.to_string()));
        }
        Ok(if state.protection_enabled {
            self.activation_status()?
        } else {
            StatusReport::Suspended
        })
    }

    pub fn doctor(&self) -> Result<String, LifecycleError> {
        match self.status()? {
            status @ (StatusReport::Enforced
            | StatusReport::AwaitingTrust
            | StatusReport::Inactive) => {
                Ok(format!("{}\nregistration: ok", status_message(&status)))
            }
            StatusReport::Suspended => Ok(format!("{STATUS_SUSPENDED}\nregistration: suspended")),
            other => Err(LifecycleError::Unhealthy(other.to_string())),
        }
    }

    pub fn update(&self) -> Result<LifecycleResult, LifecycleError> {
        self.update_with_trust(false)
    }

    pub fn update_with_trust(&self, trust: bool) -> Result<LifecycleResult, LifecycleError> {
        let state = self.read_state()?;
        let old_manifest = self.read_manifest()?;
        self.verify_manifest(&old_manifest, state.protection_enabled)?;
        let cli = self.artifacts.cli_bytes(self.paths.platform)?;
        let hook = self.artifacts.hook_bytes(self.paths.platform)?;
        let policy = policy_bytes(&self.paths)?;
        write_owned_file(&self.paths.cli_binary_path.logical, &cli, true)?;
        write_owned_file(&self.paths.hook_binary_path.logical, &hook, true)?;
        write_owned_file(&self.paths.policy_path.logical, &policy, false)?;
        let registration = self.registration();
        let manifest = self.build_manifest(
            &registration,
            old_manifest.hooks_file_created,
            &cli,
            &hook,
            &policy,
        );
        write_json(&self.paths.manifest_path.logical, &manifest)?;
        if state.protection_enabled {
            let current = read_required_text(&self.paths.hooks_path.logical, MAX_CONFIG_BYTES)?;
            let merged = merge_user_hooks(Some(&current), &registration)?;
            write_owned_file(&self.paths.hooks_path.logical, merged.as_bytes(), false)?;
        }
        if trust && state.protection_enabled {
            self.trust_activation()?;
        }
        let status = self.status()?;
        Ok(LifecycleResult {
            status: status.clone(),
            message: format!(
                "updated current-user installation\n{}",
                status_message(&status)
            ),
        })
    }

    pub fn suspend(&self) -> Result<LifecycleResult, LifecycleError> {
        let mut state = self.read_state()?;
        let manifest = self.read_manifest()?;
        self.verify_manifest(&manifest, state.protection_enabled)?;
        if state.protection_enabled {
            let current = read_required_text(&self.paths.hooks_path.logical, MAX_CONFIG_BYTES)?;
            let removed = remove_user_hook(&current, &self.registration())?;
            write_owned_file(&self.paths.hooks_path.logical, removed.as_bytes(), false)?;
            state.protection_enabled = false;
            write_json(&self.paths.state_path.logical, &state)?;
        }
        Ok(LifecycleResult {
            status: StatusReport::Suspended,
            message: STATUS_SUSPENDED.into(),
        })
    }

    pub fn resume(&self) -> Result<LifecycleResult, LifecycleError> {
        let mut state = self.read_state()?;
        let manifest = self.read_manifest()?;
        self.verify_manifest(&manifest, state.protection_enabled)?;
        if !state.protection_enabled {
            let current = read_required_text(&self.paths.hooks_path.logical, MAX_CONFIG_BYTES)?;
            let merged = merge_user_hooks(Some(&current), &self.registration())?;
            write_owned_file(&self.paths.hooks_path.logical, merged.as_bytes(), false)?;
            state.protection_enabled = true;
            write_json(&self.paths.state_path.logical, &state)?;
        }
        let status = self.status()?;
        Ok(LifecycleResult {
            status: status.clone(),
            message: status_message(&status),
        })
    }

    pub fn uninstall(&self) -> Result<LifecycleResult, LifecycleError> {
        let manifest = self.read_manifest()?;
        let current = read_required_text(&self.paths.hooks_path.logical, MAX_CONFIG_BYTES)?;
        let removed = remove_user_hook(&current, &self.registration())?;
        if manifest.hooks_file_created && hooks_document_is_empty(&removed)? {
            remove_file_if_exists(&self.paths.hooks_path.logical)?;
        } else {
            write_owned_file(&self.paths.hooks_path.logical, removed.as_bytes(), false)?;
        }
        remove_installation_dir(&self.paths.data_dir.logical)?;
        Ok(LifecycleResult {
            status: StatusReport::NotInstalled("removed".into()),
            message: "uninstalled current-user installation".into(),
        })
    }

    fn registration(&self) -> HookRegistration {
        HookRegistration::new(hook_command(&self.paths))
    }

    fn trust_activation(&self) -> Result<(), LifecycleError> {
        let hooks = read_required_text(&self.paths.hooks_path.logical, MAX_CONFIG_BYTES)?;
        let registration = self.registration();
        let identity = hook_identity(&hooks, &self.paths.hooks_path.logical, &registration)?
            .ok_or_else(|| LifecycleError::Unhealthy("DELETE-DENIED hook is missing".into()))?;
        let cwd = std::env::current_dir()?;
        let config_path = self.paths.codex_dir.logical.join("config.toml");
        let config_backup = self
            .paths
            .backups_path
            .logical
            .join("config.toml.before-trust");
        backup_config_before_trust(&config_path, &config_backup)?;
        trust_hook(TrustRequest {
            cwd: &cwd,
            hooks_path: &self.paths.hooks_path.logical,
            config_path: &config_path,
            identity: &identity,
            command: &registration.command,
        })?;
        Ok(())
    }

    fn activation_status(&self) -> Result<StatusReport, LifecycleError> {
        let hooks = read_required_text(&self.paths.hooks_path.logical, MAX_CONFIG_BYTES)?;
        let Some(identity) =
            hook_identity(&hooks, &self.paths.hooks_path.logical, &self.registration())?
        else {
            return Ok(StatusReport::AwaitingTrust);
        };
        let config_path = self.paths.codex_dir.logical.join("config.toml");
        let Some(config_text) = read_optional_text(&config_path, MAX_CONFIG_BYTES)? else {
            return Ok(StatusReport::AwaitingTrust);
        };
        let Ok(config) = config_text.parse::<toml::Value>() else {
            return Ok(StatusReport::AwaitingTrust);
        };
        Ok(status_from_hook_states(
            &config,
            &identity.key,
            &identity.hash,
        ))
    }

    fn read_state(&self) -> Result<State, LifecycleError> {
        let text = read_required_text(&self.paths.state_path.logical, MAX_CONFIG_BYTES)?;
        Ok(serde_json::from_str(&text)?)
    }

    fn read_manifest(&self) -> Result<InstallManifest, LifecycleError> {
        let text = read_required_text(&self.paths.manifest_path.logical, MAX_CONFIG_BYTES)?;
        Ok(serde_json::from_str(&text)?)
    }

    fn build_manifest(
        &self,
        registration: &HookRegistration,
        hooks_file_created: bool,
        cli: &[u8],
        hook: &[u8],
        policy: &[u8],
    ) -> InstallManifest {
        InstallManifest {
            schema_version: SCHEMA_VERSION,
            hooks_path: path_string(&self.paths.hooks_path.logical),
            cli_path: path_string(&self.paths.cli_binary_path.logical),
            hook_path: path_string(&self.paths.hook_binary_path.logical),
            policy_path: path_string(&self.paths.policy_path.logical),
            hook_command: registration.command.clone(),
            hooks_file_created,
            cli_hash: sha256_hex(cli),
            hook_hash: sha256_hex(hook),
            policy_hash: sha256_hex(policy),
        }
    }

    fn verify_manifest(
        &self,
        manifest: &InstallManifest,
        protection_enabled: bool,
    ) -> Result<(), LifecycleError> {
        for (recorded, expected) in [
            (&manifest.hooks_path, &self.paths.hooks_path.logical),
            (&manifest.cli_path, &self.paths.cli_binary_path.logical),
            (&manifest.hook_path, &self.paths.hook_binary_path.logical),
            (&manifest.policy_path, &self.paths.policy_path.logical),
        ] {
            if !hook_path_text_equal(recorded, &expected.to_string_lossy()) {
                return Err(LifecycleError::Unhealthy(
                    "installation paths do not match the current user".into(),
                ));
            }
        }
        if manifest.hook_command != self.registration().command {
            return Err(LifecycleError::Unhealthy("hook command changed".into()));
        }
        for (path, expected_hash) in [
            (&self.paths.cli_binary_path.logical, &manifest.cli_hash),
            (&self.paths.hook_binary_path.logical, &manifest.hook_hash),
            (&self.paths.policy_path.logical, &manifest.policy_hash),
        ] {
            let bytes = read_regular_file(path, MAX_ARTIFACT_BYTES)?;
            if sha256_hex(&bytes) != *expected_hash {
                return Err(LifecycleError::Unhealthy(format!(
                    "installed file changed: {}",
                    path.display()
                )));
            }
        }
        let policy = read_regular_file(&self.paths.policy_path.logical, MAX_CONFIG_BYTES)?;
        delete_denied_core::policy::Policy::from_reader(policy.as_slice())
            .map_err(|error| LifecycleError::Unhealthy(format!("policy invalid: {error}")))?;
        let hooks = read_required_text(&self.paths.hooks_path.logical, MAX_CONFIG_BYTES)?;
        let registered = contains_user_hook(&hooks, &self.registration())?;
        if registered != protection_enabled {
            return Err(LifecycleError::Unhealthy(
                "hook registration does not match protection state".into(),
            ));
        }
        Ok(())
    }
}

fn status_from_hook_states(config: &toml::Value, key: &str, current_hash: &str) -> StatusReport {
    let Some(states) = config
        .get("hooks")
        .and_then(|value| value.get("state"))
        .and_then(toml::Value::as_table)
    else {
        return StatusReport::AwaitingTrust;
    };
    let mut current_hash_disabled = false;
    for (candidate, state) in states {
        if !hook_identity_key_equal(candidate, key)
            || state.get("trusted_hash").and_then(toml::Value::as_str) != Some(current_hash)
        {
            continue;
        }
        if state.get("enabled").and_then(toml::Value::as_bool) == Some(false) {
            current_hash_disabled = true;
        } else {
            return StatusReport::Enforced;
        }
    }
    if current_hash_disabled {
        StatusReport::Inactive
    } else {
        StatusReport::AwaitingTrust
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusReport {
    Enforced,
    AwaitingTrust,
    Inactive,
    Suspended,
    NotInstalled(String),
    Unhealthy(String),
}

impl fmt::Display for StatusReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Enforced => f.write_str(STATUS_ENFORCED),
            Self::AwaitingTrust => f.write_str(STATUS_AWAITING_TRUST),
            Self::Inactive => f.write_str(STATUS_INACTIVE),
            Self::Suspended => f.write_str(STATUS_SUSPENDED),
            Self::NotInstalled(reason) => write!(f, "Not Installed: {reason}"),
            Self::Unhealthy(reason) => write!(f, "Unhealthy: {reason}"),
        }
    }
}

fn status_message(status: &StatusReport) -> String {
    match status {
        StatusReport::Enforced => format!("{STATUS_ENFORCED}\n{ACTIVATION_TRUSTED}"),
        StatusReport::AwaitingTrust => {
            format!("{STATUS_AWAITING_TRUST}\n{ACTIVATION_AWAITING_TRUST}\n{TRUST_INSTRUCTION}")
        }
        StatusReport::Inactive => {
            format!("{STATUS_INACTIVE}\n{ACTIVATION_INACTIVE}\n{INACTIVE_INSTRUCTION}")
        }
        StatusReport::Suspended => STATUS_SUSPENDED.into(),
        StatusReport::NotInstalled(reason) => format!("Not Installed: {reason}"),
        StatusReport::Unhealthy(reason) => format!("Unhealthy: {reason}"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleResult {
    pub status: StatusReport,
    pub message: String,
}

#[derive(Debug)]
pub enum LifecycleError {
    AppServer(AppServerError),
    Io(io::Error),
    Json(serde_json::Error),
    Hook(HookConfigError),
    Discovery(crate::platform::DiscoveryError),
    Environment(String),
    Unhealthy(String),
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AppServer(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Json(error) => write!(f, "JSON error: {error}"),
            Self::Hook(error) => write!(f, "hook configuration error: {error}"),
            Self::Discovery(error) => write!(f, "discovery failed: {error}"),
            Self::Environment(reason) => write!(f, "installation environment error: {reason}"),
            Self::Unhealthy(reason) => write!(f, "installation is unhealthy: {reason}"),
        }
    }
}

impl std::error::Error for LifecycleError {}

impl From<io::Error> for LifecycleError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<AppServerError> for LifecycleError {
    fn from(error: AppServerError) -> Self {
        Self::AppServer(error)
    }
}

impl From<serde_json::Error> for LifecycleError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

impl From<HookConfigError> for LifecycleError {
    fn from(error: HookConfigError) -> Self {
        Self::Hook(error)
    }
}

impl From<crate::platform::DiscoveryError> for LifecycleError {
    fn from(error: crate::platform::DiscoveryError) -> Self {
        Self::Discovery(error)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    schema_version: u32,
    protection_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InstallManifest {
    schema_version: u32,
    hooks_path: String,
    cli_path: String,
    hook_path: String,
    policy_path: String,
    hook_command: String,
    hooks_file_created: bool,
    cli_hash: String,
    hook_hash: String,
    policy_hash: String,
}

#[derive(Debug, Serialize)]
struct PolicyFile {
    schema_version: u32,
    variables: std::collections::BTreeMap<String, String>,
    protected_paths: Vec<PolicyPathFile>,
}

#[derive(Debug, Serialize)]
struct PolicyPathFile {
    kind: String,
    logical: String,
    canonical: String,
    case_sensitive: bool,
}

fn policy_bytes(paths: &PlatformPaths) -> Result<Vec<u8>, LifecycleError> {
    let home = path_string(&paths.home.logical);
    let variables = std::collections::BTreeMap::from([
        ("HOME".to_owned(), home.clone()),
        ("USERPROFILE".to_owned(), home),
    ]);
    let protected_paths = paths
        .protected_paths
        .iter()
        .map(|path: &ProtectedPath| PolicyPathFile {
            kind: path.kind.clone(),
            logical: path_string(&path.logical),
            canonical: path_string(&path.canonical),
            case_sensitive: path.case_sensitive,
        })
        .collect();
    let bytes = serde_json::to_vec_pretty(&PolicyFile {
        schema_version: SCHEMA_VERSION,
        variables,
        protected_paths,
    })?;
    delete_denied_core::policy::Policy::from_reader(bytes.as_slice())
        .map_err(|error| LifecycleError::Unhealthy(format!("policy invalid: {error}")))?;
    Ok(bytes)
}

fn hook_command(paths: &PlatformPaths) -> String {
    format!(
        "{} --policy {}",
        quote_argument(&paths.hook_binary_path.logical),
        quote_argument(&paths.policy_path.logical)
    )
}

fn quote_argument(path: &Path) -> String {
    let value = path_string(path);
    format!("\"{}\"", value.replace('"', "\\\""))
}

fn path_string(path: &Path) -> String {
    normalize_hook_path(path)
}

fn current_executable_context() -> Result<(PathBuf, PathBuf), LifecycleError> {
    let executable = std::env::current_exe()?;
    let parent = executable
        .parent()
        .ok_or_else(|| LifecycleError::Environment("current executable has no parent".into()))?
        .to_path_buf();
    Ok((executable, parent))
}

fn read_optional_text(path: &Path, max: u64) -> Result<Option<String>, LifecycleError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.len() > max => Err(LifecycleError::Environment(format!(
            "file exceeds {max} byte limit: {}",
            path.display()
        ))),
        Ok(_) => Ok(Some(fs::read_to_string(path)?)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn read_required_text(path: &Path, max: u64) -> Result<String, LifecycleError> {
    read_optional_text(path, max)?.ok_or_else(|| {
        LifecycleError::Unhealthy(format!("required file is missing: {}", path.display()))
    })
}

fn read_regular_file(path: &Path, max: u64) -> Result<Vec<u8>, LifecycleError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LifecycleError::Environment(format!(
            "not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > max {
        return Err(LifecycleError::Environment(format!(
            "file exceeds {max} byte limit: {}",
            path.display()
        )));
    }
    Ok(fs::read(path)?)
}

fn read_optional_regular_file(path: &Path, max: u64) -> Result<Option<Vec<u8>>, LifecycleError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(LifecycleError::Environment(format!(
            "not a regular file: {}",
            path.display()
        )));
    }
    if metadata.len() > max {
        return Err(LifecycleError::Environment(format!(
            "file exceeds {max} byte limit: {}",
            path.display()
        )));
    }
    Ok(Some(fs::read(path)?))
}

fn backup_config_before_trust(
    config_path: &Path,
    backup_path: &Path,
) -> Result<(), LifecycleError> {
    if fs::symlink_metadata(backup_path).is_ok() {
        return Ok(());
    }
    let Some(config) = read_optional_regular_file(config_path, MAX_CONFIG_BYTES)? else {
        return Ok(());
    };
    if fs::symlink_metadata(backup_path).is_ok() {
        return Ok(());
    }
    write_owned_file(backup_path, &config, false)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), LifecycleError> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    write_owned_file(path, &bytes, false)
}

fn write_owned_file(path: &Path, bytes: &[u8], executable: bool) -> Result<(), LifecycleError> {
    let parent = path
        .parent()
        .ok_or_else(|| LifecycleError::Environment("target has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("delete-denied"),
        std::process::id()
    ));
    remove_file_if_exists(&temp)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    set_user_permissions(&temp, executable)?;
    match fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(error) if path.exists() => {
            fs::remove_file(path)?;
            fs::rename(&temp, path).map_err(|_| error.into())
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn set_user_permissions(path: &Path, executable: bool) -> Result<(), LifecycleError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_user_permissions(_path: &Path, _executable: bool) -> Result<(), LifecycleError> {
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<(), LifecycleError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(not(windows))]
fn remove_installation_dir(path: &Path) -> Result<(), LifecycleError> {
    if path.exists() {
        fs::remove_dir_all(path)?;
    }
    Ok(())
}

#[cfg(windows)]
fn remove_installation_dir(path: &Path) -> Result<(), LifecycleError> {
    use std::process::{Command, Stdio};

    if !path.exists() {
        return Ok(());
    }
    Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command"])
        .arg("Start-Sleep -Milliseconds 500; Remove-Item -LiteralPath $args[0] -Recurse -Force")
        .arg(path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| {
            LifecycleError::Environment(format!(
                "could not start the current-user uninstall cleanup: {error}"
            ))
        })?;
    Ok(())
}

fn hooks_document_is_empty(document: &str) -> Result<bool, LifecycleError> {
    let value: serde_json::Value = serde_json::from_str(document)?;
    let Some(root) = value.as_object() else {
        return Ok(false);
    };
    if root.keys().any(|key| key != "hooks") {
        return Ok(false);
    }
    Ok(root
        .get("hooks")
        .and_then(serde_json::Value::as_object)
        .is_some_and(|hooks| {
            hooks
                .values()
                .all(|value| value.as_array().is_some_and(Vec::is_empty))
        }))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{StatusReport, backup_config_before_trust, status_from_hook_states};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn config_backup_preserves_the_first_existing_config() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "delete-denied-config-backup-{}-{unique}",
            std::process::id()
        ));
        let config = root.join(".codex/config.toml");
        let backup = root.join("backups/config.toml.before-trust");
        fs::create_dir_all(config.parent().expect("config parent")).expect("config directory");
        let original = b"[hooks.state]\nexisting = true\n";
        fs::write(&config, original).expect("config");

        backup_config_before_trust(&config, &backup).expect("backup");
        assert_eq!(fs::read(&backup).expect("backup contents"), original);

        fs::write(&config, b"[hooks.state]\nexisting = false\n").expect("updated config");
        backup_config_before_trust(&config, &backup).expect("one-time backup");
        assert_eq!(fs::read(&backup).expect("preserved backup"), original);

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn config_backup_skips_when_config_is_missing() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "delete-denied-config-backup-missing-{}-{unique}",
            std::process::id()
        ));
        let config = root.join(".codex/config.toml");
        let backup = root.join("backups/config.toml.before-trust");

        backup_config_before_trust(&config, &backup).expect("missing config is allowed");
        assert!(!backup.exists());
        assert!(!root.exists());
    }

    #[test]
    fn status_finds_windows_server_key_without_writing_an_alias() {
        let config: toml::Value = r#"
[hooks.state.'C:\Users\alice\.codex\hooks.json:pre_tool_use:0:0']
trusted_hash = "sha256:known"
enabled = true
"#
        .parse()
        .expect("config");
        let status = status_from_hook_states(
            &config,
            r"C:/Users/alice/.codex/hooks.json:pre_tool_use:0:0",
            "sha256:known",
        );
        assert_eq!(status, StatusReport::Enforced);
        assert_eq!(
            config
                .get("hooks")
                .and_then(|hooks| hooks.get("state"))
                .and_then(toml::Value::as_table)
                .expect("hook states")
                .len(),
            1
        );
    }

    #[test]
    fn status_prefers_current_hash_over_stale_equivalent_alias() {
        let config: toml::Value = r#"
[hooks.state.'C:/Users/alice/.codex/hooks.json:pre_tool_use:0:0']
trusted_hash = "sha256:stale"
enabled = true

[hooks.state.'C:\Users\alice\.codex\hooks.json:pre_tool_use:0:0']
trusted_hash = "sha256:known"
enabled = true
"#
        .parse()
        .expect("config");
        assert_eq!(
            status_from_hook_states(
                &config,
                r"C:/Users/alice/.codex/hooks.json:pre_tool_use:0:0",
                "sha256:known",
            ),
            StatusReport::Enforced
        );
    }
}
