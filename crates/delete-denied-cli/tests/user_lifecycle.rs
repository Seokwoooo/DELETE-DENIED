use delete_denied_cli::commands::{
    ArtifactSource, Lifecycle, STATUS_AWAITING_TRUST, STATUS_INACTIVE, STATUS_SUSPENDED,
    StatusReport,
};
use delete_denied_cli::hooks::{HookRegistration, hook_identity};
use delete_denied_cli::platform::{
    Architecture, LoginIdentity, ManagementPaths, PathPair, Platform, PlatformPaths,
    PlatformProvider, PlatformSnapshot,
};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

struct Artifacts;

impl ArtifactSource for Artifacts {
    fn cli_bytes(&self, _platform: Platform) -> Result<Vec<u8>, delete_denied_cli::LifecycleError> {
        Ok(b"fixture cli".to_vec())
    }

    fn hook_bytes(
        &self,
        _platform: Platform,
    ) -> Result<Vec<u8>, delete_denied_cli::LifecycleError> {
        Ok(b"fixture hook".to_vec())
    }
}

struct Fixture(PlatformSnapshot);

impl PlatformProvider for Fixture {
    fn snapshot(&self) -> Result<PlatformSnapshot, delete_denied_cli::platform::DiscoveryError> {
        Ok(self.0.clone())
    }
}

fn pair(path: impl AsRef<Path>) -> PathPair {
    PathPair::unchecked(
        path.as_ref().to_path_buf(),
        path.as_ref().to_path_buf(),
        true,
    )
}

fn fixture_paths(root: &Path) -> PlatformPaths {
    let user_parent = root.join("Users");
    let home = user_parent.join("alice");
    let codex = home.join(".codex");
    let data = codex.join("delete-denied");
    let bin = data.join("bin");
    fs::create_dir_all(&codex).unwrap();
    PlatformPaths::discover(&Fixture(PlatformSnapshot {
        platform: Platform::MacOs,
        architecture: Architecture::Arm64,
        login: LoginIdentity::new("alice", &home),
        home: pair(&home),
        inherited_home: Some(home.clone()),
        user_parent: pair(&user_parent),
        filesystem_roots: vec![pair(Path::new("/"))],
        volume_roots: vec![],
        share_roots: vec![],
        documents: pair(home.join("Documents")),
        desktop: pair(home.join("Desktop")),
        downloads: pair(home.join("Downloads")),
        redirected_paths: vec![],
        codex_dir: pair(&codex),
        management: ManagementPaths {
            hooks_dir: pair(&codex),
            hooks: pair(codex.join("hooks.json")),
            binary_dir: pair(&bin),
            cli_binary: pair(bin.join("delete-denied")),
            hook_binary: pair(bin.join("delete-denied-hook")),
            data_dir: pair(&data),
            policy: pair(data.join("policy.json")),
            state: pair(data.join("state.json")),
            manifest: pair(data.join("manifest.json")),
            backups: pair(data.join("backups")),
        },
    }))
    .unwrap()
}

#[test]
fn current_user_install_suspend_resume_and_uninstall_preserve_other_hooks() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "delete-denied-user-lifecycle-{}-{unique}",
        std::process::id()
    ));
    let paths = fixture_paths(&root);
    fs::write(
        &paths.hooks_path.logical,
        r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"echo keep"}]}]}}"#,
    )
    .unwrap();
    let lifecycle = Lifecycle::new(paths.clone(), &Artifacts);

    let installed = lifecycle.install().unwrap();
    assert_eq!(installed.status, StatusReport::AwaitingTrust);
    assert!(installed.message.contains(STATUS_AWAITING_TRUST));
    assert_eq!(lifecycle.status().unwrap(), StatusReport::AwaitingTrust);
    assert!(
        paths
            .backups_path
            .logical
            .join("hooks.json.before-install")
            .is_file()
    );
    assert!(
        fs::read_to_string(&paths.hooks_path.logical)
            .unwrap()
            .contains("echo keep")
    );

    let suspended = lifecycle.suspend().unwrap();
    assert_eq!(suspended.status, StatusReport::Suspended);
    assert_eq!(suspended.message, STATUS_SUSPENDED);
    assert_eq!(lifecycle.status().unwrap(), StatusReport::Suspended);
    assert!(
        fs::read_to_string(&paths.hooks_path.logical)
            .unwrap()
            .contains("echo keep")
    );

    let updated_while_suspended = lifecycle.update_with_trust(true).unwrap();
    assert_eq!(updated_while_suspended.status, StatusReport::Suspended);

    lifecycle.resume().unwrap();
    assert_eq!(lifecycle.status().unwrap(), StatusReport::AwaitingTrust);
    lifecycle.uninstall().unwrap();
    assert!(!paths.data_dir.logical.exists());
    let remaining = fs::read_to_string(&paths.hooks_path.logical).unwrap();
    assert!(remaining.contains("echo keep"));
    assert!(!remaining.contains("DELETE-DENIED"));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn activation_requires_exact_codex_trust_and_enabled_state() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "delete-denied-trust-activation-{}-{unique}",
        std::process::id()
    ));
    let paths = fixture_paths(&root);
    let lifecycle = Lifecycle::new(paths.clone(), &Artifacts);
    let config_path = paths.codex_dir.logical.join("config.toml");
    let original_config =
        "[hooks.state.\"/other/hooks.json:pre_tool_use:0:0\"]\ntrusted_hash = \"sha256:other\"\n";
    fs::write(&config_path, original_config).unwrap();

    assert_eq!(
        lifecycle.install().unwrap().status,
        StatusReport::AwaitingTrust
    );
    assert_eq!(fs::read_to_string(&config_path).unwrap(), original_config);
    let hooks = fs::read_to_string(&paths.hooks_path.logical).unwrap();
    let identity = hook_identity(&hooks, &paths.hooks_path.logical, &registration(&paths))
        .unwrap()
        .unwrap();
    write_codex_state(&paths, &identity.key, &identity.hash, None);
    assert_eq!(lifecycle.status().unwrap(), StatusReport::Enforced);

    write_codex_state(&paths, &identity.key, "sha256:stale", None);
    assert_eq!(lifecycle.status().unwrap(), StatusReport::AwaitingTrust);

    write_codex_state(&paths, &identity.key, &identity.hash, Some(false));
    assert_eq!(lifecycle.status().unwrap(), StatusReport::Inactive);
    let doctor = lifecycle.doctor().unwrap();
    assert!(doctor.contains(STATUS_INACTIVE));
    assert!(doctor.contains("Run `delete-denied update --trust` to re-enable this hook."));

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn codex_hook_identity_matches_known_hash() {
    let command = "\"/Users/alice/.codex/delete-denied/bin/delete-denied-hook\" --policy \"/Users/alice/.codex/delete-denied/policy.json\"";
    let registration = HookRegistration::new(command);
    let hooks = format!(
        r#"{{"hooks":{{"PreToolUse":[{{"matcher":"^Bash$","hooks":[{{"type":"command","command":{command:?},"timeout":5,"statusMessage":"DELETE-DENIED: checking shell deletion target"}}]}}]}}}}"#
    );
    let identity = hook_identity(
        &hooks,
        std::path::Path::new("/Users/alice/.codex/hooks.json"),
        &registration,
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        identity.key,
        "/Users/alice/.codex/hooks.json:pre_tool_use:0:0"
    );
    assert_eq!(
        identity.hash,
        "sha256:d6f7268323116259b6a272e97d3978e6d1746ce72a2ca011fa709d6dc90c4c28"
    );
}

fn registration(paths: &PlatformPaths) -> HookRegistration {
    HookRegistration::new(format!(
        "\"{}\" --policy \"{}\"",
        paths.hook_binary_path.logical.display(),
        paths.policy_path.logical.display()
    ))
}

fn write_codex_state(paths: &PlatformPaths, key: &str, hash: &str, enabled: Option<bool>) {
    let enabled = enabled
        .map(|value| format!("enabled = {value}\n"))
        .unwrap_or_default();
    fs::write(
        paths.codex_dir.logical.join("config.toml"),
        format!("[hooks.state.\"{key}\"]\ntrusted_hash = \"{hash}\"\n{enabled}"),
    )
    .unwrap();
}
