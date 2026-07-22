use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use delete_denied_core::command::{Dialect, parse_delete_operations};
use delete_denied_core::decision::{Decision, DenyCode, evaluate};
use delete_denied_core::hook_input::HookInput;
use delete_denied_core::path::PathResolver;
use delete_denied_core::policy::Policy;

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    documents: PathBuf,
    project: PathBuf,
    cwd: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let unique = format!(
            "delete-denied-policy-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos(),
            sequence,
        );
        let root = std::env::temp_dir().join(unique);
        let home = root.join("Users/alice");
        let documents = home.join("Documents");
        let project = documents.join("project");
        let cwd = project.join("src");
        fs::create_dir_all(&cwd).expect("fixture directories should be creatable");
        fs::create_dir_all(project.join("build"))
            .expect("fixture project build should be creatable");
        fs::create_dir_all(home.join("Desktop")).expect("fixture desktop should be creatable");
        fs::create_dir_all(home.join("Downloads")).expect("fixture downloads should be creatable");
        fs::create_dir_all(root.join("project/build"))
            .expect("fixture build directory should be creatable");
        Self {
            root,
            home,
            documents,
            project,
            cwd,
        }
    }

    fn policy(&self) -> Policy {
        let raw = policy_fixture(&self.root);
        Policy::from_reader(raw.as_bytes()).expect("fixture policy should parse")
    }

    fn input(&self, command: &str, cwd: &Path) -> HookInput {
        HookInput {
            cwd: cwd.to_path_buf(),
            command: command.to_owned(),
            permission_mode: Some("danger-full-access".to_owned()),
        }
    }

    fn assert_deny(&self, command: &str, cwd: &Path, code: DenyCode) {
        let policy = self.policy();
        let resolver = FixtureResolver::new(&self.root);
        let decision = evaluate(&self.input(command, cwd), &policy, &resolver);
        assert_eq!(decision.code(), Some(code), "{command}");
    }

    fn assert_allow(&self, command: &str, cwd: &Path) {
        let policy = self.policy();
        let resolver = FixtureResolver::new(&self.root);
        let decision = evaluate(&self.input(command, cwd), &policy, &resolver);
        assert_eq!(decision, Decision::Allow, "{command}");
    }
}

fn policy_fixture(root: &Path) -> String {
    let canonical_root = fs::canonicalize(root).expect("fixture root should canonicalize");
    let mut fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/fixtures/policy-macos.json"))
            .expect("policy fixture should be valid JSON");

    fn replace_paths(value: &mut serde_json::Value, root: &str, canonical_root: &str) {
        match value {
            serde_json::Value::String(string) => {
                *string = string
                    .replace("__CANONICAL_ROOT__", canonical_root)
                    .replace("__ROOT__", root);
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    replace_paths(value, root, canonical_root);
                }
            }
            serde_json::Value::Object(values) => {
                for value in values.values_mut() {
                    replace_paths(value, root, canonical_root);
                }
            }
            serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {
            }
        }
    }

    replace_paths(
        &mut fixture,
        &root.to_string_lossy(),
        &canonical_root.to_string_lossy(),
    );
    serde_json::to_string(&fixture).expect("policy fixture should serialize")
}

fn shell_path(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    if cfg!(windows) {
        rendered.replace('\\', "/")
    } else {
        rendered.into_owned()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct FixtureResolver {
    root: PathBuf,
}

struct NoResolveResolver;

impl PathResolver for NoResolveResolver {
    fn canonicalize(&self, _path: &Path) -> io::Result<PathBuf> {
        panic!("safe scans must not resolve a path");
    }
}

impl FixtureResolver {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
        }
    }
}

impl PathResolver for FixtureResolver {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        let fixture_parent = self.root.parent().expect("fixture root has a parent");
        assert!(
            path == self.root || path.starts_with(&self.root) || path == fixture_parent,
            "resolver must never leave the fixture root: {}",
            path.display()
        );
        fs::canonicalize(path)
    }
}

#[test]
fn policy_is_bounded_and_requires_schema_v1() {
    let fixture = Fixture::new();
    let valid = policy_fixture(&fixture.root);
    assert!(Policy::from_reader(valid.as_bytes()).is_ok());

    let mut oversized = valid;
    oversized.push_str(&" ".repeat(16_385));
    assert!(Policy::from_reader(oversized.as_bytes()).is_err());

    let invalid_schema = r#"{"schema_version":2,"protected_paths":[]}"#;
    assert!(Policy::from_reader(invalid_schema.as_bytes()).is_err());
}

#[test]
fn denies_fixture_root_users_home_and_standard_home_directories() {
    let fixture = Fixture::new();
    fixture.assert_deny(
        &format!("rm -rf {}", shell_path(&fixture.root)),
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_deny(
        &format!("rm -rf {}/Users", shell_path(&fixture.root)),
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_deny(
        &format!("rm -rf {}", shell_path(&fixture.home)),
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    for directory in ["Documents", "Desktop", "Downloads"] {
        fixture.assert_deny(
            &format!("rm -rf {}/{}", shell_path(&fixture.home), directory),
            &fixture.cwd,
            DenyCode::ProtectedPath,
        );
    }
    for command in [
        "rm -rf \"$HOME\"",
        "rm -rf \"${HOME}\"",
        "find \"$HOME\" -delete",
    ] {
        fixture.assert_deny(command, &fixture.cwd, DenyCode::ProtectedPath);
    }
    fixture.assert_deny(
        &format!("rm -rf {}/..", shell_path(&fixture.root)),
        &fixture.cwd,
        // This overlaps cwd ancestry; the evaluator gives that stable code
        // precedence while still denying the parent containing the fixture.
        DenyCode::CwdAncestor,
    );
}

#[test]
fn denies_home_contents_glob_and_canonical_symlink_target() {
    let fixture = Fixture::new();
    fixture.assert_deny(
        &format!("rm -rf {}/Documents/*", shell_path(&fixture.home)),
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "rm -rf \"$HOME\"/*",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );

    #[cfg(unix)]
    {
        let link = fixture.root.join("home-link");
        std::os::unix::fs::symlink(&fixture.home, &link).expect("fixture symlink should work");
        fixture.assert_deny(
            &format!("rm -rf {}", shell_path(&link)),
            &fixture.cwd,
            DenyCode::ProtectedPath,
        );
    }
}

#[test]
fn denies_cwd_and_every_cwd_ancestor_without_string_prefix_false_positive() {
    let fixture = Fixture::new();
    let project = shell_path(&fixture.project);
    for target in [".", "..", "../..", "../../..", project.as_str()] {
        fixture.assert_deny(
            &format!("rm -rf {target}"),
            &fixture.cwd,
            DenyCode::CwdAncestor,
        );
    }

    fixture.assert_allow(
        &format!("rm -rf {}/projector/build", shell_path(&fixture.documents)),
        &fixture.cwd,
    );
}

#[test]
fn denies_unknown_recursive_and_opaque_suspicious_commands() {
    let fixture = Fixture::new();
    fixture.assert_deny(
        "rm -rf \"$UNKNOWN\"",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "rm \"$UNKNOWN\"/*.tmp",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "env -S 'rm -rf /never-resolve'",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
}

#[test]
fn tracks_cd_context_for_following_deletion_segments() {
    let fixture = Fixture::new();
    fixture.assert_deny(
        "cd \"$HOME\" && git clean -fdx",
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_deny(
        "cd \"$HOME\" && rm -rf Documents",
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_allow("cd .. && rm -rf ./build", &fixture.cwd);
    fixture.assert_deny(
        "cd \"$UNKNOWN\" && rm -rf ./build",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
}

#[test]
fn nested_shells_preserve_deletion_context() {
    let fixture = Fixture::new();
    let safe = fixture.project.join("build");
    fixture.assert_deny(
        "bash -c 'cd \"$HOME\" && git clean -fdx'",
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_deny(
        "sh -c 'cd \"$HOME\" && rm -rf Documents'",
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_allow(
        &format!("sh -c 'HOME={}; rm -rf \"$HOME\"'", shell_path(&safe)),
        &fixture.cwd,
    );
    fixture.assert_deny(
        "sh -c 'git -C \"$HOME\" clean -fdx'",
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_deny(
        "bash -lc 'rm -rf \"$HOME\"'",
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
}

#[test]
fn denies_nested_find_and_xargs_shell_deletes_as_ambiguous() {
    let fixture = Fixture::new();
    for command in [
        r#"find "$HOME" -exec rm -rf -- {} \;"#,
        r#"find "$HOME" -execdir rm -rf -- {} \;"#,
        r#"find "$HOME" -ok rm -rf -- {} \;"#,
        r#"find "$HOME" -okdir rm -rf -- {} \;"#,
        r#"find "$HOME" -execdir sh -c 'rm -rf -- "$1"' sh {} \;"#,
        r#"printf '%s\n' x | xargs sh -c 'rm -rf -- "$@"' sh"#,
    ] {
        fixture.assert_deny(command, &fixture.cwd, DenyCode::AmbiguousRecursive);
    }
}

#[test]
fn denies_find_delete_after_escaped_exec_plus_and_unbalanced_nested_shells() {
    let fixture = Fixture::new();
    fixture.assert_deny(
        r#"find . -exec echo {} \+ -delete"#,
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    for command in [
        r#"find . -execdir sh -c 'rm -rf -- "$1" sh {} \;"#,
        r#"printf '%s\n' x | xargs sh -c 'rm -rf -- "$@" sh"#,
    ] {
        fixture.assert_deny(command, &fixture.cwd, DenyCode::AmbiguousRecursive);
    }
}

#[test]
fn safe_nested_shell_commands_are_not_suspicious() {
    let fixture = Fixture::new();
    fixture.assert_allow("sh -c 'echo safe'", &fixture.cwd);
    fixture.assert_allow("bash -c 'cargo test'", &fixture.cwd);
}

#[test]
fn rsync_only_treats_destination_as_the_deletion_target() {
    let fixture = Fixture::new();
    fixture.assert_allow(
        &format!(
            "rsync --delete {}/ {}/backup/",
            shell_path(&fixture.home),
            shell_path(&fixture.project)
        ),
        &fixture.cwd,
    );
    fixture.assert_deny(
        &format!(
            "rsync --delete {}/empty/ {}/",
            shell_path(&fixture.project),
            shell_path(&fixture.home)
        ),
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_allow(
        &format!(
            "rsync --delete {}/empty/ {}/backup/",
            shell_path(&fixture.project),
            shell_path(&fixture.project)
        ),
        &fixture.cwd,
    );
    fixture.assert_allow(
        &format!(
            "rsync --delete \"$UNKNOWN\"/ {}/backup/",
            shell_path(&fixture.project)
        ),
        &fixture.cwd,
    );
    fixture.assert_deny(
        &format!(
            "rsync --delete {}/ \"$HOME\"/ --exclude '*.tmp'",
            shell_path(&fixture.project)
        ),
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_allow(
        &format!(
            "rsync --delete {}/ {}/backup/ --exclude '*.tmp'",
            shell_path(&fixture.project),
            shell_path(&fixture.project)
        ),
        &fixture.cwd,
    );
}

#[test]
fn applies_only_prior_standalone_assignments_to_target_expansion() {
    let fixture = Fixture::new();
    let safe = fixture.project.join("build");
    fixture.assert_allow(
        &format!("HOME={}; rm -rf \"$HOME\"/child", shell_path(&safe)),
        &fixture.cwd,
    );
    fixture.assert_allow(
        &format!("HOME={}; rm -rf \"$HOME\"", shell_path(&safe)),
        &fixture.cwd,
    );
    fixture.assert_deny(
        &format!("env HOME={} rm -rf \"$HOME\"", shell_path(&safe)),
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_deny(
        "HOME=$UNKNOWN; rm -rf \"$HOME\"",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_allow("HOME=$UNKNOWN; rm \"$HOME/file\"", &fixture.cwd);
    fixture.assert_allow(
        &format!(
            "HOME=$UNKNOWN; HOME={}; rm -rf \"$HOME\"",
            shell_path(&safe)
        ),
        &fixture.cwd,
    );
}

#[test]
fn unknown_cwd_skips_only_unresolved_single_file_operations() {
    let fixture = Fixture::new();
    fixture.assert_allow("cd \"$UNKNOWN\"; rm ./file.txt", &fixture.cwd);
    fixture.assert_allow("cd \"$UNKNOWN\"; unlink ./file.txt", &fixture.cwd);
    fixture.assert_deny(
        "cd \"$UNKNOWN\"; rm ./a ./b",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "cd \"$UNKNOWN\"; rmdir ./dir",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "cd \"$UNKNOWN\"; xargs rm ./a",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "cd \"$UNKNOWN\"; rm ./*.tmp",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "cd \"$UNKNOWN\"; rm \"$HOME\"",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "cd \"$UNKNOWN\"; rm ./file.txt; rm -rf \"$HOME\"",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
    fixture.assert_deny(
        "cd \"$UNKNOWN\"; git clean -f",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
}

#[test]
fn pipeline_context_does_not_leak_assignments() {
    let fixture = Fixture::new();
    let safe = fixture.project.join("build");
    fixture.assert_deny(
        &format!("HOME={} | rm -rf \"$HOME\"", shell_path(&safe)),
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
}

#[test]
fn git_clean_honors_literal_or_dynamic_cwd_override() {
    let fixture = Fixture::new();
    fixture.assert_deny(
        "git -C \"$HOME\" clean -fdx",
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_allow(
        &format!("git -C {} clean -fdx", shell_path(&fixture.project)),
        &fixture.cwd,
    );
    fixture.assert_deny(
        &format!(
            "git -C {} -C \"$HOME\" clean -fdx",
            shell_path(&fixture.project)
        ),
        &fixture.cwd,
        DenyCode::ProtectedPath,
    );
    fixture.assert_allow(
        &format!(
            "git -C {} -C build clean -fdx",
            shell_path(&fixture.project)
        ),
        &fixture.cwd,
    );
    fixture.assert_deny(
        "git -C \"$UNKNOWN\" clean -f",
        &fixture.cwd,
        DenyCode::AmbiguousRecursive,
    );
}

#[test]
fn denies_git_clean_at_simulated_home_but_allows_project_git_clean() {
    let fixture = Fixture::new();
    fixture.assert_deny("git clean -fdx", &fixture.home, DenyCode::ProtectedPath);
    fixture.assert_allow("git clean -fdx", &fixture.project);
}

#[test]
fn allows_concrete_project_descendants_normal_children_and_non_deletion_commands() {
    let fixture = Fixture::new();
    fixture.assert_allow(
        &format!("rm -rf {}/build", shell_path(&fixture.project)),
        &fixture.cwd,
    );
    fixture.assert_allow("rm -f ./old-file.txt", &fixture.cwd);
    fixture.assert_allow("mv ./old-file.txt ./new-file.txt", &fixture.cwd);
    fixture.assert_allow("rm \"$UNKNOWN/file.txt\"", &fixture.cwd);
    fixture.assert_allow("echo rm -rf ./build", &fixture.cwd);
}

#[test]
fn safe_scan_allows_without_policy_path_resolution() {
    let fixture = Fixture::new();
    let policy = fixture.policy();
    let input = fixture.input("cargo test", &fixture.cwd);
    assert_eq!(
        evaluate(&input, &policy, &NoResolveResolver),
        Decision::Allow
    );
}

#[test]
fn parser_operations_are_the_same_inputs_evaluate_consumes() {
    let operations = parse_delete_operations("rm -rf ./build", Dialect::Posix);
    assert_eq!(operations.len(), 1);
    assert!(operations[0].recursive);
}
