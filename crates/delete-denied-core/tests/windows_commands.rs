use delete_denied_core::command::{DeleteKind, Dialect, TargetSyntax, parse_delete_operations};
use delete_denied_core::decision::{Decision, DenyCode, evaluate};
use delete_denied_core::hook_input::HookInput;
use delete_denied_core::path::PathResolver;
use delete_denied_core::policy::Policy;
use delete_denied_core::scan::{ScanResult, fast_scan};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn replace_path_placeholders(value: &mut serde_json::Value, root: &str, canonical_root: &str) {
    match value {
        serde_json::Value::String(text) => {
            *text = text
                .replace("__ROOT__", root)
                .replace("__CANONICAL_ROOT__", canonical_root);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                replace_path_placeholders(value, root, canonical_root);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                replace_path_placeholders(value, root, canonical_root);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

fn inline_runtime_path(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    if cfg!(windows) {
        rendered.replace('\\', "/")
    } else {
        rendered.into_owned()
    }
}

fn one(command: &str, dialect: Dialect) -> delete_denied_core::DeleteOperation {
    let operations = parse_delete_operations(command, dialect);
    assert_eq!(operations.len(), 1, "{command}");
    operations.into_iter().next().expect("one operation")
}

#[test]
fn powershell_remove_item_aliases_and_options_are_inspected() {
    for command in [
        r#"Remove-Item -Recurse -Force "C:\Users\Alice\Documents\old folder""#,
        r#"rm -Force "C:\tmp\old""#,
        r#"ri -Recurse "C:\tmp\old""#,
        r#"del "C:\tmp\old""#,
        r#"erase "C:\tmp\old""#,
    ] {
        assert_eq!(fast_scan(command), ScanResult::Suspicious, "{command}");
        let operation = one(command, Dialect::PowerShell);
        assert_eq!(operation.kind, DeleteKind::Rm, "{command}");
        assert!(!operation.raw_targets.is_empty(), "{command}");
    }

    for command in [r#"rd -Recurse "C:\tmp\old""#, r#"rmdir "C:\tmp\old""#] {
        let operation = one(command, Dialect::PowerShell);
        assert_eq!(operation.kind, DeleteKind::Rmdir, "{command}");
        if command.contains("Recurse") {
            assert!(operation.recursive, "{command}");
        }
    }
}

#[test]
fn powershell_literal_paths_keep_spaces_unicode_and_compounds() {
    let operations = parse_delete_operations(
        r#"Write-Output ok; Remove-Item -LiteralPath 'C:\Temp\café folder' -Force; Remove-Item '\\server\share\old'"#,
        Dialect::PowerShell,
    );
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0].raw_targets, [r#"'C:\Temp\café folder'"#]);
    assert_eq!(operations[1].raw_targets, [r#"'\\server\share\old'"#]);
}

#[test]
fn powershell_command_payloads_are_scanned_without_running_powershell() {
    for command in [
        r#"pwsh -NoProfile -Command "Remove-Item -Recurse -Force 'C:\Users\Alice'""#,
        r#"powershell -Command 'rm -Recurse C:\Users\Alice'"#,
    ] {
        assert_eq!(fast_scan(command), ScanResult::Suspicious, "{command}");
        let operation = one(command, Dialect::PowerShell);
        assert!(operation.recursive, "{command}");
        assert_eq!(operation.kind, DeleteKind::Rm, "{command}");
    }
}

#[test]
fn cmd_delete_aliases_switches_and_compounds_are_inspected() {
    for command in [
        r#"del /s /q "C:\Users\Alice\old folder\*.*""#,
        r#"erase /q "C:\tmp\old.txt""#,
    ] {
        assert_eq!(fast_scan(command), ScanResult::Suspicious, "{command}");
        let operation = one(command, Dialect::Cmd);
        assert_eq!(operation.kind, DeleteKind::Rm, "{command}");
        assert!(!operation.raw_targets.is_empty(), "{command}");
    }
    for command in [r#"rd /s /q "C:\tmp\old""#, r#"rmdir /q "C:\tmp\old""#] {
        let operation = one(command, Dialect::Cmd);
        assert_eq!(operation.kind, DeleteKind::Rmdir, "{command}");
        if command.contains("/s") {
            assert!(operation.recursive, "{command}");
        }
    }

    let operations = parse_delete_operations(
        r#"echo ok && del /q "C:\Temp\café.txt" || rmdir /s "\\server\share\old""#,
        Dialect::Cmd,
    );
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0].raw_targets, [r#""C:\Temp\café.txt""#]);
    assert_eq!(operations[1].raw_targets, [r#""\\server\share\old""#]);
}

#[test]
fn cmd_c_payloads_are_scanned_without_running_cmd() {
    for command in [
        r#"cmd /c "del /s /q C:\Users\Alice\*.*""#,
        r#"cmd.exe /c "rmdir /s /q \\server\share\old""#,
    ] {
        assert_eq!(fast_scan(command), ScanResult::Suspicious, "{command}");
        let operation = one(command, Dialect::Cmd);
        assert!(operation.recursive, "{command}");
    }
}

#[test]
fn windows_dynamic_recursive_targets_are_ambiguous() {
    for (command, dialect) in [
        (r#"Remove-Item -Recurse $target"#, Dialect::PowerShell),
        (
            r#"Remove-Item -Recurse (Get-Item $target)"#,
            Dialect::PowerShell,
        ),
        (r#"rd /s %TARGET%"#, Dialect::Cmd),
    ] {
        let operation = one(command, dialect);
        assert!(operation.recursive, "{command}");
        assert!(operation.ambiguous, "{command}");
    }
}

#[test]
fn powershell_attached_path_options_capture_literal_targets() {
    for command in [
        r#"Remove-Item -Path:C:\Users\Alice -Recurse"#,
        r#"rm -LiteralPath:C:\Users\Alice -Force -Recurse"#,
    ] {
        let operation = one(command, Dialect::PowerShell);
        assert_eq!(operation.raw_targets, [r#"C:\Users\Alice"#], "{command}");
        assert!(operation.recursive, "{command}");
        assert!(!operation.ambiguous, "{command}");
        assert_eq!(operation.target_syntax, TargetSyntax::Windows, "{command}");
    }
}

#[test]
fn powershell_missing_attached_option_values_fail_closed() {
    for command in [
        r#"Remove-Item -Path:"#,
        r#"Remove-Item -Path: -Recurse"#,
        r#"Remove-Item -LiteralPath: -Force"#,
    ] {
        let operation = one(command, Dialect::PowerShell);
        assert!(operation.ambiguous, "{command}");
    }
}

#[test]
fn powershell_tilde_targets_are_ambiguous_for_recursive_deletion() {
    for command in [
        r#"Remove-Item -Recurse ~"#,
        r#"Remove-Item -Recurse ~/Documents"#,
        r#"Remove-Item -Recurse ~\Documents"#,
        r#"pwsh -Command "Remove-Item -Recurse ~""#,
    ] {
        let operation = one(command, Dialect::PowerShell);
        assert!(operation.recursive, "{command}");
        assert!(operation.ambiguous, "{command}");
    }
}

fn nested_powershell(depth: usize) -> String {
    let mut command = String::from(r#"Remove-Item -Recurse C:\Users\Alice"#);
    for _ in 0..depth {
        command = format!("pwsh -Command \"{}\"", escape_nested_quotes(&command));
    }
    command
}

fn nested_cmd(depth: usize) -> String {
    let mut command = String::from(r#"rd /s /q C:\Users\Alice"#);
    for _ in 0..depth {
        command = format!("cmd /c \"{}\"", escape_nested_quotes(&command));
    }
    command
}

fn escape_nested_quotes(command: &str) -> String {
    let mut escaped = String::new();
    let mut chars = command.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\' {
            if chars.peek() == Some(&'"') {
                escaped.push_str("\\\\");
            } else {
                escaped.push(character);
            }
        } else if character == '"' {
            escaped.push('\\');
            escaped.push(character);
        } else {
            escaped.push(character);
        }
    }
    escaped
}

#[test]
fn windows_interpreter_recursion_is_bounded_without_resetting_depth() {
    let nested_powershell = one(&nested_powershell(2), Dialect::PowerShell);
    assert!(!nested_powershell.ambiguous);
    let nested_cmd = one(&nested_cmd(2), Dialect::Cmd);
    assert!(!nested_cmd.ambiguous);
}

#[test]
fn unrelated_windows_words_are_not_claimed_as_deletions() {
    for (command, dialect) in [
        (r#"Write-Output "Remove-Item""#, Dialect::PowerShell),
        (r#"echo del /s"#, Dialect::Cmd),
    ] {
        assert!(
            parse_delete_operations(command, dialect).is_empty(),
            "{command}"
        );
    }
}

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    cwd: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "delete-denied-task4-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos(),
            sequence,
        ));
        let home = root.join("Users/alice");
        let project = home.join("Documents/project");
        let cwd = project.join("src");
        fs::create_dir_all(&cwd).expect("fixture should be creatable");
        Self {
            root,
            home,
            project,
            cwd,
        }
    }

    fn policy(&self) -> Policy {
        let mut value: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/policy-macos.json"))
                .expect("fixture policy should be valid JSON");
        let root = self.root.to_string_lossy();
        let canonical_path =
            fs::canonicalize(&self.root).expect("fixture root should canonicalize");
        let canonical_root = canonical_path.to_string_lossy();
        replace_path_placeholders(&mut value, &root, &canonical_root);
        let raw = serde_json::to_vec(&value).expect("fixture policy should serialize");
        Policy::from_reader(raw.as_slice()).expect("fixture policy should parse")
    }

    fn input(&self, command: &str) -> HookInput {
        HookInput {
            cwd: self.cwd.clone(),
            command: command.to_owned(),
            permission_mode: Some("danger-full-access".to_owned()),
        }
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

impl PathResolver for FixtureResolver {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        assert!(
            path == self.root
                || path.starts_with(&self.root)
                || path == self.root.parent().unwrap(),
            "fixture resolver must stay inside fixture root: {}",
            path.display()
        );
        fs::canonicalize(path)
    }
}

#[test]
fn windows_and_inline_operations_feed_the_same_fixture_path_decisions() {
    let fixture = Fixture::new();
    let resolver = FixtureResolver {
        root: fixture.root.clone(),
    };
    let policy = fixture.policy();
    let native_home = fixture.home.to_string_lossy();
    let inline_home = inline_runtime_path(&fixture.home);
    if cfg!(windows) {
        assert!(native_home.contains('\\'));
        assert!(!inline_home.contains('\\'));
    }
    for command in [
        format!("Remove-Item -Recurse -Force \"{native_home}\""),
        format!("Remove-Item -Path:{native_home} -Recurse"),
        format!("rm -LiteralPath:{native_home} -Recurse"),
        format!("cmd /c \"rd /s /q {native_home}\""),
        r#"Remove-Item -Recurse $env:USERPROFILE"#.to_owned(),
        r#"Remove-Item -Recurse $env:USERPROFILE\Documents"#.to_owned(),
        r#"Remove-Item -Recurse ${USERPROFILE}\Documents"#.to_owned(),
        r#"Remove-Item -Recurse %USERPROFILE%"#.to_owned(),
        r#"cmd /c "rd /s /q %USERPROFILE%\Documents""#.to_owned(),
        r#"cmd /c "rd /s /q %USERPROFILE%""#.to_owned(),
        format!("node -e \"fs.rm('{inline_home}', {{ recursive: true }})\""),
        format!("python -c \"shutil.rmtree('{inline_home}')\""),
    ] {
        let decision = evaluate(&fixture.input(&command), &policy, &resolver);
        assert_eq!(decision.code(), Some(DenyCode::ProtectedPath), "{command}");
    }
    let mut ancestor_input = fixture.input(r#"Remove-Item -Recurse Documents\.."#);
    ancestor_input.cwd = fixture.home.clone();
    assert_eq!(
        evaluate(&ancestor_input, &policy, &resolver).code(),
        Some(DenyCode::CwdAncestor)
    );
    let inline_build = inline_runtime_path(&fixture.project.join("build"));
    for command in [
        format!(
            "Remove-Item -Recurse \"{}\"",
            fixture.project.join("build").display()
        ),
        format!("node -e \"fs.rm('{inline_build}', {{ recursive: true }})\""),
        format!("python -c \"shutil.rmtree('{inline_build}')\""),
        r#"Remove-Item -Recurse $env:USERPROFILE\Documents\project\src\child"#.to_owned(),
    ] {
        assert_eq!(
            evaluate(&fixture.input(&command), &policy, &resolver),
            Decision::Allow,
            "{command}"
        );
    }
}
