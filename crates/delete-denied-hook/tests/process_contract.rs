use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    cwd: PathBuf,
    policy: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let sequence = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let unique = format!(
            "delete-denied-hook-process-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos(),
            sequence,
        );
        let root = std::env::temp_dir().join(unique);
        let users_parent = root.join("Users");
        let home = users_parent.join("alice");
        let project = home.join("Documents/project");
        let cwd = project.join("src");
        fs::create_dir_all(&cwd).expect("fixture directories should be creatable");
        fs::create_dir_all(home.join("Desktop")).expect("desktop should be creatable");
        fs::create_dir_all(home.join("Downloads")).expect("downloads should be creatable");

        let policy = root.join("policy.json");
        let path = |value: &Path| json_string(&logical_path_text(value));
        let canonical = |value: &Path| {
            let value = fs::canonicalize(value).expect("fixture path should canonicalize");
            json_string(
                value
                    .to_str()
                    .expect("canonical fixture path should be UTF-8"),
            )
        };
        let policy_text = format!(
            r#"{{
  "schema_version": 1,
  "variables": {{
    "HOME": {home},
    "USERPROFILE": {home}
  }},
  "protected_paths": [
    {{"kind":"filesystem-root","logical":{root},"canonical":{canonical_root},"case_sensitive":true}},
    {{"kind":"users-parent","logical":{users_parent},"canonical":{canonical_users_parent},"case_sensitive":true}},
    {{"kind":"home","logical":"${{HOME}}","canonical":{canonical_home},"case_sensitive":false}},
    {{"kind":"documents","logical":"${{HOME}}/Documents","canonical":{canonical_documents},"case_sensitive":false}},
    {{"kind":"desktop","logical":"${{HOME}}/Desktop","canonical":{canonical_desktop},"case_sensitive":false}},
    {{"kind":"downloads","logical":"${{HOME}}/Downloads","canonical":{canonical_downloads},"case_sensitive":false}}
  ]
}}
"#,
            root = path(&root),
            canonical_root = canonical(&root),
            users_parent = path(&users_parent),
            canonical_users_parent = canonical(&users_parent),
            home = path(&home),
            canonical_home = canonical(&home),
            canonical_documents = canonical(&home.join("Documents")),
            canonical_desktop = canonical(&home.join("Desktop")),
            canonical_downloads = canonical(&home.join("Downloads")),
        );
        fs::write(&policy, policy_text).expect("fixture policy should be writable");
        Self {
            root,
            home,
            project,
            cwd,
            policy,
        }
    }

    fn hook_json(&self, command: &str) -> String {
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":{},"permission_mode":"danger-full-access","tool_input":{{"command":{}}}}}"#,
            json_string(&logical_path_text(&self.cwd)),
            json_string(command),
        )
    }

    fn snapshot(&self) -> Vec<PathBuf> {
        let mut entries = fs::read_dir(&self.root)
            .expect("fixture root should be readable")
            .map(|entry| entry.expect("fixture entry should be readable").path())
            .collect::<Vec<_>>();
        entries.sort();
        entries
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn logical_path_text(path: &Path) -> String {
    let value = path.to_string_lossy();
    if value
        .get(..r"\\?\UNC\".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        format!(r"\\{}", &value[r"\\?\UNC\".len()..])
    } else if value
        .get(..r"\\?\".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\"))
    {
        value[r"\\?\".len()..].to_owned()
    } else {
        value.into_owned()
    }
}

fn shell_path_text(path: &Path) -> String {
    logical_path_text(path).replace('\\', "/")
}

#[test]
fn fixture_policy_uses_json_safe_logical_and_canonical_paths() {
    let fixture = Fixture::new();
    let policy: serde_json::Value = serde_json::from_slice(
        &fs::read(&fixture.policy).expect("fixture policy should be readable"),
    )
    .expect("fixture policy should be valid JSON");

    assert_eq!(
        policy
            .pointer("/variables/HOME")
            .and_then(serde_json::Value::as_str),
        Some(logical_path_text(&fixture.home).as_str())
    );

    let home = policy
        .get("protected_paths")
        .and_then(serde_json::Value::as_array)
        .and_then(|paths| {
            paths
                .iter()
                .find(|entry| entry.get("kind").and_then(serde_json::Value::as_str) == Some("home"))
        })
        .expect("fixture policy should contain the home path");
    assert_eq!(
        home.get("canonical").and_then(serde_json::Value::as_str),
        Some(
            fs::canonicalize(&fixture.home)
                .expect("fixture home should canonicalize")
                .to_str()
                .expect("canonical fixture home should be UTF-8")
        )
    );
}

#[test]
fn logical_path_text_normalizes_windows_verbatim_prefixes() {
    assert_eq!(
        logical_path_text(Path::new(r"\\?\C:\Users\Alice\Documents")),
        r"C:\Users\Alice\Documents"
    );
    assert_eq!(
        shell_path_text(Path::new(r"\\?\UNC\server\share\Documents")),
        "//server/share/Documents"
    );
    assert_eq!(logical_path_text(Path::new("/tmp/project")), "/tmp/project");
}

fn run(binary: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(binary)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hook process should start");
    child
        .stdin
        .take()
        .expect("hook stdin should be available")
        .write_all(input.as_bytes())
        .expect("hook stdin should be writable");
    child.wait_with_output().expect("hook process should exit")
}

fn assert_bounded_denial(output: &Output) {
    assert!(output.status.success(), "structured denials use exit 0");
    assert!(
        output.stderr.is_empty(),
        "hook must not write unbounded stderr"
    );
    assert!(
        output.stdout.len() <= 4_096,
        "denial output must be bounded"
    );
    let text = std::str::from_utf8(&output.stdout).expect("denial output should be UTF-8");
    assert!(text.starts_with("{\"hookSpecificOutput\":"));
    assert!(text.contains("\"hookEventName\":\"PreToolUse\""));
    assert!(text.contains("\"permissionDecision\":\"deny\""));
    assert!(text.ends_with("}"));
}

#[test]
fn safe_command_does_not_require_policy_access() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let missing_policy = fixture.root.join("does-not-exist.json");
    let unreadable_policy = fixture.root.join("policy-directory");
    fs::create_dir(&unreadable_policy).expect("policy directory should be creatable");
    for policy in [&missing_policy, &unreadable_policy] {
        let output = run(
            binary,
            &["--policy", policy.to_str().expect("path is UTF-8")],
            &fixture.hook_json("cargo test"),
        );
        assert!(output.status.success());
        assert!(output.stdout.is_empty(), "stdout={:?}", output.stdout);
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn suspicious_protected_target_is_denied_without_stderr() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let output = run(
        binary,
        &["--policy", fixture.policy.to_str().expect("path is UTF-8")],
        &fixture.hook_json(&format!("rm -rf {}", shell_path_text(&fixture.home))),
    );
    assert_bounded_denial(&output);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("DD-PROTECTED-PATH"),
        "stdout={:?}",
        output.stdout
    );
}

#[test]
fn nested_find_and_xargs_deletes_return_structured_denial() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let policy = ["--policy", fixture.policy.to_str().expect("path is UTF-8")];

    for command in [
        r#"find "$HOME" -exec rm -rf -- {} \;"#,
        r#"printf '%s\n' x | xargs sh -c 'rm -rf -- "$@"' sh"#,
    ] {
        let output = run(binary, &policy, &fixture.hook_json(command));
        assert_bounded_denial(&output);
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("DD-AMBIGUOUS-RECURSIVE"),
            "stdout={:?}",
            output.stdout
        );
    }
}

#[test]
fn suspicious_project_descendant_is_allowed_silently() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let target = fixture.project.join("build");
    fs::create_dir_all(&target).expect("project fixture should be writable");
    let output = run(
        binary,
        &["--policy", fixture.policy.to_str().expect("path is UTF-8")],
        &fixture.hook_json(&format!("rm -rf {}", shell_path_text(&target))),
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty(), "stdout={:?}", output.stdout);
    assert!(output.stderr.is_empty());
}

#[test]
fn policy_argument_must_be_exactly_one_absolute_path() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let input = fixture.hook_json("git status");
    for args in [
        vec!["--policy"],
        vec!["--policy", "relative-policy.json"],
        vec![
            "--policy",
            fixture.policy.to_str().expect("path is UTF-8"),
            "--policy",
            fixture.policy.to_str().expect("path is UTF-8"),
        ],
    ] {
        let output = run(binary, &args, &input);
        assert_bounded_denial(&output);
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("DD-POLICY-INVALID"),
            "stdout={:?}",
            output.stdout
        );
    }
}

#[test]
fn malformed_and_oversized_inputs_fail_closed_with_bounded_json() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let policy_arg = ["--policy", fixture.policy.to_str().expect("path is UTF-8")];

    for input in [
        "not json".to_owned(),
        fixture
            .hook_json("git status")
            .replace("PreToolUse", "PostToolUse"),
        fixture
            .hook_json("git status")
            .replace("\"Bash\"", "\"Read\""),
        fixture
            .hook_json("git status")
            .replace("PreToolUse", &"X".repeat(10_000)),
        "x".repeat(262_145),
        fixture.hook_json(&("rm ".to_owned() + &"x".repeat(65_537))),
    ] {
        let output = run(binary, &policy_arg, &input);
        assert_bounded_denial(&output);
    }

    let huge_event = fixture
        .hook_json("git status")
        .replace("PreToolUse", &"X".repeat(10_000));
    let output = run(binary, &policy_arg, &huge_event);
    assert!(String::from_utf8_lossy(&output.stdout).contains("DD-HOOK-UNSUPPORTED"));
}

#[test]
fn missing_invalid_and_oversized_policy_fail_closed() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let missing = fixture.root.join("missing.json");
    let invalid = fixture.root.join("invalid.json");
    let oversized = fixture.root.join("oversized.json");
    fs::write(&invalid, b"not json").expect("invalid policy should be writable");
    fs::write(&oversized, vec![b' '; 16_385]).expect("oversized policy should be writable");
    let input = fixture.hook_json("rm -rf /never-resolve");

    for policy in [&missing, &invalid, &oversized] {
        let output = run(
            binary,
            &["--policy", policy.to_str().expect("path is UTF-8")],
            &input,
        );
        assert_bounded_denial(&output);
        assert!(String::from_utf8_lossy(&output.stdout).contains("DD-POLICY-INVALID"));
    }
}

#[test]
fn hook_does_not_create_logs_state_or_manifest_artifacts() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let before = fixture.snapshot();
    let output = run(
        binary,
        &["--policy", fixture.policy.to_str().expect("path is UTF-8")],
        &fixture.hook_json(&format!("rm -rf {}", shell_path_text(&fixture.home))),
    );
    assert_bounded_denial(&output);
    assert_eq!(before, fixture.snapshot());
}

#[test]
fn repeated_invocations_have_deterministic_exit_and_output() {
    let fixture = Fixture::new();
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied-hook"));
    let args = ["--policy", fixture.policy.to_str().expect("path is UTF-8")];
    let input = fixture.hook_json(&format!("rm -rf {}", shell_path_text(&fixture.home)));
    let first = run(binary, &args, &input);
    let second = run(binary, &args, &input);
    assert_eq!(first.status.code(), second.status.code());
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.stderr, second.stderr);
}
