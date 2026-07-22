use delete_denied_core::command::{DeleteKind, Dialect, parse_delete_operations};
use delete_denied_core::decision::{Decision, DenyCode, evaluate};
use delete_denied_core::hook_input::HookInput;
use delete_denied_core::path::PathResolver;
use delete_denied_core::policy::{Policy, ProtectedPath};
use delete_denied_core::scan::{ScanResult, fast_scan};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

fn one(command: &str) -> delete_denied_core::DeleteOperation {
    let operations = parse_delete_operations(command, Dialect::Posix);
    assert_eq!(operations.len(), 1, "{command}");
    operations.into_iter().next().expect("one operation")
}

#[test]
fn node_inline_literal_delete_apis_are_inspected() {
    for (command, kind, recursive) in [
        (
            r#"node -e "fs.rm('/tmp/old', { recursive: true })""#,
            DeleteKind::Rm,
            true,
        ),
        (
            r#"node --eval "fs.rmSync(\"./build\")""#,
            DeleteKind::Rm,
            false,
        ),
        (
            r#"node -e "fs.rmdir('/tmp/empty')""#,
            DeleteKind::Rmdir,
            false,
        ),
        (
            r#"node -e "fs.unlink('./old.txt')""#,
            DeleteKind::Unlink,
            false,
        ),
    ] {
        assert_eq!(fast_scan(command), ScanResult::Suspicious, "{command}");
        let operation = one(command);
        assert_eq!(operation.kind, kind, "{command}");
        assert_eq!(operation.recursive, recursive, "{command}");
        assert!(!operation.ambiguous, "{command}");
    }
}

#[test]
fn python_inline_literal_delete_apis_are_inspected() {
    for (command, kind, recursive) in [
        (
            r#"python -c "import shutil; shutil.rmtree('/tmp/old')""#,
            DeleteKind::Rm,
            true,
        ),
        (
            r#"python3 -c "import os; os.remove('./old.txt')""#,
            DeleteKind::Unlink,
            false,
        ),
        (
            r#"py -c "os.unlink(\"./old.txt\")""#,
            DeleteKind::Unlink,
            false,
        ),
        (
            r#"python -c "from pathlib import Path; Path('/tmp/old').unlink()""#,
            DeleteKind::Unlink,
            false,
        ),
    ] {
        assert_eq!(fast_scan(command), ScanResult::Suspicious, "{command}");
        let operation = one(command);
        assert_eq!(operation.kind, kind, "{command}");
        assert_eq!(operation.recursive, recursive, "{command}");
        assert!(!operation.ambiguous, "{command}");
    }
}

#[test]
fn inline_recursive_dynamic_targets_are_ambiguous() {
    for command in [
        r#"node -e "fs.rm(target, { recursive: true })""#,
        r#"python -c "shutil.rmtree(target)""#,
    ] {
        let operation = one(command);
        assert!(operation.recursive, "{command}");
        assert!(operation.ambiguous, "{command}");
    }
}

#[test]
fn inline_visible_delete_apis_remain_suspicious_with_home_expressions() {
    for command in [
        r#"node -e "fs.rm('$HOME', { recursive: true })""#,
        r#"python -c "shutil.rmtree(os.environ['HOME'])""#,
    ] {
        assert_eq!(fast_scan(command), ScanResult::Suspicious, "{command}");
        let operation = one(command);
        assert_eq!(operation.kind, DeleteKind::Rm, "{command}");
        assert!(operation.recursive, "{command}");
    }
}

#[test]
fn opaque_runtime_scripts_are_not_claimed_as_inspected_operations() {
    for command in [
        "node --version",
        "node cleanup.js",
        "python cleanup.py",
        "./build.sh",
    ] {
        assert!(
            parse_delete_operations(command, Dialect::Posix).is_empty(),
            "{command}"
        );
        assert_eq!(fast_scan(command), ScanResult::Safe, "{command}");
    }
}

struct NoResolve;

impl PathResolver for NoResolve {
    fn canonicalize(&self, _path: &Path) -> io::Result<PathBuf> {
        panic!("safe opaque commands must not resolve paths");
    }
}

#[test]
fn opaque_runtime_and_script_commands_are_safe_to_evaluate() {
    let policy = Policy {
        schema_version: 1,
        variables: BTreeMap::new(),
        protected_paths: vec![ProtectedPath {
            kind: "fixture".into(),
            logical: PathBuf::from("/protected"),
            canonical: PathBuf::from("/protected"),
            case_sensitive: true,
        }],
    };
    for command in [
        "node --version",
        "node cleanup.js",
        "python cleanup.py",
        "./build.sh",
    ] {
        let input = HookInput {
            cwd: PathBuf::from("/fixture/project"),
            command: command.to_owned(),
            permission_mode: None,
        };
        assert_eq!(
            evaluate(&input, &policy, &NoResolve),
            Decision::Allow,
            "{command}"
        );
    }
}

#[test]
fn opaque_inline_runtime_commands_fail_closed() {
    let policy = Policy {
        schema_version: 1,
        variables: BTreeMap::new(),
        protected_paths: vec![ProtectedPath {
            kind: "fixture".into(),
            logical: PathBuf::from("/protected"),
            canonical: PathBuf::from("/protected"),
            case_sensitive: true,
        }],
    };
    for command in [
        "python -c \"print('safe')\"",
        "node -e \"console.log('safe')\"",
    ] {
        let input = HookInput {
            cwd: PathBuf::from("/fixture/project"),
            command: command.to_owned(),
            permission_mode: None,
        };
        assert_eq!(
            evaluate(&input, &policy, &NoResolve).code(),
            Some(DenyCode::AmbiguousRecursive),
            "{command}"
        );
    }
}

#[test]
fn inline_compound_commands_yield_each_literal_operation() {
    let operations = parse_delete_operations(
        r#"echo ok; node -e "fs.rm('./build', { recursive: true })"; python -c "os.unlink('./old')""#,
        Dialect::Posix,
    );
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0].kind, DeleteKind::Rm);
    assert_eq!(operations[1].kind, DeleteKind::Unlink);
}
