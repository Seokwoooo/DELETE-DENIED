use delete_denied_core::command::{
    CommandSource, DeleteKind, Dialect, TargetSyntax, parse_delete_operations,
};
use delete_denied_core::scan::{ScanResult, fast_scan};

fn suspicious(command: &str) {
    assert_eq!(fast_scan(command), ScanResult::Suspicious, "{command}");
}

fn safe(command: &str) {
    assert_eq!(fast_scan(command), ScanResult::Safe, "{command}");
}

#[test]
fn fast_scan_allows_unrelated_commands_and_words_containing_rm() {
    for command in [
        "ls -la",
        "git status",
        "echo rm",
        "printf armchair",
        "grep rmdir",
        "command -v rm",
        "sh -c 'echo safe'",
        "bash -c 'cargo test'",
    ] {
        safe(command);
    }
}

#[test]
fn fast_scan_allows_read_only_shell_test_compound() {
    safe(
        r#"echo "=== hooks.json ==="; if [ -f /Users/example/.codex/hooks.json ]; then stat -f "%N %z bytes" -t "%Y-%m-%d %H:%M:%S" /Users/example/.codex/hooks.json; fi; echo "=== config matches ==="; rg -n -i 'hook|trust|delete-denied' /Users/example/.codex/config.toml > /tmp/delete-denied-config-matches.txt || true"#,
    );
    safe(
        "if test -f /Users/example/.codex/hooks.json; then stat /Users/example/.codex/hooks.json; fi",
    );
}

#[test]
fn fast_scan_keeps_deletion_after_shell_test_suspicious() {
    for command in [
        r#"if [ -f /Users/example/.codex/hooks.json ]; then rm -rf "$HOME"; fi"#,
        r#"if test -f /Users/example/.codex/hooks.json; then rm -rf "$HOME"; fi"#,
        r#"[ -f /Users/example/.codex/hooks.json ] && rm -rf "$HOME""#,
        r#"if [ -f "$(rm -rf "$HOME")" ]; then :; fi"#,
    ] {
        suspicious(command);
    }
}

#[test]
fn fast_scan_rejects_malformed_bracket_tests() {
    for command in [
        r#"if [ -f /Users/example/.codex/hooks.json; then :; fi"#,
        r#"if [ -f "/Users/example/.codex/hooks.json ]; then :; fi"#,
        r#"if [ -f x ] > >(rm -rf "$HOME"); then :; fi"#,
    ] {
        suspicious(command);
    }
}

#[test]
fn fast_scan_rejects_process_substitution_in_bracket_tests_but_allows_quoted_text() {
    for command in [r#"[ -f >(rm -rf "$HOME") ]"#, r#"[ -f <(rm -rf "$HOME") ]"#] {
        suspicious(command);
    }

    safe(r#"echo '>(not process substitution)'"#);
}

#[test]
fn fast_scan_finds_posix_delete_commands() {
    for command in [
        "rm -rf ./build",
        "rmdir ./empty",
        "unlink ./old-link",
        "find ./generated -delete",
        "printf '%s\\0' ./tmp | xargs -0 rm -rf",
        "rsync --delete source/ destination/",
        "rsync --delete-before source/ destination/",
        "git clean -fdx",
        "env FOO=bar rm ./old",
        "bash -c 'rm -rf ./old'",
        "bash -lc 'rm -rf ./old'",
    ] {
        suspicious(command);
    }
}

#[test]
fn fast_scan_finds_nested_find_and_xargs_deletes_but_allows_literal_commands() {
    for command in [
        r#"find "$HOME" -exec rm -rf -- {} \;"#,
        r#"find "$HOME" -execdir rm -rf -- {} \;"#,
        r#"find "$HOME" -ok rm -rf -- {} \;"#,
        r#"find "$HOME" -okdir rm -rf -- {} \;"#,
        r#"find "$HOME" -execdir sh -c 'rm -rf -- "$1"' sh {} \;"#,
        r#"printf '%s\n' x | xargs sh -c 'rm -rf -- "$@"' sh"#,
    ] {
        suspicious(command);
    }

    for command in [
        r#"find . -exec echo "$VALUE" \;"#,
        r#"printf '%s\n' x | xargs echo"#,
    ] {
        safe(command);
    }
}

#[test]
fn fast_scan_finds_find_delete_after_escaped_exec_plus() {
    suspicious(r#"find . -exec echo {} \+ -delete"#);
}

#[test]
fn fast_scan_finds_unbalanced_nested_find_and_xargs_shell_deletes() {
    for command in [
        r#"find . -execdir sh -c 'rm -rf -- "$1" sh {} \;"#,
        r#"printf '%s\n' x | xargs sh -c 'rm -rf -- "$@" sh"#,
    ] {
        suspicious(command);
    }
}

#[test]
fn fast_scan_respects_quotes_escapes_and_compound_boundaries() {
    suspicious("rm -- \"folder with spaces\"");
    suspicious("echo ok; rm ./old");
    suspicious("echo ok && rm ./old");
    suspicious("echo ok || rm ./old");
    suspicious("printf x | rm ./old");
    safe("echo ok\\; rm ./old");
    safe("printf 'rm -rf ./old'");
}

#[test]
fn parses_direct_rm_and_preserves_raw_targets() {
    let operations =
        parse_delete_operations("rm -rf -- ./build \"folder with spaces\"", Dialect::Posix);

    assert_eq!(operations.len(), 1);
    let operation = &operations[0];
    assert_eq!(operation.kind, DeleteKind::Rm);
    assert_eq!(operation.raw_targets, ["./build", "\"folder with spaces\""]);
    assert!(operation.recursive);
    assert!(!operation.ambiguous);
    assert_eq!(operation.source, CommandSource::Direct);
}

#[test]
fn posix_backslash_escaped_spaces_keep_posix_target_syntax() {
    let operations = parse_delete_operations(r#"rm -rf foo\ bar"#, Dialect::Posix);

    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].raw_targets, [r#"foo\ bar"#]);
    assert_eq!(operations[0].target_syntax, TargetSyntax::Posix);
}

#[test]
fn parses_find_xargs_rsync_and_git_clean() {
    let operations = parse_delete_operations(
        "find ./generated -type f -delete; printf x | xargs -0 rm -rf ./tmp; rsync --delete source/ destination/; git clean -fdx",
        Dialect::Posix,
    );

    assert_eq!(operations.len(), 4);
    assert_eq!(operations[0].kind, DeleteKind::FindDelete);
    assert_eq!(operations[0].raw_targets, ["./generated"]);
    assert!(operations[0].recursive);
    assert_eq!(operations[0].source, CommandSource::Find);
    assert_eq!(operations[1].kind, DeleteKind::XargsRm);
    assert_eq!(operations[1].source, CommandSource::Xargs);
    assert_eq!(operations[2].kind, DeleteKind::RsyncDelete);
    assert_eq!(operations[2].raw_targets, ["destination/"]);
    assert_eq!(operations[2].source, CommandSource::Rsync);
    assert_eq!(operations[3].kind, DeleteKind::GitClean);
    assert_eq!(operations[3].source, CommandSource::Git);
}

#[test]
fn parses_wrappers_and_inline_shell() {
    let operations = parse_delete_operations(
        "env HOME=/tmp rm \"$HOME/file\"; bash -c 'rm -rf ./nested'",
        Dialect::Posix,
    );

    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0].source, CommandSource::Wrapper);
    assert_eq!(operations[1].source, CommandSource::NestedShell);
    assert_eq!(operations[1].raw_targets, ["./nested"]);

    let combined = parse_delete_operations("bash -lc 'rm -rf ./nested'", Dialect::Posix);
    assert_eq!(combined.len(), 1);
    assert_eq!(combined[0].source, CommandSource::NestedShell);
    assert_eq!(combined[0].raw_targets, ["./nested"]);
}

#[test]
fn review_wrappers_consume_separate_values_before_finding_rm() {
    for command in [
        "env -C /tmp rm -rf /protected",
        "env -P /usr/bin rm -rf /protected",
    ] {
        suspicious(command);
        let operations = parse_delete_operations(command, Dialect::Posix);
        assert_eq!(operations.len(), 1, "{command}");
        assert_eq!(operations[0].kind, DeleteKind::Rm, "{command}");
    }
}

#[test]
fn review_env_split_string_is_conservatively_opaque() {
    for command in [
        "env -S 'rm -rf /protected'",
        "env --split-string 'echo harmless'",
    ] {
        suspicious(command);
        assert!(parse_delete_operations(command, Dialect::Posix).is_empty());
    }
}

#[test]
fn marks_dynamic_and_unbalanced_targets_ambiguous() {
    for command in [
        "rm -rf \"$(printf %s ./build)\"",
        "rm -rf \"$UNKNOWN\"",
        "rm -rf \"./unterminated",
    ] {
        let operations = parse_delete_operations(command, Dialect::Posix);
        assert_eq!(operations.len(), 1, "{command}");
        assert!(operations[0].ambiguous, "{command}");
    }

    let operations = parse_delete_operations("rm -rf \"$UNKNOWN\"", Dialect::Posix);
    assert!(operations[0].recursive);

    assert_eq!(
        fast_scan("echo \"$(rm -rf ./old)\""),
        ScanResult::Suspicious
    );

    let operations = parse_delete_operations("rm -rf '$UNKNOWN'", Dialect::Posix);
    assert!(!operations[0].ambiguous);

    let operations = parse_delete_operations("rm -rf \"$HOME\"", Dialect::Posix);
    assert!(!operations[0].ambiguous);

    for command in [
        "rm -rf ~",
        "rm -rf ~/build",
        "rm -rf ~alice/build",
        "rm -rf HOME=~/build",
        "rm -rf PATH=/bin:~/build",
    ] {
        let operations = parse_delete_operations(command, Dialect::Posix);
        assert!(operations[0].ambiguous, "{command}");
    }

    suspicious("~/bin/echo hello");
}

#[test]
fn treats_windows_short_name_tilde_as_literal_path_text() {
    let command = "rm -rf C:/Users/RUNNER~1/AppData/Local/project/build";
    let operations = parse_delete_operations(command, Dialect::Posix);

    assert_eq!(operations.len(), 1);
    assert_eq!(
        operations[0].raw_targets,
        ["C:/Users/RUNNER~1/AppData/Local/project/build"]
    );
    assert!(!operations[0].ambiguous);

    safe("C:/Users/RUNNER~1/bin/echo.exe hello");
}

#[test]
fn non_posix_dialects_are_parsed_by_their_dedicated_modules() {
    assert_eq!(
        parse_delete_operations("Remove-Item -Recurse .", Dialect::PowerShell).len(),
        1
    );
    assert_eq!(parse_delete_operations("rd /s .", Dialect::Cmd).len(), 1);
}

#[test]
fn review_dynamic_command_positions_and_eval_are_never_safe() {
    for command in [
        "$(printf safe)",
        "`printf safe`",
        "eval rm -rf ./old",
        "cmd=rm; $cmd -rf /protected",
        "cmd='rm -rf /protected'; $cmd",
        "${!cmd} -rf /protected",
        "echo \"$(printf safe)\"",
        "echo `printf safe`",
    ] {
        suspicious(command);
        assert!(
            parse_delete_operations(command, Dialect::Posix).is_empty(),
            "substitutions and eval remain opaque: {command}"
        );
    }

    for command in [
        r#"r\m -rf /protected"#,
        "r''m -rf /protected",
        "\"rm\" -rf /protected",
        "find . -del''ete",
        r#"printf x | xargs r\m"#,
        "rsync --del''ete src dst",
        "git cl''ean -fd",
    ] {
        suspicious(command);
    }

    for command in [
        "echo '$(rm -rf ./old)'",
        "echo '`rm -rf ./old`'",
        r#"echo "\$(rm -rf ./old)""#,
        r#"printf '%s' "rm -rf ./old""#,
    ] {
        safe(command);
    }
}

#[test]
fn review_fast_scan_overflow_is_conservative() {
    let mut command = String::from("env");
    for index in 0..80 {
        command.push_str(&format!(" K{index}=v"));
    }
    command.push_str(" rm -rf /protected");
    suspicious(&command);
}

#[test]
fn review_scanner_normalizes_only_supported_control_words() {
    for command in [
        "echo hello",
        "\"echo\" hello",
        "c''argo test",
        "'/bin/echo' hello",
        "'/path with spaces/echo' hello",
        "find \"$ROOT\" -print",
        "find . -exec echo \"$VALUE\" \\;",
    ] {
        safe(command);
    }

    for command in [
        "xargs /bin/rm -rf /protected",
        r#"xargs /bin/r\m -rf /protected"#,
        "find . -exec echo x \\; -delete",
        "r\\\nm -rf /protected",
        "xargs $CMD -rf /protected",
        "git $CMD -fd",
        "find . $ACTION",
        "rsync $OPTIONS src dst",
    ] {
        suspicious(command);
    }

    let xargs = parse_delete_operations("xargs /bin/rm -rf /protected", Dialect::Posix);
    assert_eq!(xargs.len(), 1);
    assert_eq!(xargs[0].kind, DeleteKind::XargsRm);

    let find = parse_delete_operations("find . -exec echo x \\; -delete", Dialect::Posix);
    assert_eq!(find.len(), 1);
    assert_eq!(find[0].kind, DeleteKind::FindDelete);

    let continuation = parse_delete_operations("r\\\nm -rf /protected", Dialect::Posix);
    assert_eq!(continuation.len(), 1);
    assert_eq!(continuation[0].kind, DeleteKind::Rm);

    let normalized_path = parse_delete_operations(r#"/bin/r\m -rf /protected"#, Dialect::Posix);
    assert_eq!(normalized_path.len(), 1);
    assert_eq!(normalized_path[0].kind, DeleteKind::Rm);
}

#[test]
fn review_fast_scan_uses_bounded_prefilter_without_parser_allocation() {
    let source = include_str!("../src/scan.rs");
    assert!(source.contains("contains_suspicious_construct"));
    assert!(!source.contains("parse_segments"));
}

#[test]
fn review_escaped_double_quotes_keep_shell_state() {
    let command = r#"rm -rf "folder\"; echo rm""#;
    let operations = parse_delete_operations(command, Dialect::Posix);

    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].raw_targets, [r#""folder\"; echo rm""#]);
    assert!(!operations[0].ambiguous);
}

#[test]
fn review_nested_shells_have_a_bounded_conservative_depth() {
    let mut command = String::from("rm -rf ./old");
    for _ in 0..16 {
        command = format!("sh -c {:?}", command);
    }
    let operations = parse_delete_operations(&command, Dialect::Posix);
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].raw_targets, ["./old"]);

    for _ in 0..8 {
        command = format!("sh -c {:?}", command);
    }
    let operations = parse_delete_operations(&command, Dialect::Posix);
    assert!(!operations.is_empty());
    assert!(operations.iter().all(|operation| operation.ambiguous));
}

#[test]
fn review_find_delete_requires_expression_position() {
    for command in [
        "find ./generated -name '-delete'",
        "find ./generated -name \"-delete\"",
        "find ./generated -exec echo -delete \\;",
    ] {
        safe(command);
        assert!(
            parse_delete_operations(command, Dialect::Posix).is_empty(),
            "{command}"
        );
    }

    let operations =
        parse_delete_operations("find ./generated -name '*.tmp' -delete", Dialect::Posix);
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].raw_targets, ["./generated"]);

    let operations = parse_delete_operations("find . '-delete'", Dialect::Posix);
    assert_eq!(operations.len(), 1);
}

#[test]
fn review_git_clean_is_only_the_subcommand_and_d_is_the_recursive_flag() {
    for command in ["git status clean", "git commit -m clean"] {
        safe(command);
        assert!(
            parse_delete_operations(command, Dialect::Posix).is_empty(),
            "{command}"
        );
    }

    suspicious("git clean -f docs");
    let operation = &parse_delete_operations("git clean -f docs", Dialect::Posix)[0];
    assert!(!operation.recursive);

    let operations = parse_delete_operations("git clean -fdx docs", Dialect::Posix);
    assert_eq!(operations.len(), 1);
    assert!(operations[0].recursive);
    assert_eq!(operations[0].raw_targets, ["docs"]);
}

#[test]
fn review_xargs_rm_must_be_the_command_not_an_argument() {
    for command in ["printf x | xargs echo rm", "xargs -I{} echo rm"] {
        safe(command);
        assert!(
            parse_delete_operations(command, Dialect::Posix).is_empty(),
            "{command}"
        );
    }

    let operations = parse_delete_operations("printf x | xargs -0 rm -rf ./tmp", Dialect::Posix);
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0].kind, DeleteKind::XargsRm);
}

#[test]
fn review_delete_kind_has_no_legacy_aliases() {
    let source = include_str!("../src/command/mod.rs");
    assert!(!source.contains("pub const Remove"));
    assert!(!source.contains("pub const Find"));
    assert!(!source.contains("pub const Xargs"));
    assert!(!source.contains("pub const Rsync"));
}
