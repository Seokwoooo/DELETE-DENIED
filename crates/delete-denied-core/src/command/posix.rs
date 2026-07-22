use super::{CommandSource, DeleteKind, DeleteOperation, TargetSyntax};
use super::{cmd, inline_runtime, powershell};

const MAX_NESTED_SHELL_DEPTH: usize = 16;

#[derive(Debug, Clone)]
pub(crate) struct Token {
    pub(crate) value: String,
    pub(crate) raw: String,
    pub(crate) dynamic: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Segment {
    pub(crate) tokens: Vec<Token>,
    pub(crate) unbalanced: bool,
    pub(crate) pipeline_before: bool,
    pub(crate) conditional_before: bool,
}

/// Parse POSIX shell deletion operations without invoking a shell.
pub fn parse_delete_operations(command: &str) -> Vec<DeleteOperation> {
    parse_segments(command)
        .into_iter()
        .flat_map(|segment| parse_segment(&segment, CommandSource::Direct, 0))
        .collect()
}

/// A standalone assignment that precedes a later compound command segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextAssignment {
    pub(crate) name: String,
    pub(crate) raw_value: String,
    pub(crate) dynamic: bool,
}

/// A deterministic `cd` step captured before a later destructive segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextCwdStep {
    pub(crate) raw_target: String,
    pub(crate) dynamic: bool,
    pub(crate) assignments: Vec<ContextAssignment>,
}

/// Deletion operation plus the bounded POSIX context that preceded it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContextualDeleteOperation {
    pub(crate) operation: DeleteOperation,
    pub(crate) cwd_steps: Vec<ContextCwdStep>,
    pub(crate) assignments: Vec<ContextAssignment>,
}

/// Parse deletion operations while retaining only simple prior `cd` and
/// standalone assignment state. Prefix assignments such as `env HOME=x` are
/// deliberately not recorded because shell expansion occurs before `env`.
pub(crate) fn analyze_delete_operations(command: &str) -> Vec<ContextualDeleteOperation> {
    analyze_context_segments(&parse_segments(command), Vec::new(), Vec::new(), 0)
}

fn analyze_context_segments(
    segments: &[Segment],
    mut assignments: Vec<ContextAssignment>,
    mut cwd_steps: Vec<ContextCwdStep>,
    nested_depth: usize,
) -> Vec<ContextualDeleteOperation> {
    let mut contextual = Vec::new();

    for segment in segments {
        if segment.pipeline_before {
            assignments.clear();
            cwd_steps.clear();
        }

        if let Some(script) = nested_shell_script(segment) {
            if nested_depth >= MAX_NESTED_SHELL_DEPTH || segment.unbalanced || script.dynamic {
                contextual.push(ContextualDeleteOperation {
                    operation: ambiguous_nested_shell(),
                    cwd_steps: cwd_steps.clone(),
                    assignments: assignments.clone(),
                });
            } else {
                contextual.extend(analyze_context_segments(
                    &parse_segments(&script.value),
                    assignments.clone(),
                    cwd_steps.clone(),
                    nested_depth + 1,
                ));
            }
        } else {
            for mut operation in parse_segment(
                segment,
                if nested_depth == 0 {
                    CommandSource::Direct
                } else {
                    CommandSource::NestedShell
                },
                nested_depth,
            ) {
                if nested_depth > 0 {
                    operation.source = CommandSource::NestedShell;
                }
                let mut operation_cwd_steps = cwd_steps.clone();
                if operation.kind == DeleteKind::GitClean {
                    operation_cwd_steps.extend(parse_git_cwd_steps(segment, &assignments));
                }
                contextual.push(ContextualDeleteOperation {
                    operation,
                    cwd_steps: operation_cwd_steps,
                    assignments: assignments.clone(),
                });
            }
        }

        if nested_shell_script(segment).is_none() && !segment.conditional_before {
            if let Some(cd) = parse_cd(segment, &assignments) {
                cwd_steps.push(cd);
            } else if let Some(new_assignments) = standalone_assignments(segment) {
                assignments.extend(new_assignments);
            }
        }
    }

    contextual
}

fn nested_shell_script(segment: &Segment) -> Option<&Token> {
    let command_index = command_index(segment)?;
    if !matches!(
        basename(&segment.tokens[command_index].value),
        "bash" | "sh" | "zsh" | "dash"
    ) {
        return None;
    }
    let script_index = command_string_index(&segment.tokens, command_index)?;
    segment.tokens.get(script_index)
}

fn ambiguous_nested_shell() -> DeleteOperation {
    DeleteOperation {
        kind: DeleteKind::Rm,
        raw_targets: Vec::new(),
        recursive: true,
        ambiguous: true,
        source: CommandSource::NestedShell,
        target_syntax: TargetSyntax::Posix,
    }
}

fn parse_git_cwd_steps(
    segment: &Segment,
    assignments: &[ContextAssignment],
) -> Vec<ContextCwdStep> {
    let Some(command_index) = command_position_index(segment) else {
        return Vec::new();
    };
    if basename(&segment.tokens[command_index].value) != "git" {
        return Vec::new();
    }
    let mut steps = Vec::new();
    let mut index = command_index + 1;
    while index < segment.tokens.len() {
        let value = segment.tokens[index].value.as_str();
        if value == "clean" {
            break;
        }
        if value == "-C" {
            if let Some(target) = segment.tokens.get(index + 1) {
                steps.push(ContextCwdStep {
                    raw_target: target.raw.clone(),
                    dynamic: target.dynamic || segment.unbalanced,
                    assignments: assignments.to_vec(),
                });
                index += 2;
                continue;
            }
            steps.push(ContextCwdStep {
                raw_target: String::new(),
                dynamic: true,
                assignments: assignments.to_vec(),
            });
            break;
        }
        if let Some(raw_target) = segment.tokens[index].raw.strip_prefix("-C") {
            if !raw_target.is_empty() {
                steps.push(ContextCwdStep {
                    raw_target: raw_target.to_owned(),
                    dynamic: segment.tokens[index].dynamic || segment.unbalanced,
                    assignments: assignments.to_vec(),
                });
                index += 1;
                continue;
            }
        }
        index += 1;
    }
    steps
}

fn standalone_assignments(segment: &Segment) -> Option<Vec<ContextAssignment>> {
    if segment.tokens.is_empty() || segment.unbalanced {
        return None;
    }
    let mut assignments = Vec::with_capacity(segment.tokens.len());
    for token in &segment.tokens {
        let (name, raw_value) = token.raw.split_once('=')?;
        if !is_assignment(token.value.as_str()) || name.is_empty() {
            return None;
        }
        assignments.push(ContextAssignment {
            name: name.to_owned(),
            raw_value: raw_value.to_owned(),
            dynamic: token.dynamic,
        });
    }
    Some(assignments)
}

fn parse_cd(segment: &Segment, assignments: &[ContextAssignment]) -> Option<ContextCwdStep> {
    let command_index = command_position_index(segment)?;
    if basename(&segment.tokens[command_index].value) != "cd" {
        return None;
    }
    let target = segment
        .tokens
        .iter()
        .skip(command_index + 1)
        .rfind(|token| token.value != "--" && !token.value.starts_with('-'));
    let Some(target) = target else {
        return Some(ContextCwdStep {
            raw_target: String::new(),
            dynamic: true,
            assignments: assignments.to_vec(),
        });
    };
    Some(ContextCwdStep {
        raw_target: target.raw.clone(),
        dynamic: target.dynamic || segment.unbalanced,
        assignments: assignments.to_vec(),
    })
}

/// The fast scan deliberately recognizes wrappers and opaque shell entry points too.
pub(crate) fn contains_suspicious_construct(command: &str) -> bool {
    fast_scan_construct(command)
}

#[derive(Clone, Copy)]
struct FastWord {
    start: usize,
    end: usize,
    dynamic: bool,
    opaque: bool,
}

const FAST_WORD_LIMIT: usize = 64;

fn fast_scan_construct(command: &str) -> bool {
    fast_scan_construct_at_depth(command, 0)
}

fn fast_scan_construct_at_depth(command: &str, nested_depth: usize) -> bool {
    let bytes = command.as_bytes();
    let empty = FastWord {
        start: 0,
        end: 0,
        dynamic: false,
        opaque: false,
    };
    let mut words = [empty; FAST_WORD_LIMIT];
    let mut count = 0usize;
    let mut start = 0usize;
    let mut started = false;
    let mut dynamic = false;
    let mut opaque = false;
    // An unquoted tilde expands only at a word or assignment-value boundary.
    let mut assignment_seen = false;
    let mut tilde_position = true;
    let mut quote = 0u8;
    let mut escaped = false;
    let mut segment_unbalanced = false;
    let mut index = 0usize;

    while index < bytes.len() {
        let byte = bytes[index];
        if escaped {
            escaped = false;
            started = true;
            tilde_position = false;
            index += 1;
            continue;
        }
        if quote == b'\'' {
            started = true;
            if byte == b'\'' {
                quote = 0;
            }
            index += 1;
            continue;
        }
        if quote == b'"' {
            started = true;
            match byte {
                b'\\' => escaped = true,
                b'"' => quote = 0,
                b'`' => opaque = true,
                b'$' => {
                    dynamic = true;
                    if bytes.get(index + 1) == Some(&b'(')
                        || bytes.get(index + 1) == Some(&b'{')
                            && bytes.get(index + 2) == Some(&b'!')
                    {
                        opaque = true;
                    }
                }
                _ => {}
            }
            index += 1;
            continue;
        }
        match byte {
            b'\\' => {
                if !started {
                    start = index;
                }
                started = true;
                escaped = true;
                tilde_position = false;
            }
            b'\'' | b'"' => {
                if !started {
                    start = index;
                }
                started = true;
                quote = byte;
                tilde_position = false;
            }
            b'$' => {
                if !started {
                    start = index;
                }
                started = true;
                dynamic = true;
                tilde_position = false;
                if bytes.get(index + 1) == Some(&b'(')
                    || bytes.get(index + 1) == Some(&b'{') && bytes.get(index + 2) == Some(&b'!')
                {
                    opaque = true;
                }
            }
            b'`' => {
                if !started {
                    start = index;
                }
                started = true;
                opaque = true;
                tilde_position = false;
            }
            b'<' | b'>' if bytes.get(index + 1) == Some(&b'(') => {
                if !started {
                    start = index;
                }
                started = true;
                opaque = true;
                tilde_position = false;
            }
            b'*' | b'?' | b'[' | b'{' | b'}' => {
                if !started {
                    start = index;
                }
                started = true;
                dynamic = true;
                tilde_position = false;
            }
            b'~' => {
                if !started {
                    start = index;
                }
                started = true;
                dynamic |= tilde_position;
                tilde_position = false;
            }
            b'=' => {
                if !started {
                    start = index;
                }
                started = true;
                assignment_seen = true;
                tilde_position = true;
            }
            b':' => {
                if !started {
                    start = index;
                }
                started = true;
                tilde_position = assignment_seen;
            }
            b';' | b'\n' | b'|' | b'&' => {
                fast_flush_word(
                    &mut words,
                    &mut count,
                    &mut start,
                    &mut started,
                    &mut dynamic,
                    &mut opaque,
                    index,
                );
                assignment_seen = false;
                tilde_position = true;
                if fast_finish_words(
                    command,
                    &words,
                    &mut count,
                    segment_unbalanced,
                    nested_depth,
                ) {
                    return true;
                }
                segment_unbalanced = false;
                if bytes.get(index + 1) == Some(&byte) && (byte == b'|' || byte == b'&') {
                    index += 1;
                }
            }
            byte if byte.is_ascii_whitespace() => {
                fast_flush_word(
                    &mut words,
                    &mut count,
                    &mut start,
                    &mut started,
                    &mut dynamic,
                    &mut opaque,
                    index,
                );
                assignment_seen = false;
                tilde_position = true;
            }
            _ => {
                if !started {
                    start = index;
                }
                started = true;
                tilde_position = false;
            }
        }
        index += 1;
    }
    if quote != 0 || escaped {
        segment_unbalanced = true;
    }
    fast_flush_word(
        &mut words,
        &mut count,
        &mut start,
        &mut started,
        &mut dynamic,
        &mut opaque,
        bytes.len(),
    );
    fast_finish_words(
        command,
        &words,
        &mut count,
        segment_unbalanced,
        nested_depth,
    )
}

fn fast_flush_word(
    words: &mut [FastWord; FAST_WORD_LIMIT],
    count: &mut usize,
    start: &mut usize,
    started: &mut bool,
    dynamic: &mut bool,
    opaque: &mut bool,
    end: usize,
) {
    if !*started {
        return;
    }
    if *count < FAST_WORD_LIMIT {
        words[*count] = FastWord {
            start: *start,
            end,
            dynamic: *dynamic,
            opaque: *opaque,
        };
        *count += 1;
    } else {
        // Preserve a conservative signal when the bounded prefilter runs out
        // of stack-token slots instead of silently dropping command words.
        words[FAST_WORD_LIMIT - 1].opaque = true;
    }
    *started = false;
    *dynamic = false;
    *opaque = false;
}

fn fast_finish_words(
    command: &str,
    words: &[FastWord; FAST_WORD_LIMIT],
    count: &mut usize,
    unbalanced: bool,
    nested_depth: usize,
) -> bool {
    let result = fast_segment_suspicious(command, &words[..*count], unbalanced, nested_depth);
    *count = 0;
    result
}

fn fast_segment_suspicious(
    command: &str,
    words: &[FastWord],
    unbalanced: bool,
    nested_depth: usize,
) -> bool {
    if words.iter().any(|word| word.opaque) {
        return true;
    }
    if fast_has_opaque_wrapper_option(command, words) {
        return true;
    }
    let Some(command_index) = fast_command_position(command, words) else {
        return false;
    };
    if fast_supported_name(command, words[command_index], "[") {
        let has_terminal_bracket = words
            .last()
            .is_some_and(|word| fast_word_matches(command, *word, "]"));
        return unbalanced || !has_terminal_bracket;
    }
    if fast_word_basename(command, words[0]) == "command"
        && words
            .get(1)
            .is_some_and(|word| matches!(fast_word_text(command, *word), "-v" | "-V"))
    {
        return false;
    }
    if words[command_index].dynamic {
        return true;
    }
    if fast_supported_name(command, words[command_index], "eval") {
        return true;
    }
    if ["bash", "sh", "zsh", "dash"]
        .iter()
        .any(|name| fast_supported_name(command, words[command_index], name))
    {
        return fast_nested_shell_suspicious(
            command,
            words,
            command_index,
            unbalanced,
            nested_depth,
        );
    }
    if fast_supported_name(command, words[command_index], "rm")
        || fast_supported_name(command, words[command_index], "rmdir")
        || fast_supported_name(command, words[command_index], "unlink")
    {
        return true;
    }
    if fast_supported_name(command, words[command_index], "find") {
        return fast_find_delete(command, words, command_index, unbalanced, nested_depth);
    }
    if fast_supported_name(command, words[command_index], "xargs") {
        return fast_xargs_rm(command, words, command_index, unbalanced, nested_depth);
    }
    if fast_supported_name(command, words[command_index], "rsync") {
        return words.iter().skip(command_index + 1).any(|word| {
            word.dynamic || word.opaque || fast_word_starts_with(command, *word, "--delete")
        });
    }
    if fast_supported_name(command, words[command_index], "git") {
        return fast_git_clean(command, words, command_index);
    }
    if fast_supported_name_ci(command, words[command_index], "remove-item")
        || fast_supported_name_ci(command, words[command_index], "ri")
        || fast_supported_name_ci(command, words[command_index], "del")
        || fast_supported_name_ci(command, words[command_index], "erase")
        || fast_supported_name_ci(command, words[command_index], "rd")
        || fast_supported_name_ci(command, words[command_index], "rmdir")
    {
        return true;
    }
    if fast_supported_name_ci(command, words[command_index], "pwsh")
        || fast_supported_name_ci(command, words[command_index], "powershell")
        || fast_supported_name_ci(command, words[command_index], "cmd")
        || fast_supported_name_ci(command, words[command_index], "cmd.exe")
    {
        return fast_interpreter_payload_suspicious(command, words, command_index);
    }
    if fast_supported_name_ci(command, words[command_index], "node")
        || fast_supported_name_ci(command, words[command_index], "python")
        || fast_supported_name_ci(command, words[command_index], "python3")
        || fast_supported_name_ci(command, words[command_index], "py")
    {
        return fast_inline_runtime_suspicious(command, words, command_index);
    }
    unbalanced && fast_supported_name(command, words[command_index], "rm")
}

fn fast_interpreter_payload_suspicious(
    command: &str,
    words: &[FastWord],
    command_index: usize,
) -> bool {
    let interpreter = fast_word_text(command, words[command_index]);
    let is_cmd = interpreter
        .as_bytes()
        .first()
        .is_some_and(|byte| *byte == b'c' || *byte == b'C');
    let mut index = command_index + 1;
    while index < words.len() {
        let option = fast_word_text(command, words[index]);
        if (is_cmd && matches!(option, "/c" | "/k" | "-c"))
            || (!is_cmd
                && (option.eq_ignore_ascii_case("-command") || option.eq_ignore_ascii_case("-c")))
        {
            return words
                .get(index + 1)
                .is_none_or(|script| fast_script_has_deletion(command, *script));
        }
        index += 1;
    }
    false
}

fn fast_inline_runtime_suspicious(command: &str, words: &[FastWord], command_index: usize) -> bool {
    let is_node = fast_supported_name_ci(command, words[command_index], "node");
    let mut index = command_index + 1;
    while index < words.len() {
        let option = fast_word_text(command, words[index]);
        let is_inline_option = if is_node {
            option == "-e" || option == "--eval" || option == "-p" || option == "--print"
        } else {
            option == "-c"
        };
        if is_inline_option {
            return true;
        }
        index += 1;
    }
    false
}

fn fast_script_has_deletion(command: &str, script: FastWord) -> bool {
    let text = fast_word_text(command, script).as_bytes();
    bytes_contains_ascii_ci(text, b"remove-item")
        || bytes_word_boundary_ci(text, b"rm")
        || bytes_word_boundary_ci(text, b"del")
        || bytes_word_boundary_ci(text, b"erase")
        || bytes_word_boundary_ci(text, b"rd")
        || bytes_word_boundary_ci(text, b"rmdir")
        || bytes_contains_ascii_ci(text, b"fs.rm")
        || bytes_contains_ascii_ci(text, b"fs.rmdir")
        || bytes_contains_ascii_ci(text, b"fs.unlink")
        || bytes_contains_ascii_ci(text, b"shutil.rmtree")
        || bytes_contains_ascii_ci(text, b"os.remove")
        || bytes_contains_ascii_ci(text, b"os.unlink")
        || (bytes_contains_ascii_ci(text, b"path(") && bytes_contains_ascii_ci(text, b"unlink"))
        || fast_word_has_script_suffix_bytes(text, b".js")
}

fn bytes_word_boundary_ci(text: &[u8], word: &[u8]) -> bool {
    text.windows(word.len()).enumerate().any(|(index, window)| {
        if !window.eq_ignore_ascii_case(word) {
            return false;
        }
        let before = index.checked_sub(1).and_then(|offset| text.get(offset));
        let after = text.get(index + word.len());
        !before.is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            && !after.is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
    })
}

fn bytes_contains_ascii_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn fast_supported_name_ci(command: &str, word: FastWord, expected: &str) -> bool {
    fast_word_basename(command, word)
        .as_bytes()
        .eq_ignore_ascii_case(expected.as_bytes())
}

fn fast_word_has_script_suffix_bytes(value: &[u8], suffix: &[u8]) -> bool {
    value.len() >= suffix.len() && value[value.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

fn fast_has_opaque_wrapper_option(command: &str, words: &[FastWord]) -> bool {
    let mut index = 0usize;
    while index < words.len() {
        let value = fast_word_text(command, words[index]);
        if is_assignment(value) {
            index += 1;
            continue;
        }
        let Some(wrapper) = fast_wrapper_name(command, words[index]) else {
            return false;
        };
        index += 1;
        while index < words.len() {
            let option = fast_word_text(command, words[index]);
            if wrapper_opaque_option(wrapper, option) {
                return true;
            }
            if is_assignment(option) || option.starts_with('-') {
                index += 1;
                if wrapper_option_takes_value(wrapper, option) {
                    index = (index + 1).min(words.len());
                }
            } else {
                break;
            }
        }
    }
    false
}

fn fast_command_position(command: &str, words: &[FastWord]) -> Option<usize> {
    let mut index = 0usize;
    while index < words.len() {
        let value = fast_word_text(command, words[index]);
        if is_assignment(value) {
            index += 1;
            continue;
        }
        if fast_shell_control_prefix(value) {
            index += 1;
            continue;
        }
        let Some(wrapper) = fast_wrapper_name(command, words[index]) else {
            return Some(index);
        };
        index += 1;
        while index < words.len() {
            let option = fast_word_text(command, words[index]);
            if is_assignment(option) || option.starts_with('-') {
                let takes = wrapper_option_takes_value(wrapper, option);
                index += 1;
                if takes {
                    index = (index + 1).min(words.len());
                }
            } else {
                break;
            }
        }
    }
    None
}

fn fast_shell_control_prefix(value: &str) -> bool {
    matches!(
        value,
        "if" | "then"
            | "else"
            | "elif"
            | "while"
            | "until"
            | "do"
            | "done"
            | "case"
            | "esac"
            | "for"
            | "in"
            | "function"
            | "exec"
            | "time"
            | "!"
            | "{"
            | "}"
            | "("
            | ")"
    )
}

fn fast_nested_shell_suspicious(
    command: &str,
    words: &[FastWord],
    command_index: usize,
    unbalanced: bool,
    nested_depth: usize,
) -> bool {
    let mut index = command_index + 1;
    while index < words.len() {
        if shell_command_option(fast_word_text(command, words[index])) {
            let Some(script_word) = words.get(index + 1) else {
                return true;
            };
            if unbalanced
                || nested_depth >= MAX_NESTED_SHELL_DEPTH
                || script_word.dynamic
                || script_word.opaque
            {
                return true;
            }
            return fast_scan_construct_at_depth(
                fast_word_text(command, *script_word),
                nested_depth + 1,
            );
        }
        index += 1;
    }
    false
}

fn fast_find_delete(
    command: &str,
    words: &[FastWord],
    command_index: usize,
    unbalanced: bool,
    nested_depth: usize,
) -> bool {
    let mut in_exec = false;
    let mut exec_start = 0usize;
    let mut pending = false;
    let mut root_count = 0usize;
    let mut expression_started = false;
    for (index, word) in words.iter().enumerate().skip(command_index + 1) {
        let value = fast_word_text(command, *word);
        if in_exec {
            if value == ";"
                || value == "+"
                || fast_word_matches(command, *word, ";")
                || fast_word_matches(command, *word, "+")
            {
                if fast_find_exec_suspicious(
                    command,
                    &words[exec_start..index],
                    unbalanced,
                    nested_depth,
                ) {
                    return true;
                }
                in_exec = false;
            }
            continue;
        }
        if pending {
            pending = false;
            continue;
        }
        if word.dynamic || word.opaque {
            // A dynamic first root is harmless for a non-deleting expression
            // (for example, `find "$ROOT" -print`).  Once a root or the
            // expression has been established, a dynamic control position is
            // ambiguous and must not be treated as safe.
            if root_count > 0 || expression_started {
                return true;
            }
            root_count += 1;
            continue;
        }
        if matches!(value, "-exec" | "-execdir" | "-ok" | "-okdir") {
            in_exec = true;
            exec_start = index + 1;
            expression_started = true;
            continue;
        }
        if find_predicate_takes_argument(value) {
            pending = true;
            expression_started = true;
            continue;
        }
        if fast_word_matches(command, *word, "-delete") {
            return true;
        }
        if !expression_started && !value.starts_with('-') {
            root_count += 1;
            continue;
        }
        if value.starts_with('-') {
            expression_started = true;
        }
    }
    in_exec && fast_find_exec_suspicious(command, &words[exec_start..], unbalanced, nested_depth)
}

fn fast_find_exec_suspicious(
    command: &str,
    words: &[FastWord],
    unbalanced: bool,
    nested_depth: usize,
) -> bool {
    let Some(command_index) = fast_command_position(command, words) else {
        return !words.is_empty();
    };
    if words[command_index].dynamic || words.iter().any(|word| word.opaque) {
        return true;
    }
    if fast_supported_name(command, words[command_index], "rm")
        || fast_supported_name(command, words[command_index], "rmdir")
        || fast_supported_name(command, words[command_index], "unlink")
    {
        return true;
    }
    if ["bash", "sh", "zsh", "dash"]
        .iter()
        .any(|name| fast_supported_name(command, words[command_index], name))
    {
        return fast_nested_shell_suspicious(
            command,
            words,
            command_index,
            unbalanced,
            nested_depth,
        );
    }
    false
}

fn fast_xargs_rm(
    command: &str,
    words: &[FastWord],
    command_index: usize,
    unbalanced: bool,
    nested_depth: usize,
) -> bool {
    let mut index = command_index + 1;
    while index < words.len() {
        let value = fast_word_text(command, words[index]);
        if value == "--" {
            index += 1;
            break;
        }
        if !value.starts_with('-') {
            break;
        }
        if xargs_option_takes_argument(value) {
            index += 2;
        } else {
            index += 1;
        }
    }
    let Some(word) = words.get(index) else {
        return false;
    };
    if word.dynamic || word.opaque || fast_supported_name(command, *word, "rm") {
        return true;
    }
    if ["bash", "sh", "zsh", "dash"]
        .iter()
        .any(|name| fast_supported_name(command, *word, name))
    {
        return fast_nested_shell_suspicious(command, &words[index..], 0, unbalanced, nested_depth);
    }
    false
}

fn fast_git_clean(command: &str, words: &[FastWord], command_index: usize) -> bool {
    let mut index = command_index + 1;
    while index < words.len() {
        let value = fast_word_text(command, words[index]);
        if !value.starts_with('-') {
            if words[index].dynamic || words[index].opaque {
                return true;
            }
            if !fast_supported_name(command, words[index], "clean") {
                return false;
            }
            return true;
        }
        if git_option_takes_argument(value) {
            index += 2;
        } else {
            index += 1;
        }
    }
    false
}

fn fast_word_text(command: &str, word: FastWord) -> &str {
    let mut text = &command[word.start..word.end];
    if text.len() >= 2 {
        let bytes = text.as_bytes();
        if (bytes[0] == b'\'' && bytes[text.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[text.len() - 1] == b'"')
        {
            text = &text[1..text.len() - 1];
        }
    }
    text
}

fn fast_word_basename(command: &str, word: FastWord) -> &str {
    let value = fast_word_text(command, word);
    basename(value.trim_start_matches(['(', '{', '!']))
}

fn fast_supported_name(command: &str, word: FastWord, expected: &str) -> bool {
    fast_word_basename(command, word) == expected
        || fast_word_matches(command, word, expected)
        || fast_word_basename_matches(command, word, expected)
}

fn fast_wrapper_name(command: &str, word: FastWord) -> Option<&'static str> {
    ["env", "command", "nice"]
        .into_iter()
        .find(|name| fast_supported_name(command, word, name))
}

fn fast_word_matches(command: &str, word: FastWord, expected: &str) -> bool {
    let raw = &command.as_bytes()[word.start..word.end];
    let expected = expected.as_bytes();
    let mut raw_index = 0usize;
    let mut expected_index = 0usize;
    while expected_index < expected.len() {
        while raw_index < raw.len() {
            if matches!(raw[raw_index], b'\'' | b'"') {
                raw_index += 1;
            } else if raw[raw_index] == b'\\' && raw.get(raw_index + 1) == Some(&b'\n') {
                raw_index += 2;
            } else {
                break;
            }
        }
        if raw_index >= raw.len() {
            return false;
        }
        if raw[raw_index] == b'\\' {
            raw_index += 1;
            if raw_index >= raw.len() {
                return false;
            }
        }
        if raw[raw_index] != expected[expected_index] {
            return false;
        }
        raw_index += 1;
        expected_index += 1;
    }
    while raw_index < raw.len() {
        if matches!(raw[raw_index], b'\'' | b'"') {
            raw_index += 1;
        } else if raw[raw_index] == b'\\' && raw.get(raw_index + 1) == Some(&b'\n') {
            raw_index += 2;
        } else {
            break;
        }
    }
    raw_index == raw.len()
}

fn fast_word_basename_matches(command: &str, word: FastWord, expected: &str) -> bool {
    let raw = &command.as_bytes()[word.start..word.end];
    let mut last_slash = None;
    let mut index = 0usize;
    while index < raw.len() {
        if raw[index] == b'/' {
            last_slash = Some(index + 1);
        }
        if raw[index] == b'\\' && raw.get(index + 1) == Some(&b'\n') {
            index += 2;
        } else {
            index += 1;
        }
    }
    let Some(offset) = last_slash else {
        return false;
    };
    let suffix = FastWord {
        start: word.start + offset,
        end: word.end,
        dynamic: word.dynamic,
        opaque: word.opaque,
    };
    fast_word_matches(command, suffix, expected)
}

fn fast_word_starts_with(command: &str, word: FastWord, expected: &str) -> bool {
    let raw = &command.as_bytes()[word.start..word.end];
    let expected = expected.as_bytes();
    let mut raw_index = 0usize;
    for expected_byte in expected {
        while raw_index < raw.len() {
            if matches!(raw[raw_index], b'\'' | b'"') {
                raw_index += 1;
            } else if raw[raw_index] == b'\\' && raw.get(raw_index + 1) == Some(&b'\n') {
                raw_index += 2;
            } else {
                break;
            }
        }
        if raw_index >= raw.len() {
            return false;
        }
        if raw[raw_index] == b'\\' {
            raw_index += 1;
            if raw_index >= raw.len() {
                return false;
            }
        }
        if raw[raw_index] != *expected_byte {
            return false;
        }
        raw_index += 1;
    }
    true
}

fn parse_segments(command: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut tokens = Vec::new();
    let mut value = String::new();
    let mut raw = String::new();
    let mut token_started = false;
    let mut dynamic = false;
    let mut quote = None;
    let mut escaped = false;
    let mut segment_unbalanced = false;
    let mut chars = command.char_indices().peekable();

    let flush_token = |tokens: &mut Vec<Token>,
                       value: &mut String,
                       raw: &mut String,
                       token_started: &mut bool,
                       dynamic: &mut bool| {
        if *token_started {
            tokens.push(Token {
                value: std::mem::take(value),
                raw: std::mem::take(raw),
                dynamic: *dynamic,
            });
            *token_started = false;
            *dynamic = false;
        }
    };
    let mut pipeline_before = false;
    let mut conditional_before = false;
    let flush_segment = |segments: &mut Vec<Segment>,
                         tokens: &mut Vec<Token>,
                         segment_unbalanced: &mut bool,
                         pipeline_before: &mut bool,
                         conditional_before: &mut bool| {
        if !tokens.is_empty() || *segment_unbalanced {
            segments.push(Segment {
                tokens: std::mem::take(tokens),
                unbalanced: *segment_unbalanced,
                pipeline_before: *pipeline_before,
                conditional_before: *conditional_before,
            });
        }
        *segment_unbalanced = false;
        *pipeline_before = false;
        *conditional_before = false;
    };

    while let Some((_, ch)) = chars.next() {
        if escaped {
            raw.push(ch);
            value.push(ch);
            token_started = true;
            escaped = false;
            continue;
        }

        if let Some(active_quote) = quote {
            raw.push(ch);
            token_started = true;
            if active_quote == '"' && ch == '\\' {
                // A backslash inside double quotes protects the following byte,
                // including a quote or command boundary.
                if let Some((_, escaped_ch)) = chars.next() {
                    raw.push(escaped_ch);
                    value.push(escaped_ch);
                } else {
                    escaped = true;
                }
            } else if ch == active_quote {
                quote = None;
            } else {
                value.push(ch);
                if active_quote == '"' {
                    mark_dynamic(ch, chars.peek().map(|(_, next)| *next), &mut dynamic);
                }
            }
            continue;
        }

        match ch {
            '\\' => {
                token_started = true;
                if chars.peek().is_some_and(|(_, next)| *next == '\n') {
                    chars.next();
                } else {
                    raw.push(ch);
                    escaped = true;
                }
            }
            '\'' | '"' => {
                raw.push(ch);
                token_started = true;
                quote = Some(ch);
            }
            ';' | '\n' => {
                flush_token(
                    &mut tokens,
                    &mut value,
                    &mut raw,
                    &mut token_started,
                    &mut dynamic,
                );
                flush_segment(
                    &mut segments,
                    &mut tokens,
                    &mut segment_unbalanced,
                    &mut pipeline_before,
                    &mut conditional_before,
                );
                pipeline_before = false;
                conditional_before = false;
            }
            '|' | '&' => {
                let is_pipeline = ch == '|' && chars.peek().map(|(_, next)| *next) != Some('|');
                let is_boundary = match (ch, chars.peek().map(|(_, next)| *next)) {
                    ('|', Some('|')) | ('&', Some('&')) => {
                        chars.next();
                        true
                    }
                    ('|', _) => true,
                    _ => false,
                };
                if is_boundary {
                    flush_token(
                        &mut tokens,
                        &mut value,
                        &mut raw,
                        &mut token_started,
                        &mut dynamic,
                    );
                    flush_segment(
                        &mut segments,
                        &mut tokens,
                        &mut segment_unbalanced,
                        &mut pipeline_before,
                        &mut conditional_before,
                    );
                    pipeline_before = is_pipeline;
                    conditional_before = !is_pipeline;
                } else {
                    raw.push(ch);
                    value.push(ch);
                    token_started = true;
                }
            }
            c if c.is_whitespace() => {
                flush_token(
                    &mut tokens,
                    &mut value,
                    &mut raw,
                    &mut token_started,
                    &mut dynamic,
                );
            }
            '$' => {
                raw.push(ch);
                value.push(ch);
                token_started = true;
                if matches!(chars.peek().map(|(_, next)| *next), Some('(')) {
                    // Command substitution remains opaque even when its output looks harmless.
                    dynamic = true;
                } else if matches!(chars.peek().map(|(_, next)| *next), Some('{')) {
                    // `${...}` is classified below when the complete token is inspected.
                }
            }
            '`' => {
                raw.push(ch);
                value.push(ch);
                token_started = true;
                dynamic = true;
            }
            '*' | '?' | '[' => {
                raw.push(ch);
                value.push(ch);
                token_started = true;
                dynamic = true;
            }
            _ => {
                raw.push(ch);
                value.push(ch);
                token_started = true;
            }
        }
    }

    if escaped || quote.is_some() {
        segment_unbalanced = true;
    }
    flush_token(
        &mut tokens,
        &mut value,
        &mut raw,
        &mut token_started,
        &mut dynamic,
    );
    flush_segment(
        &mut segments,
        &mut tokens,
        &mut segment_unbalanced,
        &mut pipeline_before,
        &mut conditional_before,
    );

    for segment in &mut segments {
        for token in &mut segment.tokens {
            token.dynamic = token_is_dynamic(&token.raw);
        }
    }
    segments
}

fn mark_dynamic(ch: char, next: Option<char>, dynamic: &mut bool) {
    if ch == '`' || matches!(next, Some('(')) {
        *dynamic = true;
    }
}

fn token_is_dynamic(raw: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    // Keep literal short-name text such as `RUNNER~1` out of the dynamic path.
    let mut assignment_seen = false;
    let mut tilde_position = true;
    let chars = raw.char_indices();
    for (index, ch) in chars {
        if escaped {
            escaped = false;
            tilde_position = false;
            continue;
        }
        if quote == Some('\'') {
            if ch == '\'' {
                quote = None;
            }
            continue;
        }
        if quote == Some('"') {
            if ch == '"' {
                quote = None;
                continue;
            }
            if ch == '`' {
                return true;
            }
            if ch == '$' && shell_expansion_is_dynamic(raw, index) {
                return true;
            }
            if ch == '\\' {
                escaped = true;
            }
            continue;
        } else {
            match ch {
                '\\' => {
                    escaped = true;
                    tilde_position = false;
                    continue;
                }
                '\'' | '"' => {
                    quote = Some(ch);
                    tilde_position = false;
                    continue;
                }
                '`' | '*' | '?' | '[' | '{' | '}' => return true,
                '~' if tilde_position => return true,
                '~' => tilde_position = false,
                '$' if shell_expansion_is_dynamic(raw, index) => return true,
                '=' => {
                    assignment_seen = true;
                    tilde_position = true;
                }
                ':' => tilde_position = assignment_seen,
                _ => tilde_position = false,
            }
        }
    }
    false
}

fn shell_expansion_is_dynamic(raw: &str, index: usize) -> bool {
    let remainder = &raw[index + 1..];
    if remainder.starts_with('(') {
        return true;
    }
    if let Some(name) = remainder.strip_prefix('{') {
        let Some(end) = name.find('}') else {
            return true;
        };
        let name = &name[..end];
        return !known_variable(name) || name.starts_with('!') || name.contains('[');
    }
    let name_end = remainder
        .char_indices()
        .take_while(|(_, candidate)| candidate.is_ascii_alphanumeric() || *candidate == '_')
        .last()
        .map(|(offset, candidate)| offset + candidate.len_utf8())
        .unwrap_or(0);
    name_end == 0 || !known_variable(&remainder[..name_end])
}

fn known_variable(name: &str) -> bool {
    matches!(
        name,
        "HOME" | "USERPROFILE" | "HOMEDRIVE" | "HOMEPATH" | "USER" | "TMP" | "TMPDIR"
    )
}

fn parse_segment(
    segment: &Segment,
    inherited_source: CommandSource,
    nested_depth: usize,
) -> Vec<DeleteOperation> {
    let Some(command_index) = command_index(segment) else {
        return Vec::new();
    };
    let tokens = &segment.tokens;
    let command = basename(&tokens[command_index].value);
    let command_lower = command.to_ascii_lowercase();

    if matches!(command, "bash" | "sh" | "zsh" | "dash") {
        let Some(script_index) = command_string_index(tokens, command_index) else {
            return Vec::new();
        };
        let source = CommandSource::NestedShell;
        if nested_depth >= MAX_NESTED_SHELL_DEPTH {
            return vec![DeleteOperation {
                kind: DeleteKind::Rm,
                raw_targets: Vec::new(),
                recursive: true,
                ambiguous: true,
                source,
                target_syntax: TargetSyntax::Posix,
            }];
        }
        return parse_segments(&tokens[script_index].value)
            .into_iter()
            .flat_map(|nested| parse_segment(&nested, source, nested_depth + 1))
            .map(|mut operation| {
                operation.ambiguous |= segment.unbalanced;
                operation.source = source;
                operation
            })
            .collect();
    }

    let runtime_source = if nested_depth == 0 {
        CommandSource::Direct
    } else {
        CommandSource::NestedShell
    };
    if command_lower == "rm"
        && tokens.iter().skip(command_index + 1).any(|token| {
            matches!(
                token.value.to_ascii_lowercase().as_str(),
                "-path" | "-literalpath" | "-recurse" | "-recursive"
            ) || token.value.to_ascii_lowercase().starts_with("-path:")
                || token
                    .value
                    .to_ascii_lowercase()
                    .starts_with("-literalpath:")
        })
    {
        return powershell::parse_delete_operations_from_tokens(
            tokens,
            command_index,
            segment.unbalanced,
            runtime_source,
            nested_depth,
        );
    }
    if matches!(
        command_lower.as_str(),
        "pwsh" | "powershell" | "pwsh.exe" | "powershell.exe"
    ) || command_lower == "remove-item"
    {
        return powershell::parse_delete_operations_from_tokens(
            tokens,
            command_index,
            segment.unbalanced,
            runtime_source,
            nested_depth,
        );
    }
    if matches!(command_lower.as_str(), "cmd" | "cmd.exe")
        || matches!(command_lower.as_str(), "del" | "erase" | "rd")
        || (command_lower == "rmdir"
            && tokens.iter().any(|token| {
                matches!(
                    token.value.to_ascii_lowercase().as_str(),
                    "/s" | "/q" | "/sq" | "/qs"
                )
            }))
    {
        return cmd::parse_delete_operations_from_tokens(
            tokens,
            command_index,
            segment.unbalanced,
            runtime_source,
            nested_depth,
        );
    }
    if matches!(
        command_lower.as_str(),
        "node" | "node.exe" | "python" | "python3" | "python.exe" | "py" | "py.exe"
    ) {
        return inline_runtime::parse_command(
            tokens,
            command_index,
            segment.unbalanced,
            runtime_source,
        );
    }

    let source = if command_index > 0 {
        CommandSource::Wrapper
    } else {
        inherited_source
    };

    match command {
        "rm" => vec![parse_delete_command(
            &tokens[command_index..],
            DeleteKind::Rm,
            source,
            segment.unbalanced,
        )],
        "rmdir" => vec![parse_delete_command(
            &tokens[command_index..],
            DeleteKind::Rmdir,
            source,
            segment.unbalanced,
        )],
        "unlink" => vec![parse_delete_command(
            &tokens[command_index..],
            DeleteKind::Unlink,
            source,
            segment.unbalanced,
        )],
        "find" => parse_find(tokens, command_index, segment.unbalanced),
        "xargs" => parse_xargs(tokens, command_index, segment.unbalanced),
        "rsync" => parse_rsync(tokens, command_index, segment.unbalanced),
        "git" => parse_git(tokens, command_index, segment.unbalanced),
        _ => Vec::new(),
    }
}

fn command_index(segment: &Segment) -> Option<usize> {
    let index = command_position_index(segment)?;
    (!segment.tokens[index].dynamic).then_some(index)
}

fn command_position_index(segment: &Segment) -> Option<usize> {
    let mut index = 0;
    while index < segment.tokens.len() {
        let value = segment.tokens[index].value.as_str();
        if is_assignment(value) {
            index += 1;
            continue;
        }
        if matches!(basename(value), "env" | "command" | "nice") {
            let wrapper = basename(value);
            index += 1;
            while index < segment.tokens.len() {
                let option = segment.tokens[index].value.as_str();
                if wrapper_opaque_option(wrapper, option) {
                    return None;
                }
                if is_assignment(option) || option.starts_with('-') {
                    index += 1;
                    if wrapper_option_takes_value(wrapper, option) {
                        index = (index + 1).min(segment.tokens.len());
                    }
                    continue;
                }
                break;
            }
            continue;
        }
        return Some(index);
    }
    None
}

fn wrapper_option_takes_value(wrapper: &str, option: &str) -> bool {
    match wrapper {
        "env" => matches!(
            option,
            "-C" | "--chdir" | "-P" | "--path" | "-S" | "--split-string" | "-u" | "--unset"
        ),
        "nice" => matches!(option, "-n" | "--adjustment"),
        _ => false,
    }
}

fn wrapper_opaque_option(wrapper: &str, option: &str) -> bool {
    wrapper == "env"
        && (option == "-S"
            || option == "--split-string"
            || option.starts_with("-S=")
            || option.starts_with("--split-string="))
}

fn command_string_index(tokens: &[Token], command_index: usize) -> Option<usize> {
    let mut index = command_index + 1;
    while index < tokens.len() {
        let value = tokens[index].value.as_str();
        if shell_command_option(value) {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        index += 1;
    }
    None
}

fn shell_command_option(value: &str) -> bool {
    if value == "-c" || value == "--command" {
        return true;
    }
    let Some(flags) = value.strip_prefix('-') else {
        return false;
    };
    !flags.starts_with('-') && flags.contains('c')
}

fn parse_delete_command(
    tokens: &[Token],
    kind: DeleteKind,
    source: CommandSource,
    unbalanced: bool,
) -> DeleteOperation {
    let mut raw_targets = Vec::new();
    let mut recursive = false;
    let mut ambiguous = unbalanced;
    let mut options_ended = false;

    for token in tokens.iter().skip(1) {
        let value = token.value.as_str();
        if !options_ended && value == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && value.starts_with('-') && value != "-" {
            let short_options = value
                .strip_prefix('-')
                .filter(|rest| !rest.starts_with('-'));
            let rmdir_parents = kind == DeleteKind::Rmdir
                && (value == "--parents"
                    || short_options.is_some_and(|options| options.contains('p')));
            let rm_directory = kind == DeleteKind::Rm
                && (value == "--dir" || short_options.is_some_and(|options| options.contains('d')));
            if value == "--recursive"
                || rmdir_parents
                || value.contains('r')
                || value.contains('R')
                || rm_directory
            {
                recursive = true;
            }
            if rmdir_parents || rm_directory {
                ambiguous = true;
            }
            continue;
        }
        raw_targets.push(token.raw.clone());
        ambiguous |= token.dynamic;
    }

    if raw_targets.is_empty() {
        ambiguous = true;
    }
    if recursive && raw_targets.iter().any(|_| ambiguous) {
        ambiguous = true;
    }

    DeleteOperation {
        kind,
        raw_targets,
        recursive,
        ambiguous,
        source,
        target_syntax: TargetSyntax::Posix,
    }
}

fn parse_find(tokens: &[Token], command_index: usize, unbalanced: bool) -> Vec<DeleteOperation> {
    let mut raw_targets = Vec::new();
    let mut ambiguous = unbalanced;
    let mut expression_started = false;
    let mut deleting = false;
    let mut exec_depth = 0usize;
    let mut pending_argument = false;
    let mut index = command_index + 1;
    while index < tokens.len() {
        let token = &tokens[index];
        let value = token.value.as_str();

        if exec_depth > 0 {
            // `find -exec ... \;` is opaque to this parser.  In particular,
            // `-delete` in the nested command is not find's expression.
            if value == ";" || value == "\\;" {
                exec_depth = 0;
            }
            index += 1;
            continue;
        }
        if pending_argument {
            pending_argument = false;
            index += 1;
            continue;
        }
        if value == "-exec" || value == "-execdir" || value == "-ok" || value == "-okdir" {
            exec_depth = 1;
            index += 1;
            continue;
        }
        if find_predicate_takes_argument(value) {
            expression_started = true;
            pending_argument = true;
            index += 1;
            continue;
        }
        if value == "-delete" {
            deleting = true;
            index += 1;
            continue;
        }
        if !expression_started && !value.starts_with('-') {
            raw_targets.push(token.raw.clone());
            ambiguous |= token.dynamic;
        } else if !value.starts_with('-') {
            // Expression arguments after a predicate (for example `*.tmp`)
            // are not search roots.
        } else if !deleting {
            expression_started = true;
        }
        index += 1;
    }
    if !deleting {
        return Vec::new();
    }
    if raw_targets.is_empty() {
        ambiguous = true;
    }
    vec![DeleteOperation {
        kind: DeleteKind::FindDelete,
        raw_targets,
        recursive: true,
        ambiguous,
        source: CommandSource::Find,
        target_syntax: TargetSyntax::Posix,
    }]
}

fn parse_xargs(tokens: &[Token], command_index: usize, unbalanced: bool) -> Vec<DeleteOperation> {
    let Some(command_start) = xargs_command_index(tokens, command_index) else {
        return Vec::new();
    };
    if basename(&tokens[command_start].value) != "rm" || tokens[command_start].dynamic {
        return Vec::new();
    }
    let mut operation = parse_delete_command(
        &tokens[command_start..],
        DeleteKind::XargsRm,
        CommandSource::Xargs,
        unbalanced,
    );
    operation.source = CommandSource::Xargs;
    vec![operation]
}

fn xargs_command_index(tokens: &[Token], command_index: usize) -> Option<usize> {
    let mut index = command_index + 1;
    while index < tokens.len() {
        let value = tokens[index].value.as_str();
        if value == "--" {
            return (index + 1 < tokens.len()).then_some(index + 1);
        }
        if value.starts_with('-') {
            // GNU/BSD xargs options that consume a following argument.
            if matches!(
                value,
                "-E" | "--eof"
                    | "-I"
                    | "--replace"
                    | "-J"
                    | "-L"
                    | "--max-lines"
                    | "-n"
                    | "--max-args"
                    | "-P"
                    | "--max-procs"
                    | "-d"
                    | "--delimiter"
            ) {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        return Some(index);
    }
    None
}

fn parse_rsync(tokens: &[Token], command_index: usize, unbalanced: bool) -> Vec<DeleteOperation> {
    let mut deleting = false;
    let mut positional = Vec::new();
    let mut ambiguous = unbalanced;
    let mut option_value_pending = false;
    for token in tokens.iter().skip(command_index + 1) {
        if option_value_pending {
            option_value_pending = false;
            continue;
        }
        if token.value.starts_with("--delete") {
            deleting = true;
            continue;
        }
        if rsync_option_takes_argument(&token.value) {
            option_value_pending = true;
            continue;
        }
        if !token.value.starts_with('-') {
            positional.push((token.raw.clone(), token.dynamic));
        }
    }
    if !deleting {
        return Vec::new();
    }
    let mut raw_targets = Vec::new();
    if let Some((destination, destination_dynamic)) = positional.pop() {
        raw_targets.push(destination);
        ambiguous |= destination_dynamic;
    } else {
        ambiguous = true;
    }
    vec![DeleteOperation {
        kind: DeleteKind::RsyncDelete,
        raw_targets,
        recursive: true,
        ambiguous,
        source: CommandSource::Rsync,
        target_syntax: TargetSyntax::Posix,
    }]
}

fn rsync_option_takes_argument(value: &str) -> bool {
    matches!(
        value,
        "--exclude"
            | "--include"
            | "--filter"
            | "--exclude-from"
            | "--include-from"
            | "--files-from"
            | "--rsh"
            | "-e"
    )
}

fn parse_git(tokens: &[Token], command_index: usize, unbalanced: bool) -> Vec<DeleteOperation> {
    let Some(clean_index) = git_subcommand_index(tokens, command_index) else {
        return Vec::new();
    };
    if tokens[clean_index].value != "clean" || tokens[clean_index].dynamic {
        return Vec::new();
    }
    let mut raw_targets = Vec::new();
    let mut ambiguous = unbalanced;
    let mut recursive = false;
    for token in tokens.iter().skip(clean_index + 1) {
        if git_clean_recursive_flag(&token.value) {
            recursive = true;
        }
        if !token.value.starts_with('-') {
            raw_targets.push(token.raw.clone());
            ambiguous |= token.dynamic;
        }
    }

    vec![DeleteOperation {
        kind: DeleteKind::GitClean,
        raw_targets,
        recursive,
        ambiguous,
        source: CommandSource::Git,
        target_syntax: TargetSyntax::Posix,
    }]
}

fn git_subcommand_index(tokens: &[Token], command_index: usize) -> Option<usize> {
    let mut index = command_index + 1;
    while index < tokens.len() {
        let value = tokens[index].value.as_str();
        if value.starts_with('-') {
            if matches!(value, "-C" | "--git-dir" | "--work-tree" | "--exec-path") {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        return Some(index);
    }
    None
}

fn git_clean_recursive_flag(value: &str) -> bool {
    if value == "--" {
        return false;
    }
    if let Some(shorts) = value.strip_prefix('-') {
        return !shorts.starts_with('-') && shorts.chars().any(|ch| ch == 'd');
    }
    false
}

fn find_predicate_takes_argument(value: &str) -> bool {
    matches!(
        value,
        "-amin"
            | "-anewer"
            | "-atime"
            | "-cmin"
            | "-cnewer"
            | "-ctime"
            | "-fstype"
            | "-group"
            | "-iname"
            | "-ipath"
            | "-iwholename"
            | "-links"
            | "-lname"
            | "-mmin"
            | "-mtime"
            | "-name"
            | "-newer"
            | "-path"
            | "-perm"
            | "-regex"
            | "-samefile"
            | "-size"
            | "-type"
            | "-user"
            | "-wholename"
    )
}

fn xargs_option_takes_argument(value: &str) -> bool {
    matches!(
        value,
        "-a" | "--arg-file"
            | "-d"
            | "--delimiter"
            | "-E"
            | "--eof"
            | "-I"
            | "--replace"
            | "-J"
            | "-L"
            | "--max-lines"
            | "-n"
            | "--max-args"
            | "-P"
            | "--max-procs"
            | "-s"
            | "--max-chars"
            | "--process-slot-var"
    )
}

fn git_option_takes_argument(value: &str) -> bool {
    matches!(
        value,
        "-C" | "--git-dir"
            | "--work-tree"
            | "-c"
            | "--config-env"
            | "--exec-path"
            | "--namespace"
            | "--super-prefix"
    )
}

fn is_assignment(value: &str) -> bool {
    let Some((name, _)) = value.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn basename(value: &str) -> &str {
    value.rsplit('/').next().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_interpreter_depth_is_bounded_from_posix_entry() {
        for command in [
            r#"pwsh -Command "Remove-Item -Recurse C:\Users\Alice""#,
            r#"cmd /c "rd /s /q C:\Users\Alice""#,
        ] {
            let segment = parse_segments(command).pop().expect("one segment");
            let within = parse_segment(
                &segment,
                CommandSource::Direct,
                super::super::MAX_INTERPRETER_DEPTH - 1,
            );
            assert_eq!(within.len(), 1, "{command}");
            assert!(!within[0].ambiguous, "{command}");

            let bounded = parse_segment(
                &segment,
                CommandSource::Direct,
                super::super::MAX_INTERPRETER_DEPTH,
            );
            assert_eq!(bounded.len(), 1, "{command}");
            assert!(bounded[0].ambiguous, "{command}");
        }
    }
}
