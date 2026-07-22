use super::posix::Token;
use super::{CommandSource, DeleteKind, DeleteOperation, TargetSyntax};

/// Parse literal Node.js and Python one-liners. This deliberately does not
/// attempt to execute or interpret either language.
pub(crate) fn parse_command(
    tokens: &[Token],
    command_index: usize,
    unbalanced: bool,
    source: CommandSource,
) -> Vec<DeleteOperation> {
    let command = tokens[command_index].value.to_ascii_lowercase();
    let is_node = matches!(command.as_str(), "node" | "node.exe");
    let is_python = matches!(
        command.as_str(),
        "python" | "python3" | "python.exe" | "py" | "py.exe"
    );
    if !is_node && !is_python {
        return Vec::new();
    }
    let Some(script) = inline_script(tokens, command_index, is_node) else {
        return Vec::new();
    };
    if unbalanced || script.dynamic {
        return vec![ambiguous_operation(source)];
    }
    if is_node {
        parse_node(script.value.as_str(), source)
    } else {
        parse_python(script.value.as_str(), source)
    }
}

fn inline_script(tokens: &[Token], command_index: usize, is_node: bool) -> Option<&Token> {
    let mut index = command_index + 1;
    while index < tokens.len() {
        let value = tokens[index].value.as_str();
        let is_inline = if is_node {
            matches!(value, "-e" | "--eval" | "-p" | "--print")
        } else {
            value == "-c"
        };
        if is_inline {
            return tokens.get(index + 1);
        }
        index += 1;
    }
    None
}

fn parse_node(script: &str, source: CommandSource) -> Vec<DeleteOperation> {
    let mut operations = Vec::new();
    for api in ["fs.rmSync", "fs.rm", "fs.rmdir", "fs.unlink"] {
        let mut cursor = 0;
        while let Some(offset) = find_identifier(script, api, cursor) {
            if let Some(operation) = parse_api_call(script, offset + api.len(), api, source) {
                operations.push(operation);
            }
            cursor = offset + api.len();
        }
    }
    operations
        .sort_by_key(|operation| script.find(&operation.raw_targets[0]).unwrap_or(usize::MAX));
    operations
}

fn parse_python(script: &str, source: CommandSource) -> Vec<DeleteOperation> {
    let mut operations = Vec::new();
    for api in ["shutil.rmtree", "os.remove", "os.unlink"] {
        let mut cursor = 0;
        while let Some(offset) = find_identifier(script, api, cursor) {
            if let Some(operation) = parse_api_call(script, offset + api.len(), api, source) {
                operations.push(operation);
            }
            cursor = offset + api.len();
        }
    }
    let mut cursor = 0;
    while let Some(path_offset) = find_identifier(script, "Path", cursor) {
        let Some(path_open) = skip_space(script, path_offset + 4) else {
            break;
        };
        if script.as_bytes().get(path_open) != Some(&b'(') {
            cursor = path_offset + 4;
            continue;
        }
        let Some(path_close) = matching_paren(script, path_open) else {
            break;
        };
        let Some(unlink) = find_identifier(&script[path_close + 1..], ".unlink", 0) else {
            cursor = path_close + 1;
            continue;
        };
        if let Some(operation) = literal_operation(
            &script[path_open + 1..path_close],
            DeleteKind::Unlink,
            false,
            source,
        ) {
            operations.push(operation);
        }
        let _ = unlink;
        cursor = path_close + 1;
    }
    operations
}

fn parse_api_call(
    script: &str,
    after_name: usize,
    api: &str,
    source: CommandSource,
) -> Option<DeleteOperation> {
    let open = skip_space(script, after_name)?;
    if script.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let close = matching_paren(script, open)?;
    let arguments = &script[open + 1..close];
    let recursive = api.ends_with(".rmtree")
        || ((api.ends_with(".rm") || api.ends_with(".rmSync") || api.ends_with(".rmdir"))
            && contains_recursive_true(arguments));
    let kind = if api.ends_with(".unlink") || api.ends_with(".remove") {
        DeleteKind::Unlink
    } else if api.ends_with(".rmdir") {
        DeleteKind::Rmdir
    } else {
        DeleteKind::Rm
    };
    literal_operation(first_argument(arguments), kind, recursive, source)
}

fn literal_operation(
    argument: &str,
    kind: DeleteKind,
    recursive: bool,
    source: CommandSource,
) -> Option<DeleteOperation> {
    let argument = argument.trim();
    let (raw_target, dynamic) = if argument.starts_with('\'') || argument.starts_with('"') {
        let quote = argument.as_bytes()[0];
        let closes = argument[1..].find(quote as char).map(|offset| offset + 1);
        if closes.is_some() {
            (argument[..=closes?].to_owned(), false)
        } else {
            ("$UNKNOWN".to_owned(), true)
        }
    } else {
        ("$UNKNOWN".to_owned(), true)
    };
    Some(DeleteOperation {
        kind,
        raw_targets: vec![raw_target],
        recursive,
        ambiguous: dynamic && recursive,
        source,
        target_syntax: TargetSyntax::Auto,
    })
}

fn first_argument(arguments: &str) -> &str {
    let mut quote = None;
    let mut depth = 0usize;
    for (index, byte) in arguments.bytes().enumerate() {
        if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => return &arguments[..index],
            _ => {}
        }
    }
    arguments
}

fn contains_recursive_true(arguments: &str) -> bool {
    let compact = arguments
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    compact.contains("recursive:true") || compact.contains("recursive=True")
}

fn find_identifier(haystack: &str, needle: &str, from: usize) -> Option<usize> {
    let mut cursor = from;
    while let Some(relative) = haystack[cursor..].find(needle) {
        let offset = cursor + relative;
        let before = haystack[..offset].chars().next_back();
        let after = haystack[offset + needle.len()..].chars().next();
        if !before.is_some_and(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '.'
        }) && !after
            .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Some(offset);
        }
        cursor = offset + needle.len();
    }
    None
}

fn skip_space(script: &str, mut index: usize) -> Option<usize> {
    while index < script.len() && script.as_bytes()[index].is_ascii_whitespace() {
        index += 1;
    }
    (index < script.len()).then_some(index)
}

fn matching_paren(script: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    for (index, byte) in script.bytes().enumerate().skip(open) {
        if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
            continue;
        }
        match byte {
            b'\'' | b'"' => quote = Some(byte),
            b'(' => depth += 1,
            b')' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn ambiguous_operation(source: CommandSource) -> DeleteOperation {
    DeleteOperation {
        kind: DeleteKind::Rm,
        raw_targets: vec!["$UNKNOWN".to_owned()],
        recursive: true,
        ambiguous: true,
        source,
        target_syntax: TargetSyntax::Auto,
    }
}
