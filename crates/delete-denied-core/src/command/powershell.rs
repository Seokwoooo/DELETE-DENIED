use super::{CommandSource, DeleteKind, DeleteOperation, TargetSyntax};

#[derive(Debug, Clone)]
struct Token {
    value: String,
    raw: String,
    dynamic: bool,
}

#[derive(Debug, Clone)]
struct Segment {
    tokens: Vec<Token>,
    unbalanced: bool,
}

/// Parse the small, literal PowerShell deletion surface supported by the hook.
pub fn parse_delete_operations(command: &str) -> Vec<DeleteOperation> {
    parse_delete_operations_at_depth(command, 0)
}

pub(crate) fn parse_delete_operations_at_depth(
    command: &str,
    depth: usize,
) -> Vec<DeleteOperation> {
    parse_segments(command)
        .into_iter()
        .flat_map(|segment| parse_segment(&segment, depth))
        .collect()
}

pub(crate) fn parse_delete_operations_from_tokens(
    tokens: &[super::posix::Token],
    command_index: usize,
    unbalanced: bool,
    source: CommandSource,
    depth: usize,
) -> Vec<DeleteOperation> {
    let converted = tokens
        .iter()
        .map(|token| Token {
            value: token.value.clone(),
            raw: token.raw.clone(),
            dynamic: token.dynamic,
        })
        .collect::<Vec<_>>();
    let command = converted[command_index].value.to_ascii_lowercase();
    if matches!(
        command.as_str(),
        "pwsh" | "powershell" | "pwsh.exe" | "powershell.exe"
    ) {
        let Some(script) = command_payload(&converted, command_index) else {
            return vec![ambiguous_operation()];
        };
        if depth >= super::MAX_INTERPRETER_DEPTH || unbalanced || script.dynamic {
            return vec![ambiguous_operation()];
        }
        let payload_text = nested_payload_text(script);
        return parse_nested_payload(&payload_text, depth.saturating_add(1))
            .into_iter()
            .map(|mut operation| {
                operation.source = CommandSource::NestedShell;
                operation
            })
            .collect();
    }
    let segment = Segment {
        tokens: converted[command_index..].to_vec(),
        unbalanced,
    };
    parse_segment(&segment, depth)
        .into_iter()
        .map(|mut operation| {
            operation.source = source;
            operation
        })
        .collect()
}

fn parse_segment(segment: &Segment, depth: usize) -> Vec<DeleteOperation> {
    let Some(command_index) = command_index(segment) else {
        return Vec::new();
    };
    let command = segment.tokens[command_index].value.to_ascii_lowercase();
    if matches!(
        command.as_str(),
        "pwsh" | "powershell" | "pwsh.exe" | "powershell.exe"
    ) {
        let Some(script) = command_payload(&segment.tokens, command_index) else {
            return vec![ambiguous_operation()];
        };
        if depth >= super::MAX_INTERPRETER_DEPTH || segment.unbalanced || script.dynamic {
            return vec![ambiguous_operation()];
        }
        return parse_nested_payload(&script.value, depth + 1)
            .into_iter()
            .map(|mut operation| {
                operation.source = CommandSource::NestedShell;
                operation
            })
            .collect();
    }
    let kind = match command.as_str() {
        "remove-item" | "rm" | "ri" | "del" | "erase" => DeleteKind::Rm,
        "rd" | "rmdir" => DeleteKind::Rmdir,
        _ => return Vec::new(),
    };
    Some(parse_delete_command(
        &segment.tokens[command_index..],
        kind,
        segment.unbalanced,
    ))
    .into_iter()
    .collect()
}

fn parse_nested_payload(command: &str, depth: usize) -> Vec<DeleteOperation> {
    let first = command
        .split(|character: char| {
            character.is_ascii_whitespace() || matches!(character, ';' | '|' | '&')
        })
        .find(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase());
    if matches!(first.as_deref(), Some("cmd" | "cmd.exe")) {
        super::cmd::parse_delete_operations_at_depth(command, depth)
    } else {
        parse_delete_operations_at_depth(command, depth)
    }
}

fn parse_delete_command(tokens: &[Token], kind: DeleteKind, unbalanced: bool) -> DeleteOperation {
    let mut raw_targets = Vec::new();
    let mut recursive = false;
    let mut ambiguous = unbalanced;
    let mut options_ended = false;
    let mut pending_value = false;

    for token in tokens.iter().skip(1) {
        let value = token.value.as_str();
        if pending_value {
            if !options_ended && value.starts_with('-') && value != "-" {
                ambiguous = true;
                pending_value = false;
            } else {
                let target = normalize_target(token.raw.as_str());
                ambiguous |= token.dynamic && target == token.raw;
                raw_targets.push(target);
                pending_value = false;
                continue;
            }
        }
        if !options_ended && value == "--" {
            options_ended = true;
            continue;
        }
        if !options_ended && value.starts_with('-') && value != "-" {
            let (option, attached) = value
                .split_once(':')
                .map_or((value, None), |(name, attached)| (name, Some(attached)));
            let option = option.to_ascii_lowercase();
            if matches!(option.as_str(), "-recurse" | "-recursive" | "-r") {
                recursive = true;
            }
            if matches!(
                option.as_str(),
                "-path" | "-literalpath" | "-target" | "-name"
            ) {
                match attached {
                    Some(target) if !target.is_empty() => {
                        let target = token
                            .raw
                            .split_once(':')
                            .map_or(target, |(_, attached)| attached);
                        raw_targets.push(normalize_target(target));
                        ambiguous |= token.dynamic;
                    }
                    _ => pending_value = true,
                }
            }
            continue;
        }
        let target = normalize_target(token.raw.as_str());
        ambiguous |= token.dynamic && target == token.raw;
        raw_targets.push(target);
    }

    if raw_targets.is_empty() {
        ambiguous = true;
        raw_targets.push("$UNKNOWN".to_owned());
    }
    if pending_value {
        ambiguous = true;
    }
    DeleteOperation {
        kind,
        raw_targets,
        recursive,
        ambiguous,
        source: CommandSource::Direct,
        target_syntax: TargetSyntax::Windows,
    }
}

fn normalize_target(raw: &str) -> String {
    raw.replace("$env:HOME", "$HOME")
        .replace("$env:USERPROFILE", "$USERPROFILE")
        .replace("$env:HOMEDRIVE", "$HOMEDRIVE")
        .replace("$env:HOMEPATH", "$HOMEPATH")
        .replace("$env:TMP", "$TMP")
        .replace("$env:TMPDIR", "$TMPDIR")
}

fn command_payload(tokens: &[Token], command_index: usize) -> Option<&Token> {
    let mut index = command_index + 1;
    while index < tokens.len() {
        let option = tokens[index].value.to_ascii_lowercase();
        if option == "-command" || option == "-c" || option == "/c" {
            return tokens.get(index + 1);
        }
        index += 1;
    }
    None
}

fn nested_payload_text(token: &Token) -> String {
    let raw = token.raw.as_str();
    let unquoted = raw
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            raw.strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        });
    unquoted.unwrap_or(&token.value).to_owned()
}

fn command_index(segment: &Segment) -> Option<usize> {
    segment.tokens.iter().position(|token| {
        !token.value.is_empty() && !token.value.starts_with('$') && !token.value.contains('=')
    })
}

fn ambiguous_operation() -> DeleteOperation {
    DeleteOperation {
        kind: DeleteKind::Rm,
        raw_targets: vec!["$UNKNOWN".to_owned()],
        recursive: true,
        ambiguous: true,
        source: CommandSource::NestedShell,
        target_syntax: TargetSyntax::Windows,
    }
}

fn parse_segments(command: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut tokens = Vec::new();
    let mut value = String::new();
    let mut raw = String::new();
    let mut started = false;
    let mut dynamic = false;
    let mut quote = None;
    let mut unbalanced = false;

    let flush_token = |tokens: &mut Vec<Token>,
                       value: &mut String,
                       raw: &mut String,
                       started: &mut bool,
                       dynamic: &mut bool| {
        if *started {
            tokens.push(Token {
                value: std::mem::take(value),
                raw: std::mem::take(raw),
                dynamic: *dynamic,
            });
            *started = false;
            *dynamic = false;
        }
    };
    let flush_segment =
        |segments: &mut Vec<Segment>, tokens: &mut Vec<Token>, unbalanced: &mut bool| {
            if !tokens.is_empty() || *unbalanced {
                segments.push(Segment {
                    tokens: std::mem::take(tokens),
                    unbalanced: *unbalanced,
                });
            }
            *unbalanced = false;
        };

    let mut chars = command.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if let Some(active) = quote {
            raw.push(character);
            started = true;
            if active == '"'
                && (character == '`'
                    || (character == '\\' && chars.peek().is_some_and(|(_, next)| *next == '"')))
            {
                if let Some((_, escaped)) = chars.next() {
                    raw.push(escaped);
                    value.push(escaped);
                }
                continue;
            }
            if character == active {
                quote = None;
            } else {
                value.push(character);
                if matches!(character, '$' | '%' | '*' | '?' | '~') {
                    dynamic |= dynamic_marker(command, index);
                    dynamic |= character == '~';
                }
            }
            continue;
        }
        match character {
            '\'' | '"' => {
                raw.push(character);
                started = true;
                quote = Some(character);
            }
            ';' | '\n' => {
                flush_token(
                    &mut tokens,
                    &mut value,
                    &mut raw,
                    &mut started,
                    &mut dynamic,
                );
                flush_segment(&mut segments, &mut tokens, &mut unbalanced);
            }
            '|' | '&' => {
                let doubled = chars.peek().is_some_and(|(_, next)| *next == character);
                flush_token(
                    &mut tokens,
                    &mut value,
                    &mut raw,
                    &mut started,
                    &mut dynamic,
                );
                flush_segment(&mut segments, &mut tokens, &mut unbalanced);
                if doubled {
                    chars.next();
                }
            }
            character if character.is_whitespace() => {
                flush_token(
                    &mut tokens,
                    &mut value,
                    &mut raw,
                    &mut started,
                    &mut dynamic,
                );
            }
            '$' | '%' | '*' | '?' | '~' => {
                raw.push(character);
                value.push(character);
                started = true;
                dynamic |= character == '~' || dynamic_marker(command, index);
            }
            character => {
                raw.push(character);
                value.push(character);
                started = true;
            }
        }
    }
    if quote.is_some() {
        unbalanced = true;
    }
    flush_token(
        &mut tokens,
        &mut value,
        &mut raw,
        &mut started,
        &mut dynamic,
    );
    flush_segment(&mut segments, &mut tokens, &mut unbalanced);
    segments
}

fn dynamic_marker(command: &str, index: usize) -> bool {
    match command.as_bytes().get(index) {
        Some(b'*' | b'?') => true,
        Some(b'%') => {
            if let Some(open) = command[..index].rfind('%') {
                let name = &command[open + 1..index];
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|character| character.is_ascii_alphanumeric() || character == '_')
                {
                    return !matches!(
                        name,
                        "HOME" | "USERPROFILE" | "HOMEDRIVE" | "HOMEPATH" | "TMP" | "TMPDIR"
                    );
                }
            }
            let rest = &command[index + 1..];
            let Some(end) = rest.find('%') else {
                return true;
            };
            !matches!(
                &rest[..end],
                "HOME" | "USERPROFILE" | "HOMEDRIVE" | "HOMEPATH" | "TMP" | "TMPDIR"
            )
        }
        Some(b'$') => {
            let rest = &command[index + 1..];
            if let Some(braced) = rest.strip_prefix('{') {
                let Some(end) = braced.find('}') else {
                    return true;
                };
                return !matches!(
                    &braced[..end],
                    "HOME" | "USERPROFILE" | "HOMEDRIVE" | "HOMEPATH" | "TMP" | "TMPDIR"
                );
            }
            let rest = rest.strip_prefix("env:").unwrap_or(rest);
            let end = rest
                .char_indices()
                .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
                .last()
                .map_or(0, |(offset, ch)| offset + ch.len_utf8());
            end == 0
                || !matches!(
                    &rest[..end],
                    "HOME" | "USERPROFILE" | "HOMEDRIVE" | "HOMEPATH" | "TMP" | "TMPDIR"
                )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_interpreter_depth_is_shared_and_bounded() {
        let one_wrapper = r#"pwsh -Command "Remove-Item -Recurse C:\Users\Alice""#;
        let two_wrappers =
            r#"pwsh -Command "pwsh -Command \"Remove-Item -Recurse C:\Users\Alice\"""#;

        let within =
            parse_delete_operations_at_depth(one_wrapper, super::super::MAX_INTERPRETER_DEPTH - 1);
        assert_eq!(within.len(), 1);
        assert!(!within[0].ambiguous);

        let bounded =
            parse_delete_operations_at_depth(two_wrappers, super::super::MAX_INTERPRETER_DEPTH - 1);
        assert_eq!(bounded.len(), 1);
        assert!(bounded[0].ambiguous);
    }
}
