use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::command::posix::{ContextAssignment, ContextCwdStep, analyze_delete_operations};
use crate::command::{DeleteKind, DeleteOperation, TargetSyntax};
use crate::hook_input::HookInput;
use crate::path::{
    PathResolver, ResolvedPath, glob_base, has_glob, lexical_normalize, path_equal,
    path_is_ancestor_or_equal, resolve,
};
use crate::policy::Policy;
use crate::scan::{ScanResult, fast_scan};

/// Stable reason codes emitted by the hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyCode {
    ProtectedPath,
    CwdAncestor,
    AmbiguousRecursive,
    PolicyInvalid,
}

impl DenyCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtectedPath => "DD-PROTECTED-PATH",
            Self::CwdAncestor => "DD-CWD-ANCESTOR",
            Self::AmbiguousRecursive => "DD-AMBIGUOUS-RECURSIVE",
            Self::PolicyInvalid => "DD-POLICY-INVALID",
        }
    }
}

impl std::fmt::Display for DenyCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Result of evaluating one suspicious shell command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { code: DenyCode, reason: String },
}

impl Decision {
    pub fn code(&self) -> Option<DenyCode> {
        match self {
            Self::Allow => None,
            Self::Deny { code, .. } => Some(*code),
        }
    }

    pub fn deny(code: DenyCode, reason: impl Into<String>) -> Self {
        Self::Deny {
            code,
            reason: reason.into(),
        }
    }
}

/// Evaluate a hook command against an already-loaded policy.
///
/// Safe scans return before consulting the policy or resolver. Suspicious
/// scans parse only the supported deletion forms; an opaque suspicious command
/// with no parsed operation is denied as ambiguous.
pub fn evaluate(input: &HookInput, policy: &Policy, resolver: &dyn PathResolver) -> Decision {
    if fast_scan(&input.command) == ScanResult::Safe {
        return Decision::Allow;
    }
    if policy.schema_version != 1 || policy.protected_paths.is_empty() {
        return Decision::deny(DenyCode::PolicyInvalid, "protected-path policy is invalid");
    }

    let operations = analyze_delete_operations(&input.command);
    if operations.is_empty() {
        return Decision::deny(
            DenyCode::AmbiguousRecursive,
            "the suspicious shell construct could not be inspected safely",
        );
    }

    let cwd = match resolve(&input.cwd, resolver) {
        Ok(cwd) => cwd,
        Err(_) => {
            return Decision::deny(
                DenyCode::PolicyInvalid,
                "current working directory could not be resolved",
            );
        }
    };

    for contextual in operations {
        let effective_cwd = match resolve_context_cwd(&cwd, &contextual.cwd_steps, policy, resolver)
        {
            Ok(Some(cwd)) => cwd,
            Ok(None) if can_skip_unknown_context(&contextual.operation) => continue,
            Ok(None) => {
                return Decision::deny(
                    DenyCode::AmbiguousRecursive,
                    "working directory contains an unknown or dynamic cd target",
                );
            }
            Err(()) => {
                return Decision::deny(
                    DenyCode::PolicyInvalid,
                    "working directory could not be resolved",
                );
            }
        };
        let operation = contextual.operation;
        if operation.raw_targets.is_empty() {
            if operation.ambiguous {
                return Decision::deny(
                    DenyCode::AmbiguousRecursive,
                    "recursive deletion target is not unambiguously resolved",
                );
            }
            if let Some(decision) = evaluate_target(
                &effective_cwd.logical,
                &effective_cwd,
                false,
                &operation,
                policy,
                resolver,
            ) {
                return decision;
            }
            continue;
        }

        for raw_target in &operation.raw_targets {
            let target = unquote_shell_path(raw_target, operation.target_syntax);
            let has_known_glob = has_glob(Path::new(&target));
            let Some(expanded) = expand_context_target(&target, &contextual.assignments, policy)
            else {
                // A single unresolved file is explicitly allowed. Recursive
                // unresolved targets were rejected above.
                if can_skip_unknown_target(&operation, &target, has_known_glob) {
                    continue;
                }
                return Decision::deny(
                    DenyCode::AmbiguousRecursive,
                    "deletion target contains an unknown variable",
                );
            };
            let target = PathBuf::from(expanded);
            if operation.ambiguous && operation.recursive && !has_known_glob {
                return Decision::deny(
                    DenyCode::AmbiguousRecursive,
                    "recursive deletion target is not unambiguously resolved",
                );
            }
            let target = if target.is_absolute() {
                target
            } else {
                effective_cwd.logical.join(target)
            };
            if is_ambiguous_directory_glob(&operation)
                && has_glob(&target)
                && !glob_base_inside_cwd(&target, &effective_cwd, policy, resolver)
            {
                return Decision::deny(
                    DenyCode::AmbiguousRecursive,
                    "recursive deletion glob is outside the current workspace",
                );
            }
            if let Some(decision) =
                evaluate_target(&target, &effective_cwd, true, &operation, policy, resolver)
            {
                return decision;
            }
        }
    }

    Decision::Allow
}

fn can_skip_unknown_context(operation: &DeleteOperation) -> bool {
    if !matches!(operation.kind, DeleteKind::Rm | DeleteKind::Unlink)
        || operation.recursive
        || operation.ambiguous
        || operation.raw_targets.len() != 1
    {
        return false;
    }
    let raw_target = &operation.raw_targets[0];
    let target = unquote_shell_path(raw_target, TargetSyntax::Posix);
    !has_glob(Path::new(&target)) && !target_has_shell_expansion(raw_target)
}

fn can_skip_unknown_target(operation: &DeleteOperation, raw_target: &str, has_glob: bool) -> bool {
    matches!(operation.kind, DeleteKind::Rm | DeleteKind::Unlink)
        && !operation.recursive
        && operation.raw_targets.len() == 1
        && !has_glob
        && !raw_target.is_empty()
}

fn is_ambiguous_directory_glob(operation: &DeleteOperation) -> bool {
    operation.recursive || matches!(operation.kind, DeleteKind::Rmdir)
}

fn glob_base_inside_cwd(
    target: &Path,
    cwd: &ResolvedPath,
    policy: &Policy,
    resolver: &dyn PathResolver,
) -> bool {
    for protected in &policy.protected_paths {
        let case_sensitive = protected.case_sensitive;
        if path_equal(&cwd.logical, &protected.logical, case_sensitive)
            || path_equal(&cwd.canonical, &protected.canonical, case_sensitive)
            || path_equal(&cwd.logical, &protected.canonical, case_sensitive)
            || path_equal(&cwd.canonical, &protected.logical, case_sensitive)
        {
            return false;
        }
    }
    let Some(base) = glob_base(target) else {
        return true;
    };
    let Ok(resolved) = resolve(&base, resolver) else {
        return false;
    };
    let case_sensitive = !cfg!(windows);
    path_is_ancestor_or_equal(&cwd.logical, &resolved.logical, case_sensitive)
        && path_is_ancestor_or_equal(&cwd.canonical, &resolved.canonical, case_sensitive)
}

fn target_has_shell_expansion(raw_target: &str) -> bool {
    let mut quote = None;
    let mut escaped = false;
    for character in raw_target.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(active_quote) = quote {
            match character {
                '\\' if active_quote == '"' => escaped = true,
                '"' if active_quote == '"' => quote = None,
                '\'' if active_quote == '\'' => quote = None,
                '$' | '`' if active_quote != '\'' => return true,
                _ => {}
            }
            continue;
        }
        match character {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(character),
            '$' | '`' => return true,
            _ => {}
        }
    }
    false
}

fn resolve_context_cwd(
    initial: &ResolvedPath,
    steps: &[ContextCwdStep],
    policy: &Policy,
    resolver: &dyn PathResolver,
) -> Result<Option<ResolvedPath>, ()> {
    let mut current = initial.clone();
    for step in steps {
        if step.dynamic || step.raw_target.is_empty() {
            return Ok(None);
        }
        let Some(expanded) = expand_context_target(
            &unquote_shell_path(&step.raw_target, TargetSyntax::Posix),
            &step.assignments,
            policy,
        ) else {
            return Ok(None);
        };
        let target = PathBuf::from(expanded);
        let target = if target.is_absolute() {
            target
        } else {
            current.logical.join(target)
        };
        let canonical = match resolver.canonicalize(&target) {
            Ok(canonical)
                if std::fs::metadata(&canonical).is_ok_and(|metadata| metadata.is_dir()) =>
            {
                canonical
            }
            Ok(_) | Err(_) => return Ok(None),
        };
        current = ResolvedPath {
            logical: lexical_normalize(&target),
            canonical: lexical_normalize(&canonical),
        };
    }
    Ok(Some(current))
}

fn expand_context_target(
    target: &str,
    assignments: &[ContextAssignment],
    policy: &Policy,
) -> Option<String> {
    let mut overrides = BTreeMap::new();
    let mut dynamic_names = std::collections::BTreeSet::new();
    for assignment in assignments {
        if assignment.dynamic {
            overrides.remove(&assignment.name);
            dynamic_names.insert(assignment.name.clone());
            continue;
        }
        let raw_value = unquote_shell_path(&assignment.raw_value, TargetSyntax::Posix);
        let expanded = policy.expand_target_with_overrides(&raw_value, &overrides)?;
        overrides.insert(assignment.name.clone(), PathBuf::from(expanded));
        dynamic_names.remove(&assignment.name);
    }
    if dynamic_names
        .iter()
        .any(|name| shell_target_references(target, name))
    {
        return None;
    }
    if overrides.is_empty() {
        policy.expand_target(target)
    } else {
        policy.expand_target_with_overrides(target, &overrides)
    }
}

fn shell_target_references(target: &str, name: &str) -> bool {
    target.contains(&format!("${name}")) || target.contains(&format!("${{{name}}}"))
}

fn evaluate_target(
    target: &Path,
    cwd: &ResolvedPath,
    explicit_target: bool,
    operation: &DeleteOperation,
    policy: &Policy,
    resolver: &dyn PathResolver,
) -> Option<Decision> {
    let resolution_target = glob_base(target).unwrap_or_else(|| target.to_path_buf());
    let resolved = match resolve(&resolution_target, resolver) {
        Ok(resolved) => resolved,
        Err(_) if operation.ambiguous && !operation.recursive => return None,
        Err(_) => {
            return Some(Decision::deny(
                DenyCode::PolicyInvalid,
                "deletion target could not be resolved",
            ));
        }
    };

    // Preserve the more actionable cwd-ancestor code for explicit `..`
    // navigation, even when that spelling lands on a protected home path.
    if explicit_target
        && target
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        && target_is_cwd_ancestor(&resolved, cwd)
    {
        return Some(Decision::deny(
            DenyCode::CwdAncestor,
            "target is the current directory or one of its ancestors",
        ));
    }

    for protected in &policy.protected_paths {
        let case_sensitive = protected.case_sensitive;
        let logical_protected = &protected.logical;
        let canonical_protected = &protected.canonical;
        if path_is_ancestor_or_equal(canonical_protected, &resolved.canonical, case_sensitive)
            || path_is_ancestor_or_equal(&resolved.canonical, canonical_protected, case_sensitive)
            || path_is_ancestor_or_equal(logical_protected, &resolved.logical, case_sensitive)
            || path_is_ancestor_or_equal(&resolved.logical, logical_protected, case_sensitive)
        {
            // A concrete descendant of a protected directory is allowed; the
            // two ancestor checks above only deny equality or deleting a
            // protected path's parent. Keep the descendant side for glob
            // bases, where selecting all protected contents is destructive.
            let target_is_protected =
                path_equal(&resolved.canonical, canonical_protected, case_sensitive)
                    || path_equal(&resolved.logical, logical_protected, case_sensitive)
                    || path_is_ancestor_or_equal(
                        &resolved.canonical,
                        canonical_protected,
                        case_sensitive,
                    )
                    || path_is_ancestor_or_equal(
                        &resolved.logical,
                        logical_protected,
                        case_sensitive,
                    );
            let glob_selects_contents = has_glob(target)
                && glob_base(target).is_some_and(|base| {
                    path_equal(&base, logical_protected, case_sensitive)
                        || path_equal(&base, canonical_protected, case_sensitive)
                });
            if target_is_protected || glob_selects_contents {
                return Some(Decision::deny(
                    DenyCode::ProtectedPath,
                    "target intersects a protected path",
                ));
            }
        }
    }

    if explicit_target && target_is_cwd_ancestor(&resolved, cwd) {
        return Some(Decision::deny(
            DenyCode::CwdAncestor,
            "target is the current directory or one of its ancestors",
        ));
    }

    None
}

fn target_is_cwd_ancestor(target: &ResolvedPath, cwd: &ResolvedPath) -> bool {
    let case_sensitive = !cfg!(windows);
    path_is_ancestor_or_equal(&target.logical, &cwd.logical, case_sensitive)
        || path_is_ancestor_or_equal(&target.canonical, &cwd.canonical, case_sensitive)
}

fn unquote_shell_path(raw: &str, syntax: TargetSyntax) -> String {
    let trimmed = raw.trim();
    let preserve_windows = matches!(syntax, TargetSyntax::Windows)
        || looks_windows_path(trimmed)
        || matches!(syntax, TargetSyntax::Auto) && looks_supported_variable_windows_path(trimmed);
    if preserve_windows {
        let unquoted = strip_shell_quotes(trimmed);
        if matches!(syntax, TargetSyntax::Windows) && !cfg!(windows) {
            return unquoted.replace('\\', "/");
        }
        return unquoted.to_owned();
    }
    let mut output = String::with_capacity(trimmed.len());
    let mut quote = None;
    let mut escaped = false;
    for character in trimmed.chars() {
        if escaped {
            output.push(character);
            escaped = false;
            continue;
        }
        if let Some(active_quote) = quote {
            if character == active_quote {
                quote = None;
            } else {
                output.push(character);
            }
            continue;
        }
        match character {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(character),
            _ => output.push(character),
        }
    }
    if escaped {
        output.push('\\');
    }
    output
}

fn strip_shell_quotes(value: &str) -> &str {
    value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value)
}

fn looks_supported_variable_windows_path(value: &str) -> bool {
    let mut remainder = strip_shell_quotes(value);
    loop {
        let Some(variable) = remainder.strip_prefix('$') else {
            return false;
        };
        let (name, suffix) = if let Some(braced) = variable.strip_prefix('{') {
            let Some(end) = braced.find('}') else {
                return false;
            };
            (&braced[..end], &braced[end + 1..])
        } else {
            let end = variable
                .char_indices()
                .take_while(|(_, character)| character.is_ascii_alphanumeric() || *character == '_')
                .last()
                .map_or(0, |(offset, character)| offset + character.len_utf8());
            (&variable[..end], &variable[end..])
        };
        if !matches!(
            name,
            "HOME" | "USERPROFILE" | "HOMEDRIVE" | "HOMEPATH" | "TMP" | "TMPDIR"
        ) {
            return false;
        }
        if suffix.starts_with('\\') {
            return true;
        }
        remainder = suffix;
    }
}

fn looks_windows_path(value: &str) -> bool {
    let value = value
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
        .or_else(|| {
            value
                .strip_prefix('\'')
                .and_then(|inner| inner.strip_suffix('\''))
        })
        .unwrap_or(value);
    value.starts_with("\\\\")
        || value.as_bytes().get(1) == Some(&b':') && value.as_bytes().get(2) == Some(&b'\\')
        || value.starts_with(".\\")
        || value.starts_with("..\\")
}
