use std::ffi::OsString;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Filesystem canonicalization boundary used by policy evaluation.
///
/// Tests provide a fixture-root implementation so no real protected path is
/// ever resolved by the decision engine.
pub trait PathResolver {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf>;
}

/// Resolver backed by the host filesystem for the production hook.
#[derive(Debug, Default, Clone, Copy)]
pub struct FsPathResolver;

impl PathResolver for FsPathResolver {
    fn canonicalize(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedPath {
    pub(crate) logical: PathBuf,
    pub(crate) canonical: PathBuf,
}

pub(crate) fn resolve(path: &Path, resolver: &dyn PathResolver) -> io::Result<ResolvedPath> {
    let logical = lexical_normalize(path);
    let canonical = match resolver.canonicalize(path) {
        Ok(canonical) => canonical,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            canonicalize_nearest_existing(&logical, resolver, error)?
        }
        Err(error) => return Err(error),
    };
    Ok(ResolvedPath {
        logical,
        canonical: lexical_normalize(&canonical),
    })
}

fn canonicalize_nearest_existing(
    logical: &Path,
    resolver: &dyn PathResolver,
    original_error: io::Error,
) -> io::Result<PathBuf> {
    let mut suffix = Vec::<OsString>::new();
    let mut cursor = logical;
    loop {
        match resolver.canonicalize(cursor) {
            Ok(mut canonical) => {
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(lexical_normalize(&canonical));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let Some(name) = cursor.file_name() else {
                    return Err(original_error);
                };
                suffix.push(name.to_os_string());
                let Some(parent) = cursor.parent() else {
                    return Err(original_error);
                };
                cursor = parent;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Remove dot segments without using string prefix checks.
pub(crate) fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                if !pop_normal_component(&mut normalized) {
                    // Never let `..` escape an absolute root. Relative paths
                    // retain leading parents, but evaluation joins command
                    // targets to an absolute cwd before reaching here.
                    if !normalized.is_absolute() {
                        normalized.push(component.as_os_str());
                    }
                }
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

fn pop_normal_component(path: &mut PathBuf) -> bool {
    let Some(last) = path.components().next_back() else {
        return false;
    };
    if matches!(last, Component::RootDir | Component::Prefix(_)) {
        return false;
    }
    path.pop()
}

pub(crate) fn path_equal(left: &Path, right: &Path, case_sensitive: bool) -> bool {
    let left = lexical_normalize(left);
    let right = lexical_normalize(right);
    component_prefix(&left, &right, case_sensitive)
        && component_count(&left) == component_count(&right)
}

pub(crate) fn path_is_ancestor_or_equal(
    ancestor: &Path,
    descendant: &Path,
    case_sensitive: bool,
) -> bool {
    let ancestor = lexical_normalize(ancestor);
    let descendant = lexical_normalize(descendant);
    component_prefix(&ancestor, &descendant, case_sensitive)
}

pub(crate) fn has_glob(path: &Path) -> bool {
    path.to_string_lossy()
        .chars()
        .any(|character| matches!(character, '*' | '?' | '[' | '{' | '}'))
}

/// Return the concrete path before a shell glob, if one can be identified.
pub(crate) fn glob_base(path: &Path) -> Option<PathBuf> {
    let text = path.to_string_lossy();
    let index = text.char_indices().find_map(|(index, character)| {
        matches!(character, '*' | '?' | '[' | '{' | '}').then_some(index)
    })?;
    let base = text[..index].trim_end_matches(['/', '\\']);
    if base.is_empty() {
        return Some(PathBuf::from(std::path::MAIN_SEPARATOR_STR));
    }
    Some(PathBuf::from(base))
}

fn component_prefix(ancestor: &Path, descendant: &Path, case_sensitive: bool) -> bool {
    let ancestor = ancestor.components();
    let descendant = descendant.components();
    let ancestor = ancestor.map(component_key).collect::<Vec<_>>();
    let descendant = descendant.map(component_key).collect::<Vec<_>>();
    if ancestor.len() > descendant.len() {
        return false;
    }
    ancestor
        .iter()
        .zip(descendant.iter())
        .all(|(left, right)| component_equal(left, right, case_sensitive))
}

fn component_count(path: &Path) -> usize {
    path.components().count()
}

fn component_key(component: Component<'_>) -> OsString {
    component.as_os_str().to_os_string()
}

fn component_equal(left: &OsString, right: &OsString, case_sensitive: bool) -> bool {
    if case_sensitive {
        return left == right;
    }
    left.to_string_lossy().to_lowercase() == right.to_string_lossy().to_lowercase()
}
