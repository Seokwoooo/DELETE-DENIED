use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};
use std::path::PathBuf;

use serde::Deserialize;

/// Maximum serialized policy size accepted by the hook.
pub const POLICY_MAX: usize = 16_384;
const POLICY_SCHEMA_VERSION: u32 = 1;
const VERIFIED_VARIABLES: &[&str] = &[
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "TMP",
    "TMPDIR",
];

/// Installed user policy consumed by a suspicious hook invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub schema_version: u32,
    pub variables: BTreeMap<String, PathBuf>,
    pub protected_paths: Vec<ProtectedPath>,
}

/// A protected path and its canonical counterpart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedPath {
    pub kind: String,
    pub logical: PathBuf,
    pub canonical: PathBuf,
    pub case_sensitive: bool,
}

impl Policy {
    /// Read a schema-v1 policy with a hard byte limit before deserialization.
    pub fn from_reader<R: Read>(reader: R) -> Result<Self, PolicyError> {
        let mut limited = reader.take((POLICY_MAX + 1) as u64);
        let mut bytes = Vec::with_capacity(POLICY_MAX.min(8 * 1024));
        let read = limited.read_to_end(&mut bytes)?;
        if read > POLICY_MAX {
            return Err(PolicyError::TooLarge {
                max: POLICY_MAX,
                actual: read,
            });
        }

        let raw: RawPolicy = serde_json::from_slice(&bytes)?;
        if raw.schema_version != POLICY_SCHEMA_VERSION {
            return Err(PolicyError::UnsupportedSchema {
                version: raw.schema_version,
            });
        }

        let mut variables = BTreeMap::new();
        for (name, value) in raw.variables {
            if !VERIFIED_VARIABLES.contains(&name.as_str()) {
                return Err(PolicyError::UnverifiedVariable { name });
            }
            let expanded = expand_variables(&value, &variables)?;
            if expanded.is_empty() {
                return Err(PolicyError::InvalidPath {
                    field: format!("variables.{name}"),
                });
            }
            variables.insert(name, PathBuf::from(expanded));
        }

        let protected_paths = raw
            .protected_paths
            .into_iter()
            .map(|raw| {
                let logical = expand_variables(&raw.logical, &variables)?;
                let canonical = expand_variables(&raw.canonical, &variables)?;
                if logical.is_empty() || canonical.is_empty() {
                    return Err(PolicyError::InvalidPath {
                        field: raw.kind.clone(),
                    });
                }
                let logical = PathBuf::from(logical);
                let canonical = PathBuf::from(canonical);
                if !logical.is_absolute() || !canonical.is_absolute() {
                    return Err(PolicyError::InvalidPath { field: raw.kind });
                }
                Ok(ProtectedPath {
                    kind: raw.kind,
                    logical,
                    canonical,
                    case_sensitive: raw.case_sensitive,
                })
            })
            .collect::<Result<Vec<_>, PolicyError>>()?;

        if protected_paths.is_empty() {
            return Err(PolicyError::NoProtectedPaths);
        }

        Ok(Self {
            schema_version: raw.schema_version,
            variables,
            protected_paths,
        })
    }

    /// Expand only variables that were verified and recorded by the policy.
    pub(crate) fn expand_target(&self, value: &str) -> Option<String> {
        expand_variables(value, &self.variables).ok()
    }

    pub(crate) fn expand_target_with_overrides(
        &self,
        value: &str,
        overrides: &BTreeMap<String, PathBuf>,
    ) -> Option<String> {
        let mut variables = self.variables.clone();
        for (name, path) in overrides {
            if !VERIFIED_VARIABLES.contains(&name.as_str()) {
                continue;
            }
            variables.insert(name.clone(), path.clone());
        }
        expand_variables(value, &variables).ok()
    }
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    schema_version: u32,
    #[serde(default)]
    variables: BTreeMap<String, String>,
    protected_paths: Vec<RawProtectedPath>,
}

#[derive(Debug, Deserialize)]
struct RawProtectedPath {
    kind: String,
    logical: String,
    canonical: String,
    case_sensitive: bool,
}

/// Errors raised while reading or validating a policy.
#[derive(Debug)]
pub enum PolicyError {
    Io(io::Error),
    TooLarge { max: usize, actual: usize },
    Json(serde_json::Error),
    UnsupportedSchema { version: u32 },
    UnverifiedVariable { name: String },
    UnknownVariable { name: String },
    InvalidPath { field: String },
    NoProtectedPaths,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "failed to read policy: {error}"),
            Self::TooLarge { max, actual } => {
                write!(formatter, "policy is {actual} bytes; maximum is {max}")
            }
            Self::Json(error) => write!(formatter, "invalid policy JSON: {error}"),
            Self::UnsupportedSchema { version } => {
                write!(formatter, "unsupported policy schema version {version}")
            }
            Self::UnverifiedVariable { name } => {
                write!(formatter, "policy variable {name} is not verified")
            }
            Self::UnknownVariable { name } => write!(formatter, "unknown policy variable {name}"),
            Self::InvalidPath { field } => write!(formatter, "invalid policy path in {field}"),
            Self::NoProtectedPaths => write!(formatter, "policy has no protected paths"),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::TooLarge { .. }
            | Self::UnsupportedSchema { .. }
            | Self::UnverifiedVariable { .. }
            | Self::UnknownVariable { .. }
            | Self::InvalidPath { .. }
            | Self::NoProtectedPaths => None,
        }
    }
}

impl From<io::Error> for PolicyError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for PolicyError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

fn expand_variables(
    value: &str,
    variables: &BTreeMap<String, PathBuf>,
) -> Result<String, PolicyError> {
    let mut output = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'$' => {
                let (name, consumed) = parse_dollar_variable(value, index)?;
                let replacement =
                    variables
                        .get(name)
                        .ok_or_else(|| PolicyError::UnknownVariable {
                            name: name.to_owned(),
                        })?;
                output.push_str(&replacement.to_string_lossy());
                index += consumed;
            }
            b'%' => {
                let remainder = &value[index + 1..];
                let Some(end) = remainder.find('%') else {
                    output.push('%');
                    index += 1;
                    continue;
                };
                let name = &remainder[..end];
                if name.is_empty() {
                    output.push('%');
                    index += 1;
                    continue;
                }
                let replacement =
                    variables
                        .get(name)
                        .ok_or_else(|| PolicyError::UnknownVariable {
                            name: name.to_owned(),
                        })?;
                output.push_str(&replacement.to_string_lossy());
                index += end + 2;
            }
            _ => {
                let ch = value[index..]
                    .chars()
                    .next()
                    .expect("index is on a UTF-8 boundary");
                output.push(ch);
                index += ch.len_utf8();
            }
        }
    }
    Ok(output)
}

fn parse_dollar_variable(value: &str, index: usize) -> Result<(&str, usize), PolicyError> {
    let remainder = &value[index + 1..];
    if let Some(braced) = remainder.strip_prefix('{') {
        let Some(end) = braced.find('}') else {
            return Err(PolicyError::UnknownVariable {
                name: braced.to_owned(),
            });
        };
        let name = &braced[..end];
        if name.is_empty() {
            return Err(PolicyError::UnknownVariable {
                name: name.to_owned(),
            });
        }
        return Ok((name, end + 3));
    }
    let end = remainder
        .char_indices()
        .take_while(|(_, ch)| ch.is_ascii_alphanumeric() || *ch == '_')
        .last()
        .map(|(offset, ch)| offset + ch.len_utf8())
        .unwrap_or(0);
    if end == 0 {
        return Err(PolicyError::UnknownVariable {
            name: String::new(),
        });
    }
    Ok((&remainder[..end], end + 1))
}
