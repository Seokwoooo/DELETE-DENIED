//! Native account and path discovery used by the management CLI.
//!
//! Discovery is deliberately separate from installation.  A provider reads
//! account/session information and returns a snapshot; [`PlatformPaths`]
//! validates that snapshot without writing to the machine.  Tests can inject
//! a snapshot backed entirely by a temporary fixture while production uses
//! the platform modules below.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(not(target_os = "macos"))]
#[path = "macos.rs"]
pub mod macos;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(not(target_os = "windows"))]
#[path = "windows.rs"]
pub mod windows;

/// Supported native host family.  Linux and WSL intentionally do not get a
/// production provider: a working Codex CLI is not evidence of App support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Platform {
    MacOs,
    Windows,
    Unsupported,
}

/// CPU architecture recorded at discovery time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Architecture {
    X86_64,
    Arm64,
    X86,
    Arm,
    Unknown(String),
}

impl Architecture {
    pub fn current() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Self::Arm64
        } else if cfg!(target_arch = "x86") {
            Self::X86
        } else if cfg!(target_arch = "arm") {
            Self::Arm
        } else {
            Self::Unknown(std::env::consts::ARCH.to_owned())
        }
    }
}

/// The current operating-system account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginIdentity {
    pub username: String,
    pub domain: Option<String>,
    pub home: PathBuf,
    /// POSIX uid where the host exposes one.  Windows providers leave this
    /// empty and may use `sid` instead.
    pub uid: Option<u32>,
    pub sid: Option<String>,
}

impl LoginIdentity {
    pub fn new(username: impl Into<String>, home: impl Into<PathBuf>) -> Self {
        Self {
            username: username.into(),
            domain: None,
            home: home.into(),
            uid: None,
            sid: None,
        }
    }
}

/// A path as presented by the OS and the path reached after resolving a
/// symlink, junction, or reparse point.  Both values are retained in policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathPair {
    pub logical: PathBuf,
    pub canonical: PathBuf,
    pub case_sensitive: bool,
}

impl PathPair {
    pub fn new(
        logical: impl Into<PathBuf>,
        canonical: impl Into<PathBuf>,
        case_sensitive: bool,
    ) -> Result<Self, DiscoveryError> {
        let pair = Self {
            logical: logical.into(),
            canonical: canonical.into(),
            case_sensitive,
        };
        validate_pair("path", &pair)?;
        Ok(pair)
    }

    /// Construct an unvalidated fixture value.  `PlatformPaths::validate`
    /// remains the authority and is useful for asserting rejection cases.
    pub fn unchecked(
        logical: impl Into<PathBuf>,
        canonical: impl Into<PathBuf>,
        case_sensitive: bool,
    ) -> Self {
        Self {
            logical: logical.into(),
            canonical: canonical.into(),
            case_sensitive,
        }
    }
}

/// A policy entry generated from a path pair.  Its shape mirrors the hook's
/// `ProtectedPath` schema so the CLI can serialize it without lossy mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedPath {
    pub kind: String,
    pub logical: PathBuf,
    pub canonical: PathBuf,
    pub case_sensitive: bool,
}

impl ProtectedPath {
    fn from_pair(kind: impl Into<String>, pair: &PathPair) -> Self {
        Self {
            kind: kind.into(),
            logical: pair.logical.clone(),
            canonical: pair.canonical.clone(),
            case_sensitive: pair.case_sensitive,
        }
    }
}

/// Management files owned by DELETE-DENIED.  Paths are pairs as well: a
/// redirected or reparse-pointed data directory must not disappear from the
/// generated protected list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementPaths {
    pub hooks_dir: PathPair,
    pub hooks: PathPair,
    pub binary_dir: PathPair,
    pub cli_binary: PathPair,
    pub hook_binary: PathPair,
    pub data_dir: PathPair,
    pub policy: PathPair,
    pub state: PathPair,
    pub manifest: PathPair,
    pub backups: PathPair,
}

/// Input returned by an injectable platform provider.  It intentionally
/// contains no filesystem handles and can be assembled from a disposable
/// fixture without touching a real home or system directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformSnapshot {
    pub platform: Platform,
    pub architecture: Architecture,
    pub login: LoginIdentity,
    /// Account-database home as presented by the provider.  Keeping this as a
    /// pair preserves a symlinked login home and its real target.
    pub home: PathPair,
    /// The inherited `$HOME`/`USERPROFILE` value, if one was available.
    pub inherited_home: Option<PathBuf>,
    pub user_parent: PathPair,
    pub filesystem_roots: Vec<PathPair>,
    pub volume_roots: Vec<PathPair>,
    pub share_roots: Vec<PathPair>,
    pub documents: PathPair,
    pub desktop: PathPair,
    pub downloads: PathPair,
    /// Redirects such as iCloud Drive or OneDrive Known Folder targets.
    pub redirected_paths: Vec<(String, PathPair)>,
    pub codex_dir: PathPair,
    pub management: ManagementPaths,
}

/// A validated, immutable discovery result used to build the user policy.
/// No constructor mutates the host filesystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformPaths {
    pub platform: Platform,
    pub architecture: Architecture,
    pub case_sensitive: bool,
    pub original_login: LoginIdentity,
    pub user_parent: PathPair,
    pub home: PathPair,
    pub roots: Vec<PathPair>,
    pub volume_roots: Vec<PathPair>,
    pub share_roots: Vec<PathPair>,
    pub documents: PathPair,
    pub desktop: PathPair,
    pub downloads: PathPair,
    pub redirected_paths: Vec<(String, PathPair)>,
    pub codex_dir: PathPair,
    pub hooks_dir_path: PathPair,
    pub hooks_path: PathPair,
    pub binary_dir: PathPair,
    pub cli_binary_path: PathPair,
    pub hook_binary_path: PathPair,
    pub data_dir: PathPair,
    pub policy_path: PathPair,
    pub state_path: PathPair,
    pub manifest_path: PathPair,
    pub backups_path: PathPair,
    pub protected_paths: Vec<ProtectedPath>,
}

/// Provider boundary used by production and fixture discovery.
pub trait PlatformProvider {
    fn snapshot(&self) -> Result<PlatformSnapshot, DiscoveryError>;
}

struct ProtectedPathInputs<'a> {
    roots: &'a [PathPair],
    user_parent: &'a PathPair,
    home: &'a PathPair,
    documents: &'a PathPair,
    desktop: &'a PathPair,
    downloads: &'a PathPair,
    redirected_paths: &'a [(String, PathPair)],
    codex_dir: &'a PathPair,
    management: &'a ManagementPaths,
}

impl PlatformPaths {
    /// Discover paths through an injected provider and validate every value.
    pub fn discover(provider: &dyn PlatformProvider) -> Result<Self, DiscoveryError> {
        Self::from_snapshot(provider.snapshot()?)
    }

    pub fn from_snapshot(snapshot: PlatformSnapshot) -> Result<Self, DiscoveryError> {
        validate_snapshot(&snapshot)?;

        let case_sensitive = snapshot
            .filesystem_roots
            .first()
            .map(|pair| pair.case_sensitive)
            .unwrap_or(true);
        let home = snapshot.home.clone();
        let roots = merge_roots(
            &snapshot.filesystem_roots,
            &snapshot.volume_roots,
            &snapshot.share_roots,
        );

        let protected_paths = build_protected_paths(ProtectedPathInputs {
            roots: &roots,
            user_parent: &snapshot.user_parent,
            home: &home,
            documents: &snapshot.documents,
            desktop: &snapshot.desktop,
            downloads: &snapshot.downloads,
            redirected_paths: &snapshot.redirected_paths,
            codex_dir: &snapshot.codex_dir,
            management: &snapshot.management,
        });

        Ok(Self {
            platform: snapshot.platform,
            architecture: snapshot.architecture,
            case_sensitive,
            original_login: snapshot.login,
            user_parent: snapshot.user_parent,
            home,
            roots,
            volume_roots: snapshot.volume_roots,
            share_roots: snapshot.share_roots,
            documents: snapshot.documents,
            desktop: snapshot.desktop,
            downloads: snapshot.downloads,
            redirected_paths: snapshot.redirected_paths,
            codex_dir: snapshot.codex_dir,
            hooks_dir_path: snapshot.management.hooks_dir.clone(),
            hooks_path: snapshot.management.hooks.clone(),
            binary_dir: snapshot.management.binary_dir.clone(),
            cli_binary_path: snapshot.management.cli_binary.clone(),
            hook_binary_path: snapshot.management.hook_binary.clone(),
            data_dir: snapshot.management.data_dir.clone(),
            policy_path: snapshot.management.policy.clone(),
            state_path: snapshot.management.state.clone(),
            manifest_path: snapshot.management.manifest.clone(),
            backups_path: snapshot.management.backups.clone(),
            protected_paths,
        })
    }

    /// Production entry point.  On Linux/WSL this returns an explicit
    /// unsupported error rather than inferring support from the CLI runtime.
    pub fn discover_for_current_login() -> Result<Self, DiscoveryError> {
        #[cfg(target_os = "macos")]
        {
            Self::discover(&macos::MacOsProvider::new())
        }
        #[cfg(target_os = "windows")]
        {
            Self::discover(&windows::WindowsProvider::new())
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            Err(DiscoveryError::UnsupportedPlatform {
                platform: std::env::consts::OS.to_owned(),
            })
        }
    }

    pub fn validate(&self) -> Result<(), DiscoveryError> {
        validate_result(self)
    }

    pub fn home_path(&self) -> &PathPair {
        &self.home
    }

    pub fn protected_paths(&self) -> &[ProtectedPath] {
        &self.protected_paths
    }
}

/// Errors are intentionally descriptive: discovery aborts rather than
/// guessing when account or path data contradicts itself.
#[derive(Debug)]
pub enum DiscoveryError {
    UnsupportedPlatform {
        platform: String,
    },
    Provider(String),
    Io(io::Error),
    EmptyPath {
        field: String,
    },
    RelativePath {
        field: String,
        path: PathBuf,
    },
    InvalidCanonicalPath {
        field: String,
        path: PathBuf,
    },
    NonCanonicalizable {
        field: String,
        path: PathBuf,
    },
    ContradictoryHome {
        account: PathBuf,
        inherited: PathBuf,
    },
    AmbiguousIdentity {
        detail: String,
    },
    RootAsHome {
        home: PathBuf,
    },
    UserParentAsHome {
        home: PathBuf,
        user_parent: PathBuf,
    },
    MissingRoot,
    InvalidRoot {
        field: String,
        path: PathBuf,
    },
    UnsafeManagementPath {
        field: String,
        path: PathBuf,
    },
    InvalidIdentity {
        field: String,
    },
    ContradictoryPath {
        field: String,
        detail: String,
    },
    CaseSensitivityUnknown {
        path: PathBuf,
    },
    AmbiguousPathCase {
        field: String,
    },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform { platform } => {
                write!(f, "platform {platform} is unsupported")
            }
            Self::Provider(detail) => write!(f, "platform provider failed: {detail}"),
            Self::Io(error) => write!(f, "platform discovery I/O failed: {error}"),
            Self::EmptyPath { field } => write!(f, "{field} is empty"),
            Self::RelativePath { field, path } => {
                write!(f, "{field} is not absolute: {}", path.display())
            }
            Self::InvalidCanonicalPath { field, path } => {
                write!(f, "{field} canonical path is invalid: {}", path.display())
            }
            Self::NonCanonicalizable { field, path } => {
                write!(f, "{field} cannot be canonicalized: {}", path.display())
            }
            Self::ContradictoryHome { account, inherited } => write!(
                f,
                "account home {} conflicts with inherited home {}",
                account.display(),
                inherited.display()
            ),
            Self::AmbiguousIdentity { detail } => write!(f, "ambiguous login identity: {detail}"),
            Self::RootAsHome { home } => {
                write!(f, "filesystem root cannot be home: {}", home.display())
            }
            Self::UserParentAsHome { home, user_parent } => write!(
                f,
                "user parent {} cannot be home {}",
                user_parent.display(),
                home.display()
            ),
            Self::MissingRoot => write!(f, "no filesystem, volume, or share root was discovered"),
            Self::InvalidRoot { field, path } => {
                write!(f, "{field} is not a root path: {}", path.display())
            }
            Self::UnsafeManagementPath { field, path } => {
                write!(f, "management path {field} is unsafe: {}", path.display())
            }
            Self::InvalidIdentity { field } => write!(f, "invalid login identity field {field}"),
            Self::ContradictoryPath { field, detail } => {
                write!(f, "contradictory path {field}: {detail}")
            }
            Self::CaseSensitivityUnknown { path } => write!(
                f,
                "filesystem case sensitivity could not be established for {}",
                path.display()
            ),
            Self::AmbiguousPathCase { field } => {
                write!(
                    f,
                    "case-insensitive path {field} contains ambiguous non-ASCII names"
                )
            }
        }
    }
}

impl std::error::Error for DiscoveryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for DiscoveryError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

fn validate_snapshot(snapshot: &PlatformSnapshot) -> Result<(), DiscoveryError> {
    if !matches!(snapshot.platform, Platform::MacOs | Platform::Windows) {
        return Err(DiscoveryError::UnsupportedPlatform {
            platform: format!("{:?}", snapshot.platform),
        });
    }
    if snapshot.login.username.trim().is_empty() {
        return Err(DiscoveryError::InvalidIdentity {
            field: "username".into(),
        });
    }
    validate_pair("home", &snapshot.home)?;
    if !path_equal(
        &snapshot.login.home,
        &snapshot.home.logical,
        snapshot.home.case_sensitive,
    ) {
        return Err(DiscoveryError::ContradictoryPath {
            field: "home".into(),
            detail: "login identity and home pair disagree".into(),
        });
    }
    if let Some(inherited) = &snapshot.inherited_home {
        validate_absolute("inherited_home", inherited)?;
        let home_matches_inherited = path_equal(
            &snapshot.home.logical,
            inherited,
            snapshot.home.case_sensitive,
        ) || path_equal(
            &snapshot.home.canonical,
            inherited,
            snapshot.home.case_sensitive,
        );
        if !home_matches_inherited {
            return Err(DiscoveryError::ContradictoryHome {
                account: snapshot.home.logical.clone(),
                inherited: inherited.clone(),
            });
        }
    }

    validate_pair("user_parent", &snapshot.user_parent)?;
    if snapshot.filesystem_roots.is_empty()
        && snapshot.volume_roots.is_empty()
        && snapshot.share_roots.is_empty()
    {
        return Err(DiscoveryError::MissingRoot);
    }
    for (name, roots) in [("filesystem_roots", snapshot.filesystem_roots.as_slice())] {
        for pair in roots {
            validate_pair(name, pair)?;
            if !is_root_like(&pair.logical) {
                return Err(DiscoveryError::InvalidRoot {
                    field: name.to_owned(),
                    path: pair.logical.clone(),
                });
            }
        }
    }
    for pair in &snapshot.volume_roots {
        validate_pair("volume_roots", pair)?;
        if is_unc_root(&pair.logical) {
            return Err(DiscoveryError::InvalidRoot {
                field: "volume_roots".into(),
                path: pair.logical.clone(),
            });
        }
    }
    for pair in &snapshot.share_roots {
        validate_pair("share_roots", pair)?;
        if !is_unc_root(&pair.logical) {
            return Err(DiscoveryError::InvalidRoot {
                field: "share_roots".into(),
                path: pair.logical.clone(),
            });
        }
    }

    let home = PathPair::unchecked(
        snapshot.home.logical.clone(),
        snapshot.home.canonical.clone(),
        snapshot.home.case_sensitive,
    );
    if is_root_like(&home.logical)
        || is_unc_root(&home.logical)
        || is_root_like(&home.canonical)
        || is_unc_root(&home.canonical)
    {
        return Err(DiscoveryError::RootAsHome {
            home: home.logical.clone(),
        });
    }
    let home_is_user_parent = path_equal(
        &home.logical,
        &snapshot.user_parent.logical,
        home.case_sensitive,
    ) || path_equal(
        &home.canonical,
        &snapshot.user_parent.logical,
        home.case_sensitive,
    ) || path_equal(
        &home.logical,
        &snapshot.user_parent.canonical,
        home.case_sensitive,
    ) || path_equal(
        &home.canonical,
        &snapshot.user_parent.canonical,
        home.case_sensitive,
    );
    if home_is_user_parent {
        return Err(DiscoveryError::UserParentAsHome {
            home: home.logical,
            user_parent: snapshot.user_parent.logical.clone(),
        });
    }
    if !path_is_strict_descendant(
        &snapshot.user_parent.logical,
        &home.logical,
        home.case_sensitive,
    ) {
        return Err(DiscoveryError::ContradictoryPath {
            field: "home".into(),
            detail: "logical home must be a strict descendant of its user parent".into(),
        });
    }

    for (name, pair) in [
        ("documents", &snapshot.documents),
        ("desktop", &snapshot.desktop),
        ("downloads", &snapshot.downloads),
        ("codex_dir", &snapshot.codex_dir),
    ] {
        validate_pair(name, pair)?;
    }
    for (name, pair) in &snapshot.redirected_paths {
        if name.trim().is_empty() {
            return Err(DiscoveryError::EmptyPath {
                field: "redirected_paths.kind".into(),
            });
        }
        validate_pair(name, pair)?;
    }

    for (name, pair) in management_pairs(&snapshot.management) {
        validate_pair(name, pair)?;
        validate_management_path(name, pair, &snapshot.codex_dir)?;
    }
    validate_management_structure(&snapshot.management)?;
    Ok(())
}

fn validate_result(result: &PlatformPaths) -> Result<(), DiscoveryError> {
    if !matches!(result.platform, Platform::MacOs | Platform::Windows) {
        return Err(DiscoveryError::UnsupportedPlatform {
            platform: format!("{:?}", result.platform),
        });
    }
    if result.original_login.username.trim().is_empty() {
        return Err(DiscoveryError::InvalidIdentity {
            field: "username".into(),
        });
    }
    if !path_equal(
        &result.original_login.home,
        &result.home.logical,
        result.home.case_sensitive,
    ) {
        return Err(DiscoveryError::ContradictoryPath {
            field: "home".into(),
            detail: "login identity and home pair disagree".into(),
        });
    }
    validate_pair("home", &result.home)?;
    validate_pair("user_parent", &result.user_parent)?;
    let home_is_user_parent = path_equal(
        &result.home.logical,
        &result.user_parent.logical,
        result.case_sensitive,
    ) || path_equal(
        &result.home.canonical,
        &result.user_parent.logical,
        result.case_sensitive,
    ) || path_equal(
        &result.home.logical,
        &result.user_parent.canonical,
        result.case_sensitive,
    ) || path_equal(
        &result.home.canonical,
        &result.user_parent.canonical,
        result.case_sensitive,
    );
    if home_is_user_parent {
        return Err(DiscoveryError::UserParentAsHome {
            home: result.home.logical.clone(),
            user_parent: result.user_parent.logical.clone(),
        });
    }
    if !path_is_strict_descendant(
        &result.user_parent.logical,
        &result.home.logical,
        result.home.case_sensitive,
    ) {
        return Err(DiscoveryError::ContradictoryPath {
            field: "home".into(),
            detail: "logical home must be a strict descendant of its user parent".into(),
        });
    }
    if is_root_like(&result.home.logical)
        || is_unc_root(&result.home.logical)
        || is_root_like(&result.home.canonical)
        || is_unc_root(&result.home.canonical)
    {
        return Err(DiscoveryError::RootAsHome {
            home: result.home.logical.clone(),
        });
    }
    if result.roots.is_empty() {
        return Err(DiscoveryError::MissingRoot);
    }
    for pair in &result.roots {
        validate_pair("roots", pair)?;
    }
    for pair in &result.volume_roots {
        validate_pair("volume_roots", pair)?;
        if is_unc_root(&pair.logical) {
            return Err(DiscoveryError::InvalidRoot {
                field: "volume_roots".into(),
                path: pair.logical.clone(),
            });
        }
    }
    for pair in &result.share_roots {
        validate_pair("share_roots", pair)?;
        if !is_unc_root(&pair.logical) {
            return Err(DiscoveryError::InvalidRoot {
                field: "share_roots".into(),
                path: pair.logical.clone(),
            });
        }
    }
    for (name, pair) in [
        ("documents", &result.documents),
        ("desktop", &result.desktop),
        ("downloads", &result.downloads),
        ("codex_dir", &result.codex_dir),
        ("hooks_dir_path", &result.hooks_dir_path),
        ("hooks_path", &result.hooks_path),
        ("binary_dir", &result.binary_dir),
        ("cli_binary_path", &result.cli_binary_path),
        ("hook_binary_path", &result.hook_binary_path),
        ("data_dir", &result.data_dir),
        ("policy_path", &result.policy_path),
        ("state_path", &result.state_path),
        ("manifest_path", &result.manifest_path),
        ("backups_path", &result.backups_path),
    ] {
        validate_pair(name, pair)?;
    }
    let management = ManagementPaths {
        hooks_dir: result.hooks_dir_path.clone(),
        hooks: result.hooks_path.clone(),
        binary_dir: result.binary_dir.clone(),
        cli_binary: result.cli_binary_path.clone(),
        hook_binary: result.hook_binary_path.clone(),
        data_dir: result.data_dir.clone(),
        policy: result.policy_path.clone(),
        state: result.state_path.clone(),
        manifest: result.manifest_path.clone(),
        backups: result.backups_path.clone(),
    };
    validate_management_structure(&management)?;
    for (name, pair) in management_pairs(&management) {
        validate_management_path(name, pair, &result.codex_dir)?;
    }
    for (name, pair) in &result.redirected_paths {
        if name.trim().is_empty() {
            return Err(DiscoveryError::EmptyPath {
                field: "redirected_paths.kind".into(),
            });
        }
        validate_pair(name, pair)?;
    }
    let expected_protected_paths = build_protected_paths(ProtectedPathInputs {
        roots: &result.roots,
        user_parent: &result.user_parent,
        home: &result.home,
        documents: &result.documents,
        desktop: &result.desktop,
        downloads: &result.downloads,
        redirected_paths: &result.redirected_paths,
        codex_dir: &result.codex_dir,
        management: &management,
    });
    if result.protected_paths != expected_protected_paths {
        return Err(DiscoveryError::ContradictoryPath {
            field: "protected_paths".into(),
            detail: "protected policy does not match discovered paths".into(),
        });
    }
    Ok(())
}

fn management_pairs(paths: &ManagementPaths) -> [(&'static str, &PathPair); 10] {
    [
        ("hooks_dir", &paths.hooks_dir),
        ("hooks", &paths.hooks),
        ("binary_dir", &paths.binary_dir),
        ("cli_binary", &paths.cli_binary),
        ("hook_binary", &paths.hook_binary),
        ("data_dir", &paths.data_dir),
        ("policy", &paths.policy),
        ("state", &paths.state),
        ("manifest", &paths.manifest),
        ("backups", &paths.backups),
    ]
}

fn validate_management_path(
    field: &str,
    pair: &PathPair,
    codex_dir: &PathPair,
) -> Result<(), DiscoveryError> {
    let inside_user_codex =
        path_is_ancestor_or_equal(&codex_dir.logical, &pair.logical, pair.case_sensitive)
            && path_is_ancestor_or_equal(
                &codex_dir.canonical,
                &pair.canonical,
                pair.case_sensitive,
            );
    if !inside_user_codex {
        return Err(DiscoveryError::UnsafeManagementPath {
            field: field.to_owned(),
            path: pair.logical.clone(),
        });
    }
    Ok(())
}

fn validate_management_structure(paths: &ManagementPaths) -> Result<(), DiscoveryError> {
    require_child("hooks", &paths.hooks_dir, &paths.hooks)?;
    require_child("data_dir", &paths.hooks_dir, &paths.data_dir)?;
    require_child("cli_binary", &paths.binary_dir, &paths.cli_binary)?;
    if !pair_is_child(&paths.binary_dir, &paths.hook_binary)
        && !pair_is_child(&paths.data_dir, &paths.hook_binary)
    {
        return Err(DiscoveryError::ContradictoryPath {
            field: "hook_binary".into(),
            detail: "hook must be beneath binary_dir or data_dir".into(),
        });
    }
    for (field, child) in [
        ("policy", &paths.policy),
        ("state", &paths.state),
        ("manifest", &paths.manifest),
        ("backups", &paths.backups),
    ] {
        require_child(field, &paths.data_dir, child)?;
    }
    Ok(())
}

fn require_child(field: &str, parent: &PathPair, child: &PathPair) -> Result<(), DiscoveryError> {
    if pair_is_child(parent, child) {
        Ok(())
    } else {
        Err(DiscoveryError::ContradictoryPath {
            field: field.to_owned(),
            detail: "path is not beneath its declared management directory".into(),
        })
    }
}

fn pair_is_child(parent: &PathPair, child: &PathPair) -> bool {
    path_is_strict_descendant(&parent.logical, &child.logical, parent.case_sensitive)
        && path_is_strict_descendant(&parent.canonical, &child.canonical, parent.case_sensitive)
}

fn path_is_strict_descendant(parent: &Path, child: &Path, case_sensitive: bool) -> bool {
    path_is_ancestor_or_equal(parent, child, case_sensitive)
        && !path_equal(parent, child, case_sensitive)
}

fn validate_pair(field: &str, pair: &PathPair) -> Result<(), DiscoveryError> {
    validate_absolute(field, &pair.logical)?;
    if pair.canonical.as_os_str().is_empty() {
        return Err(DiscoveryError::NonCanonicalizable {
            field: field.to_owned(),
            path: pair.logical.clone(),
        });
    }
    if !is_absolute_any(&pair.canonical) {
        return Err(DiscoveryError::InvalidCanonicalPath {
            field: field.to_owned(),
            path: pair.canonical.clone(),
        });
    }
    if canonical_has_dot_segments(&pair.canonical) {
        return Err(DiscoveryError::NonCanonicalizable {
            field: field.to_owned(),
            path: pair.canonical.clone(),
        });
    }
    Ok(())
}

fn canonical_has_dot_segments(path: &Path) -> bool {
    path.to_string_lossy()
        .replace('\\', "/")
        .split('/')
        .any(|component| matches!(component, "." | ".."))
}

fn validate_absolute(field: &str, path: &Path) -> Result<(), DiscoveryError> {
    if path.as_os_str().is_empty() {
        return Err(DiscoveryError::EmptyPath {
            field: field.to_owned(),
        });
    }
    if !is_absolute_any(path) {
        return Err(DiscoveryError::RelativePath {
            field: field.to_owned(),
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

fn merge_roots(
    filesystem: &[PathPair],
    volumes: &[PathPair],
    shares: &[PathPair],
) -> Vec<PathPair> {
    let mut result = Vec::new();
    for pair in filesystem.iter().chain(volumes).chain(shares) {
        if !result.iter().any(|existing: &PathPair| {
            path_equal(
                &existing.logical,
                &pair.logical,
                existing.case_sensitive && pair.case_sensitive,
            ) && path_equal(
                &existing.canonical,
                &pair.canonical,
                existing.case_sensitive && pair.case_sensitive,
            )
        }) {
            result.push(pair.clone());
        }
    }
    result
}

fn build_protected_paths(input: ProtectedPathInputs<'_>) -> Vec<ProtectedPath> {
    let mut protected_paths = Vec::new();
    for pair in input.roots {
        let kind = if is_unc_root(&pair.logical) {
            "share-root"
        } else if is_root_like(&pair.logical) {
            "filesystem-root"
        } else {
            "volume-root"
        };
        push_protected(&mut protected_paths, kind, pair);
    }
    push_protected(&mut protected_paths, "users-parent", input.user_parent);
    push_protected(&mut protected_paths, "home", input.home);
    push_protected(&mut protected_paths, "documents", input.documents);
    push_protected(&mut protected_paths, "desktop", input.desktop);
    push_protected(&mut protected_paths, "downloads", input.downloads);
    for (kind, pair) in input.redirected_paths {
        push_protected(&mut protected_paths, kind, pair);
    }
    push_protected(&mut protected_paths, "codex", input.codex_dir);
    for (kind, pair) in [
        ("hooks-dir", &input.management.hooks_dir),
        ("hooks", &input.management.hooks),
        ("cli-binary", &input.management.cli_binary),
        ("hook-binary", &input.management.hook_binary),
        ("data-dir", &input.management.data_dir),
        ("policy", &input.management.policy),
        ("state", &input.management.state),
        ("manifest", &input.management.manifest),
        ("backups", &input.management.backups),
    ] {
        push_protected(&mut protected_paths, kind, pair);
    }
    protected_paths
}

fn push_protected(target: &mut Vec<ProtectedPath>, kind: &str, pair: &PathPair) {
    let candidate = ProtectedPath::from_pair(kind, pair);
    if let Some(existing) = target.iter_mut().find(|existing| {
        existing.kind == candidate.kind
            && path_equal(
                &existing.canonical,
                &candidate.canonical,
                pair.case_sensitive,
            )
    }) {
        // Keep the newest logical spelling when two candidates resolve to the
        // same canonical target (for example `/Users` versus a relocated
        // account parent), avoiding duplicate policy entries without losing
        // the explicitly discovered logical path.
        *existing = candidate;
    } else {
        target.push(candidate);
    }
}

/// Absolute path detection that also understands Windows paths when fixture
/// tests are executed on a Unix host.
pub(crate) fn is_absolute_any(path: &Path) -> bool {
    if path.is_absolute() {
        return true;
    }
    let text = path.to_string_lossy();
    is_windows_absolute(&text)
}

pub(crate) fn is_windows_absolute(text: &str) -> bool {
    let bytes = text.as_bytes();
    (bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/'))
        || text.starts_with(r"\\")
}

pub(crate) fn is_unc_root(path: &Path) -> bool {
    let mut text = path.to_string_lossy().replace('\\', "/");
    if let Some(rest) = text.strip_prefix("//?/UNC/") {
        text = format!("//{rest}");
    } else if text.starts_with("//?/") {
        return false;
    }
    if !text.starts_with("//") {
        return false;
    }
    text.trim_matches('/').split('/').count() <= 2
}

pub(crate) fn is_root_like(path: &Path) -> bool {
    if path == Path::new("/") || path == Path::new("\\") {
        return true;
    }
    let mut text = path.to_string_lossy().replace('\\', "/");
    if let Some(rest) = text.strip_prefix("//?/") {
        text = rest.to_owned();
    }
    let bytes = text.as_bytes();
    (bytes.len() == 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/')
        || is_unc_root(path)
}

pub(crate) fn path_equal(left: &Path, right: &Path, case_sensitive: bool) -> bool {
    let left = normalize_components(left, case_sensitive);
    let right = normalize_components(right, case_sensitive);
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| component_equal(left, right, case_sensitive))
}

pub(crate) fn path_is_ancestor_or_equal(
    ancestor: &Path,
    descendant: &Path,
    case_sensitive: bool,
) -> bool {
    let ancestor = normalize_components(ancestor, case_sensitive);
    let descendant = normalize_components(descendant, case_sensitive);
    ancestor.len() <= descendant.len()
        && ancestor
            .iter()
            .zip(descendant.iter())
            .all(|(left, right)| component_equal(left, right, case_sensitive))
}

fn normalize_components(path: &Path, _case_sensitive: bool) -> Vec<String> {
    let mut text = path.to_string_lossy().replace('\\', "/");
    if let Some(rest) = text.strip_prefix("//?/UNC/") {
        text = format!("//{rest}");
    } else if let Some(rest) = text.strip_prefix("//?/") {
        text = rest.to_owned();
    }
    if text.len() > 1 {
        while text.ends_with('/') {
            text.pop();
        }
    }
    let mut components = Vec::new();
    for component in text.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            if components
                .last()
                .is_some_and(|value: &String| value != "/" && !value.ends_with(':'))
            {
                components.pop();
            }
            continue;
        }
        components.push(component.to_owned());
    }
    if text.starts_with("//") {
        components.insert(0, "//".to_owned());
    } else if text.starts_with('/') {
        components.insert(0, "/".to_owned());
    } else if text.len() >= 2 && text.as_bytes()[1] == b':' {
        // Keep drive identity as a component so the same comparison rules
        // apply to `C:\\` and `c:\\` as to every other path component.
        let drive = text[..2].to_owned();
        if components.first().map(String::as_str) != Some(drive.as_str()) {
            components.insert(0, drive);
        }
    }
    components
}

fn component_equal(left: &str, right: &str, case_sensitive: bool) -> bool {
    if case_sensitive {
        return left == right;
    }
    #[cfg(target_os = "windows")]
    {
        compare_string_ordinal(left, right)
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Host-side Windows fixtures still need deterministic Unicode
        // behavior even when the Windows API is unavailable.
        left.to_lowercase() == right.to_lowercase()
    }
}

#[cfg(target_os = "windows")]
fn compare_string_ordinal(left: &str, right: &str) -> bool {
    let left = left.encode_utf16().collect::<Vec<_>>();
    let right = right.encode_utf16().collect::<Vec<_>>();
    unsafe {
        CompareStringOrdinal(
            left.as_ptr(),
            left.len() as i32,
            right.as_ptr(),
            right.len() as i32,
            1,
        ) == CSTR_EQUAL
    }
}

#[cfg(target_os = "windows")]
const CSTR_EQUAL: i32 = 2;

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CompareStringOrdinal(
        lp_string1: *const u16,
        cch_count1: i32,
        lp_string2: *const u16,
        cch_count2: i32,
        ignore_case: i32,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    /// Keep the shared fixture descriptions absolute on every supported host.
    /// The discovery logic intentionally validates host path semantics, so a
    /// POSIX-only `/fixture/...` path would be relative when these tests run on
    /// Windows.  Windows-specific callers still pass native drive/UNC paths
    /// through unchanged.
    fn fixture_path(path: &str) -> String {
        #[cfg(target_os = "windows")]
        {
            if path == "/" {
                return r"C:\".to_owned();
            }
            if let Some(rest) = path.strip_prefix("/fixture") {
                let rest = rest.trim_start_matches('/');
                return if rest.is_empty() {
                    r"C:\fixture".to_owned()
                } else {
                    format!(r"C:\fixture\{}", rest.replace('/', "\\"))
                };
            }
            if let Some(rest) = path.strip_prefix('/') {
                return format!(r"C:\fixture\{}", rest.replace('/', "\\"));
            }
        }
        path.to_owned()
    }

    fn pair(path: &str) -> PathPair {
        let path = fixture_path(path);
        PathPair::unchecked(PathBuf::from(&path), PathBuf::from(path), true)
    }

    fn pair_with_case(logical: &str, canonical: &str, case_sensitive: bool) -> PathPair {
        let logical = fixture_path(logical);
        let canonical = fixture_path(canonical);
        PathPair::unchecked(
            PathBuf::from(logical),
            PathBuf::from(canonical),
            case_sensitive,
        )
    }

    fn snapshot(home: &str) -> PlatformSnapshot {
        let home = fixture_path(home);
        let management_root = format!("{home}/.codex/delete-denied");
        PlatformSnapshot {
            platform: Platform::MacOs,
            architecture: Architecture::Arm64,
            login: LoginIdentity::new("alice", &home),
            home: pair(&home),
            inherited_home: Some(PathBuf::from(&home)),
            user_parent: pair("/fixture/Users"),
            filesystem_roots: vec![pair("/")],
            volume_roots: vec![],
            share_roots: vec![],
            documents: pair("/fixture/Users/alice/Documents"),
            desktop: pair("/fixture/Users/alice/Desktop"),
            downloads: pair("/fixture/Users/alice/Downloads"),
            redirected_paths: vec![("icloud".into(), pair("/fixture/iCloud"))],
            codex_dir: pair("/fixture/Users/alice/.codex"),
            management: ManagementPaths {
                hooks_dir: pair("/fixture/Users/alice/.codex"),
                hooks: pair("/fixture/Users/alice/.codex/hooks.json"),
                binary_dir: pair(&format!("{management_root}/bin")),
                cli_binary: pair(&format!("{management_root}/bin/delete-denied")),
                hook_binary: pair(&format!("{management_root}/bin/delete-denied-hook")),
                data_dir: pair(&management_root),
                policy: pair(&format!("{management_root}/policy.json")),
                state: pair(&format!("{management_root}/state.json")),
                manifest: pair(&format!("{management_root}/manifest.json")),
                backups: pair(&format!("{management_root}/backups")),
            },
        }
    }

    struct Fixture(PlatformSnapshot);
    impl PlatformProvider for Fixture {
        fn snapshot(&self) -> Result<PlatformSnapshot, DiscoveryError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn preserves_logical_and_canonical_redirects() {
        let mut input = snapshot("/fixture/Users/alice");
        input.redirected_paths = vec![(
            "onedrive".into(),
            pair_with_case(
                "/fixture/Users/alice/Documents",
                "/fixture/OneDrive/Documents",
                false,
            ),
        )];
        let result = PlatformPaths::discover(&Fixture(input)).unwrap();
        let redirect = result
            .protected_paths
            .iter()
            .find(|path| path.kind == "onedrive")
            .unwrap();
        assert_eq!(
            redirect.logical,
            PathBuf::from(fixture_path("/fixture/Users/alice/Documents"))
        );
        assert_eq!(
            redirect.canonical,
            PathBuf::from(fixture_path("/fixture/OneDrive/Documents"))
        );
    }

    #[test]
    fn validate_rejects_missing_mutated_or_duplicate_protected_paths() {
        let result = PlatformPaths::discover(&Fixture(snapshot("/fixture/Users/alice")))
            .expect("fixture discovery");

        let mut cleared = result.clone();
        cleared.protected_paths.clear();
        assert!(matches!(
            cleared.validate(),
            Err(DiscoveryError::ContradictoryPath { field, .. }) if field == "protected_paths"
        ));

        let mut mutated = result.clone();
        mutated.protected_paths[0].logical.push("tampered");
        assert!(matches!(
            mutated.validate(),
            Err(DiscoveryError::ContradictoryPath { field, .. }) if field == "protected_paths"
        ));

        let mut duplicated = result.clone();
        duplicated
            .protected_paths
            .push(duplicated.protected_paths[0].clone());
        assert!(matches!(
            duplicated.validate(),
            Err(DiscoveryError::ContradictoryPath { field, .. }) if field == "protected_paths"
        ));
    }

    #[test]
    fn rejects_root_and_user_parent_as_home() {
        assert!(matches!(
            PlatformPaths::discover(&Fixture(snapshot("/"))),
            Err(DiscoveryError::RootAsHome { .. })
        ));
        assert!(matches!(
            PlatformPaths::discover(&Fixture(snapshot("/fixture/Users"))),
            Err(DiscoveryError::UserParentAsHome { .. })
        ));
    }

    #[test]
    fn rejects_unsafe_management_path() {
        let mut input = snapshot("/fixture/Users/alice");
        input.management.data_dir = pair("/fixture/Users/alice/.local/share");
        assert!(matches!(
            PlatformPaths::discover(&Fixture(input)),
            Err(DiscoveryError::UnsafeManagementPath { .. })
        ));
    }

    #[test]
    fn rejects_relative_and_noncanonicalizable_paths() {
        let mut relative = snapshot("/fixture/Users/alice");
        relative.documents = PathPair::unchecked(
            PathBuf::from(fixture_path("Documents")),
            PathBuf::from(fixture_path("/fixture/Documents")),
            true,
        );
        assert!(matches!(
            PlatformPaths::discover(&Fixture(relative)),
            Err(DiscoveryError::RelativePath { .. })
        ));

        let mut empty_canonical = snapshot("/fixture/Users/alice");
        empty_canonical.documents =
            PathPair::unchecked(fixture_path("/fixture/Documents"), "", true);
        assert!(matches!(
            PlatformPaths::discover(&Fixture(empty_canonical)),
            Err(DiscoveryError::NonCanonicalizable { .. })
        ));
    }

    #[test]
    fn requires_logical_home_to_be_below_its_actual_parent() {
        let mut input = snapshot("/fixture/other/alice");
        assert!(matches!(
            PlatformPaths::discover(&Fixture(input)),
            Err(DiscoveryError::ContradictoryPath { field, .. }) if field == "home"
        ));
        input = snapshot("/fixture/Users/alice");
        input.management.policy = pair("/fixture/else/policy.json");
        assert!(matches!(
            PlatformPaths::discover(&Fixture(input)),
            Err(DiscoveryError::UnsafeManagementPath { field, .. }) if field == "policy"
        ));
    }

    #[test]
    fn accepts_unicode_windows_case_insensitive_paths() {
        let mut input = snapshot(r"C:\Users\홍길동");
        input.platform = Platform::Windows;
        input.login.home = PathBuf::from(r"C:\Users\홍길동");
        input.home = pair_with_case(r"C:\Users\홍길동", r"C:\Users\홍길동", false);
        input.inherited_home = Some(PathBuf::from(r"c:\users\홍길동"));
        input.user_parent = pair_with_case(r"C:\Users", r"C:\Users", false);
        input.filesystem_roots = vec![pair_with_case(r"C:\", r"C:\", false)];
        input.documents = pair_with_case(r"C:\Users\홍길동\문서", r"c:\users\홍길동\문서", false);
        input.codex_dir =
            pair_with_case(r"C:\Users\홍길동\.codex", r"c:\users\홍길동\.codex", false);
        let root = r"C:\Users\홍길동\.codex\delete-denied";
        input.management = ManagementPaths {
            hooks_dir: input.codex_dir.clone(),
            hooks: pair_with_case(
                r"C:\Users\홍길동\.codex\hooks.json",
                r"c:\users\홍길동\.codex\hooks.json",
                false,
            ),
            binary_dir: pair_with_case(&format!(r"{root}\bin"), &format!(r"{root}\bin"), false),
            cli_binary: pair_with_case(
                &format!(r"{root}\bin\delete-denied.exe"),
                &format!(r"{root}\bin\delete-denied.exe"),
                false,
            ),
            hook_binary: pair_with_case(
                &format!(r"{root}\bin\delete-denied-hook.exe"),
                &format!(r"{root}\bin\delete-denied-hook.exe"),
                false,
            ),
            data_dir: pair_with_case(root, root, false),
            policy: pair_with_case(
                &format!(r"{root}\policy.json"),
                &format!(r"{root}\policy.json"),
                false,
            ),
            state: pair_with_case(
                &format!(r"{root}\state.json"),
                &format!(r"{root}\state.json"),
                false,
            ),
            manifest: pair_with_case(
                &format!(r"{root}\manifest.json"),
                &format!(r"{root}\manifest.json"),
                false,
            ),
            backups: pair_with_case(
                &format!(r"{root}\backups"),
                &format!(r"{root}\backups"),
                false,
            ),
        };
        assert!(PlatformPaths::discover(&Fixture(input)).is_ok());
        assert!(path_equal(
            Path::new(r"C:\Users\홍길동"),
            Path::new(r"c:\users\홍길동"),
            false,
        ));
    }

    #[test]
    fn extended_dos_paths_are_not_unc_roots() {
        assert!(!is_unc_root(Path::new(r"\\?\C:\Users\alice")));
        assert!(is_unc_root(Path::new(r"\\?\UNC\server\share\")));
    }

    #[test]
    fn preserves_home_redirect_and_volume_share_roots() {
        let mut input = snapshot(r"C:\Users\alice");
        input.platform = Platform::Windows;
        input.login.home = PathBuf::from(r"C:\Users\alice");
        input.home = pair_with_case(r"C:\Users\ALICE", r"C:\Profiles\alice", false);
        input.inherited_home = Some(PathBuf::from(r"C:\Profiles\alice"));
        input.user_parent = pair_with_case(r"C:\Users", r"C:\Users", false);
        input.filesystem_roots = vec![pair_with_case(r"C:\", r"C:\", false)];
        input.volume_roots = vec![pair_with_case(r"D:\", r"D:\", false)];
        input.share_roots = vec![pair_with_case(
            r"\\server\share\",
            r"\\server\share\",
            false,
        )];
        input.documents =
            pair_with_case(r"C:\Users\ALICE\Documents", r"D:\OneDrive\Documents", false);
        input.desktop = pair_with_case(r"C:\Users\ALICE\Desktop", r"C:\Users\ALICE\Desktop", false);
        input.downloads = pair_with_case(
            r"C:\Users\ALICE\Downloads",
            r"C:\Users\ALICE\Downloads",
            false,
        );
        input.codex_dir = pair_with_case(r"C:\Users\ALICE\.codex", r"C:\Users\ALICE\.codex", false);
        input.redirected_paths.clear();
        input.management = ManagementPaths {
            hooks_dir: pair_with_case(r"C:\Users\ALICE\.codex", r"C:\Users\ALICE\.codex", false),
            hooks: pair_with_case(
                r"C:\Users\ALICE\.codex\hooks.json",
                r"C:\Users\ALICE\.codex\hooks.json",
                false,
            ),
            binary_dir: pair_with_case(
                r"C:\Users\ALICE\.codex\DELETE-DENIED\bin",
                r"C:\Users\ALICE\.codex\DELETE-DENIED\bin",
                false,
            ),
            cli_binary: pair_with_case(
                r"C:\Users\ALICE\.codex\DELETE-DENIED\bin\delete-denied.exe",
                r"C:\Users\ALICE\.codex\DELETE-DENIED\bin\delete-denied.exe",
                false,
            ),
            hook_binary: pair_with_case(
                r"C:\Users\ALICE\.codex\DELETE-DENIED\bin\delete-denied-hook.exe",
                r"C:\Users\ALICE\.codex\DELETE-DENIED\bin\delete-denied-hook.exe",
                false,
            ),
            data_dir: pair_with_case(
                r"C:\Users\ALICE\.codex\DELETE-DENIED",
                r"C:\Users\ALICE\.codex\DELETE-DENIED",
                false,
            ),
            policy: pair_with_case(
                r"C:\Users\ALICE\.codex\DELETE-DENIED\policy.json",
                r"C:\Users\ALICE\.codex\DELETE-DENIED\policy.json",
                false,
            ),
            state: pair_with_case(
                r"C:\Users\ALICE\.codex\DELETE-DENIED\state.json",
                r"C:\Users\ALICE\.codex\DELETE-DENIED\state.json",
                false,
            ),
            manifest: pair_with_case(
                r"C:\Users\ALICE\.codex\DELETE-DENIED\manifest.json",
                r"C:\Users\ALICE\.codex\DELETE-DENIED\manifest.json",
                false,
            ),
            backups: pair_with_case(
                r"C:\Users\ALICE\.codex\DELETE-DENIED\backups",
                r"C:\Users\ALICE\.codex\DELETE-DENIED\backups",
                false,
            ),
        };
        let result = PlatformPaths::discover(&Fixture(input)).unwrap();
        assert_eq!(result.home.logical, PathBuf::from(r"C:\Users\ALICE"));
        assert_eq!(result.home.canonical, PathBuf::from(r"C:\Profiles\alice"));
        assert_eq!(result.roots.len(), 3);
        assert!(
            result
                .protected_paths
                .iter()
                .any(|path| path.kind == "share-root")
        );
        assert!(
            result
                .protected_paths
                .iter()
                .any(|path| path.canonical == Path::new(r"D:\OneDrive\Documents"))
        );
    }
}
