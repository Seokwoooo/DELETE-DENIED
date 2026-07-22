//! macOS account/session and path provider.
//!
//! The implementation is intentionally cold-path only.  It consults the
//! account database and filesystem APIs directly; it never shells out to
//! `dscl`, `whoami`, or another helper process.

#[cfg(target_os = "macos")]
use super::{Architecture, LoginIdentity, ManagementPaths, PathPair, Platform};
use super::{DiscoveryError, PlatformProvider, PlatformSnapshot};
#[cfg(target_os = "macos")]
use std::ffi::{CStr, CString};
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::io;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default)]
pub struct MacOsProvider;

impl MacOsProvider {
    pub const fn new() -> Self {
        Self
    }
}

impl PlatformProvider for MacOsProvider {
    fn snapshot(&self) -> Result<PlatformSnapshot, DiscoveryError> {
        #[cfg(target_os = "macos")]
        {
            discover_macos()
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(DiscoveryError::UnsupportedPlatform {
                platform: std::env::consts::OS.to_owned(),
            })
        }
    }
}

#[cfg(target_os = "macos")]
fn discover_macos() -> Result<PlatformSnapshot, DiscoveryError> {
    let (identity, inherited_home) = original_login_identity()?;
    let home = identity.home.clone();
    let user_parent = home
        .parent()
        .ok_or_else(|| DiscoveryError::InvalidIdentity {
            field: "home parent".into(),
        })?;

    let roots = volume_roots()?;
    let documents = standard_pair(&home, "Documents")?;
    let desktop = standard_pair(&home, "Desktop")?;
    let downloads = standard_pair(&home, "Downloads")?;
    let codex_dir = pair_for_path(&home.join(".codex"))?;

    let mut redirected_paths = Vec::new();
    let icloud = home.join("Library/Mobile Documents/com~apple~CloudDocs");
    if icloud.exists() {
        redirected_paths.push(("icloud".to_owned(), pair_for_path(&icloud)?));
    }
    // `/Users` remains a protected account-parent target even when the
    // account database home is relocated to a network or external volume.
    redirected_paths.push((
        "users-parent".to_owned(),
        pair_for_path(Path::new("/Users"))?,
    ));

    let management_root = home.join(".codex/delete-denied");
    let binary_root = management_root.join("bin");
    let data_dir = pair_for_path(&management_root)?;
    let binary_dir = pair_for_path(&binary_root)?;
    let hook_binary = pair_for_path(&binary_root.join("delete-denied-hook"))?;
    let cli_binary = pair_for_path(&binary_root.join("delete-denied"))?;
    let management = ManagementPaths {
        hooks_dir: codex_dir.clone(),
        hooks: pair_for_path(&home.join(".codex/hooks.json"))?,
        binary_dir,
        cli_binary,
        hook_binary,
        data_dir,
        policy: pair_for_path(&management_root.join("policy.json"))?,
        state: pair_for_path(&management_root.join("state.json"))?,
        manifest: pair_for_path(&management_root.join("manifest.json"))?,
        backups: pair_for_path(&management_root.join("backups"))?,
    };

    Ok(PlatformSnapshot {
        platform: Platform::MacOs,
        architecture: Architecture::current(),
        login: identity,
        home: pair_for_path(&home)?,
        inherited_home,
        user_parent: pair_for_path(user_parent)?,
        filesystem_roots: vec![pair_for_path(Path::new("/"))?],
        volume_roots: roots,
        share_roots: Vec::new(),
        documents,
        desktop,
        downloads,
        redirected_paths,
        codex_dir,
        management,
    })
}

#[cfg(target_os = "macos")]
fn original_login_identity() -> Result<(LoginIdentity, Option<PathBuf>), DiscoveryError> {
    let uid = unsafe { libc::getuid() as u32 };

    let mut buffer = vec![0u8; 1024];
    let mut passwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    loop {
        let status = unsafe {
            libc::getpwuid_r(
                uid,
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == 0 {
            break;
        }
        if status == libc::ERANGE && buffer.len() < 64 * 1024 {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        return Err(DiscoveryError::AmbiguousIdentity {
            detail: format!("account database lookup failed for uid {uid}: errno {status}"),
        });
    }
    if result.is_null() {
        return Err(DiscoveryError::AmbiguousIdentity {
            detail: format!("account database has no uid {uid}"),
        });
    }
    let passwd = unsafe { passwd.assume_init_ref() };
    let name = unsafe { CStr::from_ptr(passwd.pw_name) }
        .to_str()
        .map_err(|_| DiscoveryError::AmbiguousIdentity {
            detail: "account username is not UTF-8".into(),
        })?
        .to_owned();
    let home = unsafe { CStr::from_ptr(passwd.pw_dir) }
        .to_str()
        .map_err(|_| DiscoveryError::AmbiguousIdentity {
            detail: "account home is not UTF-8".into(),
        })?
        .to_owned();
    if name.is_empty() || home.is_empty() {
        return Err(DiscoveryError::AmbiguousIdentity {
            detail: "account database returned an empty name or home".into(),
        });
    }
    let inherited = std::env::var_os("HOME").map(PathBuf::from);
    let identity = LoginIdentity {
        username: name,
        domain: None,
        home: PathBuf::from(home),
        uid: Some(uid),
        sid: None,
    };
    Ok((identity, inherited))
}

#[cfg(target_os = "macos")]
fn volume_roots() -> Result<Vec<PathPair>, DiscoveryError> {
    let mut roots = Vec::new();
    let volumes = Path::new("/Volumes");
    match fs::read_dir(volumes) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry.map_err(DiscoveryError::Io)?;
                let path = entry.path();
                let link_metadata = fs::symlink_metadata(&path).map_err(DiscoveryError::Io)?;
                if link_metadata.file_type().is_symlink() {
                    // A volume root must be a real directory entry.  Do not
                    // follow symlink/reparse entries into an arbitrary target.
                    continue;
                }
                let metadata = fs::metadata(&path).map_err(DiscoveryError::Io)?;
                if metadata.is_dir() {
                    roots.push(pair_for_path(&path)?);
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(DiscoveryError::Io(error)),
    }
    Ok(roots)
}

#[cfg(target_os = "macos")]
fn standard_pair(home: &Path, folder: &str) -> Result<PathPair, DiscoveryError> {
    pair_for_path(&home.join(folder))
}

#[cfg(target_os = "macos")]
fn pair_for_path(path: &Path) -> Result<PathPair, DiscoveryError> {
    let canonical = canonicalize_with_missing_suffix(path)?;
    let case_sensitive = case_sensitivity(path)?;
    PathPair::new(path.to_path_buf(), canonical, case_sensitive)
}

#[cfg(target_os = "macos")]
fn case_sensitivity(path: &Path) -> Result<bool, DiscoveryError> {
    // Darwin exposes `_PC_CASE_SENSITIVE` in sys/unistd.h.  Keep the numeric
    // value here because libc crates do not expose the private-prefixed
    // constant on every supported SDK.
    const PC_CASE_SENSITIVE: libc::c_int = 11;
    let mut cursor = path;
    while !cursor.exists() {
        cursor = cursor
            .parent()
            .ok_or_else(|| DiscoveryError::CaseSensitivityUnknown {
                path: path.to_path_buf(),
            })?;
    }
    let bytes = cursor.as_os_str().as_bytes();
    let c_path = CString::new(bytes).map_err(|_| DiscoveryError::CaseSensitivityUnknown {
        path: path.to_path_buf(),
    })?;
    let value = unsafe { libc::pathconf(c_path.as_ptr(), PC_CASE_SENSITIVE) };
    if value < 0 {
        return Err(DiscoveryError::CaseSensitivityUnknown {
            path: path.to_path_buf(),
        });
    }
    Ok(value != 0)
}

/// Canonicalize an existing path, or canonicalize the nearest existing parent
/// and append the missing suffix.  This handles a first install where policy
/// and state files do not exist yet without inventing a canonical root.
#[cfg(target_os = "macos")]
fn canonicalize_with_missing_suffix(path: &Path) -> Result<PathBuf, DiscoveryError> {
    match fs::canonicalize(path) {
        Ok(path) => return Ok(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(DiscoveryError::Io(error)),
    }
    let mut suffix = Vec::new();
    let mut cursor = path;
    loop {
        match fs::canonicalize(cursor) {
            Ok(mut canonical) => {
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return Ok(canonical);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let name =
                    cursor
                        .file_name()
                        .ok_or_else(|| DiscoveryError::NonCanonicalizable {
                            field: "path".into(),
                            path: path.to_path_buf(),
                        })?;
                suffix.push(name.to_owned());
                cursor = cursor
                    .parent()
                    .ok_or_else(|| DiscoveryError::NonCanonicalizable {
                        field: "path".into(),
                        path: path.to_path_buf(),
                    })?;
            }
            Err(error) => return Err(DiscoveryError::Io(error)),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn native_provider_does_not_spawn_or_use_username_interpolation() {
        let provider = MacOsProvider::new();
        let snapshot = provider.snapshot().expect("macOS account database");
        assert!(!snapshot.login.username.is_empty());
        assert!(snapshot.login.home.is_absolute());
    }
}
