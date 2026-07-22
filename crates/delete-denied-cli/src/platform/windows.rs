//! Windows account and Known Folder provider.
//!
//! The Windows implementation calls the Known Folder and final-path APIs
//! directly.  In particular it never interpolates a guessed username into a
//! `C:\\Users\\...` path; profile and redirected folders come from the OS.

#[cfg(target_os = "windows")]
use super::{Architecture, LoginIdentity, ManagementPaths, PathPair, Platform};
use super::{DiscoveryError, PlatformProvider, PlatformSnapshot};
#[cfg(target_os = "windows")]
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsProvider;

impl WindowsProvider {
    pub const fn new() -> Self {
        Self
    }
}

impl PlatformProvider for WindowsProvider {
    fn snapshot(&self) -> Result<PlatformSnapshot, DiscoveryError> {
        #[cfg(target_os = "windows")]
        {
            discover_windows()
        }
        #[cfg(not(target_os = "windows"))]
        {
            Err(DiscoveryError::UnsupportedPlatform {
                platform: std::env::consts::OS.to_owned(),
            })
        }
    }
}

#[cfg(target_os = "windows")]
fn discover_windows() -> Result<PlatformSnapshot, DiscoveryError> {
    let current_sid = current_process_sid()?;
    let known_folder_token = 0;

    let profile = known_folder(&FOLDERID_PROFILE, known_folder_token)?;
    let documents = known_folder_pair(&FOLDERID_DOCUMENTS, known_folder_token)?;
    let desktop = known_folder_pair(&FOLDERID_DESKTOP, known_folder_token)?;
    let downloads = known_folder_pair(&FOLDERID_DOWNLOADS, known_folder_token)?;
    let login = LoginIdentity {
        // No account-name lookup is needed: the current token SID is the
        // unambiguous identity and is also a bounded display fallback.
        username: current_sid.clone(),
        domain: None,
        home: profile.clone(),
        uid: None,
        sid: Some(current_sid),
    };
    let home_pair = pair_for_path(&profile)?;
    let user_parent = profile
        .parent()
        .ok_or_else(|| DiscoveryError::InvalidIdentity {
            field: "profile parent".into(),
        })?;

    let mut redirected_paths = Vec::new();
    for (kind, pair) in [
        ("onedrive-documents", &documents),
        ("redirected-desktop", &desktop),
        ("redirected-downloads", &downloads),
    ] {
        if pair.logical != pair.canonical {
            redirected_paths.push((kind.to_owned(), pair.clone()));
        }
    }

    let codex_dir = pair_for_path(&profile.join(".codex"))?;
    let data_dir_path = profile.join(".codex/DELETE-DENIED");
    let binary_dir_path = data_dir_path.join("bin");
    let management = ManagementPaths {
        hooks_dir: codex_dir.clone(),
        hooks: pair_for_path(&profile.join(".codex/hooks.json"))?,
        binary_dir: pair_for_path(&binary_dir_path)?,
        cli_binary: pair_for_path(&binary_dir_path.join("delete-denied.exe"))?,
        hook_binary: pair_for_path(&binary_dir_path.join("delete-denied-hook.exe"))?,
        data_dir: pair_for_path(&data_dir_path)?,
        policy: pair_for_path(&data_dir_path.join("policy.json"))?,
        state: pair_for_path(&data_dir_path.join("state.json"))?,
        manifest: pair_for_path(&data_dir_path.join("manifest.json"))?,
        backups: pair_for_path(&data_dir_path.join("backups"))?,
    };

    let roots = logical_drive_roots()?;
    let user_parent_pair = pair_for_path(user_parent)?;
    let important = [
        &home_pair,
        &user_parent_pair,
        &documents,
        &desktop,
        &downloads,
        &codex_dir,
        &management.hooks_dir,
        &management.hooks,
        &management.binary_dir,
        &management.cli_binary,
        &management.hook_binary,
        &management.data_dir,
        &management.policy,
        &management.state,
        &management.manifest,
        &management.backups,
    ];
    let share_roots = unc_share_roots(&important)?;

    Ok(PlatformSnapshot {
        platform: Platform::Windows,
        architecture: Architecture::current(),
        login,
        home: home_pair,
        inherited_home: None,
        user_parent: user_parent_pair,
        filesystem_roots: roots,
        volume_roots: Vec::new(),
        share_roots: share_roots.into_iter().collect(),
        documents,
        desktop,
        downloads,
        redirected_paths,
        codex_dir,
        management,
    })
}

#[cfg(target_os = "windows")]
fn pair_for_path(path: &Path) -> Result<PathPair, DiscoveryError> {
    let canonical = final_path_or_nearest_existing(path)?;
    PathPair::new(path.to_path_buf(), canonical, false)
}

#[cfg(target_os = "windows")]
fn known_folder_pair(folder: &Guid, token: Handle) -> Result<PathPair, DiscoveryError> {
    let path = known_folder(folder, token)?;
    pair_for_path(&path)
}

#[cfg(target_os = "windows")]
fn known_folder(folder: &Guid, token: Handle) -> Result<PathBuf, DiscoveryError> {
    let mut value = std::ptr::null_mut();
    let result = unsafe { SHGetKnownFolderPath(folder, 0, token, &mut value) };
    if result < 0 || value.is_null() {
        if !value.is_null() {
            unsafe { CoTaskMemFree(value.cast()) };
        }
        return Err(DiscoveryError::Provider(format!(
            "SHGetKnownFolderPath failed with HRESULT 0x{result:08x}"
        )));
    }
    let path = unsafe { wide_ptr_to_path(value) };
    unsafe { CoTaskMemFree(value.cast()) };
    path
}

#[cfg(target_os = "windows")]
fn current_process_sid() -> Result<String, DiscoveryError> {
    let token = process_token()?;
    let sid = token_sid(token);
    unsafe { CloseHandle(token) };
    sid
}

#[cfg(target_os = "windows")]
fn process_token() -> Result<Handle, DiscoveryError> {
    let mut token = 0isize;
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 || token == 0
    {
        return Err(DiscoveryError::AmbiguousIdentity {
            detail: "OpenProcessToken failed".into(),
        });
    }
    Ok(token)
}

#[cfg(target_os = "windows")]
fn token_sid(token: Handle) -> Result<String, DiscoveryError> {
    let mut length = 0u32;
    unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            std::ptr::null_mut(),
            0,
            &mut length,
        );
    }
    if length == 0 || length > 64 * 1024 {
        return Err(DiscoveryError::AmbiguousIdentity {
            detail: "GetTokenInformation returned an invalid SID size".into(),
        });
    }
    let words = (length as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            TOKEN_USER_CLASS,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(DiscoveryError::AmbiguousIdentity {
            detail: "GetTokenInformation(TokenUser) failed".into(),
        });
    }
    let token_user = buffer.as_ptr().cast::<TokenUser>();
    let sid = unsafe { (*token_user).user.sid };
    if sid.is_null() {
        return Err(DiscoveryError::AmbiguousIdentity {
            detail: "TokenUser returned a null SID".into(),
        });
    }
    sid_pointer_to_string(sid)
}

#[cfg(target_os = "windows")]
fn sid_pointer_to_string(sid: *mut std::ffi::c_void) -> Result<String, DiscoveryError> {
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(DiscoveryError::AmbiguousIdentity {
            detail: "ConvertSidToStringSidW failed".into(),
        });
    }
    let mut size = 0usize;
    while unsafe { *text.add(size) } != 0 {
        size += 1;
        if size > 1024 {
            unsafe { LocalFree(text.cast()) };
            return Err(DiscoveryError::AmbiguousIdentity {
                detail: "converted SID exceeded bound".into(),
            });
        }
    }
    let result =
        String::from_utf16(unsafe { std::slice::from_raw_parts(text, size) }).map_err(|_| {
            DiscoveryError::AmbiguousIdentity {
                detail: "converted SID is not valid UTF-16".into(),
            }
        });
    unsafe { LocalFree(text.cast()) };
    result
}

#[cfg(target_os = "windows")]
fn logical_drive_roots() -> Result<Vec<PathPair>, DiscoveryError> {
    let mut buffer = vec![0u16; 256];
    loop {
        let length = unsafe { GetLogicalDriveStringsW(buffer.len() as u32, buffer.as_mut_ptr()) };
        if length == 0 {
            return Err(DiscoveryError::Provider(
                "GetLogicalDriveStringsW failed".into(),
            ));
        }
        if length < buffer.len() as u32 - 1 {
            let mut roots = Vec::new();
            let mut start = 0usize;
            for index in 0..=length as usize {
                if buffer[index] == 0 {
                    if index > start {
                        let value = String::from_utf16(&buffer[start..index]).map_err(|_| {
                            DiscoveryError::Provider("drive root is not valid UTF-16".into())
                        })?;
                        roots.push(pair_for_path(Path::new(&value))?);
                    }
                    start = index + 1;
                }
            }
            return Ok(roots);
        }
        buffer.resize(buffer.len().saturating_mul(2), 0);
        if buffer.len() > 32 * 1024 {
            return Err(DiscoveryError::Provider("drive list exceeded bound".into()));
        }
    }
}

#[cfg(target_os = "windows")]
fn unc_share_roots(paths: &[&PathPair]) -> Result<Vec<PathPair>, DiscoveryError> {
    let mut roots = Vec::new();
    for pair in paths {
        for path in [&pair.logical, &pair.canonical] {
            let Some(root) = unc_share_root(path) else {
                continue;
            };
            let root_pair = pair_for_path(&root)?;
            if !roots.iter().any(|existing: &PathPair| {
                super::path_equal(&existing.logical, &root_pair.logical, false)
            }) {
                roots.push(root_pair);
            }
        }
    }
    Ok(roots)
}

#[cfg(target_os = "windows")]
fn unc_share_root(path: &Path) -> Option<PathBuf> {
    let mut text = path.to_string_lossy().replace('/', "\\");
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        text = format!(r"\\{rest}");
    } else if text.starts_with(r"\\?\") {
        // Extended DOS paths such as `\\?\C:\...` are not UNC paths.  Do
        // not parse the device prefix as a server/share pair.
        return None;
    }
    if !text.starts_with(r"\\") {
        return None;
    }
    let mut parts = text.trim_start_matches('\\').split('\\');
    let server = parts.next()?.trim();
    let share = parts.next()?.trim();
    if server.is_empty() || share.is_empty() {
        return None;
    }
    Some(PathBuf::from(format!(r"\\{server}\{share}\")))
}

#[cfg(target_os = "windows")]
fn final_path_or_nearest_existing(path: &Path) -> Result<PathBuf, DiscoveryError> {
    if let Some(final_path) = final_path(path)? {
        return Ok(final_path);
    }
    let mut suffix = Vec::new();
    let mut cursor = path;
    loop {
        if let Some(final_path) = final_path(cursor)? {
            let mut result = final_path;
            for component in suffix.iter().rev() {
                result.push(component);
            }
            return Ok(result);
        }
        let name = cursor
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
}

#[cfg(target_os = "windows")]
fn final_path(path: &Path) -> Result<Option<PathBuf>, DiscoveryError> {
    use std::os::windows::ffi::OsStrExt;
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            0,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        let error = unsafe { GetLastError() };
        if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
            return Ok(None);
        }
        return Err(DiscoveryError::Provider(format!(
            "CreateFileW failed while resolving {} with Win32 error {error}",
            path.display()
        )));
    }
    let mut buffer = vec![0u16; 512];
    let mut length =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    if length == 0 {
        unsafe { CloseHandle(handle) };
        return Err(DiscoveryError::Provider(
            "GetFinalPathNameByHandleW returned no path".into(),
        ));
    }
    if length as usize >= buffer.len() {
        buffer.resize(length as usize + 1, 0);
        length = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        };
    }
    unsafe { CloseHandle(handle) };
    if length == 0 || length as usize >= buffer.len() {
        return Err(DiscoveryError::Provider(
            "GetFinalPathNameByHandleW exceeded its bounded retry".into(),
        ));
    }
    let text = String::from_utf16(&buffer[..length as usize]).map_err(|_| {
        DiscoveryError::Provider("GetFinalPathNameByHandleW returned invalid UTF-16".into())
    })?;
    Ok(Some(normalize_final_path(PathBuf::from(text))))
}

#[cfg(target_os = "windows")]
fn normalize_final_path(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(unc) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{unc}"));
    }
    if let Some(dos) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(dos);
    }
    path
}

#[cfg(target_os = "windows")]
unsafe fn wide_ptr_to_path(value: *mut u16) -> Result<PathBuf, DiscoveryError> {
    let mut length = 0usize;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
        if length > 32 * 1024 {
            return Err(DiscoveryError::Provider(
                "Known Folder path exceeded bound".into(),
            ));
        }
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map(PathBuf::from)
        .map_err(|_| DiscoveryError::Provider("Known Folder path is not valid UTF-16".into()))
}

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(target_os = "windows")]
const FOLDERID_PROFILE: Guid = Guid {
    data1: 0x5e6c858f,
    data2: 0x0e22,
    data3: 0x4760,
    data4: [0x9a, 0xfe, 0xea, 0x33, 0x17, 0xb6, 0x71, 0x73],
};
#[cfg(target_os = "windows")]
const FOLDERID_DOCUMENTS: Guid = Guid {
    data1: 0xfdd39ad0,
    data2: 0x238f,
    data3: 0x46af,
    data4: [0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03, 0x69, 0xc7],
};
#[cfg(target_os = "windows")]
const FOLDERID_DESKTOP: Guid = Guid {
    data1: 0xb4bfcc3a,
    data2: 0xdb2c,
    data3: 0x424c,
    data4: [0xb0, 0x29, 0x7f, 0xe9, 0x9a, 0x87, 0xc6, 0x41],
};
#[cfg(target_os = "windows")]
const FOLDERID_DOWNLOADS: Guid = Guid {
    data1: 0x374de290,
    data2: 0x123f,
    data3: 0x4565,
    data4: [0x91, 0x64, 0x39, 0xc4, 0x92, 0x5e, 0x46, 0x7b],
};
#[cfg(target_os = "windows")]
type Handle = isize;
#[cfg(target_os = "windows")]
const INVALID_HANDLE_VALUE: Handle = -1;
#[cfg(target_os = "windows")]
const FILE_SHARE_READ: u32 = 0x00000001;
#[cfg(target_os = "windows")]
const FILE_SHARE_WRITE: u32 = 0x00000002;
#[cfg(target_os = "windows")]
const FILE_SHARE_DELETE: u32 = 0x00000004;
#[cfg(target_os = "windows")]
const OPEN_EXISTING: u32 = 3;
#[cfg(target_os = "windows")]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x02000000;
#[cfg(target_os = "windows")]
const ERROR_FILE_NOT_FOUND: u32 = 2;
#[cfg(target_os = "windows")]
const ERROR_PATH_NOT_FOUND: u32 = 3;
#[cfg(target_os = "windows")]
const TOKEN_QUERY: u32 = 0x0008;
#[cfg(target_os = "windows")]
const TOKEN_USER_CLASS: u32 = 1;

#[cfg(target_os = "windows")]
#[repr(C)]
struct SidAndAttributes {
    sid: *mut std::ffi::c_void,
    attributes: u32,
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct TokenUser {
    user: SidAndAttributes,
}

#[cfg(target_os = "windows")]
#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(
        rfid: *const Guid,
        dw_flags: u32,
        h_token: Handle,
        ppsz_path: *mut *mut u16,
    ) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(pv: *mut std::ffi::c_void);
}

#[cfg(target_os = "windows")]
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
    fn GetTokenInformation(
        token: Handle,
        information_class: u32,
        information: *mut std::ffi::c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *mut std::ffi::c_void, string_sid: *mut *mut u16) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn GetLastError() -> u32;
    fn GetLogicalDriveStringsW(length: u32, buffer: *mut u16) -> u32;
    fn CreateFileW(
        name: *const u16,
        desired_access: u32,
        share_mode: u32,
        security_attributes: *const std::ffi::c_void,
        creation_disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn GetFinalPathNameByHandleW(handle: Handle, buffer: *mut u16, length: u32, flags: u32) -> u32;
    fn CloseHandle(handle: Handle) -> i32;
    fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
}

#[cfg(test)]
mod tests {
    use super::super::*;
    #[cfg(not(target_os = "windows"))]
    use super::WindowsProvider;
    #[cfg(target_os = "windows")]
    use super::unc_share_root;
    use std::path::{Path, PathBuf};

    fn pair(logical: &str, canonical: &str) -> PathPair {
        PathPair::unchecked(logical, canonical, false)
    }

    fn snapshot() -> PlatformSnapshot {
        let profile = r"C:\Users\Alice";
        let data = r"C:\Users\Alice\.codex\DELETE-DENIED";
        let program = r"C:\Users\Alice\.codex\DELETE-DENIED\bin";
        PlatformSnapshot {
            platform: Platform::Windows,
            architecture: Architecture::X86_64,
            login: LoginIdentity::new("Alice", profile),
            home: pair(profile, profile),
            inherited_home: Some(PathBuf::from(profile)),
            user_parent: pair(r"C:\Users", r"C:\Users"),
            filesystem_roots: vec![pair(r"C:\", r"C:\")],
            volume_roots: vec![pair(r"D:\", r"D:\")],
            share_roots: vec![pair(r"\\server\share\", r"\\server\share\")],
            documents: pair(
                r"C:\Users\Alice\Documents",
                r"C:\Users\Alice\OneDrive\Documents",
            ),
            desktop: pair(r"C:\Users\Alice\Desktop", r"C:\Users\Alice\Desktop"),
            downloads: pair(r"C:\Users\Alice\Downloads", r"C:\Users\Alice\Downloads"),
            redirected_paths: vec![(
                "onedrive".into(),
                pair(
                    r"C:\Users\Alice\Documents",
                    r"C:\Users\Alice\OneDrive\Documents",
                ),
            )],
            codex_dir: pair(r"C:\Users\Alice\.codex", r"C:\Users\Alice\.codex"),
            management: ManagementPaths {
                hooks_dir: pair(r"C:\Users\Alice\.codex", r"C:\Users\Alice\.codex"),
                hooks: pair(
                    r"C:\Users\Alice\.codex\hooks.json",
                    r"C:\Users\Alice\.codex\hooks.json",
                ),
                binary_dir: pair(program, program),
                cli_binary: pair(
                    r"C:\Users\Alice\.codex\DELETE-DENIED\bin\delete-denied.exe",
                    r"C:\Users\Alice\.codex\DELETE-DENIED\bin\delete-denied.exe",
                ),
                hook_binary: pair(
                    r"C:\Users\Alice\.codex\DELETE-DENIED\bin\delete-denied-hook.exe",
                    r"C:\Users\Alice\.codex\DELETE-DENIED\bin\delete-denied-hook.exe",
                ),
                data_dir: pair(data, data),
                policy: pair(
                    r"C:\Users\Alice\.codex\DELETE-DENIED\policy.json",
                    r"C:\Users\Alice\.codex\DELETE-DENIED\policy.json",
                ),
                state: pair(
                    r"C:\Users\Alice\.codex\DELETE-DENIED\state.json",
                    r"C:\Users\Alice\.codex\DELETE-DENIED\state.json",
                ),
                manifest: pair(
                    r"C:\Users\Alice\.codex\DELETE-DENIED\manifest.json",
                    r"C:\Users\Alice\.codex\DELETE-DENIED\manifest.json",
                ),
                backups: pair(
                    r"C:\Users\Alice\.codex\DELETE-DENIED\backups",
                    r"C:\Users\Alice\.codex\DELETE-DENIED\backups",
                ),
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
    fn fixture_preserves_drive_case_unc_and_known_folder_redirects() {
        let result = PlatformPaths::discover(&Fixture(snapshot())).expect("fixture discovery");
        assert_eq!(result.roots.len(), 3);
        assert!(
            result
                .protected_paths
                .iter()
                .any(|entry| entry.kind == "share-root")
        );
        assert!(result.protected_paths.iter().any(|entry| {
            entry.kind == "onedrive"
                && entry.canonical == Path::new(r"C:\Users\Alice\OneDrive\Documents")
        }));
        assert!(path_equal(
            PathBuf::from(r"c:\users\alice").as_path(),
            PathBuf::from(r"C:\Users\Alice").as_path(),
            false,
        ));
    }

    #[test]
    fn fixture_rejects_relative_drive_home_and_accepts_arm64_representation() {
        let mut relative = snapshot();
        relative.home = PathPair::unchecked(r"C:relative", r"C:\Users\Alice", false);
        assert!(matches!(
            PlatformPaths::discover(&Fixture(relative)),
            Err(DiscoveryError::RelativePath { .. })
        ));

        let mut root_home = snapshot();
        root_home.login.home = PathBuf::from(r"C:\");
        root_home.home = pair(r"C:\", r"C:\");
        root_home.inherited_home = Some(PathBuf::from(r"C:\"));
        assert!(matches!(
            PlatformPaths::discover(&Fixture(root_home)),
            Err(DiscoveryError::RootAsHome { .. })
        ));

        let mut arm = snapshot();
        arm.architecture = Architecture::Arm64;
        let result = PlatformPaths::discover(&Fixture(arm)).expect("ARM64 fixture");
        assert_eq!(result.architecture, Architecture::Arm64);
    }

    #[test]
    fn fixture_roundtrips_optional_domain_and_sid_metadata() {
        for (domain, sid) in [
            (None, "S-1-5-21-100-200-300-1001"),
            (Some("CONTOSO"), "S-1-5-21-100-200-300-1002"),
        ] {
            let mut input = snapshot();
            input.login.domain = domain.map(str::to_owned);
            input.login.sid = Some(sid.to_owned());
            let result = PlatformPaths::discover(&Fixture(input)).expect("identity fixture");
            assert_eq!(result.original_login.domain.as_deref(), domain);
            assert_eq!(result.original_login.sid.as_deref(), Some(sid));
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn unc_share_root_rejects_extended_dos_and_normalizes_extended_unc() {
        assert_eq!(unc_share_root(Path::new(r"\\?\C:\Users\Alice")), None);
        assert_eq!(
            unc_share_root(Path::new(r"\\?\UNC\server\share\folder")),
            Some(PathBuf::from(r"\\server\share\"))
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn production_provider_is_explicitly_unsupported_off_windows() {
        assert!(matches!(
            WindowsProvider::new().snapshot(),
            Err(DiscoveryError::UnsupportedPlatform { .. })
        ));
    }
}
