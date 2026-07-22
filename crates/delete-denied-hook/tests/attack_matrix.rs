//! Non-destructive adversarial verification for the native hook.
//!
//! Every executable case sends a command string to `delete-denied-hook`; no
//! shell, deletion utility, interpreter, or inline runtime is ever started.
//! The command text is only parsed by the hook.  All concrete paths are
//! created below one unique, validated OS temporary namespace fixture root.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

const MAX_REPORT_BYTES: usize = 512 * 1024;
const FIXTURE_PREFIX: &str = "delete-denied-attack-matrix-";
const FIXTURE_MARKER: &str = "DELETE-DENIED ATTACK MATRIX FIXTURE\n";
const MANIFEST: &str = include_str!("../../../tests/attack-matrix/cases.json");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Allow,
    Deny(&'static str),
    OutOfScope,
}

impl Expected {
    fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny(_) => "deny",
            Self::OutOfScope => "out_of_scope",
        }
    }

    fn code(self) -> Option<&'static str> {
        match self {
            Self::Deny(code) => Some(code),
            Self::Allow | Self::OutOfScope => None,
        }
    }
}

#[derive(Debug, Clone)]
struct Case {
    id: String,
    family: String,
    command: Option<String>,
    cwd: Option<PathBuf>,
    permission_mode: String,
    expected: Expected,
    note: String,
}

#[derive(Debug, Clone)]
struct Row {
    case: Case,
    actual: String,
    actual_code: Option<String>,
    status: &'static str,
    skip_reason: Option<String>,
    process_success: Option<bool>,
    stdout: String,
    stderr: String,
}

struct Canary {
    path: PathBuf,
    contents: Vec<u8>,
    digest: [u8; 32],
}

struct Fixture {
    root: PathBuf,
    marker: PathBuf,
    home: PathBuf,
    users_parent: PathBuf,
    documents: PathBuf,
    desktop: PathBuf,
    downloads: PathBuf,
    project: PathBuf,
    project_child: PathBuf,
    workspace: PathBuf,
    cleanup_target: PathBuf,
    volume_root: PathBuf,
    volume_child: PathBuf,
    cwd: PathBuf,
    home_link: Option<PathBuf>,
    policy: PathBuf,
    canaries: Vec<Canary>,
}

impl Fixture {
    fn new() -> Self {
        let sequence = FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_root = trusted_temp_namespace().expect("trusted temporary namespace required");
        let root = temp_root.join(format!(
            "{FIXTURE_PREFIX}{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after epoch")
                .as_nanos(),
            sequence
        ));
        guard_fixture_path(&root).expect("fixture root must be under the temporary directory");
        fs::create_dir(&root).expect("fixture root should be created without clobbering");
        let marker = root.join(".delete-denied-fixture-marker");
        fs::write(&marker, FIXTURE_MARKER).expect("fixture marker should be writable");

        let users_parent = root.join("Users");
        let home = users_parent.join("alice");
        let documents = home.join("Documents");
        let desktop = home.join("Desktop");
        let downloads = home.join("Downloads");
        let project = documents.join("project with spaces/ユニコード");
        let project_child = project.join("build/temporary-output");
        let workspace = root.join("workspace");
        let cleanup_target = workspace.join("exact-cleanup-target");
        let volume_root = root.join("Volumes/Volume A/Δ");
        let volume_child = volume_root.join("cache");
        let cwd = project.join("src");

        for directory in [
            &cwd,
            &desktop,
            &downloads,
            &project_child,
            &workspace,
            &cleanup_target,
            &volume_child,
        ] {
            fs::create_dir_all(directory).expect("fixture directories should be creatable");
        }

        let home_link: Option<PathBuf> = {
            let link = root.join("home-link");
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(&home, &link)
                    .expect("fixture symlink should be creatable on Unix");
                Some(link)
            }
            #[cfg(not(unix))]
            {
                let _ = link;
                None
            }
        };

        for path in [
            &root,
            &users_parent,
            &home,
            &documents,
            &desktop,
            &downloads,
            &project,
            &project_child,
            &workspace,
            &cleanup_target,
            &volume_root,
            &volume_child,
            &cwd,
        ] {
            guard_fixture_path(path).expect("fixture path escaped temporary directory");
        }
        if let Some(link) = &home_link {
            guard_fixture_path(link).expect("fixture symlink escaped temporary directory");
        }

        let canary_specs = [
            (&users_parent, "users"),
            (&home, "home"),
            (&documents, "documents"),
            (&desktop, "desktop"),
            (&downloads, "downloads"),
            (&project, "project"),
            (&cleanup_target, "cleanup-target"),
            (&volume_root, "volume"),
        ];
        let mut canaries = Vec::with_capacity(canary_specs.len());
        for (directory, label) in canary_specs {
            let path = directory.join(format!(".delete-denied-canary-{label}"));
            let contents = format!("DELETE-DENIED CANARY {label}\n").into_bytes();
            fs::write(&path, &contents).expect("fixture canary should be writable");
            guard_fixture_path(&path).expect("fixture canary escaped temporary directory");
            canaries.push(Canary {
                path,
                digest: sha256(&contents),
                contents,
            });
        }

        let canonical_root = fs::canonicalize(&root).expect("fixture root should canonicalize");
        let policy = root.join("policy.json");
        let policy_text = policy_json(
            &root,
            &canonical_root,
            &home,
            &users_parent,
            &documents,
            &desktop,
            &downloads,
            &volume_root,
        );
        fs::write(&policy, policy_text).expect("fixture policy should be writable");
        guard_fixture_path(&policy).expect("fixture policy escaped temporary directory");

        Self {
            root,
            marker,
            home,
            users_parent,
            documents,
            desktop,
            downloads,
            project,
            project_child,
            workspace,
            cleanup_target,
            volume_root,
            volume_child,
            cwd,
            home_link,
            policy,
            canaries,
        }
    }

    fn hook_json(&self, cwd: &Path, command: &str, permission_mode: &str) -> String {
        guard_fixture_path(cwd).expect("hook cwd escaped temporary directory");
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Bash","cwd":{},"permission_mode":{},"tool_input":{{"command":{}}}}}"#,
            json_string(&logical_path_text(cwd)),
            json_string(permission_mode),
            json_string(command),
        )
    }

    fn verify_canaries(&self) -> Result<(), String> {
        let marker_metadata = self
            .marker
            .symlink_metadata()
            .map_err(|error| format!("fixture marker is unavailable: {error}"))?;
        let marker_contents = fs::read_to_string(&self.marker)
            .map_err(|error| format!("fixture marker is unavailable: {error}"))?;
        if !marker_metadata.file_type().is_file() || marker_contents != FIXTURE_MARKER {
            return Err("fixture marker content changed".to_owned());
        }
        for canary in &self.canaries {
            let contents = fs::read(&canary.path).map_err(|error| {
                format!("canary disappeared ({}): {error}", canary.path.display())
            })?;
            if contents != canary.contents || sha256(&contents) != canary.digest {
                return Err(format!(
                    "canary content/hash changed: {}",
                    canary.path.display()
                ));
            }
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), String> {
        let metadata = self
            .root
            .symlink_metadata()
            .map_err(|error| format!("fixture root is unavailable: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("fixture root is not a regular owned directory".to_owned());
        }
        if !self
            .root
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with(FIXTURE_PREFIX))
        {
            return Err("fixture root does not have the owned prefix".to_owned());
        }
        guard_fixture_path(&self.root)?;
        let marker_metadata = self
            .marker
            .symlink_metadata()
            .map_err(|error| format!("fixture marker is unavailable: {error}"))?;
        let marker_contents = fs::read_to_string(&self.marker)
            .map_err(|error| format!("fixture marker is unavailable: {error}"))?;
        if !marker_metadata.file_type().is_file() || marker_contents != FIXTURE_MARKER {
            return Err("fixture marker is not owned by this test".to_owned());
        }
        fs::remove_dir_all(&self.root)
            .map_err(|error| format!("fixture cleanup failed: {error}"))?;
        if self.root.exists() {
            return Err("fixture root still exists after cleanup".to_owned());
        }
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let _ = self.cleanup();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn policy_json(
    root: &Path,
    canonical_root: &Path,
    home: &Path,
    users_parent: &Path,
    documents: &Path,
    desktop: &Path,
    downloads: &Path,
    volume_root: &Path,
) -> String {
    let path = |value: &Path| json_string(&logical_path_text(value));
    let canonical = |value: &Path| {
        json_string(
            fs::canonicalize(value)
                .expect("protected fixture path should canonicalize")
                .to_str()
                .expect("canonical fixture path must be UTF-8"),
        )
    };
    let canonical_root = json_string(
        canonical_root
            .to_str()
            .expect("canonical fixture root must be UTF-8"),
    );
    format!(
        r#"{{
  "schema_version": 1,
  "variables": {{
    "HOME": {},
    "USERPROFILE": {},
    "TMPDIR": {}
  }},
  "protected_paths": [
    {{"kind":"filesystem-root","logical":{},"canonical":{},"case_sensitive":true}},
    {{"kind":"users-parent","logical":{},"canonical":{},"case_sensitive":true}},
    {{"kind":"home","logical":"${{HOME}}","canonical":{},"case_sensitive":false}},
    {{"kind":"documents","logical":"${{HOME}}/Documents","canonical":{},"case_sensitive":false}},
    {{"kind":"desktop","logical":"${{HOME}}/Desktop","canonical":{},"case_sensitive":false}},
    {{"kind":"downloads","logical":"${{HOME}}/Downloads","canonical":{},"case_sensitive":false}},
    {{"kind":"volume-like-root","logical":{},"canonical":{},"case_sensitive":true}}
  ]
}}
"#,
        path(home),
        path(home),
        path(root),
        path(root),
        canonical_root,
        path(users_parent),
        canonical(users_parent),
        canonical(home),
        canonical(documents),
        canonical(desktop),
        canonical(downloads),
        path(volume_root),
        canonical(volume_root),
    )
}

fn json_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                output.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => output.push(character),
        }
    }
    output.push('"');
    output
}

fn path_text(path: &Path) -> String {
    logical_path_text(path).replace('\\', "/")
}

fn logical_path_text(path: &Path) -> String {
    let value = path.to_string_lossy();
    if value
        .get(..r"\\?\UNC\".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\UNC\"))
    {
        format!(r"\\{}", &value[r"\\?\UNC\".len()..])
    } else if value
        .get(..r"\\?\".len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\\?\"))
    {
        value[r"\\?\".len()..].to_owned()
    } else {
        value.into_owned()
    }
}

/// Return a canonical OS temp namespace only when it is a recognized safe
/// namespace. `TMPDIR`/`temp_dir()` is deliberately not trusted by itself.
fn trusted_temp_namespace() -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        for candidate in [Path::new("/tmp"), Path::new("/private/tmp")] {
            if let Ok(root) = validate_temp_namespace(candidate, None, None) {
                return Ok(root);
            }
        }
        Err("no recognized Unix temporary namespace (/tmp or /private/tmp)".to_owned())
    }
    #[cfg(windows)]
    {
        let raw_temp = windows_os_temp_path()?;
        let local_app_data = windows_known_folder(CSIDL_LOCAL_APPDATA)?;
        let windows_dir = windows_directory()?;
        let local_app_data = windows_final_path(&local_app_data)?;
        let windows_dir = windows_final_path(&windows_dir)?;
        reject_windows_reparse_components(&raw_temp)?;
        let canonical_temp = windows_final_path(&raw_temp)?;
        validate_windows_temp_candidate(&canonical_temp, &local_app_data, &windows_dir)
    }
}

#[cfg(unix)]
fn validate_temp_namespace(
    candidate: &Path,
    home: Option<&Path>,
    users_parent: Option<&Path>,
) -> Result<PathBuf, String> {
    if !candidate.is_absolute() {
        return Err(format!(
            "refusing non-temporary fixture path: {}",
            candidate.display()
        ));
    }
    let canonical = fs::canonicalize(candidate).map_err(|error| error.to_string())?;
    let forbidden = [
        Path::new("/Users"),
        Path::new("/etc"),
        Path::new("/var"),
        Path::new("/private/var"),
    ];
    if canonical == Path::new("/")
        || forbidden
            .iter()
            .any(|root| canonical == *root || canonical.starts_with(root))
        || home.is_some_and(|root| canonical == root || canonical.starts_with(root))
        || users_parent.is_some_and(|root| canonical == root || canonical.starts_with(root))
    {
        return Err(format!(
            "refusing unsafe temporary namespace: {}",
            candidate.display()
        ));
    }
    #[cfg(unix)]
    if canonical != Path::new("/tmp") && canonical != Path::new("/private/tmp") {
        return Err(format!(
            "refusing unrecognized Unix temporary namespace: {}",
            canonical.display()
        ));
    }
    Ok(canonical)
}

#[cfg(windows)]
const CSIDL_LOCAL_APPDATA: u32 = 28;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TempPathApi {
    OptionalTempPath2,
    LegacyTempPath,
}

fn select_temp_path_api(optional_temp_path2_available: bool) -> TempPathApi {
    if optional_temp_path2_available {
        TempPathApi::OptionalTempPath2
    } else {
        TempPathApi::LegacyTempPath
    }
}

#[cfg(windows)]
fn windows_wide_path(path: &Path) -> Result<Vec<u16>, String> {
    let value = path
        .to_str()
        .ok_or_else(|| format!("Windows path is not UTF-16 text: {}", path.display()))?;
    if value.contains('\0') {
        return Err("Windows path contains NUL".to_owned());
    }
    Ok(value.encode_utf16().chain(std::iter::once(0)).collect())
}

#[cfg(windows)]
fn windows_os_temp_path() -> Result<PathBuf, String> {
    use windows_sys::Win32::Storage::FileSystem::GetTempPathW;

    let temp_path2 = resolve_temp_path2();
    let api = select_temp_path_api(temp_path2.is_some());
    let mut buffer = vec![0u16; 512];
    let mut length = match (api, temp_path2) {
        (TempPathApi::OptionalTempPath2, Some(get_temp_path2)) => unsafe {
            get_temp_path2(buffer.len() as u32, buffer.as_mut_ptr())
        },
        (TempPathApi::LegacyTempPath, _) | (TempPathApi::OptionalTempPath2, None) => unsafe {
            GetTempPathW(buffer.len() as u32, buffer.as_mut_ptr())
        },
    };
    while length as usize >= buffer.len() {
        if buffer.len() >= 32 * 1024 {
            return Err("Windows OS temp path exceeds the supported limit".to_owned());
        }
        buffer.resize((length as usize + 1).min(32 * 1024), 0);
        length = match (api, temp_path2) {
            (TempPathApi::OptionalTempPath2, Some(get_temp_path2)) => unsafe {
                get_temp_path2(buffer.len() as u32, buffer.as_mut_ptr())
            },
            (TempPathApi::LegacyTempPath, _) | (TempPathApi::OptionalTempPath2, None) => unsafe {
                GetTempPathW(buffer.len() as u32, buffer.as_mut_ptr())
            },
        };
        if length == 0 {
            return Err("GetTempPath2W/GetTempPathW failed".to_owned());
        }
    }
    let value = String::from_utf16(&buffer[..length as usize])
        .map_err(|error| format!("Windows OS temp path is not UTF-16: {error}"))?;
    Ok(PathBuf::from(value.trim_end_matches(['\\', '/'])))
}

#[cfg(windows)]
type GetTempPath2Fn = unsafe extern "system" fn(u32, *mut u16) -> u32;

#[cfg(windows)]
fn resolve_temp_path2() -> Option<GetTempPath2Fn> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};

    let module = windows_wide_path(Path::new("kernel32.dll")).ok()?;
    let symbol = b"GetTempPath2W\0";
    let handle = unsafe { GetModuleHandleW(module.as_ptr()) };
    if handle.is_null() {
        return None;
    }
    let address = unsafe { GetProcAddress(handle, symbol.as_ptr()) }?;
    Some(unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, GetTempPath2Fn>(address)
    })
}

#[cfg(windows)]
fn windows_known_folder(folder: u32) -> Result<PathBuf, String> {
    use windows_sys::Win32::UI::Shell::SHGetFolderPathW;

    let mut buffer = vec![0u16; 32 * 1024];
    let result = unsafe {
        SHGetFolderPathW(
            std::ptr::null_mut(),
            folder as i32,
            std::ptr::null_mut(),
            0,
            buffer.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(format!(
            "SHGetFolderPathW failed for CSIDL {folder}: HRESULT {result:#x}"
        ));
    }
    let length = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..length])
        .map(PathBuf::from)
        .map_err(|error| format!("Windows known folder is not UTF-16: {error}"))
}

#[cfg(windows)]
fn windows_directory() -> Result<PathBuf, String> {
    use windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW;

    let mut buffer = vec![0u16; 512];
    let length = unsafe { GetWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if length == 0 || length as usize >= buffer.len() {
        return Err("GetWindowsDirectoryW failed or returned an oversized path".to_owned());
    }
    String::from_utf16(&buffer[..length as usize])
        .map(PathBuf::from)
        .map_err(|error| format!("Windows directory is not UTF-16: {error}"))
}

#[cfg(windows)]
fn windows_final_path(path: &Path) -> Result<PathBuf, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFinalPathNameByHandleW, OPEN_EXISTING, VOLUME_NAME_DOS,
    };

    let wide = windows_wide_path(path)?;
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!("CreateFileW could not open {}", path.display()));
    }
    let result = (|| {
        let mut buffer = vec![0u16; 512];
        loop {
            let length = unsafe {
                GetFinalPathNameByHandleW(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    VOLUME_NAME_DOS,
                )
            };
            if length == 0 {
                return Err(format!(
                    "GetFinalPathNameByHandleW failed for {}",
                    path.display()
                ));
            }
            if length as usize >= buffer.len() {
                if buffer.len() >= 32 * 1024 {
                    return Err("Windows final path exceeds the supported limit".to_owned());
                }
                buffer.resize((length as usize + 1).min(32 * 1024), 0);
                continue;
            }
            let value = String::from_utf16(&buffer[..length as usize])
                .map_err(|error| format!("Windows final path is not UTF-16: {error}"))?;
            return Ok(PathBuf::from(value));
        }
    })();
    unsafe {
        CloseHandle(handle);
    }
    result
}

#[cfg(windows)]
fn windows_path_key(path: &Path) -> String {
    let value = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let value = if let Some(rest) = value.strip_prefix(r"\\?\unc\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = value.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        value
    };
    value.trim_end_matches('\\').to_owned()
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    #[cfg(windows)]
    {
        windows_path_key(left) == windows_path_key(right)
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

fn path_is_same_or_descendant(candidate: &Path, root: &Path) -> bool {
    #[cfg(windows)]
    {
        let candidate = windows_path_key(candidate);
        let root = windows_path_key(root);
        candidate == root
            || (!root.is_empty()
                && candidate
                    .strip_prefix(&root)
                    .is_some_and(|suffix| suffix.starts_with('\\')))
    }
    #[cfg(not(windows))]
    {
        candidate == root || candidate.starts_with(root)
    }
}

#[cfg(windows)]
fn validate_windows_temp_candidate(
    candidate: &Path,
    local_app_data: &Path,
    windows_dir: &Path,
) -> Result<PathBuf, String> {
    if !candidate.is_absolute() {
        return Err(format!(
            "Windows temp path is not absolute: {}",
            candidate.display()
        ));
    }
    let key = windows_path_key(candidate);
    let local_temp = windows_path_key(&local_app_data.join("Temp"));
    let windows_temp = windows_path_key(&windows_dir.join("Temp"));
    if key != local_temp && key != windows_temp {
        return Err(format!(
            "Windows temp path is not LocalAppData\\Temp or Windows\\Temp: {}",
            candidate.display()
        ));
    }
    let drive_root = key
        .get(..3)
        .filter(|prefix| prefix.ends_with("\\"))
        .unwrap_or_default();
    if key == drive_root
        || key.ends_with("\\users")
        || key.ends_with("\\userprofile")
        || key.ends_with("\\windows")
        || key.ends_with("\\system32")
    {
        return Err(format!(
            "Windows temp path is a protected system root: {}",
            candidate.display()
        ));
    }
    Ok(candidate.to_path_buf())
}

#[cfg(windows)]
fn windows_reparse_inspection_paths(path: &Path) -> Result<Vec<PathBuf>, String> {
    if !path.is_absolute() {
        return Err(format!(
            "Windows reparse inspection requires an absolute path: {}",
            path.display()
        ));
    }

    let mut current = PathBuf::new();
    let mut rooted_components = Vec::new();
    let mut saw_root_dir = false;
    for component in path.components() {
        if matches!(component, std::path::Component::RootDir) {
            saw_root_dir = true;
        }
        current.push(component.as_os_str());
        // A Windows drive prefix such as `C:` is drive-relative until the
        // following RootDir component is present. Verbatim drive prefixes such
        // as `\\?\C:` report `is_absolute()` before that RootDir arrives, so
        // the component kind is the authoritative boundary here. Querying an
        // incomplete prefix can return ERROR_INVALID_FUNCTION on NTFS.
        if saw_root_dir {
            rooted_components.push(current.clone());
        }
    }
    Ok(rooted_components)
}

#[cfg(windows)]
fn reject_windows_reparse_components(path: &Path) -> Result<(), String> {
    use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
    };

    for current in windows_reparse_inspection_paths(path)? {
        let wide = windows_wide_path(&current)?;
        let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attributes == INVALID_FILE_ATTRIBUTES {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(code)
                    if code == ERROR_FILE_NOT_FOUND as i32
                        || code == ERROR_PATH_NOT_FOUND as i32
            ) {
                // Missing output suffixes are allowed. Continue instead of
                // stopping so a later `..` component cannot bypass inspection
                // of an existing ancestor.
                continue;
            }
            return Err(format!(
                "could not inspect Windows path component {}: {error}",
                current.display(),
            ));
        }
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "Windows path contains a reparse component: {}",
                current.display()
            ));
        }
    }
    Ok(())
}

/// Reject every path outside the validated temporary fixture namespace.
fn guard_fixture_path(path: &Path) -> Result<(), String> {
    let temp = trusted_temp_namespace()?;
    if !path.is_absolute() {
        return Err(format!(
            "refusing non-temporary fixture path: {}",
            path.display()
        ));
    }
    #[cfg(windows)]
    reject_windows_reparse_components(path)?;
    let candidate = if path.exists() {
        fs::canonicalize(path).map_err(|error| error.to_string())?
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| format!("fixture path has no parent: {}", path.display()))?;
        let name = path
            .file_name()
            .ok_or_else(|| format!("fixture path has no name: {}", path.display()))?;
        fs::canonicalize(parent)
            .map_err(|error| error.to_string())?
            .join(name)
    };
    if candidate == temp || !candidate.starts_with(&temp) {
        return Err(format!(
            "refusing non-temporary fixture path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn run_hook(binary: &Path, fixture: &Fixture, case: &Case) -> Output {
    let cwd = case.cwd.as_deref().expect("executable case needs cwd");
    let command = case
        .command
        .as_deref()
        .expect("executable case needs command");
    let mut child = Command::new(binary)
        .args([
            "--policy",
            fixture.policy.to_str().expect("policy must be UTF-8"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hook process should start");
    child
        .stdin
        .take()
        .expect("hook stdin should be available")
        .write_all(
            fixture
                .hook_json(cwd, command, &case.permission_mode)
                .as_bytes(),
        )
        .expect("hook stdin should be writable");
    child.wait_with_output().expect("hook process should exit")
}

fn classify(output: &Output) -> (String, Option<String>) {
    classify_parts(output.status.success(), &output.stdout, &output.stderr)
}

fn classify_parts(success: bool, stdout: &[u8], stderr: &[u8]) -> (String, Option<String>) {
    if success && stdout.is_empty() && stderr.is_empty() {
        return ("allow".to_owned(), None);
    }
    if !success || !stderr.is_empty() || stdout.len() > 4_096 {
        return ("unexpected".to_owned(), None);
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(stdout) else {
        return ("unexpected".to_owned(), None);
    };
    let Some(output) = value.get("hookSpecificOutput") else {
        return ("unexpected".to_owned(), None);
    };
    if output
        .get("hookEventName")
        .and_then(serde_json::Value::as_str)
        != Some("PreToolUse")
        || output
            .get("permissionDecision")
            .and_then(serde_json::Value::as_str)
            != Some("deny")
    {
        return ("unexpected".to_owned(), None);
    }
    let Some(reason) = output
        .get("permissionDecisionReason")
        .and_then(serde_json::Value::as_str)
    else {
        return ("unexpected".to_owned(), None);
    };
    let codes = [
        "DD-PROTECTED-PATH",
        "DD-CWD-ANCESTOR",
        "DD-AMBIGUOUS-RECURSIVE",
        "DD-POLICY-INVALID",
        "DD-INPUT-TOO-LARGE",
        "DD-HOOK-UNSUPPORTED",
        "DD-INPUT-INVALID",
    ];
    codes
        .iter()
        .find(|code| reason.starts_with(&format!("[{code}]")))
        .map_or_else(
            || ("unexpected".to_owned(), None),
            |code| ("deny".to_owned(), Some((*code).to_owned())),
        )
}

fn make_case(
    id: &str,
    family: &str,
    command: impl Into<String>,
    cwd: &Path,
    expected: Expected,
    note: &str,
) -> Case {
    Case {
        id: id.to_owned(),
        family: family.to_owned(),
        command: Some(command.into()),
        cwd: Some(cwd.to_path_buf()),
        permission_mode: "danger-full-access".to_owned(),
        expected,
        note: note.to_owned(),
    }
}

fn out_of_scope(id: &str, family: &str, reason: &str) -> Case {
    Case {
        id: id.to_owned(),
        family: family.to_owned(),
        command: None,
        cwd: None,
        permission_mode: "not_applicable".to_owned(),
        expected: Expected::OutOfScope,
        note: reason.to_owned(),
    }
}

fn cases(fixture: &Fixture) -> Vec<Case> {
    let h = path_text(&fixture.home);
    let u = path_text(&fixture.users_parent);
    let d = path_text(&fixture.documents);
    let desk = path_text(&fixture.desktop);
    let dl = path_text(&fixture.downloads);
    let p = path_text(&fixture.project);
    let pc = path_text(&fixture.project_child);
    let root = path_text(&fixture.root);
    let volume = path_text(&fixture.volume_root);
    let volume_child = path_text(&fixture.volume_child);
    let workspace = path_text(&fixture.workspace);
    let cleanup = path_text(&fixture.cleanup_target);
    let cwd = &fixture.cwd;
    let mut cases = vec![
        make_case(
            "deny-root",
            "protected_parent",
            format!("rm -rf {root}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "fixture filesystem root",
        ),
        make_case(
            "deny-users-parent",
            "protected_parent",
            format!("rm -rf {u}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "synthetic users parent",
        ),
        make_case(
            "deny-home",
            "protected_parent",
            format!("rm -rf {h}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "synthetic home",
        ),
        make_case(
            "deny-documents",
            "protected_parent",
            format!("rm -rf {d}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "Documents itself",
        ),
        make_case(
            "deny-desktop",
            "protected_parent",
            format!("rm -rf {desk}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "Desktop itself",
        ),
        make_case(
            "deny-downloads",
            "protected_parent",
            format!("rm -rf {dl}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "Downloads itself",
        ),
        make_case(
            "deny-rmdir-home",
            "direct_delete",
            format!("rmdir {h}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "direct rmdir of protected home",
        ),
        make_case(
            "deny-unlink-home",
            "direct_delete",
            format!("unlink {h}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "direct unlink targeting protected home",
        ),
        make_case(
            "deny-home-env",
            "environment",
            "rm -rf \"$HOME\"",
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "HOME expression",
        ),
        make_case(
            "deny-home-env-braced",
            "environment",
            "rm -rf \"${HOME}\"",
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "braced HOME expression",
        ),
        make_case(
            "deny-home-wildcard",
            "protected_contents",
            "rm -rf \"$HOME\"/*",
            cwd,
            Expected::Deny("DD-AMBIGUOUS-RECURSIVE"),
            "wildcard selecting home contents",
        ),
        make_case(
            "deny-documents-wildcard",
            "protected_contents",
            format!("rm -rf '{d}/*'"),
            cwd,
            Expected::Deny("DD-AMBIGUOUS-RECURSIVE"),
            "wildcard selecting Documents contents",
        ),
        make_case(
            "deny-nearest-existing-parent",
            "nearest_existing_parent",
            format!("rm -rf {h}/not-created-yet/.."),
            &fixture.workspace,
            Expected::Deny("DD-PROTECTED-PATH"),
            "missing target resolves through protected existing home parent",
        ),
        make_case(
            "deny-home-parent",
            "traversal",
            format!("rm -rf {h}/.."),
            cwd,
            Expected::Deny("DD-CWD-ANCESTOR"),
            "parent traversal to users parent",
        ),
        make_case(
            "deny-cwd-parent",
            "traversal",
            "rm -rf ..",
            cwd,
            Expected::Deny("DD-CWD-ANCESTOR"),
            "relative parent traversal",
        ),
        make_case(
            "deny-duplicate-slash",
            "path_spelling",
            format!("rm -rf {root}//Users///alice"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "duplicate separators",
        ),
        make_case(
            "deny-single-quotes",
            "path_spelling",
            format!("rm -rf '{h}'"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "single-quoted path",
        ),
        make_case(
            "deny-double-quotes",
            "path_spelling",
            format!("rm -rf \"{h}\""),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "double-quoted path",
        ),
        make_case(
            "deny-spaces-unicode",
            "path_spelling",
            format!("rm -rf '{d}/project with spaces/ユニコード/..'"),
            cwd,
            Expected::Deny("DD-CWD-ANCESTOR"),
            "spaces, Unicode, and traversal",
        ),
        make_case(
            "deny-case-insensitive-documents",
            "case_variation",
            format!("rm -rf {root}/USERS/ALICE/DOCUMENTS"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "case-insensitive Documents fixture",
        ),
        make_case(
            "allow-case-sensitive-users-variation",
            "case_variation",
            format!("rm -rf {root}/USERS2"),
            cwd,
            Expected::Allow,
            "users-parent is case-sensitive in this fixture",
        ),
        make_case(
            "deny-symlink-home",
            "symlink",
            fixture.home_link.as_ref().map_or_else(
                || "rm -rf /unsupported".to_owned(),
                |link| format!("rm -rf {}", path_text(link)),
            ),
            cwd,
            if fixture.home_link.is_some() {
                Expected::Deny("DD-PROTECTED-PATH")
            } else {
                Expected::OutOfScope
            },
            "symlink canonicalizing to protected home",
        ),
        make_case(
            "deny-volume-like-protected-root",
            "volume",
            format!("rm -rf '{volume}'"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "nested volume-like protected root; not a mounted volume",
        ),
        make_case(
            "deny-find-delete-home",
            "find",
            format!("find {h} -delete"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "find -delete",
        ),
        make_case(
            "deny-xargs-rm-home",
            "xargs",
            format!("printf x | xargs rm -rf {h}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "xargs rm",
        ),
        make_case(
            "deny-rsync-destination-home",
            "rsync",
            format!("rsync --delete {pc}/ {h}/"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "rsync destination deletion",
        ),
        make_case(
            "deny-git-clean-home",
            "git",
            "git clean -fdx",
            &fixture.home,
            Expected::Deny("DD-PROTECTED-PATH"),
            "cwd equal synthetic home",
        ),
        make_case(
            "deny-git-c-home",
            "git",
            "git -C \"$HOME\" clean -fdx",
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "git -C home",
        ),
        make_case(
            "deny-bash-wrapper",
            "shell_wrapper",
            format!("bash -c 'rm -rf {h}'"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "bash -c payload",
        ),
        make_case(
            "deny-sh-wrapper",
            "shell_wrapper",
            "sh -c 'cd \"$HOME\" && rm -rf .'".to_owned(),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "sh -c payload and cd context",
        ),
        make_case(
            "deny-powershell-wrapper",
            "powershell",
            format!("pwsh -NoProfile -Command \"Remove-Item -Recurse -Force '{h}'\""),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "PowerShell -Command payload",
        ),
        make_case(
            "deny-cmd-wrapper",
            "cmd",
            format!("cmd /c \"rd /s /q {h}\""),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "cmd /c payload",
        ),
        make_case(
            "deny-node-inline",
            "inline_runtime",
            format!("node -e \"fs.rm('{h}', {{ recursive: true }})\""),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "Node fs.rm recursive literal",
        ),
        make_case(
            "deny-python-inline",
            "inline_runtime",
            format!("python -c \"shutil.rmtree('{h}')\""),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "Python shutil.rmtree literal",
        ),
        make_case(
            "deny-ambiguous-unknown",
            "ambiguous_recursive",
            "rm -rf \"$UNKNOWN\"",
            cwd,
            Expected::Deny("DD-AMBIGUOUS-RECURSIVE"),
            "unknown recursive target",
        ),
        make_case(
            "deny-ambiguous-substitution",
            "ambiguous_recursive",
            "rm -rf \"$(printf %s ./build)\"",
            cwd,
            Expected::Deny("DD-AMBIGUOUS-RECURSIVE"),
            "command substitution target",
        ),
        make_case(
            "deny-ambiguous-node",
            "ambiguous_recursive",
            "node -e \"fs.rm(target, { recursive: true })\"",
            cwd,
            Expected::Deny("DD-AMBIGUOUS-RECURSIVE"),
            "dynamic Node target",
        ),
        make_case(
            "deny-ambiguous-python",
            "ambiguous_recursive",
            "python -c \"shutil.rmtree(target)\"",
            cwd,
            Expected::Deny("DD-AMBIGUOUS-RECURSIVE"),
            "dynamic Python target",
        ),
        make_case(
            "deny-env-home-override",
            "override_attempt",
            format!("HOME={workspace}; rm -rf \"$HOME\""),
            cwd,
            Expected::Allow,
            "explicit safe HOME override is part of the existing contract",
        ),
        make_case(
            "deny-env-wrapper-home",
            "override_attempt",
            format!("env HOME={workspace} rm -rf \"$HOME\""),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "env wrapper cannot rewrite shell expansion",
        ),
        make_case(
            "deny-codex-home-override",
            "override_attempt",
            format!("CODEX_HOME={workspace}; rm -rf \"$HOME\""),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "unverified CODEX_HOME does not alter HOME",
        ),
        make_case(
            "deny-userprofile-override",
            "override_attempt",
            format!("USERPROFILE={workspace}; rm -rf \"$HOME\""),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "USERPROFILE override does not alter HOME",
        ),
        make_case(
            "deny-home-cwd-dot",
            "cwd_context",
            "rm -rf .",
            &fixture.home,
            Expected::Deny("DD-PROTECTED-PATH"),
            "cwd equal home",
        ),
        make_case(
            "deny-users-cwd-dot",
            "cwd_context",
            "rm -rf .",
            &fixture.users_parent,
            Expected::Deny("DD-PROTECTED-PATH"),
            "cwd equal users parent",
        ),
        make_case(
            "allow-project-child",
            "allow_project",
            format!("rm -rf {pc}"),
            cwd,
            Expected::Allow,
            "project-child cleanup",
        ),
        make_case(
            "allow-unlink-project-file",
            "allow_project",
            format!("unlink {p}/old.txt"),
            cwd,
            Expected::Allow,
            "direct unlink of a project child",
        ),
        make_case(
            "allow-project-clean",
            "allow_project",
            "git clean -fdx",
            &fixture.project,
            Expected::Allow,
            "project git clean",
        ),
        make_case(
            "allow-project-under-documents",
            "allow_project",
            format!("rm -rf {p}"),
            &fixture.workspace,
            Expected::Allow,
            "exact project under Documents with non-ancestor cwd",
        ),
        make_case(
            "allow-volume-child",
            "allow_project",
            format!("rm -rf {volume_child}"),
            cwd,
            Expected::Allow,
            "child below volume-like protected root",
        ),
        make_case(
            "allow-exact-cleanup-target",
            "allow_project",
            format!("rm -rf {cleanup}"),
            &fixture.workspace,
            Expected::Allow,
            "separate exact cleanup target workspace",
        ),
        make_case(
            "allow-project-rename",
            "allow_project",
            format!("mv {pc} {p}/renamed-output"),
            cwd,
            Expected::Allow,
            "project-child rename/move",
        ),
        make_case(
            "allow-create-modify",
            "allow_project",
            format!("mkdir -p {p}/new && touch {p}/new/file"),
            cwd,
            Expected::Allow,
            "create/modify-only command",
        ),
        make_case(
            "allow-build-test-package",
            "allow_normal",
            "cargo test && npm run build && pnpm pack",
            cwd,
            Expected::Allow,
            "common build/test/package commands",
        ),
        make_case(
            "allow-query",
            "allow_normal",
            "pwd && printf '%s\\n' safe",
            cwd,
            Expected::Allow,
            "ordinary read/query command",
        ),
        make_case(
            "allow-rsync-project",
            "allow_project",
            format!("rsync --delete {pc}/ {workspace}/backup/"),
            cwd,
            Expected::Allow,
            "rsync deletion limited to project workspace",
        ),
        make_case(
            "allow-nonrecursive-single-unknown",
            "allow_contract",
            "rm \"$UNKNOWN/file.txt\"",
            cwd,
            Expected::Allow,
            "unresolved non-recursive single file is allowed by contract",
        ),
        make_case(
            "full-access-deny",
            "permission_mode",
            format!("rm -rf {h}"),
            cwd,
            Expected::Deny("DD-PROTECTED-PATH"),
            "Full Access is preserved and does not bypass hook evaluation",
        ),
    ];

    // Compare the same hook input under another profile to prove the
    // permission wording is not part of the decision.  The pair is kept as a
    // normal process case so a changed decision fails the matrix.
    if let Some(full_access) = cases.last().cloned() {
        let mut restricted = full_access;
        restricted.id = "profile-wording-does-not-change-decision".to_owned();
        restricted.permission_mode = "default".to_owned();
        restricted.note = "same command under a different permission mode".to_owned();
        cases.push(restricted);
    }

    cases.extend([
        out_of_scope(
            "out-apply-patch",
            "out_of_scope",
            "apply_patch is not a Bash hook input",
        ),
        out_of_scope(
            "out-mcp",
            "out_of_scope",
            "MCP filesystem tools are outside the supported hook surface",
        ),
        out_of_scope(
            "out-finder-explorer",
            "out_of_scope",
            "Finder/Explorer direct actions are outside the supported hook surface",
        ),
        out_of_scope(
            "out-browser-download",
            "out_of_scope",
            "browser downloads are outside the supported hook surface",
        ),
        out_of_scope(
            "out-remote-data",
            "out_of_scope",
            "remote/SSH/cloud data is outside the supported hook surface",
        ),
        out_of_scope(
            "out-e2e-subagent-shell",
            "e2e_delivery",
            "subagent shell delivery requires a qualified Codex App run; not exercised by hook-input tests",
        ),
        out_of_scope(
            "out-e2e-resumed-task",
            "e2e_delivery",
            "resumed-task hook delivery requires a qualified Codex App run; not exercised here",
        ),
        out_of_scope(
            "out-e2e-personal-hooks-disabled",
            "e2e_delivery",
            "personal hooks-disabled override behavior requires user-hook lifecycle E2E",
        ),
        out_of_scope(
            "out-e2e-alternate-codex-home",
            "e2e_delivery",
            "alternate CODEX_HOME user-hook delivery requires lifecycle/E2E verification",
        ),
        out_of_scope(
            "out-e2e-suspend-lifecycle",
            "e2e_lifecycle",
            "suspend/resume lifecycle is outside this hook-input process test",
        ),
        out_of_scope(
            "out-e2e-full-access-delivery",
            "e2e_delivery",
            "Full Access user-hook delivery requires Codex App E2E; permission_mode text alone is not proof",
        ),
        out_of_scope(
            "out-e2e-hook-failure-behavior",
            "e2e_lifecycle",
            "hook failure/timeout/invalid-output behavior belongs to the lifecycle failure workflow, not this hook-input matrix",
        ),
        out_of_scope(
            "out-e2e-repeat-install",
            "e2e_lifecycle",
            "repeat install idempotency is owned by the CLI lifecycle test workflow",
        ),
        out_of_scope(
            "out-e2e-repeat-update",
            "e2e_lifecycle",
            "repeat update and user-hook replacement is owned by the CLI lifecycle test workflow",
        ),
        out_of_scope(
            "out-e2e-repeat-uninstall",
            "e2e_lifecycle",
            "repeat uninstall idempotency is owned by the CLI lifecycle test workflow",
        ),
        out_of_scope(
            "out-e2e-residual-processes",
            "e2e_lifecycle",
            "residual process verification requires the lifecycle workflow after repeated install/update/uninstall",
        ),
        out_of_scope(
            "out-e2e-residual-handles",
            "e2e_lifecycle",
            "residual handle verification requires a qualified Windows lifecycle workflow",
        ),
        out_of_scope(
            "out-macos-mounted-volume-e2e",
            "e2e_lifecycle",
            "real mounted-volume semantics require a dedicated macOS CI workflow with a disposable hdiutil sparse image and no delete execution",
        ),
        out_of_scope(
            "out-windows-vhd-volume-e2e",
            "windows_fs_semantics",
            "Windows VHD/mounted-volume semantics require a hosted-admin Windows workflow and are not simulated by the nested fixture path",
        ),
        out_of_scope(
            "out-windows-junction",
            "windows_fs_semantics",
            "simulated logical=\\\\fixture\\Users\\Alice\\JUNCTION canonical=\\\\fixture\\Users\\Alice\\Documents; Windows junction requires Windows CI and was not host-created on macOS",
        ),
        out_of_scope(
            "out-windows-reparse",
            "windows_fs_semantics",
            "simulated logical=\\\\fixture\\Users\\Alice\\REPARSE canonical=\\\\fixture\\Users\\Alice\\Downloads; Windows reparse-point canonical pair requires Windows CI and is not claimed on macOS",
        ),
        out_of_scope(
            "out-windows-8dot3",
            "windows_fs_semantics",
            "simulated logical=C:\\\\Users\\ALICE~1 canonical=C:\\\\Users\\Alice; Windows 8.3 alias behavior requires Windows CI and is not claimed on macOS",
        ),
        out_of_scope(
            "out-windows-unc",
            "windows_fs_semantics",
            "simulated logical=\\\\server\\share\\home canonical=\\\\server\\share\\home; Windows UNC share behavior requires Windows CI and is not claimed on macOS",
        ),
    ]);
    cases
}

fn run_matrix(binary: &Path, fixture: &Fixture) -> Vec<Row> {
    cases(fixture)
        .into_iter()
        .map(|case| {
            if matches!(case.expected, Expected::OutOfScope) {
                return Row {
                    actual: "out_of_scope".to_owned(),
                    actual_code: None,
                    status: "out_of_scope",
                    skip_reason: Some(case.note.clone()),
                    process_success: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    case,
                };
            }
            let output = run_hook(binary, fixture, &case);
            let (actual, actual_code) = classify(&output);
            let matches = actual == case.expected.label()
                && case
                    .expected
                    .code()
                    .is_none_or(|expected| actual_code.as_deref() == Some(expected));
            Row {
                case,
                actual,
                actual_code,
                status: if matches { "pass" } else { "fail" },
                skip_reason: None,
                process_success: Some(output.status.success()),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            }
        })
        .collect()
}

fn resolve_hook_binary() -> Result<PathBuf, String> {
    let candidate = std::env::var_os("DELETE_DENIED_ATTACK_MATRIX_HOOK")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_delete-denied-hook")));
    validate_hook_binary(&candidate)
}

fn validate_hook_binary(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!(
            "hook binary path must be absolute: {}",
            path.display()
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(format!(
            "hook binary must be a regular non-symlink file: {}",
            path.display()
        ));
    }
    #[cfg(windows)]
    reject_windows_reparse_components(path)?;
    let expected_name = if cfg!(windows) {
        "delete-denied-hook.exe"
    } else {
        "delete-denied-hook"
    };
    let actual_name = path.file_name().and_then(|name| name.to_str());
    let expected_basename = actual_name.is_some_and(|name| {
        if cfg!(windows) {
            name.eq_ignore_ascii_case(expected_name)
        } else {
            name == expected_name
        }
    });
    if !expected_basename {
        return Err(format!(
            "hook binary has an unexpected basename: {}",
            path.display()
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| error.to_string())?;
    if !paths_equivalent(&canonical, path) {
        return Err(format!(
            "hook binary path is not canonical: {}",
            path.display()
        ));
    }
    Ok(canonical)
}

fn report_path() -> Result<PathBuf, String> {
    let path = std::env::var_os("DELETE_DENIED_ATTACK_MATRIX_REPORT")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/attack-matrix/report.json")
        });
    validate_report_path(&path)
}

fn validate_report_path(path: &Path) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("report path must be absolute: {}", path.display()));
    }
    let repo_root = fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .map_err(|error| format!("repository root is not canonicalizable: {error}"))?;
    let repo_target = repo_root.join("target/attack-matrix");
    let temp_root = trusted_temp_namespace()?;
    let parent = nearest_existing_parent(path)?;
    reject_symlink_components(path, &temp_root)?;
    let canonical_parent = fs::canonicalize(&parent).map_err(|error| error.to_string())?;
    let in_repo_target =
        path_is_same_or_descendant(&lexical_normalize_absolute(path), &repo_target);
    let in_temp = path_is_same_or_descendant(&canonical_parent, &temp_root);
    if !in_repo_target && !in_temp {
        return Err(format!(
            "report path is outside approved roots: {}",
            path.display()
        ));
    }
    if path.exists() {
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "report path is not a regular file: {}",
                path.display()
            ));
        }
    }
    Ok(path.to_path_buf())
}

fn lexical_normalize_absolute(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::RootDir => normalized.push(Path::new("/")),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                let _ = normalized.pop();
            }
            std::path::Component::Normal(value) => normalized.push(value),
            std::path::Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
        }
    }
    normalized
}

fn nearest_existing_parent(path: &Path) -> Result<PathBuf, String> {
    let mut current = path
        .parent()
        .ok_or_else(|| format!("report path has no parent: {}", path.display()))?;
    loop {
        if current.exists() {
            return Ok(current.to_path_buf());
        }
        current = current
            .parent()
            .ok_or_else(|| format!("report path has no existing parent: {}", path.display()))?;
    }
}

fn reject_symlink_components(path: &Path, trusted_temp: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let _ = trusted_temp;
        reject_windows_reparse_components(path)
    }
    #[cfg(not(windows))]
    {
        let mut current = PathBuf::new();
        for component in path.components() {
            current.push(component.as_os_str());
            let metadata = match fs::symlink_metadata(&current) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.to_string()),
            };
            if metadata.file_type().is_symlink() {
                if fs::canonicalize(&current).ok().as_deref() == Some(trusted_temp) {
                    continue;
                }
                return Err(format!(
                    "report path contains a symlink component: {}",
                    current.display()
                ));
            }
        }
        Ok(())
    }
}

fn write_report_atomic(path: &Path, report: &str) -> Result<(), String> {
    let path = validate_report_path(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| "report path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let path = validate_report_path(&path)?;
    let temporary = parent.join(format!(
        ".report-{}.{}.tmp",
        std::process::id(),
        FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    let result = (|| {
        file.write_all(report.as_bytes())
            .map_err(|error| error.to_string())?;
        file.flush().map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        atomic_replace_report(&temporary, &path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn atomic_replace_report(source: &Path, destination: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Storage::FileSystem::{
            MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
        };
        let source = windows_wide_path(source)?;
        let destination_text = destination.display().to_string();
        let destination = windows_wide_path(destination)?;
        let moved = unsafe {
            MoveFileExW(
                source.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if moved == 0 {
            return Err(format!(
                "MoveFileExW could not atomically replace {}",
                destination_text
            ));
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        fs::rename(source, destination).map_err(|error| error.to_string())
    }
}

fn binary_sha256(path: &Path) -> String {
    let bytes = fs::read(path).expect("hook binary should be readable for hashing");
    let digest = sha256(&bytes);
    use std::fmt::Write as _;
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
    }
    output
}

// Small dependency-free SHA-256 implementation for the process-tested binary
// hash in the machine-readable report.  This runs once in the test cold path.
fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let padded_len = ((input.len() + 9).div_ceil(64)) * 64;
    let mut data = vec![0u8; padded_len];
    data[..input.len()].copy_from_slice(input);
    data[input.len()] = 0x80;
    data[padded_len - 8..].copy_from_slice(&bit_len.to_be_bytes());
    for chunk in data.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (index, word) in w[..16].iter_mut().enumerate() {
            *word = u32::from_be_bytes([
                chunk[index * 4],
                chunk[index * 4 + 1],
                chunk[index * 4 + 2],
                chunk[index * 4 + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut i) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = i
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);
            i = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(i);
    }
    let mut output = [0u8; 32];
    for (index, word) in h.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

fn report_json(
    binary: &Path,
    fixture: &Fixture,
    rows: &[Row],
    canary_checked: bool,
    cleanup_verified: bool,
) -> String {
    let allow = rows.iter().filter(|row| row.actual == "allow").count();
    let deny = rows.iter().filter(|row| row.actual == "deny").count();
    let skips = rows
        .iter()
        .filter(|row| row.actual == "out_of_scope")
        .count();
    let unexpected = rows.iter().filter(|row| row.status == "fail").count();
    let binary_hash = binary_sha256(binary);
    let mut output = String::new();
    output.push_str("{\n");
    output.push_str("  \"schema_version\":1,\n");
    output.push_str("  \"codex_version\":\"not_applicable_hook_input_matrix\",\n");
    output.push_str(&format!(
        "  \"os\":{},\n  \"arch\":{},\n  \"binary\":{},\n  \"binary_sha256\":{},\n",
        json_string(std::env::consts::OS),
        json_string(std::env::consts::ARCH),
        json_string(binary.to_str().expect("binary path must be UTF-8")),
        json_string(&binary_hash),
    ));
    let invocation_count = rows
        .iter()
        .filter(|row| row.case.expected != Expected::OutOfScope)
        .count();
    output.push_str(&format!(
        "  \"execution\":{{\"hook_input_only\":true,\"no_destructive_execution\":true,\"shell_commands_executed\":0,\"canary_checked\":{},\"cleanup_verified\":{}}},\n",
        canary_checked, cleanup_verified
    ));
    output.push_str("  \"metrics\":{\"latency\":\"not_measured\",\"rss\":\"not_measured\",\"residual_processes\":\"not_measured\",\"residual_handles\":\"not_measured\",\"reason\":\"release benchmark and lifecycle residual checks are separate from this hook-input matrix\"},\n");
    output.push_str(&format!(
        "  \"fixture\":{},\n  \"invocation_count\":{},\n",
        json_string(fixture.root.to_str().expect("fixture root must be UTF-8")),
        invocation_count,
    ));
    output.push_str(&format!(
        "  \"counts\":{{\"allow\":{},\"deny\":{},\"skips\":{},\"unexpected\":{}}},\n",
        allow, deny, skips, unexpected
    ));
    output.push_str("  \"cases\":[\n");
    for (index, row) in rows.iter().enumerate() {
        let comma = if index + 1 == rows.len() { "" } else { "," };
        let command = row.case.command.as_deref().unwrap_or("");
        let cwd = row.case.cwd.as_deref().and_then(Path::to_str).unwrap_or("");
        let expected_code = row.case.expected.code().unwrap_or("");
        let actual_code = row.actual_code.as_deref().unwrap_or("");
        let skip_reason = row.skip_reason.as_deref().unwrap_or("");
        output.push_str(&format!(
            "    {{\"id\":{},\"family\":{},\"command\":{},\"cwd\":{},\"permission_mode\":{},\"expected\":{},\"expected_code\":{},\"actual\":{},\"actual_code\":{},\"status\":{},\"note\":{},\"skip_reason\":{}}}{}\n",
            json_string(&row.case.id),
            json_string(&row.case.family),
            json_string(command),
            json_string(cwd),
            json_string(&row.case.permission_mode),
            json_string(row.case.expected.label()),
            json_string(expected_code),
            json_string(&row.actual),
            json_string(actual_code),
            json_string(row.status),
            json_string(&row.case.note),
            json_string(skip_reason),
            comma,
        ));
    }
    output.push_str("  ],\n  \"skips\":[\n");
    let skipped = rows
        .iter()
        .filter(|row| row.actual == "out_of_scope")
        .collect::<Vec<_>>();
    for (index, row) in skipped.iter().enumerate() {
        let comma = if index + 1 == skipped.len() { "" } else { "," };
        output.push_str(&format!(
            "    {{\"id\":{},\"reason\":{}}}{}\n",
            json_string(&row.case.id),
            json_string(row.skip_reason.as_deref().unwrap_or("out of scope")),
            comma,
        ));
    }
    output.push_str("  ]\n}\n");
    output
}

fn validate_manifest_and_rows(rows: &[Row]) -> Result<(), String> {
    let manifest: serde_json::Value = serde_json::from_str(MANIFEST)
        .map_err(|error| format!("cases manifest is invalid JSON: {error}"))?;
    let required = manifest
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "cases manifest has no cases array".to_owned())?;
    let row_ids = rows
        .iter()
        .map(|row| row.case.id.as_str())
        .collect::<Vec<_>>();
    let unique_ids = row_ids.iter().copied().collect::<BTreeSet<_>>();
    if unique_ids.len() != row_ids.len() {
        return Err("matrix contains duplicate case IDs".to_owned());
    }
    let mut manifest_ids = BTreeSet::new();
    for case in required {
        let id = case
            .get("id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "manifest case is missing id".to_owned())?;
        if !manifest_ids.insert(id) {
            return Err(format!("manifest contains duplicate case ID: {id}"));
        }
        let family = case
            .get("family")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("manifest case {id} is missing family"))?;
        let Some(row) = rows.iter().find(|row| row.case.id == id) else {
            return Err(format!(
                "required manifest case is missing from test vector: {id}"
            ));
        };
        if row.case.family != family {
            return Err(format!("case {id} changed family"));
        }
    }
    if manifest_ids != unique_ids {
        return Err("test vector IDs do not exactly match the tracked manifest".to_owned());
    }
    let minimums = manifest
        .get("required_min_counts")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "manifest has no required_min_counts".to_owned())?;
    let mut counts = BTreeMap::new();
    for row in rows {
        *counts.entry(row.actual.as_str()).or_insert(0usize) += 1;
    }
    for (label, minimum) in minimums {
        let minimum = minimum
            .as_u64()
            .ok_or_else(|| format!("manifest minimum {label} is not numeric"))?
            as usize;
        if counts.get(label.as_str()).copied().unwrap_or(0) < minimum {
            return Err(format!(
                "matrix count for {label} is below manifest minimum"
            ));
        }
    }
    let required_families = manifest
        .get("required_families")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "manifest has no required_families".to_owned())?;
    for (family, minimum) in required_families {
        let minimum = minimum
            .as_u64()
            .ok_or_else(|| format!("manifest family {family} is not numeric"))?
            as usize;
        let count = rows
            .iter()
            .filter(|row| row.case.family == family.as_str())
            .count();
        if count < minimum {
            return Err(format!("family {family} is below manifest minimum"));
        }
    }
    Ok(())
}

fn validate_report_json(report: &str, rows: &[Row]) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_str(report)
        .map_err(|error| format!("generated report is invalid JSON: {error}"))?;
    if value
        .get("codex_version")
        .and_then(serde_json::Value::as_str)
        != Some("not_applicable_hook_input_matrix")
    {
        return Err("report codex_version is not matrix-specific".to_owned());
    }
    let metrics = value
        .get("metrics")
        .ok_or_else(|| "report lacks metrics object".to_owned())?;
    for key in ["latency", "rss", "residual_processes", "residual_handles"] {
        if metrics.get(key).and_then(serde_json::Value::as_str) != Some("not_measured") {
            return Err(format!("report metric {key} must be not_measured"));
        }
    }
    let execution = value
        .get("execution")
        .ok_or_else(|| "report lacks execution object".to_owned())?;
    if execution.get("no_destructive_execution") != Some(&serde_json::Value::Bool(true))
        || execution.get("shell_commands_executed") != Some(&serde_json::Value::from(0))
        || execution.get("canary_checked") != Some(&serde_json::Value::Bool(true))
        || execution.get("cleanup_verified") != Some(&serde_json::Value::Bool(true))
    {
        return Err("report execution safety flags are invalid".to_owned());
    }
    let expected_invocations = rows
        .iter()
        .filter(|row| row.case.expected != Expected::OutOfScope)
        .count() as u64;
    if value
        .get("invocation_count")
        .and_then(serde_json::Value::as_u64)
        != Some(expected_invocations)
    {
        return Err("report invocation_count does not match executable rows".to_owned());
    }
    let cases = value
        .get("cases")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| "report lacks cases array".to_owned())?;
    if cases.len() != rows.len() {
        return Err("report case count does not match test vector".to_owned());
    }
    for (value, row) in cases.iter().zip(rows) {
        if value.get("id").and_then(serde_json::Value::as_str) != Some(row.case.id.as_str())
            || value.get("family").and_then(serde_json::Value::as_str)
                != Some(row.case.family.as_str())
            || value.get("actual").and_then(serde_json::Value::as_str) != Some(row.actual.as_str())
        {
            return Err(format!("report row does not match case {}", row.case.id));
        }
    }
    let counts = value
        .get("counts")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "report lacks counts object".to_owned())?;
    for (label, expected) in [
        (
            "allow",
            rows.iter().filter(|row| row.actual == "allow").count(),
        ),
        (
            "deny",
            rows.iter().filter(|row| row.actual == "deny").count(),
        ),
        (
            "skips",
            rows.iter()
                .filter(|row| row.actual == "out_of_scope")
                .count(),
        ),
        (
            "unexpected",
            rows.iter().filter(|row| row.status == "fail").count(),
        ),
    ] {
        if counts.get(label).and_then(serde_json::Value::as_u64) != Some(expected as u64) {
            return Err(format!("report count mismatch for {label}"));
        }
    }
    validate_manifest_and_rows(rows)
}

#[test]
fn fixture_guard_rejects_real_and_system_roots() {
    let real_home = std::env::var_os("HOME").map(PathBuf::from);
    let mut forbidden = vec![
        PathBuf::from("/"),
        PathBuf::from("/Users"),
        PathBuf::from("/etc"),
    ];
    if let Some(home) = real_home {
        forbidden.push(home.join("Documents"));
        forbidden.push(home.join("Desktop"));
        forbidden.push(home.join("Downloads"));
        forbidden.push(home);
    }
    for path in forbidden {
        assert!(
            guard_fixture_path(&path).is_err(),
            "safety guard accepted non-temporary path {}",
            path.display()
        );
    }
}

#[test]
#[cfg(unix)]
fn temp_namespace_guard_rejects_unsafe_simulated_roots_without_env_mutation() {
    let home = Path::new("/Users/alice");
    let users = Path::new("/Users");
    for candidate in [
        Path::new("/"),
        Path::new("/Users"),
        Path::new("/etc"),
        Path::new("/var"),
        Path::new("/private/var"),
    ] {
        assert!(
            validate_temp_namespace(candidate, Some(home), Some(users)).is_err(),
            "unsafe temp namespace was accepted: {}",
            candidate.display()
        );
    }
    let trusted = trusted_temp_namespace().expect("host should expose a recognized temp root");
    assert!(trusted == Path::new("/tmp") || trusted == Path::new("/private/tmp"));
}

#[test]
fn temp_path_api_selection_prefers_optional_v2_and_has_legacy_fallback() {
    assert_eq!(select_temp_path_api(true), TempPathApi::OptionalTempPath2);
    assert_eq!(select_temp_path_api(false), TempPathApi::LegacyTempPath);
}

#[test]
fn path_text_renders_verbatim_windows_paths_for_shell_input() {
    assert_eq!(
        logical_path_text(Path::new(r"\\?\C:\Users\Alice\Documents\project")),
        r"C:\Users\Alice\Documents\project"
    );
    assert_eq!(
        logical_path_text(Path::new(r"\\?\UNC\server\share\project")),
        r"\\server\share\project"
    );
    assert_eq!(
        path_text(Path::new(r"\\?\C:\Users\Alice\Documents\project")),
        "C:/Users/Alice/Documents/project"
    );
    assert_eq!(
        path_text(Path::new(r"\\?\UNC\server\share\project")),
        "//server/share/project"
    );
    assert_eq!(
        path_text(Path::new(r"C:\Users\Alice\project")),
        "C:/Users/Alice/project"
    );
    assert_eq!(path_text(Path::new("/tmp/project")), "/tmp/project");
    assert_eq!(logical_path_text(Path::new("/tmp/project")), "/tmp/project");
}

#[test]
fn fixture_keeps_logical_policy_and_cwd_separate_from_canonical_paths() {
    let mut fixture = Fixture::new();
    let policy: serde_json::Value = serde_json::from_slice(
        &fs::read(&fixture.policy).expect("fixture policy should be readable"),
    )
    .expect("fixture policy should be valid JSON");
    let expected_home = logical_path_text(&fixture.home);
    assert_eq!(
        policy
            .pointer("/variables/HOME")
            .and_then(serde_json::Value::as_str),
        Some(expected_home.as_str())
    );

    let root_entry = policy
        .get("protected_paths")
        .and_then(serde_json::Value::as_array)
        .and_then(|paths| {
            paths.iter().find(|entry| {
                entry.get("kind").and_then(serde_json::Value::as_str) == Some("filesystem-root")
            })
        })
        .expect("fixture policy should contain its synthetic filesystem root");
    let logical_root = logical_path_text(&fixture.root);
    let canonical_root = fs::canonicalize(&fixture.root)
        .expect("fixture root should canonicalize")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        root_entry
            .get("logical")
            .and_then(serde_json::Value::as_str),
        Some(logical_root.as_str())
    );
    assert_eq!(
        root_entry
            .get("canonical")
            .and_then(serde_json::Value::as_str),
        Some(canonical_root.as_str())
    );

    let hook: serde_json::Value = serde_json::from_str(&fixture.hook_json(
        &fixture.cwd,
        "printf fixture",
        "danger-full-access",
    ))
    .expect("fixture hook input should be valid JSON");
    let expected_cwd = logical_path_text(&fixture.cwd);
    assert_eq!(
        hook.get("cwd").and_then(serde_json::Value::as_str),
        Some(expected_cwd.as_str())
    );
    #[cfg(windows)]
    {
        assert!(!logical_root.starts_with(r"\\?\"));
        assert!(canonical_root.starts_with(r"\\?\"));
        assert!(!expected_cwd.starts_with(r"\\?\"));
    }

    fixture
        .cleanup()
        .expect("logical/canonical fixture should clean up safely");
}

#[cfg(windows)]
#[test]
fn windows_reparse_walk_starts_only_after_drive_prefix_is_rooted() {
    for (path, expected_root) in [
        (Path::new(r"C:\actions\runner\_temp"), Path::new(r"C:\")),
        (
            Path::new(r"\\?\D:\actions\runner\_temp"),
            Path::new(r"\\?\D:\"),
        ),
    ] {
        let components = windows_reparse_inspection_paths(path)
            .expect("absolute Windows path should produce inspectable components");
        assert_eq!(
            components.first().map(PathBuf::as_path),
            Some(expected_root)
        );
        assert_eq!(components.last().map(PathBuf::as_path), Some(path));
        assert!(components.iter().all(|component| component.is_absolute()));
    }
    assert!(windows_reparse_inspection_paths(Path::new(r"C:relative\temp")).is_err());
}

#[cfg(windows)]
#[test]
fn windows_path_comparison_accepts_only_equivalent_bounded_representations() {
    let drive = Path::new(r"D:\a\DELETE-DENIED\target\attack-matrix");
    let verbatim = Path::new(r"\\?\d:\a\delete-denied\target\attack-matrix");
    assert!(paths_equivalent(drive, verbatim));
    assert!(path_is_same_or_descendant(
        &drive.join("report.json"),
        verbatim
    ));
    assert!(!path_is_same_or_descendant(
        Path::new(r"D:\a\DELETE-DENIED\target\attack-matrix-sibling\report.json"),
        drive
    ));

    let unc = Path::new(r"\\server\share\reports");
    let verbatim_unc = Path::new(r"\\?\UNC\SERVER\SHARE\reports");
    assert!(paths_equivalent(unc, verbatim_unc));
    assert!(!paths_equivalent(
        Path::new(r"D:\a\DELETE~1\target\attack-matrix"),
        drive
    ));
}

#[cfg(windows)]
#[test]
fn windows_temp_namespace_guard_rejects_poisoned_environment_and_reparse() {
    let local_app_data = Path::new(r"C:\Users\Alice\AppData\Local");
    let windows_dir = Path::new(r"C:\Windows");
    // Simulate poisoned TEMP/TMP values without mutating the process environment.
    for poisoned in [
        Path::new(r"C:\"),
        Path::new(r"C:\Users"),
        Path::new(r"C:\Users\Alice"),
        Path::new(r"C:\Windows"),
        Path::new(r"C:\Windows\System32"),
    ] {
        assert!(
            validate_windows_temp_candidate(poisoned, local_app_data, windows_dir).is_err(),
            "poisoned Windows temp path was accepted: {}",
            poisoned.display()
        );
    }
    assert!(
        validate_windows_temp_candidate(&local_app_data.join("Temp"), local_app_data, windows_dir)
            .is_ok()
    );
    assert!(
        validate_windows_temp_candidate(&windows_dir.join("Temp"), local_app_data, windows_dir)
            .is_ok()
    );

    let temp = trusted_temp_namespace().expect("Windows OS temp root");
    let root = temp.join(format!("{FIXTURE_PREFIX}windows-{}", std::process::id()));
    fs::create_dir(&root).expect("Windows temp test root should be new");
    reject_windows_reparse_components(&root)
        .expect("ordinary rooted NTFS components should pass reparse inspection");
    reject_windows_reparse_components(&root.join("not-created-yet"))
        .expect("a missing suffix is safe after all existing ancestors are inspected");
    let target = root.join("target");
    let junction = root.join("junction");
    fs::create_dir(&target).expect("Windows reparse target should be new");
    if std::os::windows::fs::symlink_dir(&target, &junction).is_ok() {
        assert!(reject_windows_reparse_components(&junction).is_err());
        fs::remove_dir(&junction).expect("Windows reparse test link should be removable");
    }
    fs::remove_dir_all(&root).expect("Windows temp test root should be cleaned");
    assert!(!root.exists());
}

#[test]
fn report_path_guard_rejects_arbitrary_and_symlink_paths() {
    let repo_target = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/attack-matrix");
    assert!(validate_report_path(&repo_target.join("report.json")).is_ok());
    let temp_report = trusted_temp_namespace()
        .expect("trusted temp root")
        .join(format!("{FIXTURE_PREFIX}report.json"));
    assert!(
        validate_report_path(&temp_report).is_ok(),
        "temp report validation: {:?}",
        validate_report_path(&temp_report)
    );
    for forbidden in [
        Path::new("/etc/report.json"),
        Path::new("/Users/report.json"),
    ] {
        assert!(validate_report_path(forbidden).is_err());
    }
    #[cfg(unix)]
    {
        let temp = trusted_temp_namespace().expect("trusted temp root");
        let root = temp.join(format!("{FIXTURE_PREFIX}report-{}", std::process::id()));
        guard_fixture_path(&root).expect("report test root must be safe");
        fs::create_dir(&root).expect("report test root should be new");
        let marker = root.join(".delete-denied-fixture-marker");
        fs::write(&marker, FIXTURE_MARKER).expect("report marker should be writable");
        let target = root.join("target");
        let link = root.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("report symlink should be creatable");
        assert!(validate_report_path(&link.join("report.json")).is_err());
        assert!(fs::read_to_string(&marker).is_ok_and(|contents| contents == FIXTURE_MARKER));
        fs::remove_dir_all(&root).expect("report test root should be cleaned");
        assert!(
            !root.exists(),
            "report test root should be absent after cleanup"
        );
    }
}

#[test]
fn classifier_rejects_substrings_malformed_json_and_nonempty_stderr() {
    assert_eq!(
        classify_parts(
            true,
            br#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"not DD-PROTECTED-PATH"}}"#,
            b""
        ),
        ("unexpected".to_owned(), None)
    );
    assert_eq!(
        classify_parts(true, b"DD-PROTECTED-PATH", b""),
        ("unexpected".to_owned(), None)
    );
    assert_eq!(
        classify_parts(
            true,
            br#"{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"[DD-PROTECTED-PATH] protected"}}"#,
            b"stderr"
        ),
        ("unexpected".to_owned(), None)
    );
}

#[test]
fn hook_binary_resolver_rejects_relative_symlink_and_wrong_basename() {
    let temp = trusted_temp_namespace().expect("trusted temp root");
    let root = temp.join(format!(
        "{FIXTURE_PREFIX}hook-resolver-{}",
        FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    guard_fixture_path(&root).expect("hook resolver test root should be safe");
    fs::create_dir(&root).expect("hook resolver test root should be new");
    let marker = root.join(".delete-denied-fixture-marker");
    fs::write(&marker, FIXTURE_MARKER).expect("hook resolver marker should be writable");

    assert!(validate_hook_binary(Path::new("delete-denied-hook")).is_err());
    let wrong_name = root.join("not-the-hook");
    fs::write(&wrong_name, b"not a hook").expect("wrong-name fixture should be writable");
    assert!(validate_hook_binary(&wrong_name).is_err());

    #[cfg(unix)]
    {
        let symlink = root.join("delete-denied-hook");
        let target = PathBuf::from(env!("CARGO_BIN_EXE_delete-denied-hook"));
        std::os::unix::fs::symlink(target, &symlink)
            .expect("hook resolver symlink should be creatable");
        assert!(validate_hook_binary(&symlink).is_err());
    }

    assert!(fs::read_to_string(&marker).is_ok_and(|contents| contents == FIXTURE_MARKER));
    fs::remove_dir_all(&root).expect("hook resolver test root should be cleaned");
    assert!(!root.exists());
}

#[test]
fn attack_matrix_is_non_destructive_and_fails_on_unexpected_decisions() {
    let mut fixture = Fixture::new();
    let binary = resolve_hook_binary().expect("hook binary path must be approved");
    let rows = run_matrix(&binary, &fixture);
    fixture
        .verify_canaries()
        .expect("fixture marker and canaries must survive hook-input evaluation");
    let path = report_path().expect("report path must be approved");
    fixture
        .cleanup()
        .expect("test-owned fixture cleanup must succeed");
    assert!(
        !fixture.root.exists(),
        "fixture root must be absent after cleanup"
    );
    let report = report_json(&binary, &fixture, &rows, true, true);
    assert!(
        report.len() <= MAX_REPORT_BYTES,
        "attack report exceeded bound"
    );
    let failures = rows
        .iter()
        .filter(|row| row.status == "fail")
        .map(|row| {
            format!(
                "id={} expected={}{} actual={}{} command={:?} cwd={} process_success={:?} stdout={:?} stderr={:?} note={:?}",
                row.case.id,
                row.case.expected.label(),
                row.case
                    .expected
                    .code()
                    .map_or_else(String::new, |code| format!(" ({code})")),
                row.actual,
                row.actual_code
                    .as_deref()
                    .map_or_else(String::new, |code| format!(" ({code})")),
                row.case.command.as_deref(),
                row.case
                    .cwd
                    .as_deref()
                    .map_or_else(|| "<none>".to_owned(), |cwd| cwd.display().to_string()),
                row.process_success,
                row.stdout.as_str(),
                row.stderr.as_str(),
                row.case.note.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert!(failures.is_empty(), "attack matrix failures: {failures:#?}");

    validate_report_json(&report, &rows).expect("generated report must validate");
    write_report_atomic(&path, &report).expect("report should be written atomically");
}
