use std::fs;
use std::path::PathBuf;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn bootstrap_installers_keep_the_fast_registration_contract() {
    let root = repository_root();
    let shell = fs::read_to_string(root.join("bootstrap/install.sh")).unwrap();
    let powershell = fs::read_to_string(root.join("bootstrap/install.ps1")).unwrap();
    let korean_readme = fs::read_to_string(root.join("README.md")).unwrap();
    let install_doc = fs::read_to_string(root.join("docs/install.md")).unwrap();

    assert!(shell.contains("/usr/bin/shasum -a 256"));
    assert!(shell.contains("\"$cli\" update --trust >/dev/null"));
    assert!(shell.contains("\"$cli\" install --trust >/dev/null"));
    assert!(shell.contains("\"$cli\" doctor"));
    assert!(powershell.contains("Get-FileHash -Algorithm SHA256"));
    assert!(powershell.contains("& $Cli $LifecycleCommand --trust | Out-Null"));
    assert!(powershell.contains("& $Cli doctor"));
    assert!(install_doc.contains("Protected Paths: Awaiting Codex trust"));
    assert!(install_doc.contains("config/batchWrite"));
    assert!(install_doc.contains("config.toml.before-trust"));
    assert!(install_doc.contains("--trust"));
    assert!(install_doc.contains("registration"));

    assert!(korean_readme.contains(
        "curl -fsSL https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.sh | sh"
    ));
    assert!(korean_readme.contains(
        "irm https://raw.githubusercontent.com/Seokwoooo/DELETE-DENIED/main/bootstrap/install.ps1 | iex"
    ));
}

#[test]
fn korean_readme_keeps_the_minimal_copy_paste_contract() {
    let root = repository_root();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    let start = readme
        .find("## 빠른 설치 (권장)\n")
        .expect("quick install heading");
    let body_start = start + "## 빠른 설치 (권장)\n".len();
    let end = readme[body_start..]
        .find("\n---\n")
        .map(|offset| body_start + offset)
        .expect("quick install section terminator");
    let section = &readme[start..end];

    assert_eq!(
        section,
        "## 빠른 설치 (권장)\n\n아래 한 줄을 Codex 메인 세션에 그대로 보내세요.\n\n```text\nDELETE-DENIED를 설치해. README의 현재 OS용 한 줄 명령을 바로 실행해: https://github.com/Seokwoooo/DELETE-DENIED\n```\n"
    );
}
