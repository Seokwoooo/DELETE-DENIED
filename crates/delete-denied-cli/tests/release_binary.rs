use std::path::Path;
use std::process::Command;

#[test]
fn release_binary_uses_product_name() {
    let binary = Path::new(env!("CARGO_BIN_EXE_delete-denied"));
    let basename = binary.file_name().and_then(|name| name.to_str()).unwrap();

    assert!(
        basename == "delete-denied" || basename == "delete-denied.exe",
        "unexpected binary basename: {basename}"
    );
}

#[test]
fn release_binary_has_no_install_plan_command_or_option() {
    let binary = env!("CARGO_BIN_EXE_delete-denied");
    let help = Command::new(binary).arg("--help").output().unwrap();
    assert!(help.status.success());
    assert!(!String::from_utf8_lossy(&help.stdout).contains("plan"));

    for args in [["plan"].as_slice(), ["install", "--plan"].as_slice()] {
        let output = Command::new(binary).args(args).output().unwrap();
        assert!(!output.status.success(), "unexpected success for {args:?}");
    }
}
