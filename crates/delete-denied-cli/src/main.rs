use delete_denied_cli::commands::{HostDependencies, Lifecycle, LifecycleError};

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn usage() -> &'static str {
    "delete-denied <command> [--trust]\n\nCommands:\n  install       Install for the current user\n  status        Check local protection state\n  doctor        Verify files and hook registration\n  update        Update current-user files\n  uninstall     Remove DELETE-DENIED-owned files and hook entry\n  suspend       Temporarily remove the hook entry\n  resume        Restore the hook entry\n\nOptions:\n  --trust       Trust this hook through Codex app-server (install/update only)\n  -h, --help    Show this help\n  -V, --version Show the version"
}

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        println!("{}", usage());
        return;
    }
    if matches!(command.as_str(), "--version" | "-V" | "version") {
        println!("delete-denied {VERSION}");
        return;
    }
    let extras = args.collect::<Vec<_>>();
    let trust = match command.as_str() {
        "install" | "update" if extras.is_empty() => false,
        "install" | "update" if extras == ["--trust"] => true,
        "status" | "uninstall" | "suspend" | "resume" | "doctor" if extras.is_empty() => false,
        _ => {
            eprintln!("unknown arguments\n\n{}", usage());
            std::process::exit(2);
        }
    };
    let paths = match delete_denied_cli::platform::PlatformPaths::discover_for_current_login() {
        Ok(paths) => paths,
        Err(error) => exit_error(LifecycleError::Discovery(error)),
    };
    let host = HostDependencies::default();
    let lifecycle = Lifecycle::new(paths, host.as_refs());
    let result = match command.as_str() {
        "install" => lifecycle
            .install_with_trust(trust)
            .map(|result| result.message),
        "status" => lifecycle.status().and_then(|status| match status {
            delete_denied_cli::StatusReport::Enforced
            | delete_denied_cli::StatusReport::AwaitingTrust
            | delete_denied_cli::StatusReport::Inactive
            | delete_denied_cli::StatusReport::Suspended => Ok(status.to_string()),
            other => Err(LifecycleError::Unhealthy(other.to_string())),
        }),
        "doctor" => lifecycle.doctor(),
        "update" => lifecycle
            .update_with_trust(trust)
            .map(|result| result.message),
        "suspend" => lifecycle.suspend().map(|result| result.message),
        "resume" => lifecycle.resume().map(|result| result.message),
        "uninstall" => lifecycle.uninstall().map(|result| result.message),
        _ => {
            eprintln!("unknown command: {command}\n\n{}", usage());
            std::process::exit(2);
        }
    };
    match result {
        Ok(output) => println!("{output}"),
        Err(error) => exit_error(error),
    }
}

fn exit_error(error: LifecycleError) -> ! {
    eprintln!("delete-denied: {error}");
    std::process::exit(1)
}
