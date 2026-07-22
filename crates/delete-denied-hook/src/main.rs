use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;

use delete_denied_core::decision::Decision;
use delete_denied_core::hook_input::{HookInput, HookInputError, HookOutput};
use delete_denied_core::path::FsPathResolver;
use delete_denied_core::policy::Policy;
use delete_denied_core::scan::{ScanResult, fast_scan};

const OUTPUT_FALLBACK: &str = "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"deny\",\"permissionDecisionReason\":\"[DD-OUTPUT-INVALID] hook output unavailable\"}}";

fn main() {
    let policy_path = match parse_policy_path(std::env::args_os().skip(1)) {
        Ok(path) => path,
        Err(reason) => {
            write_denial("DD-POLICY-INVALID", &reason);
            return;
        }
    };

    let input = match HookInput::from_reader(io::stdin().lock()) {
        Ok(input) => input,
        Err(error) => {
            let code = input_error_code(&error);
            write_denial(code, &error.to_string());
            return;
        }
    };

    // Keep the normal shell path independent of the installed policy.
    if fast_scan(&input.command) == ScanResult::Safe {
        return;
    }

    let policy = match File::open(&policy_path).and_then(|file| {
        Policy::from_reader(file).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }) {
        Ok(policy) => policy,
        Err(error) => {
            write_denial("DD-POLICY-INVALID", &error.to_string());
            return;
        }
    };

    match delete_denied_core::evaluate(&input, &policy, &FsPathResolver) {
        Decision::Allow => {}
        Decision::Deny { code, reason } => write_denial(code.as_str(), &reason),
    }
}

fn parse_policy_path<I>(mut args: I) -> Result<PathBuf, String>
where
    I: Iterator<Item = std::ffi::OsString>,
{
    let Some(flag) = args.next() else {
        return Err("expected exactly --policy <absolute-path>".to_owned());
    };
    if flag != "--policy" {
        return Err("expected exactly --policy <absolute-path>".to_owned());
    }
    let Some(path) = args.next() else {
        return Err("--policy requires an absolute path".to_owned());
    };
    if args.next().is_some() {
        return Err("--policy may be provided only once".to_owned());
    }
    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err("policy path must be absolute".to_owned());
    }
    Ok(path)
}

fn input_error_code(error: &HookInputError) -> &'static str {
    match error {
        HookInputError::InputTooLarge { .. } | HookInputError::CommandTooLarge { .. } => {
            "DD-INPUT-TOO-LARGE"
        }
        HookInputError::UnsupportedEvent { .. } | HookInputError::UnsupportedTool { .. } => {
            "DD-HOOK-UNSUPPORTED"
        }
        HookInputError::Io(_) | HookInputError::Json(_) => "DD-INPUT-INVALID",
    }
}

fn write_denial(code: &str, reason: &str) {
    // Keep the stable code even when an attacker supplies a very long event
    // or tool name. Denial output remains bounded without affecting the safe
    // path (this helper is only reached for errors or suspicious commands).
    let bounded_reason = reason.chars().take(512).collect::<String>();
    let output =
        HookOutput::deny(code, &bounded_reason).unwrap_or_else(|_| OUTPUT_FALLBACK.to_owned());
    let _ = io::stdout().write_all(output.as_bytes());
}
