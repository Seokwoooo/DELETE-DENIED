pub mod cmd;
pub mod inline_runtime;
pub mod posix;
pub mod powershell;

pub(crate) const MAX_INTERPRETER_DEPTH: usize = 16;

/// Shell dialect accepted by the command parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Posix,
    PowerShell,
    Cmd,
}

/// The deletion primitive represented by a parsed operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteKind {
    Rm,
    Rmdir,
    Unlink,
    FindDelete,
    XargsRm,
    RsyncDelete,
    GitClean,
}

/// Where a deletion operation was found in the shell command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandSource {
    Direct,
    Wrapper,
    NestedShell,
    Find,
    Xargs,
    Rsync,
    Git,
}

/// Original shell syntax used when normalizing path targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetSyntax {
    Posix,
    Windows,
    Auto,
}

/// A deletion operation extracted without executing the command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteOperation {
    pub kind: DeleteKind,
    pub raw_targets: Vec<String>,
    pub recursive: bool,
    pub ambiguous: bool,
    pub source: CommandSource,
    pub target_syntax: TargetSyntax,
}

/// Parse deletion operations for a supported shell dialect.
pub fn parse_delete_operations(command: &str, dialect: Dialect) -> Vec<DeleteOperation> {
    match dialect {
        Dialect::Posix => posix::parse_delete_operations(command),
        Dialect::PowerShell => powershell::parse_delete_operations(command),
        Dialect::Cmd => cmd::parse_delete_operations(command),
    }
}
