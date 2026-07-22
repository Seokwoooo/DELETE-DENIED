use crate::command::posix;

/// Result of the allocation-light command token scan used by the hook hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanResult {
    Safe,
    Suspicious,
}

/// Quickly identify command strings that need detailed deletion parsing.
pub fn fast_scan(command: &str) -> ScanResult {
    if posix::contains_suspicious_construct(command) {
        ScanResult::Suspicious
    } else {
        ScanResult::Safe
    }
}
