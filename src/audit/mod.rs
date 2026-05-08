pub mod generator;
pub mod strace;

pub use generator::generate_profile;
pub use strace::{parse_strace_log, run_audit, AuditReport};
