use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use super::event::SecurityEvent;

/// Security telemetry logger
pub struct TelemetryLogger {
    /// Path to the log file (None = stderr)
    log_file: Option<PathBuf>,
    /// Enable verbose output
    verbose: bool,
}

impl TelemetryLogger {
    /// Creates a logger that writes to stderr
    pub fn new(verbose: bool) -> Self {
        Self {
            log_file: None,
            verbose,
        }
    }

    /// Creates a logger that writes to a file
    pub fn with_file(path: PathBuf, verbose: bool) -> Self {
        Self {
            log_file: Some(path),
            verbose,
        }
    }

    /// Records a security event
    pub fn log(&self, event: &SecurityEvent) {
        let json = event.to_json();

        // Verbose output to stderr
        if self.verbose {
            eprintln!("[hajiz:telemetry] {}", json);
        }

        // Write to the file if one is configured
        if let Some(path) = &self.log_file {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(mut file) => {
                    if let Err(e) = writeln!(file, "{}", json) {
                        eprintln!("[hajiz:telemetry] error writing log: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("[hajiz:telemetry] unable to open log file: {e}");
                }
            }
        }
    }

    /// Computes a simple hash of the isolation policy
    pub fn policy_hash(config: &crate::isolation::IsolationConfig) -> String {
        let policy_str = format!(
            "net:{},caps:{},seccomp_strict:{},whitelist:{},hardening:{},kill_on_deny:{},groups:{:?},syscalls:{:?},fs:{:?},connect_ports:{:?},bind_ports:{:?}",
            config.network_mode.as_str(),
            config.drop_all_capabilities,
            config.strict_seccomp,
            config.use_seccomp_whitelist,
            config.enable_hardening_filter,
            config.kill_on_deny,
            config.seccomp_syscall_groups,
            config.seccomp_allow_syscalls,
            config.filesystem_rules.iter().map(|r| &r.path).collect::<Vec<_>>(),
            config.allow_connect_ports,
            config.allow_bind_ports,
        );

        // Simple djb2 hash
        let mut hash: u64 = 5381;
        for byte in policy_str.bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
        }
        format!("{:016x}", hash)
    }
}