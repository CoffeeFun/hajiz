use std::time::SystemTime;

/// Types of security events emitted by the sandbox
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    /// Sandbox started
    SandboxStarted {
        pid: u32,
        binary: String,
        profile: Option<String>,
        timestamp: SystemTime,
    },
    /// Syscall denied by seccomp
    SyscallDenied {
        pid: u32,
        syscall: String,
        timestamp: SystemTime,
    },
    /// Filesystem access denied
    FilesystemDenied {
        pid: u32,
        path: String,
        timestamp: SystemTime,
    },
    /// Sandbox finished
    SandboxExited {
        pid: u32,
        exit_code: i32,
        /// Number of the signal that killed the process (None = normal exit).
        /// SIGSYS (31) typically indicates a seccomp kill via KILL_PROCESS.
        signal: Option<i32>,
        timestamp: SystemTime,
    },
    /// Isolation policy applied before spawn
    PolicyApplied {
        pid: u32,
        blocked_syscalls: Vec<String>,
        allowed_paths: Vec<String>,
        features: String,
        timestamp: SystemTime,
    },
    /// Periodic sample of cgroup resource usage
    ResourceUsage {
        pid: u32,
        memory_current: u64,
        pids_current: u64,
        cpu_usage_usec: u64,
        timestamp: SystemTime,
    },
}

impl SecurityEvent {
    /// Returns the event timestamp
    pub fn timestamp(&self) -> SystemTime {
        match self {
            Self::SandboxStarted { timestamp, .. } => *timestamp,
            Self::SyscallDenied { timestamp, .. } => *timestamp,
            Self::FilesystemDenied { timestamp, .. } => *timestamp,
            Self::SandboxExited { timestamp, .. } => *timestamp,
            Self::PolicyApplied { timestamp, .. } => *timestamp,
            Self::ResourceUsage { timestamp, .. } => *timestamp,
        }
    }

    /// Returns the event name
    pub fn name(&self) -> &str {
        match self {
            Self::SandboxStarted { .. } => "sandbox_started",
            Self::SyscallDenied { .. } => "syscall_denied",
            Self::FilesystemDenied { .. } => "filesystem_denied",
            Self::SandboxExited { .. } => "sandbox_exited",
            Self::PolicyApplied { .. } => "policy_applied",
            Self::ResourceUsage { .. } => "resource_usage",
        }
    }

    /// Formats the event as simple JSON
    pub fn to_json(&self) -> String {
        let ts = self
            .timestamp()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        match self {
            Self::SandboxStarted { pid, binary, profile, .. } => {
                let profile_str = profile
                    .as_deref()
                    .map(|p| format!("\"{}\"", p))
                    .unwrap_or_else(|| "null".to_string());
                format!(
                    r#"{{"event":"sandbox_started","pid":{pid},"binary":"{binary}","profile":{profile_str},"timestamp":{ts}}}"#
                )
            }
            Self::SyscallDenied { pid, syscall, .. } => {
                format!(
                    r#"{{"event":"syscall_denied","pid":{pid},"syscall":"{syscall}","timestamp":{ts}}}"#
                )
            }
            Self::FilesystemDenied { pid, path, .. } => {
                format!(
                    r#"{{"event":"filesystem_denied","pid":{pid},"path":"{path}","timestamp":{ts}}}"#
                )
            }
            Self::SandboxExited { pid, exit_code, signal, .. } => {
                let sig = signal.map(|s| s.to_string()).unwrap_or_else(|| "null".to_string());
                format!(
                    r#"{{"event":"sandbox_exited","pid":{pid},"exit_code":{exit_code},"signal":{sig},"timestamp":{ts}}}"#
                )
            }
            Self::PolicyApplied { pid, blocked_syscalls, allowed_paths, features, .. } => {
                let blocked = blocked_syscalls
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(",");
                let paths = allowed_paths
                    .iter()
                    .map(|s| format!("\"{}\"", s))
                    .collect::<Vec<_>>()
                    .join(",");
                format!(
                    r#"{{"event":"policy_applied","pid":{pid},"blocked_syscalls":[{blocked}],"allowed_paths":[{paths}],"features":"{features}","timestamp":{ts}}}"#
                )
            }
            Self::ResourceUsage { pid, memory_current, pids_current, cpu_usage_usec, .. } => {
                format!(
                    r#"{{"event":"resource_usage","pid":{pid},"memory_current":{memory_current},"pids_current":{pids_current},"cpu_usage_usec":{cpu_usage_usec},"timestamp":{ts}}}"#
                )
            }
        }
    }
}