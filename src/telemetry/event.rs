use std::time::SystemTime;

/// Types d'événements de sécurité émis par le sandbox
#[derive(Debug, Clone)]
pub enum SecurityEvent {
    /// Sandbox démarré
    SandboxStarted {
        pid: u32,
        binary: String,
        profile: Option<String>,
        timestamp: SystemTime,
    },
    /// Syscall refusé par seccomp
    SyscallDenied {
        pid: u32,
        syscall: String,
        timestamp: SystemTime,
    },
    /// Accès filesystem refusé
    FilesystemDenied {
        pid: u32,
        path: String,
        timestamp: SystemTime,
    },
    /// Sandbox terminé
    SandboxExited {
        pid: u32,
        exit_code: i32,
        /// Numéro du signal qui a tué le processus (None = sortie normale).
        /// SIGSYS (31) indique typiquement un kill seccomp via KILL_PROCESS.
        signal: Option<i32>,
        timestamp: SystemTime,
    },
    /// Politique d'isolation appliquée avant le spawn
    PolicyApplied {
        pid: u32,
        blocked_syscalls: Vec<String>,
        allowed_paths: Vec<String>,
        features: String,
        timestamp: SystemTime,
    },
    /// Échantillon périodique de l'utilisation des ressources cgroup
    ResourceUsage {
        pid: u32,
        memory_current: u64,
        pids_current: u64,
        cpu_usage_usec: u64,
        timestamp: SystemTime,
    },
}

impl SecurityEvent {
    /// Retourne le timestamp de l'événement
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

    /// Retourne le nom de l'événement
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

    /// Formate l'événement en JSON simple
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