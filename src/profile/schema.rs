use serde::Deserialize;

/// Complete configuration of a sandboxing profile
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    /// Profile name (e.g. "firefox", "untrusted")
    pub name: String,

    /// Profile description
    pub description: Option<String>,

    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Filesystem configuration
    #[serde(default)]
    pub filesystem: FilesystemConfig,

    /// Seccomp configuration
    #[serde(default)]
    pub seccomp: SeccompConfig,
}

/// Network configuration of the profile
///
/// `mode` accepts three values:
/// - `"none"` (default): own network namespace, no interface — no network access
/// - `"loopback"`: own network namespace with `lo` up — local 127.0.0.1 services only
/// - `"full"`: shares the host network namespace — full network access
///
/// `allow_connect` / `allow_bind` (optional): TCP port allowlists enforced by
/// Landlock (kernel >= 6.7). If non-empty, only the listed ports are allowed for
/// `connect()` (outbound) and `bind()` (listen) respectively. Independent of
/// `mode` — also works in `full` mode.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NetworkConfig {
    #[serde(default = "default_network_mode")]
    pub mode: String,
    #[serde(default)]
    pub allow_connect: Vec<u16>,
    #[serde(default)]
    pub allow_bind: Vec<u16>,
}

fn default_network_mode() -> String {
    "none".to_string()
}

/// Filesystem configuration of the profile
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FilesystemConfig {
    /// Paths allowed read-only
    #[serde(default)]
    pub read_only: Vec<String>,

    /// Paths allowed read/write
    #[serde(default)]
    pub read_write: Vec<String>,
}

/// Seccomp configuration of the profile
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SeccompConfig {
    /// Enable strict mode
    #[serde(default)]
    pub strict: bool,

    /// Enable allowlist mode
    #[serde(default)]
    pub whitelist: bool,

    /// Enable the hardening filter
    #[serde(default = "default_true")]
    pub hardening: bool,

    /// Allowed syscall groups
    #[serde(default)]
    pub allow_groups: Vec<String>,

    /// Individually allowed syscalls
    #[serde(default)]
    pub allow_syscalls: Vec<String>,
}

fn default_true() -> bool {
    true
}