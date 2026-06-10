pub mod capabilities;
pub mod filesystem;
pub mod namespaces;
pub mod seccomp;
use std::os::fd::{BorrowedFd, RawFd};

use crate::error::HajizError;
#[derive(Debug, Clone)]
pub struct FilesystemRule {
    pub path: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkMode {
    /// Own network namespace, no interfaces up. Cannot reach anything.
    None,
    /// Own network namespace with loopback (`lo`) brought up. Allows
    /// 127.0.0.1 / ::1 traffic to local services in the same sandbox,
    /// but no host or external network.
    Loopback,
    /// Share the host network namespace. Unrestricted access.
    Full,
}

impl NetworkMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Self::None),
            "loopback" | "lo" => Some(Self::Loopback),
            "full" => Some(Self::Full),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Loopback => "loopback",
            Self::Full => "full",
        }
    }

    /// True when the child should run in its own network namespace.
    pub fn unshare_netns(self) -> bool {
        matches!(self, Self::None | Self::Loopback)
    }
}

#[derive(Debug, Clone)]
pub struct IsolationConfig {
    pub network_mode: NetworkMode,
    pub drop_all_capabilities: bool,
    pub strict_seccomp: bool,
    pub use_seccomp_whitelist: bool,
    pub enable_hardening_filter: bool,
    pub seccomp_syscall_groups: Vec<String>,
    pub seccomp_allow_syscalls: Vec<String>,
    pub filesystem_rules: Vec<FilesystemRule>,
    /// TCP destination ports allowed for `connect()`. Empty = no port restriction
    /// (subject to network_mode). Non-empty = enforce Landlock TCP-connect allowlist.
    pub allow_connect_ports: Vec<u16>,
    /// TCP listen ports allowed for `bind()`. Empty = no restriction.
    pub allow_bind_ports: Vec<u16>,
    /// When true, denied syscalls cause the child process to be killed
    /// (SECCOMP_RET_KILL_PROCESS) instead of returning EPERM. The kernel
    /// still emits a SECCOMP audit record so the parent can log it.
    pub kill_on_deny: bool,
    /// Use SECCOMP_RET_USER_NOTIF for hardening-filter denials so the parent
    /// can log SyscallDenied directly, without depending on /dev/kmsg.
    /// Requires kernel >= 5.0; has no effect with kill_on_deny (the kill
    /// action stays in-kernel). Set by the parent before spawn.
    pub seccomp_notify: bool,
    /// Also notify on filesystem syscalls so the parent can emit
    /// FilesystemDenied telemetry (the parent answers CONTINUE and Landlock
    /// remains the enforcement point). Requires kernel >= 5.5.
    pub seccomp_fs_notify: bool,
    /// Also notify on connect/bind so the parent can emit NetworkDenied
    /// telemetry against the Landlock TCP-port allowlist. Same contract as
    /// the filesystem path: parent answers CONTINUE, Landlock decides.
    /// Requires kernel >= 5.5.
    pub seccomp_net_notify: bool,
    /// Child end of the socketpair over which the seccomp notify fd is sent
    /// back to the parent via SCM_RIGHTS. Set by the runtime, not by users.
    pub notify_socket_fd: Option<RawFd>,
}

impl IsolationConfig {
    pub fn restrict_tcp_connect(&self) -> bool {
        !self.allow_connect_ports.is_empty()
    }

    pub fn restrict_tcp_bind(&self) -> bool {
        !self.allow_bind_ports.is_empty()
    }
}

impl Default for IsolationConfig {
    fn default() -> Self {
        Self {
            network_mode: NetworkMode::None,
            drop_all_capabilities: true,
            strict_seccomp: false,
            use_seccomp_whitelist: false,
            enable_hardening_filter: true,
            seccomp_syscall_groups: Vec::new(),
            seccomp_allow_syscalls: Vec::new(),
            filesystem_rules: Vec::new(),
            allow_connect_ports: Vec::new(),
            allow_bind_ports: Vec::new(),
            kill_on_deny: false,
            seccomp_notify: false,
            seccomp_fs_notify: false,
            seccomp_net_notify: false,
            notify_socket_fd: None,
        }
    }
}
pub fn apply_in_child(config: &IsolationConfig) -> Result<(), HajizError> {
    let kernel_caps = crate::kernel::KernelCapabilities::detect();

    let skip_ns = kernel_caps.as_ref().map(|k| !k.user_namespaces).unwrap_or(false);
    if skip_ns {
        eprintln!("[hajiz] warning: user namespaces unavailable (kernel < 3.8)");
    } else {
        namespaces::setup_namespaces(config)?;
    }

    capabilities::drop_capabilities(config)?;

    let skip_landlock = kernel_caps.as_ref().map(|k| !k.landlock).unwrap_or(false);
    filesystem::setup_landlock(config, skip_landlock)?;

    let notify_fd = seccomp::apply_seccomp(config)?;

    // Hand the seccomp notify fd back to the parent. The parent always waits
    // for one message when it set up the socket, so send a plain marker when
    // no listener fd was created (e.g. the filter mode changed underneath).
    // Failures here only degrade telemetry — never abort the sandbox.
    if let Some(sock_raw) = config.notify_socket_fd {
        // SAFETY: the parent keeps this fd open across fork; we only borrow it
        // here in the pre-exec child, before exec closes it (CLOEXEC).
        let sock = unsafe { BorrowedFd::borrow_raw(sock_raw) };
        let _ = match notify_fd {
            Some(fd) => crate::privesc::send_fds(sock, &[fd]),
            None => crate::privesc::send_marker(sock),
        };
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_config_is_core_isolation_only() {
        let config = IsolationConfig::default();
        assert_eq!(config.network_mode, NetworkMode::None);
        assert!(config.drop_all_capabilities);
        assert!(!config.use_seccomp_whitelist);
        assert!(config.enable_hardening_filter);
        assert!(config.seccomp_allow_syscalls.is_empty());
    }

    #[test]
    fn network_mode_parses_known_strings() {
        assert_eq!(NetworkMode::parse("none"), Some(NetworkMode::None));
        assert_eq!(NetworkMode::parse("loopback"), Some(NetworkMode::Loopback));
        assert_eq!(NetworkMode::parse("lo"), Some(NetworkMode::Loopback));
        assert_eq!(NetworkMode::parse("full"), Some(NetworkMode::Full));
        assert_eq!(NetworkMode::parse("bogus"), None);
    }

    #[test]
    fn network_mode_unshare_netns_for_none_and_loopback() {
        assert!(NetworkMode::None.unshare_netns());
        assert!(NetworkMode::Loopback.unshare_netns());
        assert!(!NetworkMode::Full.unshare_netns());
    }
}