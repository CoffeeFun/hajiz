use std::fs;

/// Linux kernel version
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    /// Reads the kernel version from /proc/version
    pub fn detect() -> Option<Self> {
        let content = fs::read_to_string("/proc/version").ok()?;
        let version_str = content.split_whitespace().nth(2)?;
        Self::parse(version_str)
    }

    /// Parses a version string like "5.15.0-91-generic"
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.split('-').next()?;
        let mut parts = s.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        Some(Self { major, minor, patch })
    }

    /// Checks whether this version is >= the given version
    pub fn is_at_least(&self, major: u32, minor: u32, patch: u32) -> bool {
        if self.major != major {
            return self.major > major;
        }
        if self.minor != minor {
            return self.minor > minor;
        }
        self.patch >= patch
    }

}

impl std::fmt::Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Matrix of available features by kernel version
#[derive(Debug, Clone)]
pub struct KernelCapabilities {
    pub version: KernelVersion,
    /// Landlock LSM available (kernel >= 5.13)
    pub landlock: bool,
    /// Landlock TCP bind/connect network rules (kernel >= 6.7, ABI 4)
    pub landlock_net: bool,
    /// Cgroups v2 available (kernel >= 4.5)
    pub cgroups_v2: bool,
    /// Seccomp notify available (kernel >= 5.0)
    pub seccomp_notify: bool,
    /// Seccomp notify CONTINUE responses available (kernel >= 5.5),
    /// required for filesystem-access telemetry
    pub seccomp_notify_continue: bool,
    /// User namespaces available (kernel >= 3.8)
    pub user_namespaces: bool,
}

impl KernelCapabilities {
    /// Detects the features available on the current kernel
    pub fn detect() -> Option<Self> {
        let version = KernelVersion::detect()?;

        let landlock = version.is_at_least(5, 13, 0);
        let landlock_net = version.is_at_least(6, 7, 0);
        let cgroups_v2 = version.is_at_least(4, 5, 0);
        let seccomp_notify = version.is_at_least(5, 0, 0);
        let seccomp_notify_continue = version.is_at_least(5, 5, 0);
        let user_namespaces = version.is_at_least(3, 8, 0);

        Some(Self {
            version,
            landlock,
            landlock_net,
            cgroups_v2,
            seccomp_notify,
            seccomp_notify_continue,
            user_namespaces,
        })
    }

    /// Renders a report of the available features
    pub fn report(&self) -> String {
        format!(
            "kernel: {}\n  landlock: {}\n  landlock_net: {}\n  cgroups_v2: {}\n  seccomp_notify: {}\n  seccomp_notify_continue: {}\n  user_namespaces: {}",
            self.version,
            if self.landlock { "✓" } else { "✗ (kernel >= 5.13 required)" },
            if self.landlock_net { "✓" } else { "✗ (kernel >= 6.7 required)" },
            if self.cgroups_v2 { "✓" } else { "✗ (kernel >= 4.5 required)" },
            if self.seccomp_notify { "✓" } else { "✗ (kernel >= 5.0 required)" },
            if self.seccomp_notify_continue { "✓" } else { "✗ (kernel >= 5.5 required)" },
            if self.user_namespaces { "✓" } else { "✗ (kernel >= 3.8 required)" },
        )
    }
}