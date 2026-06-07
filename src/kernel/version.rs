use std::fs;

/// Version du kernel Linux
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    /// Lit la version du kernel depuis /proc/version
    pub fn detect() -> Option<Self> {
        let content = fs::read_to_string("/proc/version").ok()?;
        let version_str = content.split_whitespace().nth(2)?;
        Self::parse(version_str)
    }

    /// Parse une version du type "5.15.0-91-generic"
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.split('-').next()?;
        let mut parts = s.split('.');
        let major = parts.next()?.parse().ok()?;
        let minor = parts.next()?.parse().ok()?;
        let patch = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        Some(Self { major, minor, patch })
    }

    /// Vérifie si la version est >= à la version donnée
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

/// Matrice des fonctionnalités disponibles selon la version kernel
#[derive(Debug, Clone)]
pub struct KernelCapabilities {
    pub version: KernelVersion,
    /// Landlock LSM disponible (kernel >= 5.13)
    pub landlock: bool,
    /// Landlock règles réseau TCP bind/connect (kernel >= 6.7, ABI 4)
    pub landlock_net: bool,
    /// Cgroups v2 disponible (kernel >= 4.5)
    pub cgroups_v2: bool,
    /// Seccomp notify disponible (kernel >= 5.0)
    pub seccomp_notify: bool,
    /// User namespaces disponible (kernel >= 3.8)
    pub user_namespaces: bool,
}

impl KernelCapabilities {
    /// Détecte les fonctionnalités disponibles sur le kernel actuel
    pub fn detect() -> Option<Self> {
        let version = KernelVersion::detect()?;

        let landlock = version.is_at_least(5, 13, 0);
        let landlock_net = version.is_at_least(6, 7, 0);
        let cgroups_v2 = version.is_at_least(4, 5, 0);
        let seccomp_notify = version.is_at_least(5, 0, 0);
        let user_namespaces = version.is_at_least(3, 8, 0);

        Some(Self {
            version,
            landlock,
            landlock_net,
            cgroups_v2,
            seccomp_notify,
            user_namespaces,
        })
    }

    /// Affiche un rapport des fonctionnalités disponibles
    pub fn report(&self) -> String {
        format!(
            "kernel: {}\n  landlock: {}\n  landlock_net: {}\n  cgroups_v2: {}\n  seccomp_notify: {}\n  user_namespaces: {}",
            self.version,
            if self.landlock { "✓" } else { "✗ (kernel >= 5.13 requis)" },
            if self.landlock_net { "✓" } else { "✗ (kernel >= 6.7 requis)" },
            if self.cgroups_v2 { "✓" } else { "✗ (kernel >= 4.5 requis)" },
            if self.seccomp_notify { "✓" } else { "✗ (kernel >= 5.0 requis)" },
            if self.user_namespaces { "✓" } else { "✗ (kernel >= 3.8 requis)" },
        )
    }
}