use serde::Deserialize;

/// Configuration complète d'un profil de sandboxing
#[derive(Debug, Clone, Deserialize)]
pub struct Profile {
    /// Nom du profil (ex: "firefox", "untrusted")
    pub name: String,

    /// Description du profil
    pub description: Option<String>,

    /// Configuration réseau
    #[serde(default)]
    pub network: NetworkConfig,

    /// Configuration filesystem
    #[serde(default)]
    pub filesystem: FilesystemConfig,

    /// Configuration seccomp
    #[serde(default)]
    pub seccomp: SeccompConfig,
}

/// Configuration réseau du profil
///
/// `mode` accepte trois valeurs:
/// - `"none"` (défaut): propre namespace réseau, aucune interface — pas d'accès réseau
/// - `"loopback"`: propre namespace réseau avec `lo` activé — services locaux 127.0.0.1 uniquement
/// - `"full"`: partage du namespace réseau de l'hôte — accès réseau complet
///
/// `allow_connect` / `allow_bind` (optionnels): listes blanches de ports TCP
/// appliquées par Landlock (kernel >= 6.7). Si non vide, seuls les ports listés
/// sont autorisés pour `connect()` (sortant) et `bind()` (écoute) respectivement.
/// Indépendant de `mode` — fonctionne aussi en mode `full`.
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

/// Configuration filesystem du profil
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FilesystemConfig {
    /// Chemins autorisés en lecture seule
    #[serde(default)]
    pub read_only: Vec<String>,

    /// Chemins autorisés en lecture/écriture
    #[serde(default)]
    pub read_write: Vec<String>,
}

/// Configuration seccomp du profil
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SeccompConfig {
    /// Activer le mode strict
    #[serde(default)]
    pub strict: bool,

    /// Activer le mode allowlist
    #[serde(default)]
    pub whitelist: bool,

    /// Activer le filtre de durcissement
    #[serde(default = "default_true")]
    pub hardening: bool,

    /// Groupes de syscalls autorisés
    #[serde(default)]
    pub allow_groups: Vec<String>,

    /// Syscalls individuels autorisés
    #[serde(default)]
    pub allow_syscalls: Vec<String>,
}

fn default_true() -> bool {
    true
}