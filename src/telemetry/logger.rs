use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use super::event::SecurityEvent;

/// Logger de télémétrie de sécurité
pub struct TelemetryLogger {
    /// Chemin vers le fichier de log (None = stderr)
    log_file: Option<PathBuf>,
    /// Activer la sortie verbose
    verbose: bool,
}

impl TelemetryLogger {
    /// Crée un logger qui écrit sur stderr
    pub fn new(verbose: bool) -> Self {
        Self {
            log_file: None,
            verbose,
        }
    }

    /// Crée un logger qui écrit dans un fichier
    pub fn with_file(path: PathBuf, verbose: bool) -> Self {
        Self {
            log_file: Some(path),
            verbose,
        }
    }

    /// Enregistre un événement de sécurité
    pub fn log(&self, event: &SecurityEvent) {
        let json = event.to_json();

        // Affichage verbose sur stderr
        if self.verbose {
            eprintln!("[hajiz:telemetry] {}", json);
        }

        // Écriture dans le fichier si configuré
        if let Some(path) = &self.log_file {
            match OpenOptions::new().create(true).append(true).open(path) {
                Ok(mut file) => {
                    if let Err(e) = writeln!(file, "{}", json) {
                        eprintln!("[hajiz:telemetry] erreur écriture log: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("[hajiz:telemetry] impossible d'ouvrir le fichier log: {e}");
                }
            }
        }
    }

    /// Calcule un hash simple de la politique d'isolation
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

        // Hash djb2 simple
        let mut hash: u64 = 5381;
        for byte in policy_str.bytes() {
            hash = hash.wrapping_mul(33).wrapping_add(byte as u64);
        }
        format!("{:016x}", hash)
    }
}