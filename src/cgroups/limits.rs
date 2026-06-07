use std::fs;
use std::path::{Path, PathBuf};
use crate::error::HajizError;

/// Configuration des limites de ressources
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    /// Limite mémoire en bytes (ex: 512 * 1024 * 1024 = 512MB)
    pub memory_bytes: Option<u64>,
    /// Limite CPU en pourcentage (ex: 50 = 50%)
    pub cpu_percent: Option<u64>,
    /// Nombre maximum de processus
    pub max_pids: Option<u64>,
}

/// Applique les limites cgroups v2 au processus courant
pub fn apply_limits(limits: &ResourceLimits) -> Result<(), HajizError> {
    let pid = std::process::id();
    let cgroup_path = create_cgroup(pid)?;

    // Ajouter le processus courant au cgroup
    write_cgroup(&cgroup_path, "cgroup.procs", &pid.to_string())?;

    // Limite mémoire
    if let Some(mem) = limits.memory_bytes {
        write_cgroup(&cgroup_path, "memory.max", &mem.to_string())?;
        write_cgroup(&cgroup_path, "memory.swap.max", "0")?;
    }

    // Limite CPU (en microsecondes : percent% de 100ms)
    if let Some(cpu) = limits.cpu_percent {
        let quota = cpu * 1000; // percent% de 100000 microsecondes
        let period = 100_000u64;
        write_cgroup(&cgroup_path, "cpu.max", &format!("{} {}", quota, period))?;
    }

    // Limite nombre de processus
    if let Some(pids) = limits.max_pids {
        write_cgroup(&cgroup_path, "pids.max", &pids.to_string())?;
    }

    Ok(())
}

/// Crée un cgroup dédié pour le sandbox
fn create_cgroup(pid: u32) -> Result<PathBuf, HajizError> {
    let cgroup_path = PathBuf::from(format!("/sys/fs/cgroup/hajiz_{}", pid));

    fs::create_dir_all(&cgroup_path).map_err(|e| {
        HajizError::Isolation(format!(
            "impossible de créer le cgroup '{}': {e}",
            cgroup_path.display()
        ))
    })?;

    Ok(cgroup_path)
}

/// Écrit une valeur dans un fichier cgroup
fn write_cgroup(cgroup_path: &Path, file: &str, value: &str) -> Result<(), HajizError> {
    let path = cgroup_path.join(file);
    fs::write(&path, value).map_err(|e| {
        HajizError::Isolation(format!(
            "impossible d'écrire '{}' dans '{}': {e}",
            value,
            path.display()
        ))
    })
}

/// Nettoie le cgroup après utilisation
pub fn cleanup_cgroup(pid: u32) {
    let cgroup_path = cgroup_path_for(pid);
    if cgroup_path.exists() {
        let _ = fs::remove_dir(&cgroup_path);
    }
}

/// Chemin cgroup associé à un pid hajiz (parent process).
pub fn cgroup_path_for(pid: u32) -> PathBuf {
    PathBuf::from(format!("/sys/fs/cgroup/hajiz_{}", pid))
}