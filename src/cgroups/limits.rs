use std::fs;
use std::path::{Path, PathBuf};
use crate::error::HajizError;

/// Resource limit configuration
#[derive(Debug, Clone, Default)]
pub struct ResourceLimits {
    /// Memory limit in bytes (e.g. 512 * 1024 * 1024 = 512MB)
    pub memory_bytes: Option<u64>,
    /// CPU limit as a percentage (e.g. 50 = 50%)
    pub cpu_percent: Option<u64>,
    /// Maximum number of processes
    pub max_pids: Option<u64>,
}

/// Creates the hajiz cgroup and writes the cgroups v2 limits into it. Adds NO
/// process: the sandboxed binary is moved in after its spawn via
/// `add_to_cgroup`, which keeps the hajiz parent out of the cgroup (so the
/// limits target only the child, and cleanup can rmdir the directory).
pub fn apply_limits(limits: &ResourceLimits) -> Result<(), HajizError> {
    let pid = std::process::id();
    let cgroup_path = create_cgroup(pid)?;

    // Memory limit
    if let Some(mem) = limits.memory_bytes {
        write_cgroup(&cgroup_path, "memory.max", &mem.to_string())?;
        write_cgroup(&cgroup_path, "memory.swap.max", "0")?;
    }

    // CPU limit (in microseconds: percent% of 100ms)
    if let Some(cpu) = limits.cpu_percent {
        let quota = cpu * 1000; // percent% of 100000 microseconds
        let period = 100_000u64;
        write_cgroup(&cgroup_path, "cpu.max", &format!("{} {}", quota, period))?;
    }

    // Process count limit
    if let Some(pids) = limits.max_pids {
        write_cgroup(&cgroup_path, "pids.max", &pids.to_string())?;
    }

    Ok(())
}

/// Moves a process (the sandboxed binary) into the hajiz cgroup so the limits
/// defined by `apply_limits` apply to it. Call from the parent right after the
/// child is spawned.
pub fn add_to_cgroup(pid: u32) -> Result<(), HajizError> {
    let cgroup_path = cgroup_path_for(std::process::id());
    write_cgroup(&cgroup_path, "cgroup.procs", &pid.to_string())
}

/// Creates a dedicated cgroup for the sandbox
fn create_cgroup(pid: u32) -> Result<PathBuf, HajizError> {
    let cgroup_path = PathBuf::from(format!("/sys/fs/cgroup/hajiz_{}", pid));

    fs::create_dir_all(&cgroup_path).map_err(|e| {
        HajizError::Isolation(format!(
            "unable to create cgroup '{}': {e}",
            cgroup_path.display()
        ))
    })?;

    Ok(cgroup_path)
}

/// Writes a value to a cgroup file
fn write_cgroup(cgroup_path: &Path, file: &str, value: &str) -> Result<(), HajizError> {
    let path = cgroup_path.join(file);
    fs::write(&path, value).map_err(|e| {
        HajizError::Isolation(format!(
            "unable to write '{}' to '{}': {e}",
            value,
            path.display()
        ))
    })
}

/// Cleans up the cgroup after use
pub fn cleanup_cgroup(pid: u32) {
    let cgroup_path = cgroup_path_for(pid);
    if cgroup_path.exists() {
        let _ = fs::remove_dir(&cgroup_path);
    }
}

/// Cgroup path associated with a hajiz pid (parent process).
pub fn cgroup_path_for(pid: u32) -> PathBuf {
    PathBuf::from(format!("/sys/fs/cgroup/hajiz_{}", pid))
}
