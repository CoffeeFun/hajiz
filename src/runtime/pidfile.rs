use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::error::HajizError;

/// Directory where pid-files are stored.
const PIDFILE_DIR: &str = "/tmp/hajiz";

/// Write a named pidfile so the sandbox can be found later by name.
pub fn write(name: &str, pid: u32) -> Result<PathBuf, HajizError> {
    fs::create_dir_all(PIDFILE_DIR)?;
    let path = pidfile_path(name);
    fs::write(&path, pid.to_string())?;
    Ok(path)
}

/// Read a PID from a named pidfile.
pub fn read(name: &str) -> Result<u32, HajizError> {
    let path = pidfile_path(name);
    let raw = fs::read_to_string(&path)
        .map_err(|_| HajizError::Config(format!("no running sandbox named '{name}'")))?;
    raw.trim()
        .parse::<u32>()
        .map_err(|_| HajizError::Config(format!("corrupt pidfile for '{name}'")))
}

/// Remove a named pidfile (best-effort, does not fail).
pub fn remove(name: &str) {
    let _ = fs::remove_file(pidfile_path(name));
}

/// List all active sandbox names found in the pidfile directory.
pub fn list_all() -> Vec<(String, u32)> {
    let Ok(entries) = fs::read_dir(PIDFILE_DIR) else {
        return vec![];
    };
    entries
        .filter_map(|e| {
            let entry = e.ok()?;
            let name = entry.file_name().to_string_lossy().to_string();
            let name = name.strip_suffix(".pid")?.to_string();
            let pid = read(&name).ok()?;
            Some((name, pid))
        })
        .collect()
}

fn pidfile_path(name: &str) -> PathBuf {
    Path::new(PIDFILE_DIR).join(format!("{name}.pid"))
}
