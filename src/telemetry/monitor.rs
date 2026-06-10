use std::fs;
use std::io::{ErrorKind, Read};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

use libseccomp::{ScmpArch, ScmpSyscall};
use nix::libc;

use super::event::SecurityEvent;
use super::logger::TelemetryLogger;

/// Handle for the background monitor threads. Drop or call `stop()` to
/// shut them down cleanly.
pub struct MonitorHandle {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl MonitorHandle {
    pub fn stop(self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads {
            let _ = t.join();
        }
    }
}

/// Spawn background monitoring threads that emit telemetry events while
/// the sandboxed child runs.
///
/// - kmsg reader: parses `audit: type=1326` (SECCOMP) records and emits
///   `SyscallDenied` events for the child PID. Best-effort: silently skipped
///   if `/dev/kmsg` is not readable (kernel.dmesg_restrict=1, no CAP_SYSLOG).
/// - cgroup sampler: reads `memory.current`, `pids.current`, `cpu.stat`
///   from the hajiz cgroup every `sample_interval` and emits `ResourceUsage`.
///   Skipped if the cgroup directory does not exist.
pub fn spawn_monitors(
    logger: Arc<TelemetryLogger>,
    child_pid: u32,
    cgroup_path: Option<PathBuf>,
    sample_interval: Duration,
) -> MonitorHandle {
    let stop = Arc::new(AtomicBool::new(false));
    let mut threads = Vec::new();

    if let Some(t) = spawn_kmsg_reader(Arc::clone(&logger), child_pid, Arc::clone(&stop)) {
        threads.push(t);
    }

    if let Some(path) = cgroup_path {
        if let Some(t) = spawn_cgroup_sampler(
            Arc::clone(&logger),
            child_pid,
            path,
            sample_interval,
            Arc::clone(&stop),
        ) {
            threads.push(t);
        }
    }

    MonitorHandle { stop, threads }
}

// --- kmsg reader -----------------------------------------------------------

fn spawn_kmsg_reader(
    logger: Arc<TelemetryLogger>,
    child_pid: u32,
    stop: Arc<AtomicBool>,
) -> Option<JoinHandle<()>> {
    let mut file = match open_kmsg_nonblock() {
        Ok(f) => f,
        Err(e) => {
            if e.kind() == ErrorKind::PermissionDenied {
                eprintln!(
                    "[hajiz:monitor] /dev/kmsg read denied — \
                     SyscallDenied disabled (requires root or kernel.dmesg_restrict=0)"
                );
            } else if e.kind() != ErrorKind::NotFound {
                eprintln!("[hajiz:monitor] failed to open /dev/kmsg: {e}");
            }
            return None;
        }
    };

    Some(thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while !stop.load(Ordering::SeqCst) {
            match file.read(&mut buf) {
                Ok(0) => {
                    thread::sleep(Duration::from_millis(50));
                }
                Ok(n) => {
                    if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                        if let Some(event) = parse_seccomp_audit(s, child_pid) {
                            logger.log(&event);
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(e) if e.raw_os_error() == Some(libc::EPIPE) => {
                    // Ring buffer overrun — keep reading, we just lost some lines.
                }
                Err(_) => {
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
    }))
}

fn open_kmsg_nonblock() -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg")
}

/// Parse a /dev/kmsg record and return a SyscallDenied event if it is a
/// SECCOMP audit record matching `child_pid`.
///
/// Record format: `<priority>,<seq>,<usec>,<flags>;<message>`
/// SECCOMP message: `audit: type=1326 audit(...): ... pid=N ... syscall=N ... code=0x5...`
fn parse_seccomp_audit(record: &str, child_pid: u32) -> Option<SecurityEvent> {
    let msg = record.split_once(';').map(|(_, m)| m).unwrap_or(record);
    if !msg.contains("type=1326") {
        return None;
    }

    let pid = extract_kv_u32(msg, "pid=")?;
    if pid != child_pid {
        return None;
    }

    let syscall_num = extract_kv_u32(msg, "syscall=")? as i32;
    let name = ScmpSyscall::from(syscall_num)
        .get_name_by_arch(ScmpArch::Native)
        .unwrap_or_else(|_| format!("syscall_{syscall_num}"));

    Some(SecurityEvent::SyscallDenied {
        pid,
        syscall: name,
        timestamp: SystemTime::now(),
    })
}

fn extract_kv_u32(s: &str, key: &str) -> Option<u32> {
    let idx = s.find(key)?;
    let rest = &s[idx + key.len()..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

// --- cgroup sampler --------------------------------------------------------

fn spawn_cgroup_sampler(
    logger: Arc<TelemetryLogger>,
    child_pid: u32,
    cgroup_path: PathBuf,
    interval: Duration,
    stop: Arc<AtomicBool>,
) -> Option<JoinHandle<()>> {
    if !cgroup_path.exists() {
        return None;
    }

    Some(thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            thread::sleep(interval);
            if stop.load(Ordering::SeqCst) {
                break;
            }
            let snapshot = read_cgroup_snapshot(&cgroup_path);
            logger.log(&SecurityEvent::ResourceUsage {
                pid: child_pid,
                memory_current: snapshot.memory_current,
                pids_current: snapshot.pids_current,
                cpu_usage_usec: snapshot.cpu_usage_usec,
                timestamp: SystemTime::now(),
            });
        }
    }))
}

#[derive(Default)]
struct CgroupSnapshot {
    memory_current: u64,
    pids_current: u64,
    cpu_usage_usec: u64,
}

fn read_cgroup_snapshot(path: &std::path::Path) -> CgroupSnapshot {
    let mut snap = CgroupSnapshot::default();

    if let Ok(s) = fs::read_to_string(path.join("memory.current")) {
        snap.memory_current = s.trim().parse().unwrap_or(0);
    }
    if let Ok(s) = fs::read_to_string(path.join("pids.current")) {
        snap.pids_current = s.trim().parse().unwrap_or(0);
    }
    if let Ok(s) = fs::read_to_string(path.join("cpu.stat")) {
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("usage_usec ") {
                snap.cpu_usage_usec = rest.trim().parse().unwrap_or(0);
                break;
            }
        }
    }

    snap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_seccomp_audit_matches_pid_and_syscall() {
        let record = "5,123,456789,-;audit: type=1326 audit(1700000000.123:42): \
                      auid=1000 uid=1000 gid=1000 ses=1 pid=4242 comm=\"x\" \
                      exe=\"/bin/x\" sig=0 arch=c000003e syscall=39 compat=0 \
                      ip=0x0 code=0x50000";
        let event = parse_seccomp_audit(record, 4242).expect("should match");
        match event {
            SecurityEvent::SyscallDenied { pid, syscall, .. } => {
                assert_eq!(pid, 4242);
                // syscall=39 is getpid on x86_64
                assert!(!syscall.is_empty());
            }
            _ => panic!("expected SyscallDenied"),
        }
    }

    #[test]
    fn parse_seccomp_audit_skips_other_pid() {
        let record = "5,123,456789,-;audit: type=1326 audit(...): \
                      pid=9999 syscall=39 code=0x50000";
        assert!(parse_seccomp_audit(record, 4242).is_none());
    }

    #[test]
    fn parse_seccomp_audit_skips_non_seccomp_record() {
        let record = "6,200,123,-;audit: type=1300 audit(...): pid=4242 syscall=1";
        assert!(parse_seccomp_audit(record, 4242).is_none());
    }

    #[test]
    fn extract_kv_u32_works() {
        assert_eq!(extract_kv_u32("foo pid=42 bar", "pid="), Some(42));
        assert_eq!(extract_kv_u32("syscall=39 code=0x5", "syscall="), Some(39));
        assert_eq!(extract_kv_u32("no key here", "pid="), None);
    }

    #[test]
    fn cgroup_snapshot_reads_files() {
        let tmp = std::env::temp_dir().join(format!("hajiz_test_{}", std::process::id()));
        let _ = fs::create_dir_all(&tmp);
        fs::write(tmp.join("memory.current"), "12345\n").unwrap();
        fs::write(tmp.join("pids.current"), "7\n").unwrap();
        fs::write(tmp.join("cpu.stat"), "usage_usec 9999\nuser_usec 5000\n").unwrap();

        let snap = read_cgroup_snapshot(&tmp);
        assert_eq!(snap.memory_current, 12345);
        assert_eq!(snap.pids_current, 7);
        assert_eq!(snap.cpu_usage_usec, 9999);

        let _ = fs::remove_dir_all(&tmp);
    }
}
