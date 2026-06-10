//! seccomp user-notification supervisor.
//!
//! When the hardening filter is loaded with SECCOMP_RET_USER_NOTIF actions,
//! the child hands the kernel listener fd back to the parent (SCM_RIGHTS) and
//! this thread services it:
//!
//! - hardened denied syscalls → log `SyscallDenied`, answer EPERM. This
//!   replaces the /dev/kmsg audit-record parsing and works regardless of
//!   `kernel.dmesg_restrict`.
//! - filesystem syscalls (only with `seccomp_fs_notify`) → read the path from
//!   the target's memory, predict the Landlock outcome from the profile rules,
//!   log `FilesystemDenied` on a miss, and answer CONTINUE so the kernel runs
//!   the syscall normally — Landlock remains the actual enforcement point.
//! - connect/bind (only with `seccomp_net_notify`) → read the sockaddr,
//!   predict against the Landlock TCP-port allowlist, log `NetworkDenied` on a
//!   miss, and answer CONTINUE — again Landlock makes the final decision.
//!
//! The fs/net predictions are best-effort telemetry: they resolve relative
//! paths via /proc/<pid>/cwd and dirfds via /proc/<pid>/fd, but do not chase
//! symlinks the way the kernel does. Enforcement is never based on them.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::SystemTime;

use libseccomp::{notify_id_valid, ScmpNotifReq, ScmpNotifResp, ScmpNotifRespFlags};
use nix::libc;

use crate::isolation::{seccomp::hardened_denied_syscalls, FilesystemRule};

use super::event::SecurityEvent;
use super::logger::TelemetryLogger;

/// Landlock rules the supervisor replays to predict denials.
pub struct PredictRules {
    pub fs_rules: Vec<FilesystemRule>,
    pub connect_ports: Vec<u16>,
    pub bind_ports: Vec<u16>,
}

pub fn spawn_notify_supervisor(
    logger: Arc<TelemetryLogger>,
    fd: OwnedFd,
    rules: PredictRules,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let raw = fd.as_raw_fd();
        // One reusable handle on the target's memory, instead of reopening
        // /proc/<pid>/mem on every intercepted filesystem syscall.
        let mut mem = MemReader::new();
        while !stop.load(Ordering::SeqCst) {
            let mut pfd = libc::pollfd {
                fd: raw,
                events: libc::POLLIN,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, 100) };
            if n < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if n == 0 {
                continue;
            }
            if pfd.revents & libc::POLLIN == 0 {
                // POLLHUP/POLLERR without data: every process under the
                // filter has exited — nothing more will arrive.
                break;
            }
            match ScmpNotifReq::receive(raw) {
                Ok(req) => handle_request(&logger, raw, &rules, &mut mem, req),
                // ENOENT: the syscall was aborted (signal / target died)
                // before we picked it up. Anything else: retry via poll;
                // a dead fd surfaces as POLLHUP on the next iteration.
                Err(_) => continue,
            }
        }
    })
}

fn handle_request(
    logger: &TelemetryLogger,
    fd: RawFd,
    rules: &PredictRules,
    mem: &mut MemReader,
    req: ScmpNotifReq,
) {
    let name = req
        .data
        .syscall
        .get_name_by_arch(req.data.arch)
        .unwrap_or_else(|_| format!("syscall_{}", i32::from(req.data.syscall)));

    if hardened_denied_syscalls().contains(&name.as_str()) {
        logger.log(&SecurityEvent::SyscallDenied {
            pid: req.pid,
            syscall: name,
            timestamp: SystemTime::now(),
        });
        // ENOENT on respond = target died mid-syscall; nothing to do.
        let _ = ScmpNotifResp::new_error(req.id, -libc::EPERM, ScmpNotifRespFlags::empty())
            .respond(fd);
        return;
    }

    // Telemetry-only syscalls (fs + net). We validate the notification id
    // first — it guards against pid reuse between reading /proc/<pid>/mem and
    // trusting what we read — then predict, log on a miss, and always CONTINUE
    // so the kernel (Landlock) makes the real decision.
    if notify_id_valid(fd, req.id).is_ok() {
        if let Some(net) = resolve_net_access(&req, &name, mem) {
            let allowed = match net.operation {
                "connect" => port_allowed(&rules.connect_ports, net.port),
                _ => port_allowed(&rules.bind_ports, net.port),
            };
            if !allowed {
                logger.log(&SecurityEvent::NetworkDenied {
                    pid: req.pid,
                    operation: net.operation.to_string(),
                    address: net.address,
                    port: net.port,
                    timestamp: SystemTime::now(),
                });
            }
        } else if let Some(access) = resolve_fs_access(&req, &name, mem)
            && !path_allowed(&rules.fs_rules, &access.path, access.write)
        {
            logger.log(&SecurityEvent::FilesystemDenied {
                pid: req.pid,
                path: access.path.to_string_lossy().into_owned(),
                timestamp: SystemTime::now(),
            });
        }
    }
    let _ = ScmpNotifResp::new_continue(req.id, ScmpNotifRespFlags::empty()).respond(fd);
}

struct FsAccess {
    path: PathBuf,
    write: bool,
}

/// Extract the (path, write?) pair for an intercepted filesystem syscall.
/// Returns None for unreadable paths or syscalls we don't classify — callers
/// then just CONTINUE without logging.
fn resolve_fs_access(req: &ScmpNotifReq, name: &str, mem: &mut MemReader) -> Option<FsAccess> {
    let (path_arg, dirfd_arg, write) = match name {
        "open" => (0, None, open_flags_write(req.data.args[1])),
        "creat" | "truncate" | "mkdir" | "rmdir" | "unlink" | "rename" => (0, None, true),
        "openat" => (1, Some(0), open_flags_write(req.data.args[2])),
        "mkdirat" | "unlinkat" | "renameat" | "renameat2" => (1, Some(0), true),
        _ => return None,
    };

    let raw_path = mem.read_path(req.pid, req.data.args[path_arg])?;
    let dirfd = dirfd_arg.map(|i| req.data.args[i] as i32);
    Some(FsAccess {
        path: absolutize(req.pid, raw_path, dirfd),
        write,
    })
}

fn open_flags_write(flags: u64) -> bool {
    let flags = flags as i32;
    (flags & libc::O_ACCMODE) != libc::O_RDONLY
        || flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0
}

struct NetAccess {
    /// "connect" or "bind" — a `&'static str` from the caller's match.
    operation: &'static str,
    address: String,
    port: u16,
}

/// Extract the destination/listen endpoint for an intercepted connect/bind.
/// Returns None for non-IP families (AF_UNIX, AF_NETLINK, …) and malformed
/// sockaddrs — callers then CONTINUE without logging.
fn resolve_net_access(req: &ScmpNotifReq, name: &str, mem: &mut MemReader) -> Option<NetAccess> {
    let operation = match name {
        "connect" => "connect",
        "bind" => "bind",
        _ => return None,
    };
    // connect(fd, sockaddr*, addrlen) / bind(fd, sockaddr*, addrlen)
    let addr_ptr = req.data.args[1];
    if addr_ptr == 0 {
        return None;
    }
    let mut buf = [0u8; 28]; // max(sizeof sockaddr_in, sockaddr_in6)
    let n = mem.read_into(req.pid, addr_ptr, &mut buf)?;
    if n < 4 {
        return None;
    }
    // sa_family is host byte order; the port is network byte order (big-endian).
    let family = u16::from_ne_bytes([buf[0], buf[1]]) as i32;
    let port = u16::from_be_bytes([buf[2], buf[3]]);
    let address = match family {
        libc::AF_INET if n >= 8 => {
            std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]).to_string()
        }
        libc::AF_INET6 if n >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[8..24]);
            std::net::Ipv6Addr::from(octets).to_string()
        }
        _ => return None,
    };
    Some(NetAccess { operation, address, port })
}

/// Predict the Landlock TCP-port decision. An empty allowlist means the
/// operation is unrestricted (Landlock isn't applied to it), so it's allowed.
fn port_allowed(allowed: &[u16], port: u16) -> bool {
    allowed.is_empty() || allowed.contains(&port)
}

/// Reads NUL-terminated path strings out of a target process's memory,
/// caching the open `/proc/<pid>/mem` handle between calls.
///
/// A single slot is enough: filesystem syscalls cluster within one process,
/// so the common case (one busy child) reuses the same fd for its whole run.
/// When the pid changes we reopen; a read error drops the handle so the next
/// call reopens — this is how we recover if the process exits (the fd to a
/// dead process's mem errors out, it never silently rebinds to a reused pid).
struct MemReader {
    cached: Option<(u32, fs::File)>,
}

impl MemReader {
    fn new() -> Self {
        Self { cached: None }
    }

    /// Read raw bytes at `addr` from the target into `buf`, returning the
    /// number read. A read error drops the cached handle so the next call
    /// reopens (recovers from process exit / pid reuse).
    fn read_into(&mut self, pid: u32, addr: u64, buf: &mut [u8]) -> Option<usize> {
        if addr == 0 {
            return None;
        }
        if self.cached.as_ref().map(|(p, _)| *p) != Some(pid) {
            self.cached = fs::File::open(format!("/proc/{pid}/mem")).ok().map(|f| (pid, f));
        }
        let (_, file) = self.cached.as_mut()?;
        let result = file.seek(SeekFrom::Start(addr)).and_then(|_| file.read(buf));
        match result {
            Ok(n) => Some(n),
            Err(_) => {
                self.cached = None;
                None
            }
        }
    }

    /// Read a NUL-terminated path string at `addr` from the target.
    fn read_path(&mut self, pid: u32, addr: u64) -> Option<PathBuf> {
        let mut buf = [0u8; libc::PATH_MAX as usize];
        let n = self.read_into(pid, addr, &mut buf)?;
        let end = buf[..n].iter().position(|&b| b == 0)?;
        let s = std::str::from_utf8(&buf[..end]).ok()?;
        Some(PathBuf::from(s))
    }
}

/// Make a relative path absolute from the target's point of view, using its
/// cwd or the directory behind the dirfd. The child shares our mount view
/// (no pivot_root), so the resulting path is meaningful in the parent too.
fn absolutize(pid: u32, path: PathBuf, dirfd: Option<i32>) -> PathBuf {
    if path.is_absolute() {
        return path;
    }
    let base = match dirfd {
        Some(fd) if fd != libc::AT_FDCWD => fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok(),
        _ => fs::read_link(format!("/proc/{pid}/cwd")).ok(),
    };
    match base {
        Some(base) => base.join(path),
        None => path,
    }
}

/// Predict the Landlock decision: access is allowed when some rule path is a
/// component-wise prefix of the target path, and the rule is rw for writes.
fn path_allowed(rules: &[FilesystemRule], path: &Path, write: bool) -> bool {
    rules.iter().any(|rule| {
        if write && rule.read_only {
            return false;
        }
        path.starts_with(Path::new(&rule.path))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(specs: &[(&str, bool)]) -> Vec<FilesystemRule> {
        specs
            .iter()
            .map(|(path, read_only)| FilesystemRule {
                path: path.to_string(),
                read_only: *read_only,
            })
            .collect()
    }

    #[test]
    fn path_allowed_matches_component_prefix() {
        let rules = rules(&[("/usr", true)]);
        assert!(path_allowed(&rules, Path::new("/usr/lib/libc.so"), false));
        assert!(path_allowed(&rules, Path::new("/usr"), false));
        // String prefix but not a path-component prefix.
        assert!(!path_allowed(&rules, Path::new("/usrlocal/x"), false));
        assert!(!path_allowed(&rules, Path::new("/etc/hostname"), false));
    }

    #[test]
    fn path_allowed_write_requires_rw_rule() {
        let rules = rules(&[("/data", true), ("/tmp/out", false)]);
        assert!(!path_allowed(&rules, Path::new("/data/file"), true));
        assert!(path_allowed(&rules, Path::new("/data/file"), false));
        assert!(path_allowed(&rules, Path::new("/tmp/out/file"), true));
    }

    #[test]
    fn open_flags_write_classification() {
        assert!(!open_flags_write(libc::O_RDONLY as u64));
        assert!(open_flags_write(libc::O_WRONLY as u64));
        assert!(open_flags_write(libc::O_RDWR as u64));
        assert!(open_flags_write((libc::O_RDONLY | libc::O_CREAT) as u64));
        assert!(open_flags_write((libc::O_RDONLY | libc::O_TRUNC) as u64));
    }

    #[test]
    fn port_allowed_semantics() {
        // Empty allowlist = unrestricted.
        assert!(port_allowed(&[], 443));
        // Non-empty: only listed ports pass.
        assert!(port_allowed(&[443, 80], 443));
        assert!(!port_allowed(&[443, 80], 8080));
    }
}
