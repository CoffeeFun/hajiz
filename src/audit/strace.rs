use std::collections::BTreeSet;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;

use crate::error::HajizError;

#[derive(Debug, Default, Clone)]
pub struct AuditReport {
    pub syscalls: BTreeSet<String>,
    pub paths_read: BTreeSet<String>,
    pub paths_written: BTreeSet<String>,
    pub network_addrs: BTreeSet<String>,
    /// TCP destination ports observed via connect()/sendto()/sendmsg()
    pub connect_ports: BTreeSet<u16>,
    /// TCP listen ports observed via bind()/listen()
    pub bind_ports: BTreeSet<u16>,
    pub exit_code: i32,
}

pub fn run_audit(binary: &str, args: &[String]) -> Result<AuditReport, HajizError> {
    if Command::new("strace").arg("--version").output().is_err() {
        return Err(HajizError::Config(
            "strace is not installed (the 'strace' package is required)".into(),
        ));
    }

    let log_path = format!("/tmp/hajiz-audit-{}.log", std::process::id());

    let status = Command::new("strace")
        .args(["-f", "-e", "trace=all", "-o", &log_path, "--", binary])
        .args(args)
        .status()
        .map_err(|e| HajizError::Isolation(format!("strace failed to start: {e}")))?;

    let mut report = parse_strace_log(Path::new(&log_path))?;
    report.exit_code = status.code().unwrap_or(-1);

    let _ = std::fs::remove_file(&log_path);

    Ok(report)
}

pub fn parse_strace_log(path: &Path) -> Result<AuditReport, HajizError> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);

    let mut report = AuditReport::default();
    for line in reader.lines() {
        let line = line?;
        parse_line(&line, &mut report);
    }
    Ok(report)
}

fn parse_line(raw: &str, report: &mut AuditReport) {
    let line = strip_pid_prefix(raw);

    if line.starts_with("<...") || line.contains("<unfinished") {
        return;
    }
    if line.starts_with("---") || line.starts_with("+++") {
        return;
    }

    let paren = match line.find('(') {
        Some(i) if i > 0 => i,
        _ => return,
    };
    let syscall = &line[..paren];
    if !syscall
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return;
    }
    report.syscalls.insert(syscall.to_string());

    let rest = &line[paren..];
    match syscall {
        "openat" | "open" => {
            if let Some(path) = first_string_arg_in_open(rest) {
                if rest.contains("O_WRONLY") || rest.contains("O_RDWR") || rest.contains("O_CREAT")
                {
                    report.paths_written.insert(path);
                } else {
                    report.paths_read.insert(path);
                }
            }
        }
        "stat" | "lstat" | "newfstatat" | "access" | "faccessat" | "readlink" | "readlinkat" => {
            if let Some(path) = first_string_arg(rest) {
                report.paths_read.insert(path);
            }
        }
        "connect" | "sendto" | "sendmsg" => {
            if let Some(addr) = extract_inet_addr(rest) {
                report.network_addrs.insert(addr);
            }
            if let Some(port) = extract_inet_port(rest) {
                report.connect_ports.insert(port);
            }
        }
        "bind" => {
            if let Some(port) = extract_inet_port(rest) {
                report.bind_ports.insert(port);
            }
        }
        _ => {}
    }
}

fn strip_pid_prefix(line: &str) -> &str {
    if let Some(rest) = line.strip_prefix('[')
        && let Some(idx) = rest.find("] ")
    {
        return &rest[idx + 2..];
    }
    line
}

fn first_string_arg(s: &str) -> Option<String> {
    let start = s.find('"')?;
    let after = &s[start + 1..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

fn first_string_arg_in_open(s: &str) -> Option<String> {
    if s.starts_with("(AT_FDCWD") {
        let rest = &s[s.find(',')? + 1..];
        return first_string_arg(rest);
    }
    first_string_arg(s)
}

fn extract_inet_port(line: &str) -> Option<u16> {
    let idx = line.find("htons(")?;
    let rest = &line[idx + 6..];
    let end = rest.find(')')?;
    rest[..end].parse::<u16>().ok()
}

fn extract_inet_addr(line: &str) -> Option<String> {
    if let Some(idx) = line.find("inet_addr(\"") {
        let rest = &line[idx + 11..];
        let end = rest.find('"')?;
        return Some(rest[..end].to_string());
    }
    if let Some(idx) = line.find("inet_pton(") {
        let rest = &line[idx..];
        return first_string_arg(rest);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(lines: &[&str]) -> AuditReport {
        let mut r = AuditReport::default();
        for l in lines {
            parse_line(l, &mut r);
        }
        r
    }

    #[test]
    fn parse_openat_read() {
        let r = parse(&[r#"openat(AT_FDCWD, "/etc/passwd", O_RDONLY) = 3"#]);
        assert!(r.syscalls.contains("openat"));
        assert!(r.paths_read.contains("/etc/passwd"));
        assert!(r.paths_written.is_empty());
    }

    #[test]
    fn parse_openat_write() {
        let r = parse(&[
            r#"openat(AT_FDCWD, "/tmp/out.log", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4"#,
        ]);
        assert!(r.paths_written.contains("/tmp/out.log"));
        assert!(r.paths_read.is_empty());
    }

    #[test]
    fn parse_pid_prefix() {
        let r = parse(&[r#"[pid 1234] read(3, "abc", 4096) = 3"#]);
        assert!(r.syscalls.contains("read"));
    }

    #[test]
    fn parse_unfinished_skipped() {
        let r = parse(&[
            r#"openat(AT_FDCWD, "/etc/passwd",  <unfinished ...>"#,
            r#"<... openat resumed>O_RDONLY) = 3"#,
        ]);
        assert!(r.syscalls.is_empty());
    }

    #[test]
    fn parse_signal_lines_skipped() {
        let r = parse(&["--- SIGCHLD {si_signo=SIGCHLD} ---", "+++ exited with 0 +++"]);
        assert!(r.syscalls.is_empty());
    }

    #[test]
    fn parse_connect_inet() {
        let r = parse(&[
            r#"connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("8.8.8.8")}, 16) = 0"#,
        ]);
        assert!(r.syscalls.contains("connect"));
        assert!(r.network_addrs.contains("8.8.8.8"));
        assert!(r.connect_ports.contains(&443));
    }

    #[test]
    fn parse_bind_inet_extracts_port() {
        let r = parse(&[
            r#"bind(4, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("0.0.0.0")}, 16) = 0"#,
        ]);
        assert!(r.syscalls.contains("bind"));
        assert!(r.bind_ports.contains(&8080));
    }

    #[test]
    fn parse_access() {
        let r = parse(&[r#"access("/etc/ld.so.preload", R_OK) = -1 ENOENT"#]);
        assert!(r.paths_read.contains("/etc/ld.so.preload"));
    }
}
