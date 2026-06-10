//! Real escape attempts. Each test verifies that an action `hajiz` claims to
//! block actually fails.
//!
//! Difference with `exploit_tests.rs`: these tests *attack* the sandbox
//! (forbidden reads, dangerous syscalls, writes outside the allowlist...)
//! instead of merely checking that a binary runs.

use std::path::Path;
use std::process::Command;

fn hajiz() -> String {
    std::env::var("HAJIZ_BIN").unwrap_or_else(|_| env!("CARGO_BIN_EXE_hajiz").to_string())
}

fn landlock_supported() -> bool {
    let out = Command::new(hajiz())
        .arg("--kernel-info")
        .output()
        .expect("hajiz --kernel-info");
    let s = String::from_utf8_lossy(&out.stdout);
    s.lines()
        .find(|l| l.contains("landlock"))
        .map(|l| l.contains("yes") || l.contains("true"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// General hardening
// ---------------------------------------------------------------------------

/// no_new_privs must be set in the sandbox: it prevents execve of a setuid
/// binary from gaining privileges.
#[test]
fn escape_no_new_privs_is_set() {
    let out = Command::new(hajiz())
        .args(["/usr/bin/cat", "/proc/self/status"])
        .output()
        .expect("failed to launch hajiz");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout
        .lines()
        .find(|l| l.starts_with("NoNewPrivs:"))
        .expect("NoNewPrivs missing from /proc/self/status");
    assert!(
        line.contains("1"),
        "NoNewPrivs must be set in the sandbox, got: {line:?}"
    );
}

// ---------------------------------------------------------------------------
// Seccomp hardening: dangerous syscalls
// ---------------------------------------------------------------------------

/// keyctl is in the list of syscalls blocked by the hardening filter.
/// The keyctl binary must fail to manipulate the keyring.
#[test]
fn escape_keyctl_syscall_blocked() {
    if !Path::new("/usr/bin/keyctl").exists() {
        eprintln!("[skip] /usr/bin/keyctl not found");
        return;
    }
    let out = Command::new(hajiz())
        .args(["/usr/bin/keyctl", "show"])
        .output()
        .expect("failed to launch hajiz");
    assert!(
        !out.status.success(),
        "keyctl show must not succeed: the keyctl syscall is forbidden by the hardening filter"
    );
}

/// The bpf() syscall must be denied. We trigger it from Python via ctypes
/// to avoid needing a dedicated binary.
#[test]
fn escape_bpf_syscall_returns_eperm() {
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("[skip] python3 not found");
        return;
    }
    let probe = "
import ctypes, errno, sys
libc = ctypes.CDLL('libc.so.6', use_errno=True)
# SYS_bpf == 321 on x86_64
ret = libc.syscall(321, 0, 0, 0)
err = ctypes.get_errno()
# Without seccomp: EINVAL (bad args). With seccomp hardening: EPERM.
sys.exit(0 if (ret == -1 and err == errno.EPERM) else 1)
";
    let out = Command::new(hajiz())
        .args(["/usr/bin/python3", "--", "-c", probe])
        .output()
        .expect("failed to launch hajiz");
    assert!(
        out.status.success(),
        "bpf() must return EPERM under seccomp hardening, got status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Filesystem: Landlock
// ---------------------------------------------------------------------------

/// With a restrictive Landlock allowlist (/usr ro + /tmp rw), reading a file
/// outside the allowlist (/etc) must fail.
#[test]
fn escape_fs_read_outside_allowlist_blocked() {
    if !landlock_supported() {
        eprintln!("[skip] Landlock unavailable on this kernel");
        return;
    }
    let out = Command::new(hajiz())
        .args([
            "--fs", "/usr:ro",
            "--fs", "/tmp:rw",
            "/usr/bin/cat", "/etc/hostname",
        ])
        .output()
        .expect("failed to launch hajiz");
    assert!(
        !out.status.success(),
        "cat /etc/hostname must not succeed with Landlock limited to /usr+/tmp"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Permission") || stderr.contains("denied"),
        "stderr must mention an access denial, got: {stderr}"
    );
}

/// With /usr read-only via Landlock, dd must fail to write into /usr.
/// (The user normally has no such right either, but Landlock guarantees the
/// denial independently of classic UNIX permissions.)
#[test]
fn escape_fs_write_outside_rules_blocked() {
    if !landlock_supported() {
        eprintln!("[skip] Landlock unavailable");
        return;
    }
    // Target in the test's home: without hajiz the user can write there, so a
    // success indicates a real escape. With hajiz and /home not allowlisted,
    // the write must fail.
    let target = format!(
        "{}/hajiz_escape_test_{}.tmp",
        std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
        std::process::id()
    );
    let _ = std::fs::remove_file(&target);

    let out = Command::new(hajiz())
        .args([
            "--fs", "/usr:ro",
            "--fs", "/tmp:rw",
            "/usr/bin/dd",
            "if=/dev/zero",
            &format!("of={}", target),
            "bs=1",
            "count=1",
        ])
        .output()
        .expect("failed to launch hajiz");

    let wrote = Path::new(&target).exists();
    let _ = std::fs::remove_file(&target);

    assert!(
        !out.status.success() && !wrote,
        "dd wrote {target} while $HOME is not Landlock-allowlisted — filesystem escape"
    );
}

// ---------------------------------------------------------------------------
// Kill-on-deny: the sandbox kills the process, not just EPERM
// ---------------------------------------------------------------------------

/// With --seccomp-whitelist without the network group + --kill-on-deny, a call
/// to socket() must kill the process with SIGSYS (signal 31), not return
/// EPERM.
#[test]
fn escape_kill_on_deny_terminates_with_sigsys() {
    if !Path::new("/usr/bin/python3").exists() {
        eprintln!("[skip] python3 not found");
        return;
    }
    let probe = "
import socket, sys
try:
    socket.socket()
except Exception:
    sys.exit(0)
# If we get here, socket() succeeded -> escape.
sys.exit(99)
";
    let out = Command::new(hajiz())
        .args([
            "--seccomp-whitelist",
            "--allow-group", "io",
            "--allow-group", "memory",
            "--allow-group", "threading",
            "--allow-group", "process",
            "--kill-on-deny",
            "/usr/bin/python3", "--", "-c", probe,
        ])
        .output()
        .expect("failed to launch hajiz");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "hajiz must return an error when the child dies from SIGSYS, \
         status={:?}, stderr={stderr}",
        out.status
    );
    // hajiz does not inherit the child's signal: it records it in stderr and
    // in the telemetry (signal=31 field). We check the trace.
    assert!(
        stderr.contains("SIGSYS") || stderr.contains("signal: 31"),
        "stderr must indicate a death by SIGSYS (kill_on_deny active), got: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// Audit mode: the command produces a usable profile
// ---------------------------------------------------------------------------

/// The --audit mode produces a TOML profile containing at least one [seccomp]
/// section with observed syscalls.
#[test]
fn escape_audit_mode_generates_profile() {
    if Command::new("strace").arg("--version").output().is_err() {
        eprintln!("[skip] strace not found");
        return;
    }
    let out_path = format!("/tmp/hajiz_audit_{}.toml", std::process::id());
    let _ = std::fs::remove_file(&out_path);

    let out = Command::new(hajiz())
        .args([
            "--audit",
            "--audit-output", &out_path,
            "/usr/bin/echo", "ok",
        ])
        .output()
        .expect("failed to launch hajiz");

    let profile = std::fs::read_to_string(&out_path).unwrap_or_default();
    let _ = std::fs::remove_file(&out_path);

    assert!(
        out.status.success() || out.status.code() == Some(0),
        "audit mode must finish normally, stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        profile.contains("[seccomp]") && profile.contains("allow_syscalls"),
        "the profile must contain a seccomp section with allow_syscalls, got:\n{profile}"
    );
}
