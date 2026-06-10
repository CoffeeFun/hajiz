
use std::collections::BTreeSet;

use libseccomp::{
    ScmpAction,
    ScmpFilterContext,
    ScmpSyscall,
};
use nix::libc;

use crate::{error::HajizError, isolation::IsolationConfig};

pub fn apply_seccomp(config: &IsolationConfig) -> Result<(), HajizError> {
    // Precedence: an explicitly requested mode (whitelist or strict) overrides
    // the default-on hardening filter. The hardening filter is the fallback when
    // the user asked for nothing more specific. Checking strict before hardening
    // is what makes `--strict-seccomp` take effect without also needing
    // `--no-hardening` (the two explicit modes are stricter than hardening anyway).
    if config.use_seccomp_whitelist {
        apply_whitelist_filter(config)?;
        return Ok(());
    }

    if config.strict_seccomp {
        let result = unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_STRICT, 0, 0, 0) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            return Err(HajizError::Isolation(format!(
                "failed to enable strict seccomp mode: {err}"
            )));
        }
        return Ok(());
    }

    if config.enable_hardening_filter {
        apply_hardening_filter(config.kill_on_deny)?;
        return Ok(());
    }

    Ok(())
}

fn apply_hardening_filter(kill_on_deny: bool) -> Result<(), HajizError> {
    // Default-allow, then deny high-risk primitives often used to expand privilege
    // or escape sandboxes when user namespaces are available.
    let mut filter = ScmpFilterContext::new_filter(ScmpAction::Allow)
        .map_err(|e| HajizError::Isolation(format!("failed to create hardening seccomp filter: {e}")))?;

    let deny_action = deny_action(kill_on_deny);
    for syscall_name in hardened_denied_syscalls() {
        let syscall = ScmpSyscall::from_name(syscall_name)
            .map_err(|_| HajizError::Config(format!("unknown hardening syscall name: {syscall_name}")))?;
        filter
            .add_rule(deny_action, syscall)
            .map_err(|e| HajizError::Isolation(format!(
                "failed to add hardening seccomp rule for {syscall_name}: {e}"
            )))?;
    }

    // Emit kernel audit messages on denied syscalls so the parent can read
    // them via /dev/kmsg and surface SyscallDenied telemetry events.
    let _ = filter.set_ctl_log(true);

    filter
        .load()
        .map_err(|e| HajizError::Isolation(format!("failed to load hardening seccomp filter: {e}")))?;

    Ok(())
}

/// Action applied to a denied syscall.
/// - `kill_on_deny=false` → return EPERM (program continues with errno)
/// - `kill_on_deny=true`  → SECCOMP_RET_KILL_PROCESS (kernel kills entire process,
///   still emits an audit record so SyscallDenied can be logged)
fn deny_action(kill_on_deny: bool) -> ScmpAction {
    if kill_on_deny {
        ScmpAction::KillProcess
    } else {
        ScmpAction::Errno(libc::EPERM)
    }
}

pub fn hardened_denied_syscalls() -> &'static [&'static str] {
    &[
        "unshare",
        "setns",
        "clone3",
        "bpf",
        "userfaultfd",
        "add_key",
        "request_key",
        "keyctl",
        // Block process injection (T1055.008): ptrace for the classic
        // attach, process_vm_readv/writev for direct memory read/write
        // that bypasses ptrace.
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
    ]
}

fn apply_whitelist_filter(config: &IsolationConfig) -> Result<(), HajizError> {
    let allowed = resolve_allowed_syscalls(config);

    let mut filter = ScmpFilterContext::new_filter(deny_action(config.kill_on_deny))
        .map_err(|e| HajizError::Isolation(format!("failed to create seccomp filter: {e}")))?;

    for syscall_name in allowed {
        let syscall = ScmpSyscall::from_name(&syscall_name)
            .map_err(|_| HajizError::Config(format!("unknown syscall in seccomp policy: {syscall_name}")))?;
        filter
            .add_rule(ScmpAction::Allow, syscall)
            .map_err(|e| HajizError::Isolation(format!("failed to add seccomp rule for {syscall_name}: {e}")))?;
    }

    let _ = filter.set_ctl_log(true);

    filter
        .load()
        .map_err(|e| HajizError::Isolation(format!("failed to load seccomp filter: {e}")))?;

    Ok(())
}

pub(crate) fn resolve_allowed_syscalls(config: &IsolationConfig) -> BTreeSet<String> {
    resolve_allowed_syscalls_from_policy(
        &config.seccomp_syscall_groups,
        &config.seccomp_allow_syscalls,
    )
}

pub fn resolve_allowed_syscalls_from_policy(
    groups: &[String],
    explicit_allow: &[String],
) -> BTreeSet<String> {
    let mut allowed: BTreeSet<String> = baseline_syscalls()
        .into_iter()
        .map(|name| name.to_string())
        .collect();

    for group in groups {
        for syscall_name in syscall_group(group) {
            allowed.insert(syscall_name.to_string());
        }
    }

    for syscall_name in explicit_allow {
        allowed.insert(syscall_name.to_string());
    }

    allowed
}

fn baseline_syscalls() -> BTreeSet<&'static str> {
    [
        "read",
        "write",
        "close",
        "fstat",
        "newfstatat",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "futex",
        "set_tid_address",
        "set_robust_list",
        "arch_prctl",
        "prlimit64",
        "clock_gettime",
        "getrandom",
        "getpid",
        "gettid",
        "exit",
        "exit_group",
        "execve",
        "execveat",
        "openat",
        "access",
    ]
    .into_iter()
    .collect()
}

fn syscall_group(group: &str) -> &'static [&'static str] {
    match group {
        "io" => &["open", "openat", "close", "read", "write", "lseek", "fstat", "newfstatat", "stat"],
        "memory" => &["mmap", "mprotect", "munmap", "brk", "madvise"],
        "threading" => &["clone", "clone3", "futex", "set_tid_address", "set_robust_list"],
        "network" => &["socket", "connect", "sendto", "sendmsg", "recvfrom", "recvmsg", "bind", "listen", "accept", "accept4"],
        "process" => &["fork", "vfork", "execve", "execveat", "wait4", "waitid", "kill", "getpid"],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apply_seccomp,
        resolve_allowed_syscalls,
    };
    use nix::{
        libc,
        sys::wait::{
            waitpid,
            WaitStatus,
        },
        unistd::{
            fork,
            ForkResult,
        },
    };
    use crate::isolation::IsolationConfig;

    fn config_with_groups(groups: &[&str]) -> IsolationConfig {
        IsolationConfig {
            use_seccomp_whitelist: true,
            seccomp_syscall_groups: groups.iter().map(|g| g.to_string()).collect(),
            ..IsolationConfig::default()
        }
    }

    #[test]
    fn network_group_adds_socket_calls() {
        let config = config_with_groups(&["network"]);
        let allowed = resolve_allowed_syscalls(&config);
        assert!(allowed.contains("socket"));
        assert!(allowed.contains("connect"));
    }

    #[test]
    fn no_network_group_keeps_socket_denied() {
        let config = config_with_groups(&["io", "memory", "threading", "process"]);
        let allowed = resolve_allowed_syscalls(&config);
        assert!(!allowed.contains("socket"));
        assert!(!allowed.contains("connect"));
    }

    #[test]
    fn explicit_allow_adds_known_syscall() {
        let mut config = config_with_groups(&[]);
        config.seccomp_allow_syscalls = vec!["wait4".to_string()];
        let allowed = resolve_allowed_syscalls(&config);
        assert!(allowed.contains("wait4"));
    }

    #[test]
    fn runtime_seccomp_blocks_socket_without_network_group() {
        let config = config_with_groups(&["io", "memory", "threading", "process"]);
        let exit_code = run_socket_probe_under_seccomp(config);
        assert_eq!(exit_code, 0, "expected socket to be denied with EPERM");
    }

    #[test]
    fn runtime_seccomp_allows_socket_with_network_group() {
        let config = config_with_groups(&["io", "memory", "threading", "process", "network"]);
        let exit_code = run_socket_probe_under_seccomp(config);
        assert_eq!(exit_code, 0, "expected socket to be allowed with network group");
    }

    #[test]
    fn hardening_profile_blocks_namespace_entry_syscalls() {
        let denied = super::hardened_denied_syscalls();
        assert!(denied.contains(&"unshare"));
        assert!(denied.contains(&"setns"));
        assert!(denied.contains(&"clone3"));
    }

    #[test]
    fn hardening_profile_blocks_process_injection_syscalls() {
        let denied = super::hardened_denied_syscalls();
        assert!(denied.contains(&"ptrace"));
        assert!(denied.contains(&"process_vm_readv"));
        assert!(denied.contains(&"process_vm_writev"));
    }

    #[test]
    fn strict_seccomp_overrides_default_hardening() {
        // Regression test for the seccomp precedence fix: when --strict-seccomp
        // is requested while the default hardening filter is still enabled,
        // strict mode must win. Under SECCOMP_MODE_STRICT only read/write/exit/
        // sigreturn are allowed, so socket() gets the process SIGKILL'd. If the
        // hardening filter were applied instead (the old buggy behavior),
        // socket() would be allowed and the child would exit 7.
        let config = IsolationConfig {
            strict_seccomp: true,
            enable_hardening_filter: true, // default-on; strict must override it
            ..IsolationConfig::default()
        };

        let fork_result = unsafe { fork() }.expect("fork should succeed");
        match fork_result {
            ForkResult::Parent { child } => {
                let status = waitpid(child, None).expect("waitpid should succeed");
                match status {
                    WaitStatus::Signaled(_, signal, _) => {
                        assert_eq!(
                            signal,
                            nix::sys::signal::Signal::SIGKILL,
                            "strict seccomp must SIGKILL on a non-allowed syscall"
                        );
                    }
                    other => panic!(
                        "expected child SIGKILL'd by strict seccomp, got {other:?} \
                         (hardening filter was applied instead of strict?)"
                    ),
                }
            }
            ForkResult::Child => {
                if apply_seccomp(&config).is_err() {
                    unsafe { libc::_exit(2) };
                }
                // socket() is not in the strict allowlist → kernel kills us.
                let _ = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                // Reached only if strict was NOT applied (i.e. the bug regressed).
                unsafe { libc::_exit(7) };
            }
        }
    }

    #[test]
    fn kill_on_deny_kills_child_on_denied_syscall() {
        use nix::sys::wait::WaitStatus;
        let mut config = config_with_groups(&["io", "memory", "threading", "process"]);
        config.use_seccomp_whitelist = true;
        config.kill_on_deny = true;

        let fork_result = unsafe { fork() }.expect("fork should succeed");
        match fork_result {
            ForkResult::Parent { child } => {
                let status = waitpid(child, None).expect("waitpid should succeed");
                match status {
                    WaitStatus::Signaled(_, signal, _) => {
                        assert_eq!(
                            signal,
                            nix::sys::signal::Signal::SIGSYS,
                            "expected SIGSYS from KILL_PROCESS"
                        );
                    }
                    other => panic!(
                        "expected child killed by SIGSYS, got {other:?}"
                    ),
                }
            }
            ForkResult::Child => {
                if apply_seccomp(&config).is_err() {
                    unsafe { libc::_exit(2) };
                }
                // socket() is not in the io/memory/threading/process groups,
                // so it is denied. With kill_on_deny=true, calling it must
                // cause the kernel to kill us with SIGSYS rather than return EPERM.
                let _ = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
                // If we get here, the kernel did not kill us — fail visibly.
                unsafe { libc::_exit(7) };
            }
        }
    }

    fn run_socket_probe_under_seccomp(mut config: IsolationConfig) -> i32 {
        config.use_seccomp_whitelist = true;

        let fork_result = unsafe { fork() }.expect("fork should succeed");
        match fork_result {
            ForkResult::Parent { child } => {
                match waitpid(child, None).expect("waitpid should succeed") {
                    WaitStatus::Exited(_, code) => code,
                    other => panic!("unexpected child status: {other:?}"),
                }
            }
            ForkResult::Child => {
                let outcome = child_socket_probe(config);
                unsafe {
                    libc::_exit(outcome);
                }
            }
        }
    }

    fn child_socket_probe(config: IsolationConfig) -> i32 {
        if apply_seccomp(&config).is_err() {
            return 2;
        }

        let socket_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
        if config.seccomp_syscall_groups.iter().any(|group| group == "network") {
            if socket_fd >= 0 {
                unsafe {
                    libc::close(socket_fd);
                }
                return 0;
            }
            return 3;
        }

        if socket_fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return 0;
            }
            return 4;
        }

        unsafe {
            libc::close(socket_fd);
        }
        5
    }
}
