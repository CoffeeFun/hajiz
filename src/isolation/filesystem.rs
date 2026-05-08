use std::{
    ffi::CString,
    os::fd::RawFd,
};

use nix::libc;

use crate::{
    error::HajizError,
    isolation::{FilesystemRule, IsolationConfig},
};

#[repr(C)]
struct LandlockRulesetAttrAbi4 {
    handled_access_fs: u64,
    handled_access_net: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct LandlockNetPortAttr {
    allowed_access: u64,
    port: u64,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_RULE_NET_PORT: u32 = 2;

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

const ACCESS_EXECUTE: u64 = 1 << 0;
const ACCESS_WRITE_FILE: u64 = 1 << 1;
const ACCESS_READ_FILE: u64 = 1 << 2;
const ACCESS_READ_DIR: u64 = 1 << 3;

const ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

fn fs_handled_mask() -> u64 {
    ACCESS_EXECUTE | ACCESS_WRITE_FILE | ACCESS_READ_FILE | ACCESS_READ_DIR
}

fn fs_allowed_mask(rule: &FilesystemRule) -> u64 {
    if rule.read_only {
        ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR
    } else {
        ACCESS_EXECUTE | ACCESS_READ_FILE | ACCESS_READ_DIR | ACCESS_WRITE_FILE
    }
}

/// Returns the running kernel's Landlock ABI version (>= 1) or None if unsupported.
fn detect_abi() -> Option<i64> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttrAbi4>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if result < 0 {
        None
    } else {
        Some(result)
    }
}

pub fn setup_landlock(config: &IsolationConfig, skip_landlock: bool) -> Result<(), HajizError> {
    let want_fs = !config.filesystem_rules.is_empty();
    let want_net = config.restrict_tcp_connect() || config.restrict_tcp_bind();

    if skip_landlock {
        if want_fs || want_net {
            eprintln!(
                "[hajiz] avertissement: Landlock non disponible (kernel < 5.13), \
                 {} règles fs / {} ports connect / {} ports bind ignorés",
                config.filesystem_rules.len(),
                config.allow_connect_ports.len(),
                config.allow_bind_ports.len(),
            );
        }
        return Ok(());
    }

    if !want_fs && !want_net {
        return Ok(());
    }

    let abi = detect_abi();
    let net_supported = abi.map(|v| v >= 4).unwrap_or(false);

    if want_net && !net_supported {
        eprintln!(
            "[hajiz] avertissement: Landlock ABI < 4 (kernel < 6.7), \
             règles réseau ignorées — utilisez network_mode=none pour bloquer tout le trafic"
        );
    }

    let effective_net = want_net && net_supported;
    let mut handled_fs: u64 = 0;
    let mut handled_net: u64 = 0;

    if want_fs {
        handled_fs = fs_handled_mask();
    }
    if effective_net {
        if config.restrict_tcp_connect() {
            handled_net |= ACCESS_NET_CONNECT_TCP;
        }
        if config.restrict_tcp_bind() {
            handled_net |= ACCESS_NET_BIND_TCP;
        }
    }

    let ruleset_fd = create_ruleset(handled_fs, handled_net)?;

    for rule in &config.filesystem_rules {
        add_path_rule(ruleset_fd, rule)?;
    }

    if effective_net {
        for port in &config.allow_connect_ports {
            add_net_port_rule(ruleset_fd, *port, ACCESS_NET_CONNECT_TCP)?;
        }
        for port in &config.allow_bind_ports {
            add_net_port_rule(ruleset_fd, *port, ACCESS_NET_BIND_TCP)?;
        }
    }

    let restrict_result =
        unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };
    let close_result = unsafe { libc::close(ruleset_fd) };
    if close_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to close Landlock ruleset fd: {err}"
        )));
    }

    if restrict_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to enforce Landlock ruleset: {err}"
        )));
    }

    Ok(())
}

fn create_ruleset(handled_fs: u64, handled_net: u64) -> Result<RawFd, HajizError> {
    let attr = LandlockRulesetAttrAbi4 {
        handled_access_fs: handled_fs,
        handled_access_net: handled_net,
    };

    // Pass the size matching the fields we actually set. If only fs is requested
    // and kernel is ABI 1-3, it accepts size=8; ABI 4+ accepts size=16.
    let size = if handled_net != 0 {
        std::mem::size_of::<LandlockRulesetAttrAbi4>()
    } else {
        std::mem::size_of::<u64>()
    };

    let result = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const LandlockRulesetAttrAbi4,
            size,
            0,
        )
    };

    if result < 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to create Landlock ruleset (kernel may not support it): {err}"
        )));
    }

    Ok(result as RawFd)
}

fn add_path_rule(ruleset_fd: RawFd, rule: &FilesystemRule) -> Result<(), HajizError> {
    let c_path = CString::new(rule.path.clone())
        .map_err(|_| HajizError::Config(format!("invalid filesystem path '{}': contains NUL", rule.path)))?;

    let path_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if path_fd < 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to open Landlock path '{}': {err}",
            rule.path
        )));
    }

    let attr = LandlockPathBeneathAttr {
        allowed_access: fs_allowed_mask(rule),
        parent_fd: path_fd,
    };

    let add_result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_PATH_BENEATH,
            &attr as *const LandlockPathBeneathAttr,
            0,
        )
    };

    let close_result = unsafe { libc::close(path_fd) };
    if close_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to close Landlock path fd for '{}': {err}",
            rule.path
        )));
    }

    if add_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to add Landlock rule for '{}': {err}",
            rule.path
        )));
    }

    Ok(())
}

fn add_net_port_rule(ruleset_fd: RawFd, port: u16, allowed_access: u64) -> Result<(), HajizError> {
    let attr = LandlockNetPortAttr {
        allowed_access,
        port: port as u64,
    };

    let add_result = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd,
            LANDLOCK_RULE_NET_PORT,
            &attr as *const LandlockNetPortAttr,
            0,
        )
    };

    if add_result != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to add Landlock net rule for port {port}: {err}"
        )));
    }

    Ok(())
}
