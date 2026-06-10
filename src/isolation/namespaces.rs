use std::mem::MaybeUninit;

use nix::{
    libc,
    mount::{mount, MsFlags},
    sched::{unshare, CloneFlags},
};

use crate::{
    error::HajizError,
    isolation::{IsolationConfig, NetworkMode},
};

pub fn setup_namespaces(config: &IsolationConfig) -> Result<(), HajizError> {
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    let mut flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS;
    if config.network_mode.unshare_netns() {
        flags |= CloneFlags::CLONE_NEWNET;
    }

    unshare(flags).map_err(|e| {
        HajizError::Isolation(format!("failed to unshare namespaces: {e}{}", userns_hint(e)))
    })?;

    // Deny setgroups before writing gid_map (required by kernel)
    std::fs::write("/proc/self/setgroups", "deny")
        .map_err(|e| HajizError::Isolation(format!("failed to deny setgroups: {e}")))?;

    // Identity UID mapping: process keeps its real UID inside the namespace
    std::fs::write("/proc/self/uid_map", format!("{uid} {uid} 1"))
        .map_err(|e| HajizError::Isolation(format!("failed to write uid_map: {e}")))?;

    // Identity GID mapping
    std::fs::write("/proc/self/gid_map", format!("{gid} {gid} 1"))
        .map_err(|e| HajizError::Isolation(format!("failed to write gid_map: {e}")))?;

    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| HajizError::Isolation(format!("failed to set mount propagation: {e}")))?;

    if config.network_mode == NetworkMode::Loopback {
        // CAP_NET_ADMIN inside our user namespace lets us configure interfaces
        // in the netns we just created, even though we have no real privileges.
        bring_loopback_up()?;
    }

    Ok(())
}

/// On an `EPERM` from `unshare(CLONE_NEWUSER)`, return a hint string explaining
/// the most common cause. Ubuntu 23.10+ ships
/// `kernel.apparmor_restrict_unprivileged_userns=1`, which blocks unprivileged
/// user namespaces unless the binary has an AppArmor profile granting `userns,`.
/// Returns an empty string for any other error or platform.
fn userns_hint(err: nix::errno::Errno) -> String {
    if err != nix::errno::Errno::EPERM {
        return String::new();
    }
    let restricted = std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    if restricted {
        "\n[hajiz] kernel.apparmor_restrict_unprivileged_userns=1 (Ubuntu 23.10+) \
         blocks unprivileged user namespaces. Install the bundled AppArmor \
         profile:\n  sudo cp packaging/apparmor/hajiz /etc/apparmor.d/hajiz\n  \
         sudo systemctl reload apparmor"
            .to_string()
    } else {
        String::new()
    }
}

fn bring_loopback_up() -> Result<(), HajizError> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(HajizError::Isolation(format!(
            "loopback up: socket() failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let result = configure_loopback(fd);
    unsafe { libc::close(fd) };
    result
}

fn configure_loopback(fd: i32) -> Result<(), HajizError> {
    // A fresh netns has `lo` present but DOWN with no addresses. Assigning
    // 127.0.0.1/8 then setting IFF_UP makes loopback usable for local services.
    set_inaddr(fd, libc::SIOCSIFADDR, [127, 0, 0, 1])?;
    set_inaddr(fd, libc::SIOCSIFNETMASK, [255, 0, 0, 0])?;
    set_iff_up(fd)
}

fn lo_ifreq() -> libc::ifreq {
    let mut ifr: libc::ifreq = unsafe { MaybeUninit::zeroed().assume_init() };
    let name = b"lo";
    for (i, b) in name.iter().enumerate() {
        ifr.ifr_name[i] = *b as libc::c_char;
    }
    ifr
}

fn set_inaddr(fd: i32, request: libc::c_ulong, octets: [u8; 4]) -> Result<(), HajizError> {
    let mut ifr = lo_ifreq();
    let mut sin: libc::sockaddr_in = unsafe { MaybeUninit::zeroed().assume_init() };
    sin.sin_family = libc::AF_INET as libc::sa_family_t;
    sin.sin_addr.s_addr = u32::from_ne_bytes(octets);

    unsafe {
        let dest = &mut ifr.ifr_ifru.ifru_addr as *mut libc::sockaddr;
        std::ptr::copy_nonoverlapping(
            &sin as *const libc::sockaddr_in as *const u8,
            dest as *mut u8,
            std::mem::size_of::<libc::sockaddr_in>(),
        );
    }

    let res = unsafe { libc::ioctl(fd, request, &ifr) };
    if res < 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "loopback up: ioctl(0x{request:x}) failed: {err}"
        )));
    }
    Ok(())
}

fn set_iff_up(fd: i32) -> Result<(), HajizError> {
    let mut ifr = lo_ifreq();
    let res = unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS, &mut ifr) };
    if res < 0 {
        return Err(HajizError::Isolation(format!(
            "loopback up: SIOCGIFFLAGS failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    unsafe {
        ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
    }
    let res = unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS, &ifr) };
    if res < 0 {
        return Err(HajizError::Isolation(format!(
            "loopback up: SIOCSIFFLAGS failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}
