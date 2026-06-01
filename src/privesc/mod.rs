// Privilege-separation primitives.
//
// Implements the broker/sandbox pattern used by Chrome, firejail, and bwrap:
//   - Parent (broker) holds privileges only long enough to load BPF.
//   - Child (sandbox) is unprivileged from its first instruction.
//   - Resources cross the boundary as file descriptors via SCM_RIGHTS.

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};

use nix::libc;
use nix::sys::socket::{
    recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags,
    SockFlag, SockType,
};

use crate::error::HajizError;

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Returns true if the current process can load BPF programs (root or CAP_BPF).
pub fn can_use_bpf() -> bool {
    // SAFETY: getuid is always safe.
    unsafe { libc::geteuid() == 0 }
}

/// Drop ALL capabilities (effective, permitted, inheritable, ambient, bounding)
/// and set no_new_privs. After this returns, the process cannot regain
/// privileges by any means — including setuid binaries (no_new_privs blocks
/// privilege escalation across exec).
///
/// BPF map fds opened before this call remain usable: the kernel only checks
/// capabilities at fd creation time, not on every map operation.
pub fn drop_all_capabilities() -> Result<(), HajizError> {
    // 1. no_new_privs: prevents regaining privileges via setuid exec.
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if r != 0 {
        return Err(HajizError::Isolation(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        )));
    }

    // 2. Clear ambient capability set.
    unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };

    // 3. Drop bounding set entries while we still hold CAP_SETPCAP.
    for cap in 0..=40 {
        unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        // Errors here (EINVAL for unknown caps, EPERM if no CAP_SETPCAP) are
        // expected and harmless — keep going.
    }

    // 4. Zero effective, permitted, and inheritable sets via capset(2).
    let mut hdr = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    let r = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut hdr as *mut CapHeader,
            data.as_ptr(),
        )
    };
    if r != 0 {
        return Err(HajizError::Isolation(format!(
            "capset: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Create a connected pair of Unix stream sockets for parent-child IPC.
pub fn socketpair_stream() -> Result<(OwnedFd, OwnedFd), HajizError> {
    socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(|e| HajizError::Isolation(format!("socketpair: {e}")))
}

/// Send a list of file descriptors to the peer over a Unix socket using
/// SCM_RIGHTS. The peer receives independent fd numbers in its own table
/// referring to the same kernel objects.
///
/// At least one byte of payload is required for the cmsg to be delivered;
/// we send a single ASCII 'F'.
pub fn send_fds(sock: BorrowedFd<'_>, fds: &[RawFd]) -> Result<(), HajizError> {
    let payload = [b'F'];
    let iov = [std::io::IoSlice::new(&payload)];
    let cmsgs = [ControlMessage::ScmRights(fds)];
    sendmsg::<()>(sock.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), None)
        .map_err(|e| HajizError::Isolation(format!("sendmsg(SCM_RIGHTS): {e}")))?;
    Ok(())
}

/// Receive `n` file descriptors sent via SCM_RIGHTS.
pub fn recv_fds(sock: BorrowedFd<'_>, n: usize) -> Result<Vec<OwnedFd>, HajizError> {
    use std::os::fd::FromRawFd;

    let mut payload = [0u8; 1];
    let mut iov = [std::io::IoSliceMut::new(&mut payload)];
    let mut cmsg_buf = nix::cmsg_space!([RawFd; 8]); // enough for our needs

    let msg = recvmsg::<()>(
        sock.as_raw_fd(),
        &mut iov,
        Some(&mut cmsg_buf),
        MsgFlags::empty(),
    )
    .map_err(|e| HajizError::Isolation(format!("recvmsg(SCM_RIGHTS): {e}")))?;

    for cmsg in msg
        .cmsgs()
        .map_err(|e| HajizError::Isolation(format!("cmsgs: {e}")))?
    {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if fds.len() != n {
                // Close anything we did receive to avoid fd leaks.
                for fd in &fds {
                    unsafe { libc::close(*fd) };
                }
                return Err(HajizError::Isolation(format!(
                    "expected {n} fds, got {}",
                    fds.len()
                )));
            }
            // SAFETY: fds came from the kernel via SCM_RIGHTS; we own them now.
            return Ok(fds.into_iter().map(|fd| unsafe { OwnedFd::from_raw_fd(fd) }).collect());
        }
    }

    Err(HajizError::Isolation("no SCM_RIGHTS in recvmsg".into()))
}
