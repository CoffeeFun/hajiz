use nix::{
    libc,
    sys::prctl,
};

use crate::{error::HajizError, isolation::IsolationConfig};

#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

pub fn drop_capabilities(config: &IsolationConfig) -> Result<(), HajizError> {
    // `--keep-caps` (drop_all_capabilities = false) is a debugging escape hatch:
    // skip the entire capability teardown so the target actually retains its
    // capabilities. Setting no_new_privs or zeroing the cap sets here would
    // defeat that, so guard the whole routine — not just the bounding-set drop.
    if !config.drop_all_capabilities {
        return Ok(());
    }

    prctl::set_no_new_privs()
        .map_err(|e| HajizError::Isolation(format!("failed to set no_new_privs: {e}")))?;

    let clear_ambient = unsafe {
        libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        )
    };
    if clear_ambient != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to clear ambient capabilities: {err}"
        )));
    }

    // Drop bounding set first, while we still have CAP_SETPCAP in the effective set.
    // PR_CAPBSET_DROP requires CAP_SETPCAP — doing this before capset() ensures we have it.
    for capability in 0..=40 {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if result != 0 {
            let err = std::io::Error::last_os_error();
            // EINVAL means the capability number is out of range — safe to ignore.
            // EPERM means we don't have CAP_SETPCAP — warn and continue.
            if err.raw_os_error() != Some(libc::EINVAL)
                && err.raw_os_error() != Some(libc::EPERM)
            {
                return Err(HajizError::Isolation(format!(
                    "failed to drop capability {capability}: {err}"
                )));
            }
        }
    }

    // Zero effective, permitted, and inheritable capability sets.
    let mut cap_header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut cap_data = [
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapUserData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];

    let clear_sets = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut cap_header as *mut CapUserHeader,
            cap_data.as_mut_ptr(),
        )
    };
    if clear_sets != 0 {
        let err = std::io::Error::last_os_error();
        return Err(HajizError::Isolation(format!(
            "failed to clear capability sets: {err}"
        )));
    }

    Ok(())
}
