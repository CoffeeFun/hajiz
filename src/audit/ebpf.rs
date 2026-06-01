// eBPF-backed audit mode using the broker/sandbox privilege-separation pattern.
//
// Compiled in only when:
//   - feature "ebpf" is enabled (brings in the aya crate), AND
//   - build.rs successfully compiled bpf/audit_syscalls.c with clang
//     (sets the `ebpf_compiled` cfg flag).
//
// Architecture:
//
//   parent (broker — privileged briefly)     child (sandbox — never privileged)
//     socketpair(AF_UNIX, STREAM)
//     fork() ─────────────────────────────────→ first instruction:
//                                                  drop_all_capabilities()
//     load BPF program + maps                     recv_fds()  ← gets map fds
//     attach raw_tracepoint/sys_enter             spawn target binary
//     SCM_RIGHTS send map fds  ──────────────→    bpf(MAP_UPDATE) filter PID
//     drop_all_capabilities()                     wait for target
//     read serialized report from socket  ←──    iterate syscall_map via bpf()
//     waitpid(child)                              send report bytes back
//     return AuditReport                          exit
//
// The child uses raw bpf(2) syscalls (not aya) because aya's higher-level
// types own internal state from program load — the child only has fd numbers.

#[cfg(all(feature = "ebpf", ebpf_compiled))]
pub mod inner {
    use std::collections::BTreeSet;
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, AsRawFd, OwnedFd, RawFd};
    use std::process::Command;

    use aya::{maps::Map, programs::RawTracePoint, Ebpf};
    use libseccomp::{ScmpArch, ScmpSyscall};
    use nix::sys::wait::{waitpid, WaitStatus};
    use nix::unistd::{fork, ForkResult, Pid};

    use crate::{
        audit::AuditReport,
        error::HajizError,
        privesc::{
            drop_all_capabilities, recv_fds, send_fds, socketpair_stream,
        },
    };

    static BPF_OBJ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/audit_syscalls.o"));

    pub fn run_audit_ebpf(binary: &str, args: &[String]) -> Result<AuditReport, HajizError> {
        let (parent_sock, child_sock) = socketpair_stream()?;

        // SAFETY: must be single-threaded at fork time.
        match unsafe { fork() }
            .map_err(|e| HajizError::Isolation(format!("fork: {e}")))?
        {
            ForkResult::Child => {
                // Close the parent's end immediately.
                drop(parent_sock);
                child_main(child_sock, binary, args);
            }
            ForkResult::Parent { child: child_pid } => {
                drop(child_sock);
                parent_main(parent_sock, child_pid, binary)
            }
        }
    }

    // ─── Child (sandbox) ─────────────────────────────────────────────────────
    //
    // The very first thing the child does is drop ALL capabilities. From that
    // point on it cannot load BPF programs, mount filesystems, or do anything
    // privileged. It can only USE the fds the broker hands it.
    fn child_main(sock: OwnedFd, binary: &str, args: &[String]) -> ! {
        if let Err(e) = drop_all_capabilities() {
            eprintln!("[hajiz:audit:child] drop caps: {e}");
            std::process::exit(101);
        }

        let exit_code = match child_run(sock, binary, args) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("[hajiz:audit:child] {e}");
                102
            }
        };
        std::process::exit(exit_code);
    }

    fn child_run(sock: OwnedFd, binary: &str, args: &[String]) -> Result<i32, HajizError> {
        // Receive [config_map_fd, syscall_map_fd] from the broker.
        let fds = recv_fds(sock.as_fd(), 2)?;
        let config_fd = fds[0].as_raw_fd();
        let syscall_fd = fds[1].as_raw_fd();

        // Spawn target.
        let mut target = Command::new(binary)
            .args(args)
            .spawn()
            .map_err(|e| HajizError::Isolation(format!("spawn target: {e}")))?;
        let target_pid = target.id();

        // Set BPF filter: config_map[0] = target_pid.
        bpf_sys::map_update_u32_u64(config_fd, 0, target_pid as u64)?;

        // Wait for target.
        let status = target
            .wait()
            .map_err(|e| HajizError::Isolation(format!("wait target: {e}")))?;
        let exit_code = status.code().unwrap_or(-1);

        // Stop filtering.
        let _ = bpf_sys::map_update_u32_u64(config_fd, 0, 0);

        // Drain syscall_map by iterating keys.
        let mut syscalls: BTreeSet<String> = BTreeSet::new();
        let mut current: Option<u32> = None;
        loop {
            match bpf_sys::map_get_next_key_u32(syscall_fd, current)? {
                Some(next_key) => {
                    let name = ScmpSyscall::from(next_key as i32)
                        .get_name_by_arch(ScmpArch::Native)
                        .unwrap_or_else(|_| format!("syscall_{next_key}"));
                    syscalls.insert(name);
                    current = Some(next_key);
                }
                None => break,
            }
        }

        // Send results back to broker as a simple line protocol.
        let mut buf = String::new();
        buf.push_str(&format!("EXIT:{exit_code}\n"));
        for s in &syscalls {
            buf.push_str(s);
            buf.push('\n');
        }

        // Write to the socket and drop it so the broker sees EOF.
        let mut sock_file = std::fs::File::from(sock);
        sock_file
            .write_all(buf.as_bytes())
            .map_err(|e| HajizError::Isolation(format!("write report: {e}")))?;
        drop(sock_file);

        Ok(exit_code)
    }

    // ─── Parent (broker) ─────────────────────────────────────────────────────
    fn parent_main(
        sock: OwnedFd,
        child_pid: Pid,
        _binary: &str,
    ) -> Result<AuditReport, HajizError> {
        // Load BPF and attach. This is the privileged window.
        let mut bpf = Ebpf::load(BPF_OBJ)
            .map_err(|e| HajizError::Isolation(format!("BPF load: {e}")))?;

        let prog: &mut RawTracePoint = bpf
            .program_mut("audit_sys_enter")
            .ok_or_else(|| HajizError::Isolation("BPF program not found".into()))?
            .try_into()
            .map_err(|e| HajizError::Isolation(format!("BPF program type: {e}")))?;
        prog.load()
            .map_err(|e| HajizError::Isolation(format!("BPF prog load: {e}")))?;
        // The link is owned by the program inside `bpf`; it stays attached for
        // as long as `bpf` lives. We keep `bpf` on the stack for the whole audit.
        prog.attach("sys_enter")
            .map_err(|e| HajizError::Isolation(format!("BPF attach: {e}")))?;

        // Get raw fds for the two maps and hand them to the child.
        let config_fd = map_raw_fd(&bpf, "config_map")?;
        let syscall_fd = map_raw_fd(&bpf, "syscall_map")?;
        send_fds(sock.as_fd(), &[config_fd, syscall_fd])?;

        // Privileged window ends NOW. From here on the broker is unprivileged.
        // The BPF objects stay alive because we still hold the aya `bpf` handle
        // (which keeps the prog/link/maps pinned in the kernel).
        drop_all_capabilities()?;

        // Read the report the child sends back.
        let mut sock_file = std::fs::File::from(sock);
        let mut text = String::new();
        sock_file
            .read_to_string(&mut text)
            .map_err(|e| HajizError::Isolation(format!("read report: {e}")))?;

        // Reap the child.
        match waitpid(child_pid, None) {
            Ok(WaitStatus::Exited(_, _)) | Ok(WaitStatus::Signaled(_, _, _)) => {}
            Ok(other) => eprintln!("[hajiz:audit:broker] unexpected wait: {other:?}"),
            Err(e) => eprintln!("[hajiz:audit:broker] waitpid: {e}"),
        }

        // Parse simple line protocol: "EXIT:N" then one syscall per line.
        let mut report = AuditReport::default();
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("EXIT:") {
                report.exit_code = rest.parse().unwrap_or(-1);
            } else if !line.is_empty() {
                report.syscalls.insert(line.to_string());
            }
        }

        Ok(report)
    }

    // Extract the raw fd of a named map. aya 0.13's `Map` is an enum whose
    // variants all wrap a `MapData`; we pattern-match the two we use.
    fn map_raw_fd(bpf: &Ebpf, name: &str) -> Result<RawFd, HajizError> {
        let map = bpf
            .map(name)
            .ok_or_else(|| HajizError::Isolation(format!("map {name} missing")))?;
        let map_data = match map {
            Map::Array(d) | Map::HashMap(d) => d,
            _ => {
                return Err(HajizError::Isolation(format!(
                    "map {name}: unsupported variant"
                )))
            }
        };
        Ok(map_data.fd().as_fd().as_raw_fd())
    }

    // ─── Raw bpf(2) syscall helpers (used by the unprivileged child) ─────────
    //
    // The child can't use aya — aya owns map state in user memory that the
    // child doesn't have. It only has fd numbers. So we issue bpf(2) directly.
    mod bpf_sys {
        use nix::libc;

        use crate::error::HajizError;

        // Subset of `enum bpf_cmd` from <linux/bpf.h> we use.
        const BPF_MAP_LOOKUP_ELEM: i32 = 1;
        const BPF_MAP_UPDATE_ELEM: i32 = 2;
        const BPF_MAP_GET_NEXT_KEY: i32 = 4;

        // Subset of `union bpf_attr` for map ops. The kernel reads exactly
        // size_of::<MapAttr> bytes; layout matches the struct in bpf.h:
        //   __u32 map_fd; (4 bytes + 4 padding to align next __aligned_u64)
        //   __aligned_u64 key;
        //   __aligned_u64 value | next_key;
        //   __u64 flags;
        #[repr(C)]
        struct MapAttr {
            map_fd: u32,
            _pad: u32,
            key: u64,
            value_or_next_key: u64,
            flags: u64,
        }

        unsafe fn bpf(cmd: i32, attr: &MapAttr) -> i64 {
            libc::syscall(
                libc::SYS_bpf,
                cmd,
                attr as *const MapAttr,
                std::mem::size_of::<MapAttr>() as u32,
            )
        }

        pub fn map_update_u32_u64(map_fd: i32, key: u32, value: u64) -> Result<(), HajizError> {
            let attr = MapAttr {
                map_fd: map_fd as u32,
                _pad: 0,
                key: &key as *const u32 as u64,
                value_or_next_key: &value as *const u64 as u64,
                flags: 0, // BPF_ANY
            };
            let r = unsafe { bpf(BPF_MAP_UPDATE_ELEM, &attr) };
            if r < 0 {
                Err(HajizError::Isolation(format!(
                    "bpf(MAP_UPDATE_ELEM): {}",
                    std::io::Error::last_os_error()
                )))
            } else {
                Ok(())
            }
        }

        pub fn map_get_next_key_u32(
            map_fd: i32,
            current: Option<u32>,
        ) -> Result<Option<u32>, HajizError> {
            let mut next: u32 = 0;
            let key_ptr = match &current {
                Some(k) => k as *const u32 as u64,
                None => 0, // NULL → returns the first key
            };
            let attr = MapAttr {
                map_fd: map_fd as u32,
                _pad: 0,
                key: key_ptr,
                value_or_next_key: &mut next as *mut u32 as u64,
                flags: 0,
            };
            let r = unsafe { bpf(BPF_MAP_GET_NEXT_KEY, &attr) };
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENOENT) {
                    Ok(None) // end of iteration
                } else {
                    Err(HajizError::Isolation(format!("bpf(GET_NEXT_KEY): {err}")))
                }
            } else {
                Ok(Some(next))
            }
        }

        // Currently unused but kept for completeness (could be useful if we
        // want call counts in the report).
        #[allow(dead_code)]
        pub fn map_lookup_u32_u64(map_fd: i32, key: u32) -> Result<u64, HajizError> {
            let mut value: u64 = 0;
            let attr = MapAttr {
                map_fd: map_fd as u32,
                _pad: 0,
                key: &key as *const u32 as u64,
                value_or_next_key: &mut value as *mut u64 as u64,
                flags: 0,
            };
            let r = unsafe { bpf(BPF_MAP_LOOKUP_ELEM, &attr) };
            if r < 0 {
                Err(HajizError::Isolation(format!(
                    "bpf(MAP_LOOKUP_ELEM): {}",
                    std::io::Error::last_os_error()
                )))
            } else {
                Ok(value)
            }
        }
    }
}
