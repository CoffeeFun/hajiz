pub mod ebpf;
pub mod generator;
pub mod strace;

pub use generator::generate_profile;
pub use strace::{parse_strace_log, AuditReport};

use crate::error::HajizError;

/// Run an audit of `binary` with `args`, collecting its syscall usage.
///
/// Backend selection at runtime:
///   1. eBPF (feature "ebpf" + clang compiled `audit_syscalls.o`):
///      used when the process has root / CAP_BPF.  Implements the
///      fork-and-orphan privilege-separation pattern — no strace required.
///   2. strace fallback: used when BPF is unavailable or unprivileged.
pub fn run_audit(binary: &str, args: &[String]) -> Result<AuditReport, HajizError> {
    #[cfg(all(feature = "ebpf", ebpf_compiled))]
    if crate::privesc::can_use_bpf() {
        eprintln!("[hajiz:audit] backend: eBPF (fork-and-orphan)");
        return ebpf::inner::run_audit_ebpf(binary, args);
    }

    eprintln!("[hajiz:audit] backend: strace (fallback)");
    strace::run_audit(binary, args)
}
