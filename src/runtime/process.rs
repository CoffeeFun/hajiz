use std::{
    ffi::c_int,
    path::PathBuf,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    os::unix::process::CommandExt,
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::Duration,
};

use nix::{
    libc,
    sys::signal::{self, Signal},
    unistd::Pid,
};

use crate::{
    error::HajizError,
    isolation::{
        self,
        IsolationConfig,
    },
    privesc,
};

// ---------------------------------------------------------------------------
// Global termination flag — written only from signal handler (atomic, safe).
// ---------------------------------------------------------------------------
static TERMINATE_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination(_sig: c_int) {
    TERMINATE_REQUESTED.store(true, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// SandboxProcess
// ---------------------------------------------------------------------------

/// A sandboxed child process managed by hajiz.
pub struct SandboxProcess {
    /// The underlying OS child handle.
    child: Child,
    /// OS process ID.
    pub pid: u32,
    /// Seccomp user-notification listener fd received from the child
    /// (present when the isolation config requested seccomp_notify).
    notify_fd: Option<OwnedFd>,
}

#[derive(Debug, Clone)]
pub struct SpawnOptions {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub verbose: bool,
    pub isolation: IsolationConfig,
}

impl SandboxProcess {
    /// Spawn the target binary in a core isolation configuration.
    pub fn spawn(options: SpawnOptions) -> Result<Self, HajizError> {
        // Validate the binary exists.
        if !options.binary.exists() {
            return Err(HajizError::Config(format!(
                "binary not found: {}",
                options.binary.display()
            )));
        }

        if options.verbose {
            eprintln!("[hajiz] spawning: {}", options.binary.display());
        }

        let mut isolation_config = options.isolation;

        // Socketpair over which the child sends back the seccomp notify fd
        // (SCM_RIGHTS). Created before fork so both sides inherit it; the
        // child end is closed at exec (CLOEXEC), the parent reads after spawn.
        let notify_sockets = if isolation_config.seccomp_notify {
            match privesc::socketpair_stream() {
                Ok(pair) => Some(pair),
                Err(e) => {
                    eprintln!("[hajiz] seccomp notify disabled (socketpair failed: {e})");
                    isolation_config.seccomp_notify = false;
                    isolation_config.seccomp_fs_notify = false;
                    None
                }
            }
        } else {
            None
        };
        if let Some((_, child_end)) = &notify_sockets {
            isolation_config.notify_socket_fd = Some(child_end.as_raw_fd());
        }

        let mut command = Command::new(&options.binary);
        command
            .args(&options.args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        unsafe {
            command.pre_exec(move || {
                isolation::apply_in_child(&isolation_config)
                    .map_err(|error| std::io::Error::other(error.to_string()))
            });
        }

        let child = command.spawn()?;

        // The child sent the fd during pre_exec, strictly before exec, and
        // spawn() only returns once exec succeeded — so the message is already
        // queued and this does not block. The timeout is pure defensiveness.
        let notify_fd = notify_sockets.and_then(|(parent_end, child_end)| {
            drop(child_end);
            recv_notify_fd(&parent_end)
        });

        let pid = child.id();

        eprintln!("[hajiz] sandboxed process started (PID {pid})");

        Ok(Self { child, pid, notify_fd })
    }

    /// Take the seccomp user-notification listener fd, if one was received.
    pub fn take_notify_fd(&mut self) -> Option<OwnedFd> {
        self.notify_fd.take()
    }

    // -----------------------------------------------------------------------
    // Monitoring & graceful shutdown
    // -----------------------------------------------------------------------

    /// Block until the child exits or a termination signal is received.
    /// On signal: SIGTERM → 2 s → SIGKILL → cleanup.
    pub fn monitor(mut self) -> Result<ExitStatus, HajizError> {
        // Register SIGINT / SIGTERM handlers.
        // SAFETY: we only write to a static AtomicBool — correct for signal handlers.
        unsafe {
            signal::signal(Signal::SIGINT, signal::SigHandler::Handler(handle_termination))
                .map_err(|e| HajizError::Isolation(format!("signal setup failed: {e}")))?;
            signal::signal(Signal::SIGTERM, signal::SigHandler::Handler(handle_termination))
                .map_err(|e| HajizError::Isolation(format!("signal setup failed: {e}")))?;
        }

        loop {
            // Check if the child has exited on its own.
            if let Some(status) = self.child.try_wait()? {
                eprintln!("[hajiz] process exited: {status}");
                self.cleanup();
                return Ok(status);
            }

            // Check if we received a termination signal.
            if TERMINATE_REQUESTED.load(Ordering::SeqCst) {
                eprintln!("[hajiz] termination signal received — killing sandbox (PID {})", self.pid);
                self.kill_child(false);
                // Wait for child to actually exit.
                let status = self.child.wait()?;
                eprintln!("[hajiz] sandbox terminated: {status}");
                self.cleanup();
                return Ok(status);
            }

            thread::sleep(Duration::from_millis(100));
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Send SIGTERM, wait 2 seconds, then SIGKILL if still alive.
    fn kill_child(&mut self, force: bool) {
        let pid = self.pid;
        if force {
            eprintln!("[hajiz] sending SIGKILL to PID {pid}");
            let _ = send_signal(pid, true);
        } else {
            eprintln!("[hajiz] sending SIGTERM to PID {pid}");
            if send_signal(pid, false).is_err() {
                return; // Already dead.
            }
            // Give the process 2 seconds to exit gracefully.
            thread::sleep(Duration::from_secs(2));
            // Check if it's still alive.
            if self.child.try_wait().ok().flatten().is_none() {
                eprintln!("[hajiz] process did not exit — sending SIGKILL to PID {pid}");
                let _ = send_signal(pid, true);
            }
        }
    }

    /// Best-effort cleanup hook.
    fn cleanup(&mut self) {
        eprintln!("[hajiz] cleanup complete for PID {}", self.pid);
    }
}

/// Wait briefly for the child's SCM_RIGHTS message and extract the notify fd.
/// A marker message without fds (or a timeout) means notify is not active.
fn recv_notify_fd(sock: &OwnedFd) -> Option<OwnedFd> {
    let mut pfd = libc::pollfd {
        fd: sock.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let n = unsafe { libc::poll(&mut pfd, 1, 3000) };
    if n <= 0 || pfd.revents & libc::POLLIN == 0 {
        eprintln!("[hajiz] warning: no seccomp notify fd received — SyscallDenied telemetry degraded");
        return None;
    }
    match privesc::recv_fds(sock.as_fd(), 1) {
        Ok(mut fds) => Some(fds.remove(0)),
        Err(_) => None,
    }
}

fn send_signal(pid: u32, force: bool) -> Result<(), HajizError> {
    let nix_pid = Pid::from_raw(pid as i32);
    let sig = if force { Signal::SIGKILL } else { Signal::SIGTERM };
    signal::kill(nix_pid, sig)
        .map_err(|e| HajizError::Isolation(format!("kill({pid}) failed: {e}")))?;
    Ok(())
}
