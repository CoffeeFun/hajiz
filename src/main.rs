use clap::{CommandFactory, Parser};
use hajiz::{
    audit::{generate_profile, run_audit},
    cgroups::{add_to_cgroup, apply_limits, cgroup_path_for, cleanup_cgroup, ResourceLimits},
    isolation::{seccomp::hardened_denied_syscalls, FilesystemRule, IsolationConfig, NetworkMode},
    kernel::KernelCapabilities,
    profile::load_profile,
    runtime::process::{SandboxProcess, SpawnOptions},
    telemetry::{spawn_monitors, NotifyTelemetry, SecurityEvent, TelemetryLogger},
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

#[derive(Parser, Debug)]
#[command(name = "hajiz", version, about, arg_required_else_help = true)]
struct Cli {
    #[arg(long)]
    kernel_info: bool,
    #[arg(long)]
    audit: bool,
    #[arg(long = "audit-output", value_name = "FILE")]
    audit_output: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    profile: Option<PathBuf>,
    #[arg(long, value_name = "FILE")]
    log: Option<PathBuf>,
    /// Network mode: none (default, isolated), loopback (lo only), full (host)
    #[arg(long = "net", value_name = "MODE", default_value = "none")]
    net: String,
    /// Allowed outbound TCP port (connect): a single port (443) or a range (8000-8100).
    /// Repeatable. Enables a Landlock allowlist.
    #[arg(long = "allow-connect-port", value_name = "PORT|START-END")]
    allow_connect_ports: Vec<String>,
    /// Allowed listening TCP port (bind): a single port (8080) or a range (8000-8100).
    /// Repeatable. Enables a Landlock allowlist.
    #[arg(long = "allow-bind-port", value_name = "PORT|START-END")]
    allow_bind_ports: Vec<String>,
    #[arg(long)]
    keep_caps: bool,
    #[arg(long)]
    strict_seccomp: bool,
    #[arg(long)]
    seccomp_whitelist: bool,
    #[arg(long)]
    no_hardening: bool,
    /// Kill the child process when a denied syscall is observed
    /// (instead of returning EPERM). The syscall_denied event is
    /// always emitted before the process dies.
    #[arg(long = "kill-on-deny")]
    kill_on_deny: bool,
    #[arg(long = "allow-group", value_name = "GROUP")]
    syscall_groups: Vec<String>,
    #[arg(long = "allow-syscall", value_name = "SYSCALL")]
    allow_syscalls: Vec<String>,
    #[arg(long = "fs", value_name = "PATH:MODE")]
    fs_rules: Vec<String>,
    /// Memory limit (e.g. 512M, 1G)
    #[arg(long = "max-mem", value_name = "SIZE")]
    max_memory: Option<String>,
    /// CPU limit as a percentage (e.g. 50)
    #[arg(long = "max-cpu", value_name = "PERCENT")]
    max_cpu: Option<u64>,
    /// Maximum number of processes
    #[arg(long = "max-pids", value_name = "N")]
    max_pids: Option<u64>,
    #[arg(short, long)]
    verbose: bool,
    #[arg(required = false)]
    binary: Option<String>,
    /// Arguments passed through to the sandboxed binary — never parsed as
    /// hajiz options, even when they look like flags (e.g. `unshare --pid`).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

fn parse_fs_rule(s: &str) -> Option<FilesystemRule> {
    let (path, mode) = s.rsplit_once(':')?;
    let read_only = match mode {
        "ro" => true,
        "rw" => false,
        _ => return None,
    };
    Some(FilesystemRule { path: path.to_string(), read_only })
}

/// Parse a list of port specifications into a flat list of ports. Each spec is
/// either a single port ("443") or an inclusive range ("8000-8100"). Returns an
/// error describing the first malformed spec.
fn parse_port_specs(specs: &[String]) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for spec in specs {
        match spec.split_once('-') {
            Some((start, end)) => {
                let start: u16 = start
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port range '{spec}'"))?;
                let end: u16 = end
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port range '{spec}'"))?;
                if start > end {
                    return Err(format!("invalid port range '{spec}': start > end"));
                }
                ports.extend(start..=end);
            }
            None => {
                let port: u16 = spec
                    .trim()
                    .parse()
                    .map_err(|_| format!("invalid port '{spec}'"))?;
                ports.push(port);
            }
        }
    }
    Ok(ports)
}

/// Parse a memory size (e.g. "512M", "1G") into bytes
fn parse_memory(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        n.parse::<u64>().ok().map(|v| v * 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        n.parse::<u64>().ok().map(|v| v * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('K').or_else(|| s.strip_suffix('k')) {
        n.parse::<u64>().ok().map(|v| v * 1024)
    } else {
        s.parse::<u64>().ok()
    }
}

fn main() {
    if std::env::args().any(|a| a == "--help" || a == "-h") {
        Cli::command().print_help().unwrap();
        println!();
        std::process::exit(0);
    }
    if std::env::args().any(|a| a == "--version" || a == "-V") {
        println!("hajiz {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }

    let cli = Cli::parse();

    if cli.kernel_info {
        match KernelCapabilities::detect() {
            Some(caps) => println!("{}", caps.report()),
            None => eprintln!("[hajiz] unable to detect the kernel version"),
        }
        std::process::exit(0);
    }

    let binary_str = match &cli.binary {
        Some(b) => b.clone(),
        None => {
            eprintln!("[hajiz] error: a binary is required");
            std::process::exit(2);
        }
    };

    if cli.audit {
        eprintln!("[hajiz] audit mode: running WITHOUT isolation to observe syscalls");
        eprintln!("[hajiz] launching '{binary_str}'...");
        let report = match run_audit(&binary_str, &cli.args) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[hajiz] audit error: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("[hajiz] audit finished:");
        eprintln!("  - {} unique syscalls", report.syscalls.len());
        eprintln!("  - {} paths read", report.paths_read.len());
        eprintln!("  - {} paths written", report.paths_written.len());
        eprintln!("  - {} network targets", report.network_addrs.len());

        let name = std::path::Path::new(&binary_str)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("audit")
            .to_string();
        let profile_text = generate_profile(&report, &name, &binary_str);

        match &cli.audit_output {
            Some(path) => {
                if let Err(e) = std::fs::write(path, &profile_text) {
                    eprintln!("[hajiz] error writing profile: {e}");
                    std::process::exit(1);
                }
                eprintln!("[hajiz] profile written to {}", path.display());
            }
            None => {
                print!("{profile_text}");
            }
        }
        std::process::exit(report.exit_code);
    }

    // --seccomp-whitelist and --strict-seccomp are mutually exclusive explicit
    // modes; if both are given, the allowlist wins (see apply_seccomp precedence).
    if cli.seccomp_whitelist && cli.strict_seccomp {
        eprintln!(
            "[hajiz] warning: --seccomp-whitelist and --strict-seccomp \
             together — allowlist mode is applied, --strict-seccomp ignored"
        );
    }

    let logger = Arc::new(match &cli.log {
        Some(path) => TelemetryLogger::with_file(path.clone(), cli.verbose),
        None => TelemetryLogger::new(cli.verbose),
    });

    let cli_net_mode = match NetworkMode::parse(&cli.net) {
        Some(mode) => mode,
        None => {
            eprintln!(
                "[hajiz] invalid --net value '{}': expected none, loopback or full",
                cli.net
            );
            std::process::exit(2);
        }
    };
    let net_mode_from_cli = cli.net != "none";

    let cli_connect_ports = match parse_port_specs(&cli.allow_connect_ports) {
        Ok(ports) => ports,
        Err(e) => {
            eprintln!("[hajiz] invalid --allow-connect-port value: {e}");
            std::process::exit(2);
        }
    };
    let cli_bind_ports = match parse_port_specs(&cli.allow_bind_ports) {
        Ok(ports) => ports,
        Err(e) => {
            eprintln!("[hajiz] invalid --allow-bind-port value: {e}");
            std::process::exit(2);
        }
    };

    let mut config = IsolationConfig {
        network_mode: cli_net_mode,
        drop_all_capabilities: !cli.keep_caps,
        strict_seccomp: cli.strict_seccomp,
        use_seccomp_whitelist: cli.seccomp_whitelist,
        enable_hardening_filter: !cli.no_hardening,
        seccomp_syscall_groups: cli.syscall_groups,
        seccomp_allow_syscalls: cli.allow_syscalls,
        filesystem_rules: Vec::new(),
        allow_connect_ports: cli_connect_ports.clone(),
        allow_bind_ports: cli_bind_ports.clone(),
        kill_on_deny: cli.kill_on_deny,
        seccomp_notify: false,     // decided below, once the policy is final
        seccomp_fs_notify: false,
        seccomp_net_notify: false,
        notify_socket_fd: None,
    };

    let profile_name = if let Some(profile_path) = &cli.profile {
        match load_profile(profile_path) {
            Ok(profile) => {
                let name = profile.name.clone();
                if !net_mode_from_cli {
                    match NetworkMode::parse(&profile.network.mode) {
                        Some(mode) => config.network_mode = mode,
                        None => {
                            eprintln!(
                                "[hajiz] profile '{}': invalid network.mode '{}': expected none, loopback or full",
                                name, profile.network.mode
                            );
                            std::process::exit(2);
                        }
                    }
                }
                for path in &profile.filesystem.read_only {
                    config.filesystem_rules.push(FilesystemRule { path: path.clone(), read_only: true });
                }
                for path in &profile.filesystem.read_write {
                    config.filesystem_rules.push(FilesystemRule { path: path.clone(), read_only: false });
                }
                config.seccomp_syscall_groups.extend(profile.seccomp.allow_groups);
                config.seccomp_allow_syscalls.extend(profile.seccomp.allow_syscalls);
                if cli_connect_ports.is_empty() {
                    config.allow_connect_ports = profile.network.allow_connect.clone();
                }
                if cli_bind_ports.is_empty() {
                    config.allow_bind_ports = profile.network.allow_bind.clone();
                }
                Some(name)
            }
            Err(e) => {
                eprintln!("[hajiz] error loading profile: {e}");
                std::process::exit(2);
            }
        }
    } else {
        None
    };

    for rule_str in &cli.fs_rules {
        match parse_fs_rule(rule_str) {
            Some(rule) => config.filesystem_rules.push(rule),
            None => {
                eprintln!("[hajiz] invalid --fs value '{}': expected PATH:ro or PATH:rw", rule_str);
                std::process::exit(2);
            }
        }
    }

    // Build the cgroup limits
    let limits = ResourceLimits {
        memory_bytes: cli.max_memory.as_deref().and_then(parse_memory),
        cpu_percent: cli.max_cpu,
        max_pids: cli.max_pids,
    };

    let has_limits = limits.memory_bytes.is_some()
        || limits.cpu_percent.is_some()
        || limits.max_pids.is_some();

    // Apply cgroups only if limits are defined
    if has_limits {
        if let Err(e) = apply_limits(&limits) {
            eprintln!("[hajiz] cgroups warning: {e}");
        } else if cli.verbose {
            eprintln!("[hajiz] cgroups applied");
        }
    }

    let policy_hash = TelemetryLogger::policy_hash(&config);
    if cli.verbose {
        eprintln!("[hajiz] policy hash: {}", policy_hash);
    }

    let binary = PathBuf::from(&binary_str);

    // Report the hardening deny-list only when hardening is the *effective* mode.
    // An explicit whitelist or strict mode takes precedence (see apply_seccomp),
    // so reporting the hardening list in those cases would misrepresent policy.
    let hardening_effective = config.enable_hardening_filter
        && !config.use_seccomp_whitelist
        && !config.strict_seccomp;

    // Denial telemetry transport. Preferred: seccomp user notification — the
    // parent services denials directly, no /dev/kmsg needed. Only available
    // for the hardening filter in EPERM mode (kill-on-deny stays in-kernel,
    // whitelist mode would have to notify on its own fd handoff syscalls).
    // Filesystem telemetry additionally needs CONTINUE responses (>= 5.5),
    // Landlock rules to predict against, and a telemetry consumer.
    let kernel_caps = KernelCapabilities::detect();
    config.seccomp_notify = hardening_effective
        && !config.kill_on_deny
        && kernel_caps.as_ref().map(|k| k.seccomp_notify).unwrap_or(false);
    let notify_continue = kernel_caps.as_ref().map(|k| k.seccomp_notify_continue).unwrap_or(false);
    let telemetry_consumer = cli.log.is_some() || cli.verbose;
    config.seccomp_fs_notify = config.seccomp_notify
        && notify_continue
        && !config.filesystem_rules.is_empty()
        && telemetry_consumer;
    // Network telemetry mirrors the filesystem path: predict + CONTINUE, with
    // Landlock the final decision. Only meaningful when a TCP-port allowlist
    // is active (otherwise there's no Landlock network restriction to predict).
    config.seccomp_net_notify = config.seccomp_notify
        && notify_continue
        && (config.restrict_tcp_connect() || config.restrict_tcp_bind())
        && telemetry_consumer;

    let blocked_syscalls: Vec<String> = if hardening_effective {
        hardened_denied_syscalls().iter().map(|s| s.to_string()).collect()
    } else {
        Vec::new()
    };
    let allowed_paths: Vec<String> = config.filesystem_rules.iter().map(|r| r.path.clone()).collect();
    let mut feats: Vec<&str> = vec!["namespaces"];
    if config.drop_all_capabilities { feats.push("capabilities"); }
    if !config.filesystem_rules.is_empty() { feats.push("landlock"); }
    if config.enable_hardening_filter || config.use_seccomp_whitelist || config.strict_seccomp {
        feats.push("seccomp");
    }
    if config.kill_on_deny { feats.push("kill-on-deny"); }
    if config.seccomp_notify { feats.push("seccomp-notify"); }
    if config.seccomp_fs_notify { feats.push("fs-telemetry"); }
    if config.seccomp_net_notify { feats.push("net-telemetry"); }
    if config.restrict_tcp_connect() || config.restrict_tcp_bind() {
        feats.push("landlock-net");
    }
    if has_limits { feats.push("cgroups"); }

    logger.log(&SecurityEvent::SandboxStarted {
        pid: std::process::id(),
        binary: binary_str.clone(),
        profile: profile_name,
        timestamp: SystemTime::now(),
    });

    logger.log(&SecurityEvent::PolicyApplied {
        pid: std::process::id(),
        blocked_syscalls,
        allowed_paths,
        features: feats.join(","),
        timestamp: SystemTime::now(),
    });

    let pid = std::process::id();
    let cgroup_path = if has_limits { Some(cgroup_path_for(pid)) } else { None };

    // The supervisor predicts Landlock decisions from the same rules the
    // child enforces with.
    let fs_rules_for_telemetry = if config.seccomp_fs_notify {
        config.filesystem_rules.clone()
    } else {
        Vec::new()
    };
    let (connect_ports_for_telemetry, bind_ports_for_telemetry) = if config.seccomp_net_notify {
        (config.allow_connect_ports.clone(), config.allow_bind_ports.clone())
    } else {
        (Vec::new(), Vec::new())
    };

    let result = SandboxProcess::spawn(SpawnOptions {
        binary,
        args: cli.args,
        verbose: cli.verbose,
        isolation: config,
    })
    .and_then(|mut sandbox| {
        let child_pid = sandbox.pid;
        // Move the sandboxed child into its cgroup so the limits apply to it.
        // hajiz itself stays out, which keeps cleanup_cgroup's rmdir able to
        // succeed once the child exits.
        if has_limits
            && let Err(e) = add_to_cgroup(child_pid)
        {
            eprintln!("[hajiz] cgroups warning: {e}");
        }
        let notify = sandbox.take_notify_fd().map(|fd| NotifyTelemetry {
            fd,
            fs_rules: fs_rules_for_telemetry,
            connect_ports: connect_ports_for_telemetry,
            bind_ports: bind_ports_for_telemetry,
        });
        let monitors = spawn_monitors(
            Arc::clone(&logger),
            child_pid,
            cgroup_path.clone(),
            Duration::from_secs(1),
            notify,
        );
        let outcome = sandbox.monitor();
        monitors.stop();
        outcome.inspect(|status| {
            use std::os::unix::process::ExitStatusExt;
            logger.log(&SecurityEvent::SandboxExited {
                pid: child_pid,
                exit_code: status.code().unwrap_or(-1),
                signal: status.signal(),
                timestamp: SystemTime::now(),
            });
        })
    });

    // cgroup cleanup
    if has_limits {
        cleanup_cgroup(pid);
    }

    match result {
        Ok(status) => {
            if !status.success() {
                std::process::exit(status.code().unwrap_or(1));
            }
        }
        Err(e) => {
            eprintln!("[hajiz] error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_specs_single_ports() {
        assert_eq!(
            parse_port_specs(&["443".into(), "80".into()]).unwrap(),
            vec![443, 80]
        );
    }

    #[test]
    fn parse_port_specs_expands_ranges() {
        assert_eq!(
            parse_port_specs(&["8000-8003".into()]).unwrap(),
            vec![8000, 8001, 8002, 8003]
        );
    }

    #[test]
    fn parse_port_specs_mixes_ranges_and_singles() {
        assert_eq!(
            parse_port_specs(&["8000-8001".into(), "443".into()]).unwrap(),
            vec![8000, 8001, 443]
        );
    }

    #[test]
    fn parse_port_specs_single_value_range_is_one_port() {
        assert_eq!(parse_port_specs(&["8080-8080".into()]).unwrap(), vec![8080]);
    }

    #[test]
    fn parse_port_specs_rejects_reversed_range() {
        assert!(parse_port_specs(&["8100-8000".into()]).is_err());
    }

    #[test]
    fn parse_port_specs_rejects_non_numeric() {
        assert!(parse_port_specs(&["abc".into()]).is_err());
        assert!(parse_port_specs(&["80-xx".into()]).is_err());
    }
}