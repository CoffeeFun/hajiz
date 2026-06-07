use clap::{CommandFactory, Parser};
use hajiz::{
    audit::{generate_profile, run_audit},
    cgroups::{apply_limits, cgroup_path_for, cleanup_cgroup, ResourceLimits},
    isolation::{seccomp::hardened_denied_syscalls, FilesystemRule, IsolationConfig, NetworkMode},
    kernel::KernelCapabilities,
    profile::load_profile,
    runtime::process::{SandboxProcess, SpawnOptions},
    telemetry::{spawn_monitors, SecurityEvent, TelemetryLogger},
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
    #[arg(long = "audit-output", value_name = "FICHIER")]
    audit_output: Option<PathBuf>,
    #[arg(long, value_name = "FICHIER")]
    profile: Option<PathBuf>,
    #[arg(long, value_name = "FICHIER")]
    log: Option<PathBuf>,
    /// Mode réseau: none (défaut, isolé), loopback (lo seulement), full (hôte)
    #[arg(long = "net", value_name = "MODE", default_value = "none")]
    net: String,
    /// Port TCP autorisé en sortie (connect). Répétable. Active une allowlist Landlock.
    #[arg(long = "allow-connect-port", value_name = "PORT")]
    allow_connect_ports: Vec<u16>,
    /// Port TCP autorisé en écoute (bind). Répétable. Active une allowlist Landlock.
    #[arg(long = "allow-bind-port", value_name = "PORT")]
    allow_bind_ports: Vec<u16>,
    #[arg(long)]
    keep_caps: bool,
    #[arg(long)]
    strict_seccomp: bool,
    #[arg(long)]
    seccomp_whitelist: bool,
    #[arg(long)]
    no_hardening: bool,
    /// Tue le processus enfant si un syscall refusé est observé
    /// (au lieu de retourner EPERM). L'évènement syscall_denied est
    /// toujours émis avant la mort du processus.
    #[arg(long = "kill-on-deny")]
    kill_on_deny: bool,
    #[arg(long = "allow-group", value_name = "GROUPE")]
    syscall_groups: Vec<String>,
    #[arg(long = "allow-syscall", value_name = "SYSCALL")]
    allow_syscalls: Vec<String>,
    #[arg(long = "fs", value_name = "CHEMIN:MODE")]
    fs_rules: Vec<String>,
    /// Limite mémoire (ex: 512M, 1G)
    #[arg(long = "max-mem", value_name = "TAILLE")]
    max_memory: Option<String>,
    /// Limite CPU en pourcentage (ex: 50)
    #[arg(long = "max-cpu", value_name = "POURCENT")]
    max_cpu: Option<u64>,
    /// Nombre maximum de processus
    #[arg(long = "max-pids", value_name = "N")]
    max_pids: Option<u64>,
    #[arg(short, long)]
    verbose: bool,
    #[arg(required = false)]
    binary: Option<String>,
    #[arg(trailing_var_arg = true)]
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

/// Parse une taille mémoire (ex: "512M", "1G") en bytes
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
            None => eprintln!("[hajiz] impossible de détecter la version kernel"),
        }
        std::process::exit(0);
    }

    let binary_str = match &cli.binary {
        Some(b) => b.clone(),
        None => {
            eprintln!("[hajiz] erreur: un binaire est requis");
            std::process::exit(2);
        }
    };

    if cli.audit {
        eprintln!("[hajiz] mode audit: exécution SANS isolation pour observer les syscalls");
        eprintln!("[hajiz] lancement de '{binary_str}'...");
        let report = match run_audit(&binary_str, &cli.args) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[hajiz] erreur audit: {e}");
                std::process::exit(1);
            }
        };
        eprintln!("[hajiz] audit terminé:");
        eprintln!("  - {} syscalls uniques", report.syscalls.len());
        eprintln!("  - {} chemins lus", report.paths_read.len());
        eprintln!("  - {} chemins écrits", report.paths_written.len());
        eprintln!("  - {} cibles réseau", report.network_addrs.len());

        let name = std::path::Path::new(&binary_str)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("audit")
            .to_string();
        let profile_text = generate_profile(&report, &name, &binary_str);

        match &cli.audit_output {
            Some(path) => {
                if let Err(e) = std::fs::write(path, &profile_text) {
                    eprintln!("[hajiz] erreur écriture profil: {e}");
                    std::process::exit(1);
                }
                eprintln!("[hajiz] profil écrit dans {}", path.display());
            }
            None => {
                print!("{profile_text}");
            }
        }
        std::process::exit(report.exit_code);
    }

    let logger = Arc::new(match &cli.log {
        Some(path) => TelemetryLogger::with_file(path.clone(), cli.verbose),
        None => TelemetryLogger::new(cli.verbose),
    });

    let cli_net_mode = match NetworkMode::parse(&cli.net) {
        Some(mode) => mode,
        None => {
            eprintln!(
                "[hajiz] valeur --net invalide '{}': attendu none, loopback ou full",
                cli.net
            );
            std::process::exit(2);
        }
    };
    let net_mode_from_cli = cli.net != "none";

    let mut config = IsolationConfig {
        network_mode: cli_net_mode,
        drop_all_capabilities: !cli.keep_caps,
        strict_seccomp: cli.strict_seccomp,
        use_seccomp_whitelist: cli.seccomp_whitelist,
        enable_hardening_filter: !cli.no_hardening,
        seccomp_syscall_groups: cli.syscall_groups,
        seccomp_allow_syscalls: cli.allow_syscalls,
        filesystem_rules: Vec::new(),
        allow_connect_ports: cli.allow_connect_ports.clone(),
        allow_bind_ports: cli.allow_bind_ports.clone(),
        kill_on_deny: cli.kill_on_deny,
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
                                "[hajiz] profil '{}': network.mode invalide '{}': attendu none, loopback ou full",
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
                if cli.allow_connect_ports.is_empty() {
                    config.allow_connect_ports = profile.network.allow_connect.clone();
                }
                if cli.allow_bind_ports.is_empty() {
                    config.allow_bind_ports = profile.network.allow_bind.clone();
                }
                Some(name)
            }
            Err(e) => {
                eprintln!("[hajiz] erreur chargement profil: {e}");
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
                eprintln!("[hajiz] valeur --fs invalide '{}': attendu CHEMIN:ro ou CHEMIN:rw", rule_str);
                std::process::exit(2);
            }
        }
    }

    // Construction des limites cgroups
    let limits = ResourceLimits {
        memory_bytes: cli.max_memory.as_deref().and_then(parse_memory),
        cpu_percent: cli.max_cpu,
        max_pids: cli.max_pids,
    };

    let has_limits = limits.memory_bytes.is_some()
        || limits.cpu_percent.is_some()
        || limits.max_pids.is_some();

    // Appliquer les cgroups si des limites sont définies
    if has_limits {
        if let Err(e) = apply_limits(&limits) {
            eprintln!("[hajiz] avertissement cgroups: {e}");
        } else if cli.verbose {
            eprintln!("[hajiz] cgroups appliqués");
        }
    }

    let policy_hash = TelemetryLogger::policy_hash(&config);
    if cli.verbose {
        eprintln!("[hajiz] hash politique: {}", policy_hash);
    }

    let binary = PathBuf::from(&binary_str);

    let blocked_syscalls: Vec<String> = if config.enable_hardening_filter {
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

    let result = SandboxProcess::spawn(SpawnOptions {
        binary,
        args: cli.args,
        verbose: cli.verbose,
        isolation: config,
    })
    .and_then(|sandbox| {
        let child_pid = sandbox.pid;
        let monitors = spawn_monitors(
            Arc::clone(&logger),
            child_pid,
            cgroup_path.clone(),
            Duration::from_secs(1),
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

    // Nettoyage cgroups
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
            eprintln!("[hajiz] erreur: {e}");
            std::process::exit(1);
        }
    }
}