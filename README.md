# hajiz

A **rootless, default-deny Linux application sandbox** written in Rust.

`hajiz` runs an untrusted binary inside a tightly-constrained execution
environment built entirely from Linux kernel primitives — user/mount/network
namespaces, Landlock, seccomp-BPF, and capability dropping. No daemon, no setuid
helper, no kernel module, and no `sudo` required for the common case.

Think of it as a smaller, more pedagogical cousin of `bubblewrap` / `firejail`,
with an extra eBPF-backed **audit mode** that learns what a binary actually needs
and writes a policy for you.

> Built as a 3rd-year systems-security project. See [ARCHITECTURE.md](ARCHITECTURE.md)
> for the internals and [docs/user-guide.md](docs/user-guide.md) for full usage.

## Features

- **Rootless & default-deny.** A regular user can sandbox a binary with nothing
  permitted unless it's explicitly allowed.
- **Namespaces.** New user, mount, IPC, UTS, and network namespaces with
  identity uid/gid maps and a private mount tree.
- **Capability hardening.** `no_new_privs`, ambient set cleared,
  effective/permitted/inheritable cleared, and the full bounding set dropped.
- **Landlock filesystem rules.** Per-path `ro`/`rw` allowlists, plus TCP
  connect/bind port allowlists on kernel ≥ 6.7.
- **Three seccomp modes.** Hardening-deny (default; blocks `unshare`, `setns`,
  `clone3`, `bpf`, `userfaultfd`, the keyring calls, and `ptrace`/`process_vm_*`),
  allowlist, and strict.
- **Three network tiers.** `none`, `loopback`, `full` (see below).
- **Resource limits.** Memory, CPU, and PID caps via cgroups v2.
- **Audit mode.** Observe a binary's real syscalls and auto-generate a TOML
  profile — via an eBPF backend (privileged) or an strace fallback (unprivileged).
- **Structured telemetry.** JSON events for every isolation decision.
- **Adaptive.** Detects kernel capabilities at runtime and degrades gracefully.

## How it works

When you run `hajiz <binary>`, the parent forks the target with a `pre_exec`
hook. Inside the child — after `fork()` but before `exec()` — the isolation
pipeline runs in a deliberate order:

1. **Namespaces** — `unshare(CLONE_NEWUSER|NEWNS|NEWIPC|NEWUTS|[NEWNET])`, write
   identity uid/gid maps, remount `/` private.
2. **Capabilities** — drop the bounding set, clear ambient, `capset(0)`, set
   `no_new_privs`.
3. **Landlock** — install path and TCP-port rules (kernel ≥ 5.13).
4. **Seccomp** — install the BPF filter.
5. **exec** — the target now runs under everything above.

The ordering is load-bearing (e.g. caps must drop *after* entering the user-ns,
seccomp must come *after* Landlock); the reasoning is documented in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Installation

Requires a Rust toolchain and `libseccomp`. `clang` is optional — if present at
build time, the eBPF audit backend is compiled in; otherwise audit mode falls
back to `strace`.

```bash
cargo build --release
sudo install -m 755 target/release/hajiz /usr/local/bin/hajiz
```

### Ubuntu 23.10+: AppArmor profile

On Ubuntu 23.10 and later (including 24.04 LTS) the sysctl
`kernel.apparmor_restrict_unprivileged_userns` is enabled by default, which
blocks `unshare(CLONE_NEWUSER)` for unprivileged binaries without an explicit
AppArmor profile — `hajiz` would fail with `EPERM` on startup (it prints a hint
pointing here when it detects this). Install the bundled profile
([packaging/apparmor/hajiz](packaging/apparmor/hajiz)):

```bash
sudo cp packaging/apparmor/hajiz /etc/apparmor.d/hajiz
sudo systemctl reload apparmor
```

Other distributions (Debian, Arch, Fedora, RHEL, Ubuntu ≤ 23.04) have no such
restriction and need no extra configuration.

## Quick start

```bash
# Default: complete network isolation, hardened seccomp, caps dropped
hajiz /usr/bin/echo hello

# Read-only /usr, writable /tmp, offline
hajiz --fs /usr:ro --fs /tmp:rw /usr/bin/python3 script.py

# Loopback-only (local services on 127.0.0.1)
hajiz --net loopback /usr/bin/python3 -m http.server 8000

# Full network restricted to specific ports (kernel 6.7+)
hajiz --net full --allow-connect-port 443 --allow-connect-port 80 \
  /usr/bin/curl https://example.com

# Port ranges are accepted too (START-END, inclusive)
hajiz --net full --allow-connect-port 8000-8100 /usr/bin/myapp

# Resource caps
hajiz --max-mem 512M --max-cpu 50 --max-pids 64 /usr/bin/myapp

# Load a reusable profile
hajiz --profile profiles/firefox.toml /usr/bin/firefox

# Inspect what your kernel supports
hajiz --kernel-info
```

### Network modes

| Mode | Behavior |
| --- | --- |
| `none` *(default)* | Own netns, no interfaces — complete isolation |
| `loopback` | Own netns with `lo` up and `127.0.0.1/8` — local services only |
| `full` | Share the host network; still honors Landlock port allowlists on kernel ≥ 6.7 |

### Audit mode

Audit mode runs the binary **without isolation**, records the syscalls it makes,
and emits a TOML profile for you to review and apply on real runs:

```bash
# Generate a profile (strace backend, unprivileged)
hajiz --audit --audit-output curl.toml /usr/bin/curl https://example.com

# Privileged eBPF backend (lower overhead) when run as root
sudo hajiz --audit --audit-output curl.toml /usr/bin/curl https://example.com

# Review curl.toml, then run for real under it
hajiz --profile curl.toml /usr/bin/curl https://example.com
```

The backend is chosen at runtime: eBPF when run as root (or with `CAP_BPF`) on a
build where the BPF program compiled, otherwise strace. The eBPF backend uses a
privileged-broker / unprivileged-sandbox split so the target binary never runs
with elevated privileges. Details in [ARCHITECTURE.md](ARCHITECTURE.md).

## Profiles

Profiles are TOML files describing network mode, filesystem rules, and seccomp
policy. Bundled examples live in [profiles/](profiles/): `untrusted`, `firefox`,
`document-viewer`, `media-player`, `office`.

```toml
name = "untrusted"
description = "Minimal profile for untrusted files"

[network]
mode = "none"            # none | loopback | full

[filesystem]
read_only  = ["/usr", "/lib", "/lib64", "/bin"]
read_write = ["/tmp"]

[seccomp]
hardening = true         # default-on hardening filter
allow_groups = []        # for allowlist mode
allow_syscalls = []
```

## Threat model

- **Trusted:** the kernel, the `hajiz` binary, and the profile files it reads.
- **Untrusted:** the sandboxed binary and everything it produces.
- **Defended against:** filesystem escape, namespace re-entry, network
  exfiltration, capability abuse, syscall-based exploits, privilege escalation
  through `exec()`.
- **Out of scope:** side channels (Spectre/timing), kernel exploits, hardware
  attacks, and a compromised `hajiz` binary itself.

## Known limitations

- **Ubuntu 23.10+ needs the AppArmor profile.** Unprivileged user namespaces are
  blocked by default; without the [bundled profile](packaging/apparmor/hajiz)
  startup fails with `EPERM`. `hajiz` detects this and prints a hint.
- **Kernel version gates features.** Landlock filesystem rules need kernel ≥ 5.13
  and Landlock TCP-port rules need ≥ 6.7. On older kernels those rules are
  skipped with a warning rather than failing — verify with `hajiz --kernel-info`.
- **`full` network mode shares the host netns.** Without kernel ≥ 6.7 port
  allowlists it grants unrestricted network access. Use `none`/`loopback` for
  hard isolation.
- **Denial telemetry has kernel gates.** On kernel ≥ 5.0, `syscall_denied`
  events are delivered through seccomp user notification — no privileges or
  `/dev/kmsg` access needed. `filesystem_denied` events (predicted Landlock
  misses) additionally need kernel ≥ 5.5 and are only collected when `--log`
  or `--verbose` is active, since each intercepted filesystem syscall costs a
  round-trip to the supervisor. On older kernels both fall back to best-effort
  `/dev/kmsg` parsing (requires root or `kernel.dmesg_restrict=0`), and with
  `--kill-on-deny` the kill stays in-kernel, so only the kmsg path applies.
- **`filesystem_denied` and `network_denied` are predictions, not the kernel's
  verdict.** The supervisor replays the profile rules against the accessed path
  or TCP port (resolving cwd/dirfds and sockaddrs via `/proc`) but does not
  chase symlinks the way Landlock does; enforcement always remains with
  Landlock in the kernel. `network_denied` only applies when a
  `--allow-connect-port`/`--allow-bind-port` allowlist is set.
- **Resource limits require cgroups v2.** `--max-mem`/`--max-cpu`/`--max-pids`
  warn and continue if a writable cgroups v2 hierarchy is unavailable.

## Testing

```bash
cargo test          # unit + integration tests
cargo clippy        # lints (clean)
```

The suite includes integration tests against the compiled binary
([tests/exploit_tests.rs](tests/exploit_tests.rs)), adversarial escape attempts
([tests/escape_tests.rs](tests/escape_tests.rs)), and a Docker-based escape
harness with CVE PoCs ([tests/container/](tests/container/)).

## Documentation

- [docs/user-guide.md](docs/user-guide.md) — full CLI reference and examples.
- [ARCHITECTURE.md](ARCHITECTURE.md) — internals: isolation pipeline, eBPF audit
  broker/sandbox split, build system, telemetry.

## License

MIT.
