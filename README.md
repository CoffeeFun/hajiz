# hajiz

A default-deny Linux application sandbox written in Rust. Built as a 3rd year systems security project.

Isolates untrusted binaries using Linux kernel primitives — namespaces, Landlock, seccomp-BPF, and capabilities — with no root required.

## Current status

- Child pre-exec isolation pipeline is active for command execution.
- Implemented isolation primitives:
  - Linux namespaces (mount, IPC, UTS, network with three-tier modes)
  - Capability hardening (`no_new_privs`, ambient clear, effective/permitted/inheritable clear, bounding-set drop)
  - Landlock filesystem path restrictions + TCP port allowlisting (kernel 6.7+)
  - Seccomp enforcement (strict mode, allowlist mode, hardening-deny mode)
- Hardening seccomp mode blocks high-risk syscalls (`unshare`, `setns`, `clone3`, `bpf`, `userfaultfd`, keyring).
- Network isolation modes:
  - **none** (default): own netns, no interfaces — complete isolation
  - **loopback**: own netns with `lo` UP and 127.0.0.1/8 — local services only
  - **full**: host netns — unrestricted (can add Landlock port restrictions)
- Port-level allowlisting via Landlock: `--allow-connect-port PORT` and `--allow-bind-port PORT`
- Audit mode discovers required syscalls, filesystem paths, and network ports; generates profiles automatically

## Security note (Landlock RFC compatibility)

Recent Landlock RFC work proposes first-class namespace/capability permissions in kernel Landlock ABI 9.
This project currently targets stable kernels where these hooks are not generally available yet.

Current equivalent approach:

- Keep namespace isolation in the sandbox launcher
- Enforce Landlock for filesystem access control
- Strip capabilities aggressively in-process
- Deny namespace re-entry and related escalation primitives with seccomp hardening

When Landlock ABI 9 becomes broadly available, this policy can migrate from seccomp-based fallback to native Landlock namespace/capability permissions.

## Installation

```bash
cargo build --release
sudo install -m 755 target/release/hajiz /usr/local/bin/hajiz
```

### Ubuntu 23.10+: AppArmor profile

On Ubuntu 23.10 and later (including 24.04 LTS), the sysctl
`kernel.apparmor_restrict_unprivileged_userns` is enabled by default.
This blocks `unshare(CLONE_NEWUSER)` for unprivileged binaries without an
explicit AppArmor profile — hajiz will fail with EPERM on startup.

Install the provided profile:

```bash
sudo cp packaging/apparmor/hajiz /etc/apparmor.d/hajiz
sudo systemctl reload apparmor
```

Other distributions (Debian, Arch, Fedora, RHEL, Ubuntu ≤ 23.04)
do not have this restriction and require no additional configuration.

## Quick examples

```bash
# Default: complete network isolation
hajiz /usr/bin/echo hello

# Loopback-only mode (local services on 127.0.0.1)
hajiz --net loopback /usr/bin/python3 -m http.server 8000

# Full network with port restrictions (kernel 6.7+)
hajiz --net full --allow-connect-port 443 --allow-connect-port 80 /usr/bin/curl https://example.com

# Load a profile
hajiz --profile profiles/firefox.toml /usr/bin/firefox

# Audit mode: discover what the app needs, generate a profile
hajiz --audit /usr/bin/curl https://example.com > curl-profile.toml
# Review the profile, then run with it:
hajiz --profile curl-profile.toml /usr/bin/curl https://example.com
```

## Architecture highlights

**Network isolation**: Three tiers managed via network namespaces and Landlock:
- `--net none`: own netns, no interfaces (default, safest)
- `--net loopback`: own netns with loopback interface configured, useful for apps that spawn local services
- `--net full`: share host network, optionally restricted by Landlock port allowlists (`--allow-connect-port`, `--allow-bind-port`)

**Audit mode**: Runs the binary under `strace`, parses syscalls/files/network, auto-generates a TOML profile. User reviews and applies it for production runs.

**Landlock**: Kernel-enforced filesystem rules (paths) and TCP port rules (kernel 6.7+), no privilege escalation needed.
