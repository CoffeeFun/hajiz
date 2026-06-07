# User Guide

`hajiz` is a rootless, default-deny Linux application sandbox. You hand it a
binary; it runs that binary inside namespaces, with capabilities dropped,
Landlock filesystem rules applied, and a seccomp filter installed — all without
`sudo` and without a daemon.

## Basic usage

```bash
hajiz [OPTIONS] <BINARY> [ARGS...]
```

- `<BINARY>` is the program to sandbox.
- Everything after it is forwarded verbatim to the sandboxed process.
- Options must come **before** the binary; arguments after it belong to the target.

```bash
# Run cat under the default policy (no network, hardened seccomp, caps dropped)
hajiz /bin/cat /etc/hostname

# Give the target read-only /usr and a writable /tmp, keep it offline
hajiz --fs /usr:ro --fs /tmp:rw /usr/bin/python3 script.py
```

Run with no arguments to print help. `hajiz --version` prints the version.

## Inspecting kernel support

Capabilities are detected at runtime and the sandbox degrades gracefully on
older kernels. To see what your kernel supports:

```bash
hajiz --kernel-info
```

This reports kernel version plus support for Landlock, Landlock network rules,
cgroups v2, seccomp-notify, and user namespaces.

## Default policy

With no flags, `hajiz` applies:

1. **Namespaces** — new user, mount, IPC, UTS, and (by default) network namespace.
2. **Capabilities** — bounding set dropped, ambient set cleared, `capset(0)`,
   and `no_new_privs` set.
3. **Landlock** — only the paths you allow with `--fs` are reachable (skipped if
   no rules are given or the kernel is older than 5.13).
4. **Seccomp** — hardening-deny filter blocking high-risk syscalls.

Order matters and is enforced internally; see `ARCHITECTURE.md` for the rationale.

## Filesystem rules

Repeatable `--fs CHEMIN:MODE` flag. Mode is `ro` (read + execute) or `rw`
(read + write + execute):

```bash
hajiz --fs /usr:ro --fs /lib:ro --fs /home/me/work:rw /usr/bin/myapp
```

Without any `--fs` rule, no Landlock path restriction is applied. Combine with a
profile (below) to ship a reusable rule set.

## Network modes

`--net MODE`, default `none`:

| Mode | Effect |
| --- | --- |
| `none` | New network namespace, no interfaces — fully offline. |
| `loopback` | New netns with `lo` up and `127.0.0.1/8` configured — local services only. |
| `full` | Shares the host network. Still honors port allowlists on kernel ≥ 6.7. |

On a Landlock-network-capable kernel you can restrict TCP ports even in `full`
mode (both flags are repeatable):

```bash
hajiz --net full --allow-connect-port 443 --allow-bind-port 8080 /usr/bin/myapp
```

## Capability hardening

Applied by default:

- `PR_SET_NO_NEW_PRIVS`
- ambient capability clear (`PR_CAP_AMBIENT_CLEAR_ALL`)
- effective/permitted/inheritable set clear (`capset`)
- bounding-set drop for all capabilities

Use `--keep-caps` to skip the capability drop (debugging only — this weakens the
sandbox).

## Seccomp modes

Pick one behavior:

| Flag | Mode | Behavior |
| --- | --- | --- |
| *(default)* | Hardening-deny | Blocks high-risk primitives, allows the rest. |
| `--seccomp-whitelist` | Allowlist | Only explicitly-allowed syscalls/groups run; everything else is denied. |
| `--strict-seccomp` | Strict | Minimal allowlist (`read`/`write`/`exit`/`sigreturn`). |
| `--no-hardening` | Off | Disables the default hardening filter. |

Hardening mode denies, among others: `unshare`, `setns`, `clone3`, `bpf`,
`userfaultfd`, and the keyring syscalls (`add_key`, `request_key`, `keyctl`).

In allowlist mode, build the allowed set from named groups and individual
syscalls (both repeatable):

```bash
hajiz --seccomp-whitelist \
  --allow-group io --allow-group memory --allow-group process \
  --allow-syscall getrandom \
  /usr/bin/myapp
```

Available `--allow-group` names:

| Group | Syscalls |
| --- | --- |
| `io` | open, openat, close, read, write, lseek, fstat, newfstatat, stat |
| `memory` | mmap, mprotect, munmap, brk, madvise |
| `threading` | clone, clone3, futex, set_tid_address, set_robust_list |
| `network` | socket, connect, sendto, sendmsg, recvfrom, recvmsg, bind, listen, accept, accept4 |
| `process` | fork, vfork, execve, execveat, wait4, waitid, kill, getpid |

### Kill on deny

By default a denied syscall returns `EPERM`. With `--kill-on-deny` the offending
process is killed instead (a `syscall_denied` telemetry event is still emitted
first).

## Resource limits (cgroups v2)

| Flag | Meaning | Example |
| --- | --- | --- |
| `--max-mem` | Memory cap (`M`/`G` suffix) | `--max-mem 512M` |
| `--max-cpu` | CPU cap, percent | `--max-cpu 50` |
| `--max-pids` | Max processes | `--max-pids 64` |

```bash
hajiz --max-mem 512M --max-cpu 50 --max-pids 64 /usr/bin/myapp
```

## Profiles

Instead of long flag lists, load a reusable TOML profile with `--profile`:

```bash
hajiz --profile profiles/untrusted.toml /usr/bin/myapp
```

Bundled profiles live in `profiles/`: `untrusted`, `firefox`, `document-viewer`,
`media-player`, and `office`. A profile looks like:

```toml
name = "untrusted"
description = "Minimal profile for untrusted files"

[network]
mode = "none"            # none | loopback | full
allow_connect = []       # TCP ports for outbound connect
allow_bind = []          # TCP ports for bind/listen

[filesystem]
read_only  = ["/usr", "/lib", "/lib64", "/bin"]
read_write = ["/tmp"]

[seccomp]
strict       = false
whitelist    = false
hardening    = true      # default-on hardening filter
allow_groups = []        # group names, allowlist mode
allow_syscalls = []      # individual syscalls, allowlist mode
```

## Audit mode — generate a profile automatically

`--audit` runs the binary **without isolation**, observes the syscalls it
actually makes, and emits a TOML profile you can review and apply on real runs:

```bash
# Print a suggested profile to stdout
hajiz --audit /usr/bin/curl https://example.com

# Write it to a file
hajiz --audit --audit-output curl.toml /usr/bin/curl https://example.com
```

There are two backends, chosen automatically:

- **eBPF** — used when run as root (or with `CAP_BPF`) on a build where the BPF
  program compiled. Loads a tiny syscall-counting tracepoint with a privileged
  broker / unprivileged sandbox split. Captures syscall names.
- **strace** — the unprivileged fallback. Slower, but additionally captures file
  paths and network addresses.

```bash
# Force the privileged eBPF backend
sudo hajiz --audit --audit-output curl.toml /usr/bin/curl https://example.com
```

## Telemetry

`hajiz` emits structured `SecurityEvent`s (policy applied, sandbox started,
syscall/filesystem denied, resource usage, sandbox exited).

- `--verbose` (`-v`) prints events to stderr.
- `--log FICHIER` writes the events as JSON to a file.

```bash
hajiz -v --log run.json --fs /usr:ro /usr/bin/myapp
```

## Flag reference

| Flag | Description |
| --- | --- |
| `--kernel-info` | Print detected kernel capabilities and exit |
| `--audit` | Run unsandboxed and emit a suggested profile |
| `--audit-output FICHIER` | Write the audit profile to a file |
| `--profile FICHIER` | Load policy from a TOML profile |
| `--log FICHIER` | Write JSON telemetry to a file |
| `--net MODE` | `none` (default), `loopback`, or `full` |
| `--allow-connect-port PORT` | Allow outbound TCP port (repeatable) |
| `--allow-bind-port PORT` | Allow bind TCP port (repeatable) |
| `--fs CHEMIN:MODE` | Landlock path rule, `ro` or `rw` (repeatable) |
| `--keep-caps` | Skip capability drop (debugging) |
| `--strict-seccomp` | Minimal seccomp allowlist |
| `--seccomp-whitelist` | Allowlist seccomp mode |
| `--no-hardening` | Disable the default hardening filter |
| `--kill-on-deny` | Kill on denied syscall instead of returning EPERM |
| `--allow-group GROUPE` | Allow a syscall group (repeatable) |
| `--allow-syscall SYSCALL` | Allow a single syscall (repeatable) |
| `--max-mem TAILLE` | Memory limit, e.g. `512M`, `1G` |
| `--max-cpu POURCENT` | CPU limit in percent |
| `--max-pids N` | Maximum number of processes |
| `-v`, `--verbose` | Print telemetry events to stderr |
