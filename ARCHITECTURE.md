# hajiz — architecture & internals

Internal reference doc. Not intended for the public README; kept here so AI sessions and future-you can pick up the context without spelunking.

---

## 1. What this project actually is

**hajiz** is a default-deny Linux application sandbox written in Rust. You hand it a binary, it runs the binary inside a heavily-constrained execution environment using only Linux kernel primitives — no daemon, no setuid, no kernel module.

It's a 3rd-year systems-security project. Think of it as a smaller, more pedagogical cousin of `bubblewrap`/`firejail`, with an additional eBPF-backed audit mode that learns what a binary actually needs.

### Goals
1. **Rootless by default.** A regular user can sandbox a binary without `sudo`.
2. **Default-deny.** No filesystem, no network, no syscalls beyond what's explicitly permitted.
3. **Composable policy.** TOML profiles describe network mode, filesystem rules, and seccomp groups.
4. **Observable.** Structured telemetry (JSON) for every isolation decision and every denied syscall.
5. **Adaptive.** Detects kernel capabilities at runtime; degrades gracefully on older kernels.

### Threat model
- **Trusted**: the kernel, hajiz binary, profile files we read.
- **Untrusted**: the binary we're sandboxing and everything it produces.
- **Defended against**: filesystem escape, namespace re-entry, network exfiltration, capability abuse, syscall-based exploits, privilege escalation through `exec()`.
- **Out of scope**: side channels (Spectre/timing), kernel exploits, hardware attacks, compromised hajiz binary itself.

---

## 2. Module map

```
src/
├── main.rs                        CLI parsing, top-level orchestration
├── lib.rs                         module re-exports
├── error.rs                       HajizError { Config, Isolation, Io }
│
├── kernel/
│   └── version.rs                 KernelCapabilities — reads /proc/version,
│                                  feature matrix (user_ns, landlock, landlock_net,
│                                  seccomp_strict, cap_bpf, …)
│
├── profile/
│   ├── schema.rs                  serde structs for TOML
│   ├── parser.rs                  load + validate
│   └── mod.rs                     load_profile()
│
├── isolation/
│   ├── mod.rs                     apply_in_child() — the pre-exec pipeline
│   ├── namespaces.rs              unshare(CLONE_NEWUSER|NEWNS|NEWIPC|NEWUTS|NEWNET)
│   │                              + uid/gid identity maps + MS_PRIVATE remount
│   ├── capabilities.rs            bounding-set drop → capset(0) → no_new_privs
│   ├── filesystem.rs              Landlock paths + TCP port allowlists
│   └── seccomp.rs                 strict / allowlist / hardening-deny modes
│
├── runtime/
│   ├── process.rs                 SandboxProcess::spawn (uses pre_exec hook)
│   └── pidfile.rs                 PID-file helpers
│
├── cgroups/
│   ├── mod.rs                     apply_limits, cgroup_path_for, cleanup_cgroup
│   └── limits.rs                  ResourceLimits (mem/cpu/pids)
│
├── telemetry/
│   ├── event.rs                   SecurityEvent enum (PolicyApplied, SandboxStarted,
│   │                              SyscallDenied, FilesystemDenied, ResourceUsage,
│   │                              SandboxExited)
│   ├── logger.rs                  TelemetryLogger (verbose stderr + JSON file),
│   │                              policy_hash()
│   ├── monitor.rs                 background threads: kmsg reader, cgroup sampler
│   └── mod.rs                     spawn_monitors()
│
├── privesc/
│   └── mod.rs                     ★ NEW — broker/sandbox primitives:
│                                  socketpair, send_fds, recv_fds (SCM_RIGHTS),
│                                  drop_all_capabilities, can_use_bpf
│
└── audit/
    ├── mod.rs                     run_audit() — dispatches eBPF or strace
    ├── strace.rs                  legacy backend: spawn strace, parse output
    ├── ebpf.rs                    ★ NEW — eBPF backend with privilege separation
    └── generator.rs               AuditReport → TOML profile

bpf/
└── audit_syscalls.c               ★ NEW — BPF C program (raw_tracepoint/sys_enter)

build.rs                           ★ NEW — compiles bpf/*.c with clang -target bpf

tests/
├── exploit_tests.rs               integration tests against the compiled binary
├── escape_tests.rs                active escape attempts (attacks the sandbox)
├── integration_tests.rs           scaffold
├── namespace_tests.rs             scaffold
└── container/                     Docker-based escape probes (atomics, CVEs)

profiles/
├── untrusted.toml                 example default-deny profile
├── firefox.toml                   browser profile
├── document-viewer.toml           PDF/document reader profile
├── media-player.toml              audio/video player profile
└── office.toml                    office-suite profile

examples/
└── basic_isolation.rs            minimal library-usage example

docs/
└── user-guide.md                 end-user documentation

packaging/
└── apparmor/hajiz                AppArmor profile for distro packaging
```

---

## 3. The isolation pipeline

When you run `hajiz <binary>`, the parent process forks via `Command::spawn` with a `pre_exec` hook. The hook runs **inside the child, after fork() but before exec()** and applies the pipeline below. **Order matters.**

```
[parent: hajiz]                                  [child: pre_exec, before exec()]
   │                                                            │
   ├─ parse CLI                                                 │
   ├─ load profile (optional)                                   │
   ├─ build IsolationConfig                                     │
   ├─ optional: apply cgroups limits to self                    │
   ├─ spawn child via Command + pre_exec ─────────────────────► │
   ├─ optional: spawn telemetry monitors                        │  1. setup_namespaces
   │     (kmsg reader, cgroup sampler)                          │     unshare(CLONE_NEWUSER|NEWNS|NEWIPC|NEWUTS|[NEWNET])
   ├─ wait on child                                             │     write /proc/self/{uid,gid}_map (identity)
   └─ on exit: log SandboxExited, cleanup cgroups               │     mount(MS_PRIVATE|MS_REC) on /
                                                                │
                                                                │  2. drop_capabilities
                                                                │     PR_CAPBSET_DROP for caps 0..40
                                                                │     (must happen BEFORE capset — needs CAP_SETPCAP)
                                                                │     PR_CAP_AMBIENT_CLEAR_ALL
                                                                │     capset(0,0,0)
                                                                │     PR_SET_NO_NEW_PRIVS
                                                                │
                                                                │  3. setup_filesystem (Landlock)
                                                                │     skipped if no rules or kernel < 5.13
                                                                │     adds path rules + TCP port rules
                                                                │
                                                                │  4. apply_seccomp
                                                                │     hardening-deny (default) | allowlist | strict
                                                                │     installs BPF filter via prctl(PR_SET_SECCOMP)
                                                                │
                                                                │  5. exec(binary, args)
                                                                │     ← target now runs under all the above
```

### Critical ordering invariants

| Wrong order | Why it breaks |
|---|---|
| `capset()` before `PR_CAPBSET_DROP` | `capset(0)` removes `CAP_SETPCAP`, so the bounding-set drop fails with EPERM |
| Caps drop before user namespace | Unprivileged user has no caps to drop with — must enter user-ns first to gain in-namespace caps |
| Seccomp before Landlock | Landlock load uses syscalls (`landlock_create_ruleset`) that the strict seccomp filter blocks |
| Mount remount before user-ns | `mount(MS_PRIVATE)` requires `CAP_SYS_ADMIN`, only available in user-ns for unprivileged users |

### Network mode tiers

| Mode | unshare(NEWNET)? | Interfaces | Use case |
|---|---|---|---|
| `none` (default) | yes | none | maximally isolated |
| `loopback` | yes | `lo` UP, `127.0.0.1/8` configured | local services |
| `full` | no | host's | online apps; can still apply Landlock port allowlists if kernel ≥ 6.7 |

---

## 4. Audit mode — eBPF backend with broker/sandbox split

Audit mode runs the binary **without isolation** and observes which syscalls it actually makes, then emits a TOML profile that you can review and apply on real runs.

### Two backends, one dispatcher

[`src/audit/mod.rs`](src/audit/mod.rs) picks the backend at runtime:

```rust
if cfg!(all(feature = "ebpf", ebpf_compiled)) && privesc::can_use_bpf() {
    return ebpf::inner::run_audit_ebpf(binary, args);   // requires root / CAP_BPF
}
strace::run_audit(binary, args)                         // unprivileged fallback
```

- `feature = "ebpf"` controls whether `aya` compiles in (default-on in `Cargo.toml`).
- `ebpf_compiled` is set by [build.rs](build.rs) **only if** clang successfully compiled `bpf/audit_syscalls.c`. If clang isn't installed or compilation fails, the cfg flag stays unset and the eBPF code path is gated out completely — including the `include_bytes!` of the `.o` file that wouldn't exist.
- `can_use_bpf()` checks `geteuid() == 0` at runtime. Without it, fall back to strace even with the feature enabled.

### Why the broker/sandbox pattern

Loading eBPF programs needs `CAP_BPF` (kernel ≥ 5.8) or root. Naively, you'd run the whole tool privileged. We don't — the **child that runs the target binary is never privileged**, not for a single instruction. This is the same pattern Chrome's sandbox, firejail, and bwrap use.

Why it's safe to drop privileges *after* loading BPF: the kernel only checks `CAP_BPF` at fd creation time. Once a BPF map/program fd exists, it's just a file descriptor — anyone holding it can use it. So we load privileged, hand the fds across, then drop.

### Execution flow (audit, eBPF path)

```
USER SHELL                                    
   │                                          
   └─ sudo hajiz --audit /usr/bin/curl ...    
        │                                     
        ▼                                     
┌────────────────────────────────────────────────────────────────────────┐
│ hajiz process (privileged, has CAP_BPF or is root)                     │
│                                                                        │
│  socketpair(AF_UNIX, SOCK_STREAM)                                      │
│  fork() ───────────────────────────────────────────┐                   │
│   │                                                │                   │
│   │ PARENT (broker)                                │ CHILD (sandbox)   │
│   │                                                │                   │
│   │ load BPF object                                │ ★ FIRST INSTRUCTION:
│   │  └─ include_bytes!(audit_syscalls.o)           │   drop_all_capabilities()
│   │  └─ aya::Ebpf::load                            │   (capset(0) + bounding set
│   │  └─ RawTracePoint::attach("sys_enter")         │    + ambient clear + no_new_privs)
│   │  ↑ kernel checks CAP_BPF here                  │                   │
│   │                                                │   recv_fds() ←─── │
│   │ get raw fds: config_map, syscall_map           │   (already unprivileged
│   │                                                │    when this runs)
│   │ send_fds() ─────────SCM_RIGHTS────────────────►│                   │
│   │                                                │   spawn target binary
│   │ drop_all_capabilities()                        │   (Command::new(binary).spawn)
│   │ ★ broker is now also unprivileged              │                   │
│   │   BPF stays alive because we hold the fd       │   bpf(MAP_UPDATE_ELEM,
│   │                                                │       config_map[0] = target.pid)
│   │                                                │                   │
│   │                                                │   target runs ─── kernel:
│   │                                                │                   raw_tracepoint
│   │                                                │                   /sys_enter
│   │                                                │                   fires per syscall,
│   │                                                │                   filters by tgid,
│   │                                                │                   bumps syscall_map
│   │                                                │                   │
│   │                                                │   target.wait()   │
│   │                                                │   bpf(MAP_UPDATE,  │
│   │                                                │       config[0]=0) │
│   │                                                │                   │
│   │                                                │   loop:
│   │                                                │     bpf(GET_NEXT_KEY)
│   │                                                │     resolve syscall_nr → name
│   │                                                │       (libseccomp::ScmpSyscall)
│   │                                                │                   │
│   │                                                │   serialize report:
│   │                                                │     "EXIT:<code>\n"
│   │                                                │     "<syscall>\n" * N
│   │                                                │                   │
│   │ read from socket ◄────────────────write ───────│                   │
│   │ parse text protocol                            │   close socket    │
│   │                                                │   exit            │
│   │ waitpid(child)                                 │                   │
│   │                                                │                   │
│   │ Ebpf dropped → BPF prog detached, maps freed  │                   │
│   │                                                │                   │
│   │ return AuditReport                             │                   │
│   ▼                                                │                   │
│ main.rs:                                                               │
│   generate_profile(&report, …)                                         │
│   write to --audit-output or stdout                                    │
│   exit(report.exit_code)                                               │
└────────────────────────────────────────────────────────────────────────┘
```

### The privilege windows

| Process | Privilege window | What's in it |
|---|---|---|
| Broker | start → `drop_all_capabilities()` after `send_fds()` | BPF load + attach + sendmsg. Microseconds. No user input handled, no exec. |
| Sandbox | fork() → first instruction returning to userspace | One syscall return. `drop_all_capabilities()` is the literal first thing it does. |

### The BPF program ([bpf/audit_syscalls.c](bpf/audit_syscalls.c))

Tiny — ~30 lines — by design:
- Two maps: `config_map` (1-entry ARRAY, holds the target TGID), `syscall_map` (HASH, syscall_nr → call count).
- One program: `raw_tracepoint/sys_enter`. On every syscall:
  - Check filter PID; bail if not target.
  - `__sync_fetch_and_add` the counter for `ctx->args[1]` (= syscall id).

The kernel's BPF verifier statically proves bounds-checks, no infinite loops, no uninitialized reads. That's the actual security boundary; the source language doesn't matter.

### Why C, not Rust (aya-ebpf)

| | C + clang | Rust + aya-ebpf |
|---|---|---|
| Build deps | `clang` (we have it), `libbpf` headers (we have them) | `bpf-linker` (not installed) + nightly Rust + separate `no_std` workspace targeting `bpfel-unknown-none` |
| Audit reference material | Kernel docs, every CVE writeup, bcc/bpftrace examples | Mostly aya's own examples |
| Bytecode mapping | 1:1 with the C source | Macros hide what's emitted |
| Kernel verifier | Same | Same (this is the actual security boundary) |

For 30 lines of code, C wins on toolchain simplicity and audit clarity. Switch to Rust eBPF only when programs grow large enough to want shared types with userspace.

### Raw bpf(2) syscall in the child

aya stays in the broker. The sandbox can't use aya (aya owns map state in user memory that doesn't survive the parent/child split — it only has fd numbers). Instead, [src/audit/ebpf.rs](src/audit/ebpf.rs) defines a tiny `bpf_sys` submodule with three functions over `libc::syscall(SYS_bpf, …)`:

```rust
struct MapAttr { map_fd, _pad, key, value_or_next_key, flags }   // 32 bytes

fn map_update_u32_u64(fd, k, v)       -> uses BPF_MAP_UPDATE_ELEM   (cmd=2)
fn map_get_next_key_u32(fd, current)  -> uses BPF_MAP_GET_NEXT_KEY  (cmd=4)
fn map_lookup_u32_u64(fd, k)          -> uses BPF_MAP_LOOKUP_ELEM   (cmd=1)  [unused]
```

That's all the BPF syscall surface the sandbox needs.

### Limitation of the eBPF backend

Currently only **syscall names** are populated in `AuditReport`. The strace backend additionally extracts file paths (from `openat` args) and network addresses (from `connect`/`bind`). To match that with eBPF you'd add a `BPF_MAP_TYPE_RINGBUF`, hook `tracepoint/syscalls/sys_enter_openat`, `bpf_probe_read_user_str()` the path arg into the ringbuf, and drain it in the broker. Future work.

---

## 5. The strace backend (fallback)

Used when:
- not root (most common case),
- `--no-default-features` builds, or
- clang wasn't available at build time.

[`src/audit/strace.rs`](src/audit/strace.rs) `Command::spawn`s strace with `-f -e trace=all -o /tmp/hajiz-audit-<pid>.log`, then parses the text log line-by-line. Slower (ptrace overhead per syscall), more brittle (text parsing), but **captures paths and network addrs** which the eBPF backend doesn't.

---

## 6. Build system

### `Cargo.toml`

```toml
[features]
default = ["ebpf"]
ebpf = ["dep:aya"]

[dependencies]
nix = { …, features = ["signal","process","sched","mount","socket","uio"] }
aya = { version = "0.13", optional = true }
libseccomp = "0.3"
…
```

### `build.rs`

Runs at `cargo build` time:
1. Tries `clang -target bpf -O2 -g -I/usr/include -c bpf/audit_syscalls.c -o $OUT_DIR/audit_syscalls.o`
2. **If it succeeds**: emits `cargo:rustc-cfg=ebpf_compiled`, which gates the `include_bytes!` of the `.o` and the entire `inner` module in [src/audit/ebpf.rs](src/audit/ebpf.rs).
3. **If clang is missing or compilation fails**: emits a warning and skips the cfg flag. The eBPF module compiles down to nothing; the dispatcher falls back to strace.

Because the BPF object lands in `$OUT_DIR` (always under `target/`, already gitignored), there's nothing extra to ignore.

### Build matrix

| `--features` | clang available | Result |
|---|---|---|
| default (`ebpf`) | yes | both backends compiled in, eBPF preferred at runtime |
| default (`ebpf`) | no | aya compiles, but `ebpf_compiled` not set → eBPF code gated out, strace only |
| `--no-default-features` | (irrelevant) | aya not compiled, strace only |

---

## 7. Telemetry & monitoring

The parent process emits structured `SecurityEvent`s via `TelemetryLogger`:

| Event | When | Data |
|---|---|---|
| `SandboxStarted` | before spawn | pid, binary, profile, timestamp |
| `PolicyApplied` | before spawn | blocked syscalls, allowed paths, feature list |
| `SyscallDenied` | runtime (best effort) | pid, syscall name |
| `FilesystemDenied` | runtime (currently unwired) | pid, path |
| `ResourceUsage` | every `sample_interval` | pid, mem, pids, cpu_usec |
| `SandboxExited` | after wait | pid, exit_code, signal |

`SyscallDenied` events come from a background thread reading `/dev/kmsg` and parsing `audit: type=1326` records. Best-effort: requires `kernel.dmesg_restrict=0` or `CAP_SYSLOG`. **Replacement candidates** (in order of complexity):

1. **seccomp-notify** (simplest): switch the hardening filter from `SECCOMP_RET_ERRNO` to `SECCOMP_RET_USER_NOTIF`, read denials from the notify fd. No special privileges.
2. **eBPF ringbuf**: attach `tracepoint/raw_syscalls/sys_exit` filtering on `ret == -EPERM`, drain via aya `RingBuf`. Catches any EPERM, not just seccomp.

---

## 8. Testing

[`tests/exploit_tests.rs`](tests/exploit_tests.rs) — integration tests that exec the compiled binary (`env!("CARGO_BIN_EXE_hajiz")`):

| Test | What it verifies |
|---|---|
| `test_sandbox_basique` | basic launch doesn't panic |
| `test_isolation_pid` | uid_map non-empty (user-ns active) |
| `test_caps_vides` | `CapEff` is `0000000000000000` |
| `test_seccomp_bloque_unshare` | `unshare --pid true` fails with EPERM |
| `test_reseau_coupe` | curl fails inside isolated netns |
| `test_uid_non_remappé` | UID inside == UID outside |
| … | (see file) |

[`tests/escape_tests.rs`](tests/escape_tests.rs) — the adversarial counterpart: instead of checking a binary *runs*, each test *attacks* the sandbox and asserts the attack fails.

| Test | What it attacks |
|---|---|
| `escape_no_new_privs_is_set` | `no_new_privs` is on (setuid exec can't escalate) |
| `escape_keyctl_syscall_blocked` | `keyctl` denied by seccomp |
| `escape_bpf_syscall_returns_eperm` | `bpf()` returns EPERM inside sandbox |
| `escape_fs_read_outside_allowlist_blocked` | Landlock blocks reads outside allowlist |
| `escape_fs_write_outside_rules_blocked` | Landlock blocks writes outside rules |
| `escape_kill_on_deny_terminates_with_sigsys` | kill-on-deny seccomp kills with SIGSYS |
| `escape_audit_mode_generates_profile` | audit mode emits a profile |

(Landlock-dependent tests self-skip when the kernel lacks Landlock.)

Plus 30 unit tests across `audit::strace`, `audit::generator`, `isolation::seccomp`, `isolation::tests`, `telemetry::monitor`.

[`tests/container/`](tests/container/) — Docker-based escape harness ([run.sh](tests/container/run.sh) + [Dockerfile](tests/container/Dockerfile)): MITRE-ATT&CK-style `atomics/`, compiled `known_escapes/` CVE PoCs (CVE-2017-5226 TIOCSTI, CVE-2019-5736 /proc/self/exe, CVE-2022-0492 cgroup release_agent, nested userns), and `probes/` for fs/net/syscall reachability.

The eBPF backend doesn't have an automated test yet — running it needs root and `cargo test` doesn't do that by default.

---

## 9. Known limitations / future work

- `SyscallDenied` events rare at runtime — fix with seccomp-notify or eBPF ringbuf (above).
- No `CLONE_NEWPID` — `unshare(NEWPID)` only affects future children, not the exec'd binary. Would need a `setsid()` + double-fork + remount /proc dance.
- Cgroups v2 partially wired: limits applied, telemetry samples, but no events on OOM/limit-hit.
- eBPF audit: syscalls only, no path/network extraction (ringbuf migration is the path).
- No file capability install in `Cargo.toml` post-build script — installer documented in README but not automated.

---

## 10. Quick reference: where things live

| You're looking for | File |
|---|---|
| CLI flag | [src/main.rs](src/main.rs) |
| Pre-exec pipeline | [src/isolation/mod.rs](src/isolation/mod.rs) `apply_in_child` |
| User-ns + uid/gid maps | [src/isolation/namespaces.rs](src/isolation/namespaces.rs) |
| Cap drop order rationale | [src/isolation/capabilities.rs](src/isolation/capabilities.rs) |
| Hardening seccomp deny list | [src/isolation/seccomp.rs](src/isolation/seccomp.rs) `hardened_denied_syscalls()` |
| Landlock paths + ports | [src/isolation/filesystem.rs](src/isolation/filesystem.rs) |
| Kernel feature detection | [src/kernel/version.rs](src/kernel/version.rs) |
| eBPF audit broker/sandbox | [src/audit/ebpf.rs](src/audit/ebpf.rs) |
| BPF C program | [bpf/audit_syscalls.c](bpf/audit_syscalls.c) |
| Privilege primitives | [src/privesc/mod.rs](src/privesc/mod.rs) |
| Telemetry events | [src/telemetry/event.rs](src/telemetry/event.rs) |
| Profile schema | [src/profile/schema.rs](src/profile/schema.rs) |

---

## 11. Glossary

- **Bounding set**: per-process capability bitmap that limits what caps can ever be acquired (even by setuid exec). Dropped via `prctl(PR_CAPBSET_DROP)`.
- **Ambient set**: caps preserved across non-setuid exec. Cleared via `prctl(PR_CAP_AMBIENT_CLEAR_ALL)`.
- **CO-RE** (Compile Once Run Everywhere): BPF feature using BTF to relocate field offsets at load time. We don't use it — our struct accesses are straightforward enough.
- **BTF** (BPF Type Format): debug info embedded by clang `-g`, used by the kernel to type-check map definitions and CO-RE relocations.
- **Raw tracepoint**: lower-level tracepoint with direct access to the kernel function args (vs. the formatted `tracepoint/` interface that pre-decodes args via the trace event format).
- **SCM_RIGHTS**: Unix domain socket control message that passes file descriptors across processes; the receiver gets a new fd in its own table referring to the same kernel object.
- **`no_new_privs`**: `prctl(PR_SET_NO_NEW_PRIVS)`. Once set, setuid bits and file capabilities are ignored on `execve()`. Cannot be unset.
