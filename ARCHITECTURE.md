# hajiz — 架构与内部实现

内部参考文档。不面向公开 README；放在这里，是为了让 AI 会话和未来的自己不用翻代码就能接上上下文。

---

## 1. 这个项目实际上是什么

**hajiz** 是用 Rust 编写的默认拒绝（default-deny）Linux 应用沙箱。你交给它一个二进制，它就只使用 Linux 内核原语，把这个二进制放进一个严格约束的执行环境里运行——没有守护进程，没有 setuid，也没有内核模块。

这是一个大学三年级的系统安全课程项目。可以把它看成 `bubblewrap` / `firejail` 更小、更偏教学的同类工具，并额外带有一个基于 eBPF 的审计模式：观察二进制实际需要什么，再据此写出策略。

### 目标
1. **默认无根（rootless）。** 普通用户无需 `sudo` 就能沙箱化一个二进制。
2. **默认拒绝。** 除明确允许的内容外，没有文件系统、没有网络、也没有系统调用。
3. **可组合的策略。** TOML 配置描述网络模式、文件系统规则和 seccomp 分组。
4. **可观测。** 每一次隔离决策、每一次被拒绝的系统调用，都有结构化遥测（JSON）。
5. **自适应。** 运行时检测内核能力；在较旧的内核上优雅降级。

### 威胁模型
- **受信任**：内核、hajiz 二进制，以及我们读取的配置文件。
- **不受信任**：被沙箱化的二进制，以及它产生的一切。
- **防御目标**：文件系统逃逸、重新进入命名空间、网络外泄、权能滥用、基于系统调用的利用，以及通过 `exec()` 的权限提升。
- **不在范围内**：侧信道（Spectre / 时序）、内核漏洞利用、硬件攻击，以及 hajiz 二进制本身已被攻破的情况。

---

## 2. 模块地图

```
src/
├── main.rs                        CLI 解析与顶层编排
├── lib.rs                         模块再导出
├── error.rs                       HajizError { Config, Isolation, Io }
│
├── kernel/
│   └── version.rs                 KernelCapabilities — 读取 /proc/version，
│                                  特性矩阵（user_ns、landlock、landlock_net、
│                                  seccomp_strict、cap_bpf 等）
│
├── profile/
│   ├── schema.rs                  TOML 的 serde 结构体
│   ├── parser.rs                  加载并校验
│   └── mod.rs                     load_profile()
│
├── isolation/
│   ├── mod.rs                     apply_in_child() — exec 前的隔离流水线
│   ├── namespaces.rs              unshare(CLONE_NEWUSER|NEWNS|NEWIPC|NEWUTS|NEWNET)
│   │                              + uid/gid 恒等映射 + MS_PRIVATE 重新挂载
│   ├── capabilities.rs            丢弃 bounding set → capset(0) → no_new_privs
│   ├── filesystem.rs              Landlock 路径规则 + TCP 端口允许列表
│   └── seccomp.rs                 strict / allowlist / hardening-deny 三种模式
│
├── runtime/
│   ├── process.rs                 SandboxProcess::spawn（使用 pre_exec 钩子）
│   └── pidfile.rs                 PID 文件辅助函数
│
├── cgroups/
│   ├── mod.rs                     apply_limits、cgroup_path_for、cleanup_cgroup
│   └── limits.rs                  ResourceLimits（内存 / CPU / PID）
│
├── telemetry/
│   ├── event.rs                   SecurityEvent 枚举（PolicyApplied、SandboxStarted、
│   │                              SyscallDenied、FilesystemDenied、NetworkDenied、
│   │                              ResourceUsage、SandboxExited）
│   ├── logger.rs                  TelemetryLogger（详细 stderr + JSON 文件），
│   │                              policy_hash()
│   ├── monitor.rs                 后台线程：kmsg 读取器、cgroup 采样器
│   └── mod.rs                     spawn_monitors()
│
├── privesc/
│   └── mod.rs                     ★ 新增 — broker/sandbox 原语：
│                                  socketpair、send_fds、recv_fds（SCM_RIGHTS）、
│                                  drop_all_capabilities、can_use_bpf
│
└── audit/
    ├── mod.rs                     run_audit() — 分发到 eBPF 或 strace
    ├── strace.rs                  旧后端：启动 strace 并解析输出
    ├── ebpf.rs                    ★ 新增 — 带权限分离的 eBPF 后端
    └── generator.rs               AuditReport → TOML 配置

bpf/
└── audit_syscalls.c               ★ 新增 — BPF C 程序（raw_tracepoint/sys_enter）

build.rs                           ★ 新增 — 用 clang -target bpf 编译 bpf/*.c

tests/
├── exploit_tests.rs               针对已编译二进制的集成测试
├── escape_tests.rs                主动逃逸尝试（攻击沙箱）
└── container/                     基于 Docker 的逃逸探测（atomics、CVE）

profiles/
├── untrusted.toml                 默认拒绝的示例配置
├── firefox.toml                   浏览器配置
├── document-viewer.toml           PDF / 文档阅读器配置
├── media-player.toml              音视频播放器配置
└── office.toml                    办公套件配置

examples/
└── basic_isolation.rs            最小的库用法示例

docs/
└── user-guide.md                 终端用户文档

packaging/
└── apparmor/hajiz                用于发行版打包的 AppArmor 配置
```

---

## 3. 隔离流水线

运行 `hajiz <binary>` 时，父进程通过带 `pre_exec` 钩子的 `Command::spawn` 创建子进程。钩子在**子进程内部、`fork()` 之后、`exec()` 之前**运行，并按下述流水线施加隔离。**顺序至关重要。**

```
[父进程: hajiz]                                  [子进程: pre_exec，exec() 之前]
   │                                                            │
   ├─ 解析 CLI                                                  │
   ├─ 加载配置（可选）                                          │
   ├─ 构建 IsolationConfig                                      │
   ├─ 可选：对自身施加 cgroup 限制                              │
   ├─ 经 Command + pre_exec 创建子进程 ───────────────────────► │
   ├─ 可选：启动遥测监控                                        │  1. setup_namespaces
   │     （kmsg 读取器、cgroup 采样器）                         │     unshare(CLONE_NEWUSER|NEWNS|NEWIPC|NEWUTS|[NEWNET])
   ├─ 等待子进程                                                │     写入 /proc/self/{uid,gid}_map（恒等映射）
   └─ 退出时：记录 SandboxExited，清理 cgroup                   │     对 / 执行 mount(MS_PRIVATE|MS_REC)
                                                                │
                                                                │  2. drop_capabilities
                                                                │     对权能 0..40 执行 PR_CAPBSET_DROP
                                                                │     （必须发生在 capset 之前 — 需要 CAP_SETPCAP）
                                                                │     PR_CAP_AMBIENT_CLEAR_ALL
                                                                │     capset(0,0,0)
                                                                │     PR_SET_NO_NEW_PRIVS
                                                                │
                                                                │  3. setup_filesystem（Landlock）
                                                                │     没有规则或内核 < 5.13 时跳过
                                                                │     添加路径规则 + TCP 端口规则
                                                                │
                                                                │  4. apply_seccomp
                                                                │     hardening-deny（默认）| allowlist | strict
                                                                │     加固模式拒绝：unshare、setns、clone3、bpf、
                                                                │       userfaultfd、add_key、request_key、keyctl、
                                                                │       ptrace、process_vm_readv、process_vm_writev
                                                                │     通过 prctl(PR_SET_SECCOMP) 安装 BPF 过滤器
                                                                │
                                                                │  5. exec(binary, args)
                                                                │     ← 目标进程从此在上述全部约束下运行
```

### 关键的顺序不变量

| 错误顺序 | 为什么会坏 |
|---|---|
| `capset()` 早于 `PR_CAPBSET_DROP` | `capset(0)` 会去掉 `CAP_SETPCAP`，随后丢弃 bounding set 会以 EPERM 失败 |
| 先丢权能、后进入用户命名空间 | 非特权用户手里没有可丢弃的权能——必须先进入 user-ns，才能获得命名空间内的权能 |
| Seccomp 早于 Landlock | Landlock 加载会使用 `landlock_create_ruleset` 等系统调用，严格 seccomp 过滤器会拦住它们 |
| 先重新挂载、后进入 user-ns | `mount(MS_PRIVATE)` 需要 `CAP_SYS_ADMIN`，非特权用户只有在 user-ns 里才具备它 |

### 网络模式分层

| 模式 | 是否 unshare(NEWNET) | 网络接口 | 适用场景 |
|---|---|---|---|
| `none`（默认） | 是 | 无 | 最大限度隔离 |
| `loopback` | 是 | `lo` 为 UP，并配置 `127.0.0.1/8` | 本地服务 |
| `full` | 否 | 使用宿主机的接口 | 需要联网的应用；内核 ≥ 6.7 时仍可施加 Landlock 端口允许列表 |

---

## 4. 审计模式 — 带 broker/sandbox 分离的 eBPF 后端

审计模式在**不加隔离**的情况下运行二进制，观察它实际发出了哪些系统调用，然后生成一份 TOML 配置，供你审阅后再用于真正的沙箱运行。

### 两个后端，一个分发器

[`src/audit/mod.rs`](src/audit/mod.rs) 在运行时选择后端：

```rust
if cfg!(all(feature = "ebpf", ebpf_compiled)) && privesc::can_use_bpf() {
    return ebpf::inner::run_audit_ebpf(binary, args);   // requires root / CAP_BPF
}
strace::run_audit(binary, args)                         // unprivileged fallback
```

- `feature = "ebpf"` 控制是否把 `aya` 编译进来（`Cargo.toml` 里默认开启）。
- `ebpf_compiled` 由 [build.rs](build.rs) 设置，**仅当** clang 成功编译了 `bpf/audit_syscalls.c`。如果没有安装 clang，或编译失败，这个 cfg 标志保持未设置，eBPF 代码路径会被完全门控掉——包括对那个并不存在的 `.o` 文件的 `include_bytes!`。
- `can_use_bpf()` 在运行时检查 `geteuid() == 0`。不满足时，即使启用了该 feature，也会回退到 strace。

### 为什么采用 broker/sandbox 模式

加载 eBPF 程序需要 `CAP_BPF`（内核 ≥ 5.8）或 root。朴素做法是让整个工具都以特权运行。我们不这么做——**运行目标二进制的子进程在任何一条指令上都不持有特权**。Chrome 沙箱、firejail 和 bwrap 用的是同一模式。

为什么在加载 BPF **之后**再丢弃特权是安全的：内核只在创建 fd 时检查 `CAP_BPF`。BPF map / program 的 fd 一旦存在，就只是一个文件描述符——持有它的人就能使用它。因此我们先在特权状态下加载，把 fd 交出去，然后再丢权能。

### 执行流程（审计，eBPF 路径）

```
用户 shell
   │
   └─ sudo hajiz --audit /usr/bin/curl ...
        │
        ▼
┌────────────────────────────────────────────────────────────────────────┐
│ hajiz 进程（特权，拥有 CAP_BPF 或为 root）                              │
│                                                                        │
│  socketpair(AF_UNIX, SOCK_STREAM)                                      │
│  fork() ───────────────────────────────────────────┐                   │
│   │                                                │                   │
│   │ 父进程（broker）                               │ 子进程（sandbox） │
│   │                                                │                   │
│   │ 加载 BPF 对象                                  │ ★ 第一条指令：     │
│   │  └─ include_bytes!(audit_syscalls.o)           │   drop_all_capabilities()
│   │  └─ aya::Ebpf::load                            │   （capset(0) + bounding set
│   │  └─ RawTracePoint::attach("sys_enter")         │    + 清空 ambient + no_new_privs）
│   │  ↑ 内核在这里检查 CAP_BPF                      │                   │
│   │                                                │   recv_fds() ←─── │
│   │ 取得原始 fd：config_map、syscall_map           │   （执行到这里时   │
│   │                                                │    已经没有特权） │
│   │ send_fds() ─────────SCM_RIGHTS────────────────►│                   │
│   │                                                │   启动目标二进制   │
│   │ drop_all_capabilities()                        │   （Command::new(binary).spawn）
│   │ ★ broker 此刻同样不再持有特权                  │                   │
│   │   BPF 仍然存活，因为我们持有 fd                │   bpf(MAP_UPDATE_ELEM,
│   │                                                │       config_map[0] = target.pid)
│   │                                                │                   │
│   │                                                │   目标运行 ─── 内核：
│   │                                                │                   raw_tracepoint
│   │                                                │                   /sys_enter
│   │                                                │                   每次系统调用触发，
│   │                                                │                   按 tgid 过滤，
│   │                                                │                   递增 syscall_map
│   │                                                │                   │
│   │                                                │   target.wait()   │
│   │                                                │   bpf(MAP_UPDATE,  │
│   │                                                │       config[0]=0) │
│   │                                                │                   │
│   │                                                │   循环：          │
│   │                                                │     bpf(GET_NEXT_KEY)
│   │                                                │     把 syscall_nr 解析成名字
│   │                                                │       （libseccomp::ScmpSyscall）
│   │                                                │                   │
│   │                                                │   序列化报告：    │
│   │                                                │     "EXIT:<code>\n"
│   │                                                │     "<syscall>\n" * N
│   │                                                │                   │
│   │ 从 socket 读取 ◄────────────────写入 ──────────│                   │
│   │ 解析文本协议                                   │   关闭 socket     │
│   │                                                │   退出            │
│   │ waitpid(child)                                 │                   │
│   │                                                │                   │
│   │ Ebpf 被丢弃 → BPF 程序分离，map 释放           │                   │
│   │                                                │                   │
│   │ 返回 AuditReport                               │                   │
│   ▼                                                │                   │
│ main.rs:                                                               │
│   generate_profile(&report, …)                                         │
│   写入 --audit-output，或写到 stdout                                   │
│   exit(report.exit_code)                                               │
└────────────────────────────────────────────────────────────────────────┘
```

### 特权窗口

| 进程 | 特权窗口 | 窗口里做什么 |
|---|---|---|
| Broker | 从启动到 `send_fds()` 之后的 `drop_all_capabilities()` | 加载并挂载 BPF，再 sendmsg。持续数微秒。不处理用户输入，也不 exec。 |
| Sandbox | 从 `fork()` 到返回用户态的第一条指令 | 一次系统调用返回。`drop_all_capabilities()` 是它做的第一件事。 |

### BPF 程序（[bpf/audit_syscalls.c](bpf/audit_syscalls.c)）

刻意写得很小，大约 30 行：
- 两张 map：`config_map`（1 项的 ARRAY，保存目标 TGID）、`syscall_map`（HASH，syscall_nr → 调用次数）。
- 一个程序：`raw_tracepoint/sys_enter`。每次系统调用时：
  - 检查过滤 PID；不是目标就直接返回。
  - 对 `ctx->args[1]`（即系统调用号）做 `__sync_fetch_and_add`。

内核的 BPF 验证器会静态证明边界检查、没有无限循环、没有未初始化读取。这才是真正的安全边界；源语言本身并不重要。

### 为什么用 C，不用 Rust（aya-ebpf）

| | C + clang | Rust + aya-ebpf |
|---|---|---|
| 构建依赖 | `clang`（已有）、`libbpf` 头文件（已有） | `bpf-linker`（未安装）+ nightly Rust + 单独的 `no_std` 工作区，目标为 `bpfel-unknown-none` |
| 审计参考材料 | 内核文档、各类 CVE 分析、bcc/bpftrace 示例 | 主要是 aya 自己的示例 |
| 字节码对应关系 | 与 C 源码一一对应 | 宏会隐藏实际发出的内容 |
| 内核验证器 | 相同 | 相同（这才是真正的安全边界） |

对 30 行代码来说，C 在工具链简单程度和审计清晰度上更合适。只有当程序大到需要与用户态共享类型时，再改用 Rust eBPF。

### 子进程里的原始 bpf(2) 系统调用

aya 留在 broker 里。sandbox 不能使用 aya（aya 把 map 状态放在用户内存中，父/子进程分离后这份状态不会跟着走——子进程手里只有 fd 号）。因此 [src/audit/ebpf.rs](src/audit/ebpf.rs) 定义了一个很小的 `bpf_sys` 子模块，用 `libc::syscall(SYS_bpf, …)` 包了三个函数：

```rust
struct MapAttr { map_fd, _pad, key, value_or_next_key, flags }   // 32 bytes

fn map_update_u32_u64(fd, k, v)       -> uses BPF_MAP_UPDATE_ELEM   (cmd=2)
fn map_get_next_key_u32(fd, current)  -> uses BPF_MAP_GET_NEXT_KEY  (cmd=4)
fn map_lookup_u32_u64(fd, k)          -> uses BPF_MAP_LOOKUP_ELEM   (cmd=1)  [unused]
```

sandbox 需要的 BPF 系统调用面就这些。

### eBPF 后端的局限

目前 `AuditReport` 里只填了**系统调用名**。strace 后端还会从 `openat` 参数提取文件路径，从 `connect` / `bind` 提取网络地址。要用 eBPF 做到同样的事，需要增加 `BPF_MAP_TYPE_RINGBUF`，挂上 `tracepoint/syscalls/sys_enter_openat`，用 `bpf_probe_read_user_str()` 把路径参数读进 ringbuf，再由 broker 排空。这是后续工作。

第二个、较小的缺口：sandbox 在把目标 PID 写入 `config_map` **之前**就 `spawn()` 了目标（fork+exec），因此目标在 exec 之后、过滤器武装之前发出的那几次系统调用可能被漏掉。这个窗口很小，只影响审计完整性（从不影响真正运行时的隔离），但意味着生成的配置可能会低估最早的那几次调用。要补上，需要在 exec 之前就对一个已知 PID 武装过滤器（例如多一次 fork，或者 stop-on-exec、更新 map、再继续这一套动作）。

---

## 5. strace 后端（回退）

在以下情况使用：
- 不是 root（最常见），
- 以 `--no-default-features` 构建，或
- 构建时没有 clang。

[`src/audit/strace.rs`](src/audit/strace.rs) 用 `Command::spawn` 启动 strace，参数为 `-f -e trace=all -o /tmp/hajiz-audit-<pid>.log`，然后逐行解析文本日志。它更慢（每个系统调用都有 ptrace 开销），也更脆（依赖文本解析），但**能捕获路径和网络地址**，这是 eBPF 后端做不到的。

---

## 6. 构建系统

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

在 `cargo build` 时运行：
1. 尝试执行 `clang -target bpf -O2 -g -I/usr/include -c bpf/audit_syscalls.c -o $OUT_DIR/audit_syscalls.o`。
2. **成功时**：发出 `cargo:rustc-cfg=ebpf_compiled`，用来门控对 `.o` 的 `include_bytes!`，以及 [src/audit/ebpf.rs](src/audit/ebpf.rs) 里的整个 `inner` 模块。
3. **clang 缺失或编译失败时**：发出警告并跳过该 cfg 标志。eBPF 模块会编译成空实现；分发器回退到 strace。

BPF 对象落在 `$OUT_DIR`（始终位于 `target/` 下，已被 gitignore），因此不需要额外忽略任何文件。

### 构建矩阵

| `--features` | clang 是否可用 | 结果 |
|---|---|---|
| 默认（`ebpf`） | 是 | 两个后端都编译进来，运行时优先 eBPF |
| 默认（`ebpf`） | 否 | aya 会编译，但未设置 `ebpf_compiled` → eBPF 代码被门控掉，只剩 strace |
| `--no-default-features` | （无关） | 不编译 aya，只剩 strace |

---

## 7. 遥测与监控

父进程通过 `TelemetryLogger` 发出结构化的 `SecurityEvent`：

| 事件 | 时机 | 数据 |
|---|---|---|
| `SandboxStarted` | spawn 之前 | pid、二进制、配置、时间戳 |
| `PolicyApplied` | spawn 之前 | 被阻断的系统调用、允许的路径、特性列表 |
| `SyscallDenied` | 运行时 | pid、系统调用名 |
| `FilesystemDenied` | 运行时（预测，内核 ≥ 5.5） | pid、路径 |
| `NetworkDenied` | 运行时（预测，内核 ≥ 5.5） | pid、操作、地址、端口 |
| `ResourceUsage` | 每个 `sample_interval` | pid、内存、pids、cpu_usec |
| `SandboxExited` | wait 之后 | pid、exit_code、signal |

### 拒绝遥测：seccomp 用户通知

在内核 ≥ 5.0 上，加固过滤器对被拒绝的系统调用加载的是 `SECCOMP_RET_USER_NOTIF`，而不是 `SECCOMP_RET_ERRNO`。流程如下：

1. pre-exec 子进程加载过滤器，取得监听 fd（`seccomp_notify_fd`），把它标成 CLOEXEC，使目标进程永远不能自己处理这些通知，再通过 socketpair 用 SCM_RIGHTS（`privesc::send_fds`）把它发给父进程——与审计 broker 用的是同一原语。
2. 父进程里的监督线程（`telemetry/notify.rs`）轮询这个 fd。加固拒绝被记录为 `SyscallDenied`，并以 `-EPERM` 应答；沙箱中的调用线程看到的就是普通的 EPERM，与 `SECCOMP_RET_ERRNO` 时相同。
3. 当存在 Landlock 规则、遥测消费者处于活动状态（`--log` / `--verbose`），且内核 ≥ 5.5 时，文件系统系统调用（`open` / `openat` / `unlink` / `mkdir` / `rename` 等族）也会走通知路径：监督者从 `/proc/<pid>/mem` 读取路径（对照 pid 复用校验通知 id），根据配置规则预测 Landlock 的决定，未命中时发出 `FilesystemDenied`，并以 `SECCOMP_USER_NOTIF_FLAG_CONTINUE` 应答，让内核照常执行该系统调用——**Landlock 仍然是强制执行点；预测只用于遥测**（它会解析 cwd 和 dirfd，但不会像内核那样追踪符号链接）。
4. 当 TCP 端口允许列表处于活动状态时，`connect` / `bind` 以同样方式走通知路径：监督者从 `/proc/<pid>/mem` 读取 sockaddr，预测 Landlock 的 TCP 端口决定，未命中时发出 `NetworkDenied`，并应答 CONTINUE——真正的决定仍由 Landlock 做出。契约与文件系统路径相同：只做预测。

回退路径：内核 < 5.0、`--kill-on-deny`（杀死动作必须留在内核内），以及白名单 / strict 模式，仍走原先的路径——一个后台线程读取 `/dev/kmsg` 并解析 `audit: type=1326` 记录，这需要 `kernel.dmesg_restrict=0` 或 `CAP_SYSLOG`。一种可能的后续升级，是在 `tracepoint/raw_syscalls/sys_exit` 上使用 eBPF ringbuf，过滤 `ret == -EPERM`，这样能捕获任何 EPERM，而不仅是 seccomp 产生的。

---

## 8. 测试

[`tests/exploit_tests.rs`](tests/exploit_tests.rs) — 执行已编译二进制的集成测试（`env!("CARGO_BIN_EXE_hajiz")`）：

| 测试 | 验证内容 |
|---|---|
| `test_sandbox_basique` | 基本启动不会 panic |
| `test_isolation_pid` | uid_map 非空（user-ns 已生效） |
| `test_caps_vides` | `CapEff` 为 `0000000000000000` |
| `test_seccomp_bloque_unshare` | `unshare --pid true` 以 EPERM 失败 |
| `test_reseau_coupe` | curl 在隔离的网络命名空间中失败 |
| `test_uid_non_remappé` | 内部 UID 等于外部 UID |
| … | （见源文件） |

[`tests/escape_tests.rs`](tests/escape_tests.rs) — 对抗性的另一面：每个测试不是检查二进制*能否运行*，而是*攻击*沙箱，并断言攻击失败。

| 测试 | 攻击什么 |
|---|---|
| `escape_no_new_privs_is_set` | `no_new_privs` 已开启（setuid exec 无法提权） |
| `escape_keyctl_syscall_blocked` | seccomp 拒绝 `keyctl` |
| `escape_bpf_syscall_returns_eperm` | 沙箱内 `bpf()` 返回 EPERM |
| `escape_fs_read_outside_allowlist_blocked` | Landlock 阻止允许列表之外的读取 |
| `escape_fs_write_outside_rules_blocked` | Landlock 阻止规则之外的写入 |
| `escape_kill_on_deny_terminates_with_sigsys` | kill-on-deny seccomp 以 SIGSYS 杀死进程 |
| `escape_audit_mode_generates_profile` | 审计模式会生成一份配置 |

（依赖 Landlock 的测试会在内核没有 Landlock 时自行跳过。）

另外还有分布在 `audit::strace`、`audit::generator`、`isolation::seccomp`、`isolation::tests`、`telemetry::monitor` 中的 30 个单元测试。

[`tests/container/`](tests/container/) — 基于 Docker 的逃逸测试框架（[run.sh](tests/container/run.sh) + [Dockerfile](tests/container/Dockerfile)）：MITRE-ATT&CK 风格的 `atomics/`、编译好的 `known_escapes/` CVE PoC（CVE-2017-5226 TIOCSTI、CVE-2019-5736 /proc/self/exe、CVE-2022-0492 cgroup release_agent、嵌套 userns），以及用于探测文件系统 / 网络 / 系统调用可达性的 `probes/`。

eBPF 后端还没有自动化测试——运行它需要 root，而 `cargo test` 默认不会这么做。

---

## 9. 已知局限 / 后续工作

- `FilesystemDenied` 是基于规则的预测（不做符号链接解析）；在没有 eBPF 或 Landlock 审计（内核 ≥ 6.15）的情况下，观察不到内核自己的裁决。
- 没有 `CLONE_NEWPID`——`unshare(NEWPID)` 只影响之后的子进程，不影响已经 exec 的二进制。要做到这一点，需要 `setsid()` + 双重 fork + 重新挂载 /proc 这一套动作。
- cgroups v2 只接了一部分：限制会施加，遥测会采样，但 OOM / 触及上限时没有事件。
- eBPF 审计：只有系统调用，没有路径 / 网络提取（迁移到 ringbuf 是那条路）。
- `Cargo.toml` 的构建后脚本里没有安装文件权能——README 里写了安装步骤，但没有自动化。

---

## 10. 速查：东西在哪里

| 你要找的 | 文件 |
|---|---|
| CLI 标志 | [src/main.rs](src/main.rs) |
| exec 前流水线 | [src/isolation/mod.rs](src/isolation/mod.rs) `apply_in_child` |
| user-ns 与 uid/gid 映射 | [src/isolation/namespaces.rs](src/isolation/namespaces.rs) |
| 丢弃权能的顺序理由 | [src/isolation/capabilities.rs](src/isolation/capabilities.rs) |
| 加固 seccomp 拒绝列表 | [src/isolation/seccomp.rs](src/isolation/seccomp.rs) `hardened_denied_syscalls()` |
| Landlock 路径与端口 | [src/isolation/filesystem.rs](src/isolation/filesystem.rs) |
| 内核特性检测 | [src/kernel/version.rs](src/kernel/version.rs) |
| eBPF 审计 broker/sandbox | [src/audit/ebpf.rs](src/audit/ebpf.rs) |
| BPF C 程序 | [bpf/audit_syscalls.c](bpf/audit_syscalls.c) |
| 特权原语 | [src/privesc/mod.rs](src/privesc/mod.rs) |
| 遥测事件 | [src/telemetry/event.rs](src/telemetry/event.rs) |
| 配置 schema | [src/profile/schema.rs](src/profile/schema.rs) |

---

## 11. 术语表

- **Bounding set（权能边界集）**：每个进程一份的权能位图，限制该进程此后能获得哪些权能（即使通过 setuid exec）。通过 `prctl(PR_CAPBSET_DROP)` 丢弃。
- **Ambient set（环境权能集）**：在非 setuid 的 exec 之间保留的权能。通过 `prctl(PR_CAP_AMBIENT_CLEAR_ALL)` 清空。
- **CO-RE**（Compile Once Run Everywhere，一次编译到处运行）：利用 BTF 在加载时重定位字段偏移的 BPF 特性。我们没有使用它——我们的结构体访问足够直接。
- **BTF**（BPF Type Format）：由 clang `-g` 嵌入的调试信息，内核用它做 map 定义的类型检查和 CO-RE 重定位。
- **Raw tracepoint**：更底层的 tracepoint，可以直接访问内核函数参数（相对于已经按 trace event 格式预先解码参数的 `tracepoint/` 接口）。
- **SCM_RIGHTS**：Unix 域套接字的控制消息，用来在进程之间传递文件描述符；接收方在自己的 fd 表里得到一个新 fd，指向同一个内核对象。
- **`no_new_privs`**：`prctl(PR_SET_NO_NEW_PRIVS)`。一旦设置，`execve()` 时会忽略 setuid 位和文件权能。不能取消。
