# User Guide

## Current usage

```bash
hajiz /path/to/binary -- arg1 arg2
```

The first argument is the target binary. Remaining arguments are forwarded to the target process.

## Isolation pipeline

Each launched process is configured in child pre-exec order:

1. Namespace setup
2. Capability hardening
3. Landlock filesystem rules
4. Seccomp enforcement

## Namespaces

- Mount, IPC, and UTS namespaces are created.
- Network namespace isolation can be enabled through config (`disable_network = true` by default in `IsolationConfig`).

## Landlock filesystem enforcement

Landlock path-based rules are applied before `exec`.

- `read_only = true` allows read/execute semantics.
- `read_only = false` allows read/write/execute semantics for the path.

Rules are defined through `IsolationConfig.filesystem_rules`.

## Capability hardening

The runtime applies:

- `PR_SET_NO_NEW_PRIVS`
- ambient capability clear (`PR_CAP_AMBIENT_CLEAR_ALL`)
- effective/permitted/inheritable capability set clear (`capset` syscall)
- optional bounding-set drop for all capabilities

## Seccomp modes

The runtime supports three seccomp behaviors:

1. Whitelist mode (`use_seccomp_whitelist = true`)
2. Hardening mode (`enable_hardening_filter = true`, default)
3. Strict mode (`strict_seccomp = true`)

Hardening mode denies high-risk primitives such as:

- `unshare`, `setns`, `clone3`
- `bpf`, `userfaultfd`
- keyring syscalls (`add_key`, `request_key`, `keyctl`)

## Landlock namespace/capability RFC context

Landlock namespace and capability controls discussed in RFC patches require newer kernel support (ABI changes).
Until broadly available, this project approximates the same security goal with:

- namespace policy in launcher logic,
- capability stripping,
- and seccomp hardening to block namespace re-entry and escalation vectors.

More examples can be added as CLI options are reintroduced.
