# Container-isolated test harness

Double-isolation test harness for hajiz. Wraps the sandbox under test inside a
Docker container with `--network none`, dropped capabilities, and a read-only
rootfs so that any escape from hajiz still has to defeat a second layer
before reaching the host.

## Layered isolation

From outermost to innermost :

1. `docker --network none` — no interface, no route.
2. `docker --read-only` + tmpfs mounts — rootfs immuable, écritures volatiles.
3. `docker --cap-drop=ALL` puis `--cap-add SYS_ADMIN/SETUID/SETGID` — caps
   restantes minimales pour que hajiz puisse poser ses namespaces.
4. `docker --security-opt seccomp=unconfined apparmor=unconfined` — la profile
   par défaut Docker bloque `unshare`/`mount` ; on désactive pour laisser hajiz
   poser sa propre policy.
5. `hajiz --net none` — netns enfant vide.
6. seccomp / Landlock / cgroups internes à hajiz.

Si une couche tombe, la suivante absorbe.

## Pré-requis

- Docker daemon en marche (vérifié sur Docker 29.4.2).
- Kernel ≥ 6.7 pour Landlock TCP networking (testé sur 6.19.14-arch1-1).
- Binaire hajiz construit en release :

```bash
cargo build --release
```

## Reproduire les résultats

```bash
# Construit l'image jetable hajiz-test:latest (Arch + gcc + strace + binaires).
tests/container/run.sh build

# Enchaîne tous les tests : 3 synthétiques + 4 CVE + 5 atomics MITRE.
tests/container/run.sh all

# Probes individuels :
tests/container/run.sh net               # sortie réseau
tests/container/run.sh fs                # lecture/écriture hors allowlist Landlock
tests/container/run.sh syscall           # syscalls dangereux (unshare/bpf/keyctl)

# CVE publiques :
tests/container/run.sh cve-tiocsti       # CVE-2017-5226 (Bubblewrap TIOCSTI)
tests/container/run.sh cve-cgroup        # CVE-2022-0492 (runC cgroups v1)
tests/container/run.sh cve-procexe       # CVE-2019-5736 (runC /proc/self/exe)
tests/container/run.sh cve-userns        # nested user namespace abuse
tests/container/run.sh cve               # les 4 enchaînées

# Atomics MITRE ATT&CK (Tier 2) :
tests/container/run.sh atomic-procmaps   # T1003.007 — credential dump via /proc
tests/container/run.sh atomic-destruct   # T1485 — data destruction
tests/container/run.sh atomic-procroot   # T1611 — escape to host via /proc/1/root
tests/container/run.sh atomic-ptrace     # T1055.008 — ptrace process injection
tests/container/run.sh atomic-discovery  # T1083 — file/directory discovery
tests/container/run.sh atomic            # les 5 enchaînées

tests/container/run.sh shell             # shell interactif dans le container
```

## Convention des probes

Chaque probe retourne :

- `exit=0` si l'évasion a réussi (mauvais signe — la sandbox est cassée).
- `exit=1` si la tentative a été refusée (bon signe).

Les messages stderr indiquent quelle couche a refusé (errno renvoyé).

## Résultats de référence

Environnement de test :

- hajiz 0.1.0
- Linux 6.19.14-arch1-1
- Docker 29.4.2

```text
$ tests/container/run.sh all
=== net_probe ===
[hajiz] sandboxed process started (PID 8)
blocked: Network is unreachable
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== fs_probe ===
[hajiz] sandboxed process started (PID 8)
read /etc/shadow: Permission denied
read /proc/1/root/etc/hostname: Permission denied
read /root/.bash_history: Permission denied
write /escape_marker: Read-only file system
write /etc/hajiz_escape: Read-only file system
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== syscall_probe ===
[hajiz] sandboxed process started (PID 8)
unshare(CLONE_NEWUSER): Operation not permitted
bpf(): Operation not permitted
keyctl(): Operation not permitted
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== cve_2017_5226_tiocsti ===
[hajiz] sandboxed process started (PID 8)
TIOCSTI blocked: Input/output error
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== cve_2022_0492_cgroup_release ===
[hajiz] sandboxed process started (PID 8)
/sys/fs/cgroup/release_agent blocked: No such file or directory
/sys/fs/cgroup/memory/release_agent blocked: No such file or directory
/sys/fs/cgroup/cpu/release_agent blocked: No such file or directory
/sys/fs/cgroup/systemd/release_agent blocked: No such file or directory
/sys/fs/cgroup/rdma/release_agent blocked: No such file or directory
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== cve_2019_5736_procselfexe ===
[hajiz] sandboxed process started (PID 8)
/proc/self/exe O_WRONLY blocked: Permission denied
/proc/self/exe O_RDWR blocked: Permission denied
/proc/7/exe O_WRONLY blocked: Permission denied
/proc/7/exe O_RDWR blocked: Permission denied
/proc/1/exe O_WRONLY blocked: Permission denied
/proc/1/exe O_RDWR blocked: Permission denied
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== nested_userns ===
[hajiz] sandboxed process started (PID 8)
unshare(CLONE_NEWUSER) blocked: Operation not permitted
unshare(NEWUSER|NEWNS) blocked: Operation not permitted
open /proc/1/ns/user blocked: Permission denied
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
```

```text
$ tests/container/run.sh atomic
=== atomics/T1003.007_proc_maps_read.sh ===
[hajiz] sandboxed process started (PID 8)
blocked: /proc/1/maps unreadable
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== atomics/T1485_destructive_overwrite.sh ===
[hajiz] sandboxed process started (PID 8)
blocked: /etc/hostname write refused
blocked: /etc/passwd write refused
blocked: /usr/bin/ls write refused
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== atomics/T1611_proc_root_traversal.sh ===
[hajiz] sandboxed process started (PID 7)
blocked: /proc/1/root/etc/shadow unreadable
blocked: /proc/1/root/etc/hostname unreadable
blocked: /proc/1/root/root/.bash_history unreadable
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 7
exit=1
=== atomics/T1055_ptrace_injection.sh ===
[hajiz] sandboxed process started (PID 8)
blocked: ptrace refused
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
=== atomics/T1083_file_discovery.sh ===
[hajiz] sandboxed process started (PID 8)
blocked: /etc unlisted
blocked: /root unlisted
blocked: /home unlisted
blocked: /var/log unlisted
[hajiz] process exited: exit status: 1
[hajiz] cleanup complete for PID 8
exit=1
```

## Lecture des résultats — quelle couche a vraiment bloqué ?

Tous les probes terminent avec `exit=1` (refus). Mais le refus n'a pas
toujours été imposé par hajiz lui-même — parfois c'est l'environnement
extérieur (kernel sysctl, container) qui a absorbé l'attaque avant qu'elle
n'atteigne les filtres hajiz. Distinction importante pour évaluer la sandbox.

| Probe | errno observé | Couche qui refuse | Test réel de hajiz ? |
|---|---|---|---|
| `net_probe` | `ENETUNREACH` | hajiz `--net none` (netns enfant vide) | ✅ |
| `fs_probe` | `EACCES` / `EROFS` | hajiz Landlock + container `--read-only` | ✅ |
| `syscall_probe` | `EPERM` | hajiz hardening seccomp | ✅ |
| `cve-tiocsti` | `EIO` | kernel sysctl `dev.tty.legacy_tiocsti=0` | ❌ — défense-en-profondeur |
| `cve-cgroup` | `ENOENT` | container, pas de mount `/sys/fs/cgroup` | ❌ — défense-en-profondeur |
| `cve-procexe` | `EACCES` | **hajiz Landlock** | ✅ |
| `cve-userns` | `EPERM` | **hajiz hardening seccomp** | ✅ |
| `atomic-procmaps` (T1003.007) | `EACCES` | **hajiz Landlock** | ✅ |
| `atomic-destruct` (T1485) | `EACCES` (open W) | **hajiz Landlock** | ✅ |
| `atomic-procroot` (T1611) | `EACCES` | **hajiz Landlock + mnt namespace** | ✅ |
| `atomic-ptrace` (T1055.008) | `EPERM` | **hajiz hardening seccomp** (corrigé) | ✅ |
| `atomic-discovery` (T1083) | `EACCES` | **hajiz Landlock** | ✅ |

Les deux probes CVE qui ne testent pas réellement hajiz (`cve-tiocsti` et
`cve-cgroup`) sont conservées comme régression d'environnement : si un jour
le sysctl est modifié ou si le container est lancé avec `/sys/fs/cgroup`
mount, c'est hajiz qui doit prendre le relai.

## Constats actionnables

### Lacune corrigée : `ptrace` non bloqué par défaut (T1055.008)

#### Ce qu'on avait observé avant correction

Sous hajiz en mode hardening normal, le test atomique T1055.008 produisait :

```text
=== atomics/T1055_ptrace_injection.sh ===
[hajiz] sandboxed process started (PID 8)
ESCAPE: strace/ptrace succeeded
[hajiz] process exited: exit status: 0
exit=0
```

`exit=0` = la sandbox laissait passer. Le script lance `strace -e trace=none
/bin/true`, qui requiert `ptrace(PTRACE_TRACEME, ...)` puis
`ptrace(PTRACE_SYSCALL, ...)`. Aucun de ces appels n'était intercepté.

#### Pourquoi le `--seccomp-whitelist` strict n'aide pas non plus

Première tentative pour bloquer ptrace : passer `--seccomp-whitelist` avec
les groupes minimaux. Résultat :

```text
=== atomics/T1055_ptrace_injection.sh ===
[hajiz] sandboxed process started (PID 8)
[hajiz] process exited: exit status: 127
exit=127
```

`exit=127` = le shell `/bin/sh` n'a même pas démarré. Cause : les 5 groupes
définis dans [src/isolation/seccomp.rs:176-184](../../src/isolation/seccomp.rs#L176-L184)
sont :

| Groupe | Couvre |
|---|---|
| `io` | open/openat/close/read/write/lseek/fstat/newfstatat/stat |
| `memory` | mmap/mprotect/munmap/brk/madvise |
| `threading` | clone/clone3/futex/set_tid_address/set_robust_list |
| `network` | socket/connect/sendto/sendmsg/recvfrom/recvmsg/bind/listen/accept/accept4 |
| `process` | fork/vfork/execve/execveat/wait4/waitid/kill/getpid |

Aucun groupe ne couvre les syscalls qu'un shell utilise dès l'init :
`rt_sigaction`, `rt_sigprocmask`, `rt_sigreturn`, `prlimit64`, `getrandom`,
`getuid`, `geteuid`, `getgid`, `getegid`, `getppid`, `dup`, `dup2`, `pipe2`,
`fcntl`, `ioctl`, `getcwd`, `getdents64`, `readlinkat`. bash reçoit SIGSYS
sur le premier syscall manquant et meurt → exit 127.

Donc le whitelist actuel n'est pas utilisable pour un workload générique :
trop coarse. Et il n'y a pas de CLI pour étendre la denylist du mode
hardening (`--allow-syscall` n'ajoute qu'au whitelist, pas à la denylist).

#### Correctif appliqué

[src/isolation/seccomp.rs:77-93](../../src/isolation/seccomp.rs#L77-L93) —
trois entrées ajoutées à `hardened_denied_syscalls` :

```rust
pub fn hardened_denied_syscalls() -> &'static [&'static str] {
    &[
        "unshare",
        "setns",
        "clone3",
        "bpf",
        "userfaultfd",
        "add_key",
        "request_key",
        "keyctl",
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
    ]
}
```

Pourquoi les trois :

- `ptrace` : primitive d'attache et d'inspection. Bloque `strace`, `gdb`,
  injection classique.
- `process_vm_readv` / `process_vm_writev` : lecture/écriture directe dans
  la mémoire d'un autre process sans passer par ptrace. Si on bloque ptrace
  seul, l'attaquant migre sur ces deux-là.

Test unitaire ajouté :
`hardening_profile_blocks_process_injection_syscalls` dans
[src/isolation/seccomp.rs](../../src/isolation/seccomp.rs) (run :
`cargo test --release --lib hardening_profile_blocks_process_injection_syscalls`).

#### Sortie après correction

```text
=== atomics/T1055_ptrace_injection.sh ===
[hajiz] sandboxed process started (PID 8)
blocked: ptrace refused
[hajiz] process exited: exit status: 1
exit=1
```

Si on voit toujours `ESCAPE: strace/ptrace succeeded`, vérifier que
`cargo build --release` a bien recompilé (le binaire est bind-mounté dans
le container, pas reconstruit à chaque `run.sh`).

## Drapeaux Docker — pourquoi chacun

Toutes les couches sont posées par `run.sh`. Détail des flags critiques :

| Flag | Raison |
|---|---|
| `--network none` | Aucune interface dans le netns container. Filet de secours si hajiz `--net none` échoue. |
| `--read-only` | Rootfs en CoW lecture-seule. Toute écriture hors `tmpfs` échoue. |
| `--tmpfs /tmp:exec,size=64m` | Espace d'écriture volatile pour le sandbox enfant. |
| `--cap-drop ALL` puis `--cap-add SYS_ADMIN` | hajiz a besoin de SYS_ADMIN pour `unshare()`, mais on retire tout le reste. |
| `--cap-add SETUID --cap-add SETGID` | Pour que les user namespaces puissent appeler `setgroups` / `setresuid`. |
| `--security-opt seccomp=unconfined` | La default Docker bloque `unshare(CLONE_NEW*)` ; hajiz pose son propre filtre, donc on lève le filtre Docker. |
| `--security-opt apparmor=unconfined` | La policy `docker-default` bloque les écritures `/proc/*/attr` nécessaires à hajiz. Sur l'hôte (hors container), utiliser plutôt le profil `packaging/apparmor`. |
| `--security-opt no-new-privileges=true` | Empêche tout binaire setuid hérité de regagner des privilèges. |
| `-v target/release/hajiz:/usr/local/bin/hajiz:ro` | Bind-mount du binaire construit sur l'hôte ; pas de rebuild dans le container. |

## Ajouter un nouveau probe

1. Écrire `probes/<nom>.c` (ou `known_escapes/<nom>.c` pour une CVE).
2. Compilation automatique via `Dockerfile` (boucle `for src in /probes/...`).
3. Ajouter une branche `case` dans `run.sh` listant les flags hajiz spécifiques.
4. `tests/container/run.sh build` puis `tests/container/run.sh <nom>`.
