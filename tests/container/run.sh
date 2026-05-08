#!/usr/bin/env bash
# Lance hajiz à l'intérieur d'un container Docker sans réseau.
#
# Couches d'isolation, du plus extérieur au plus intérieur :
#   1. Docker --network none      : aucune interface, aucune route.
#   2. Docker --read-only + tmpfs : rootfs immuable, écritures volatiles.
#   3. Docker --cap-drop=ALL      : on ne rend que ce qu'hajiz exige.
#   4. hajiz --net none           : netns enfant vide.
#   5. hajiz seccomp/Landlock/cgroups : le sandbox lui-même.
#
# Si une couche tombe, la suivante absorbe.
#
# Usage :
#   tests/container/run.sh build         # construit l'image hajiz-test
#   tests/container/run.sh net           # exécute net_probe
#   tests/container/run.sh fs            # exécute fs_probe
#   tests/container/run.sh syscall       # exécute syscall_probe
#   tests/container/run.sh shell         # shell interactif dans le container
#   tests/container/run.sh all           # enchaîne net + fs + syscall

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
HAJIZ_BIN="${HAJIZ_BIN:-$ROOT/target/release/hajiz}"
IMAGE="${HAJIZ_TEST_IMAGE:-hajiz-test:latest}"


# Flags Docker partagés. Notes :
# - SYS_ADMIN requis pour que hajiz puisse créer de nouveaux namespaces.
#   Sans, unshare(CLONE_NEW*) renvoie EPERM dans le container.
# - SETUID/SETGID retenus pour que les namespaces utilisateur fonctionnent
#   si le code en utilise (sinon EPERM sur setgroups).
# - seccomp=unconfined : la profile par défaut de Docker bloque unshare()
#   et clone3(CLONE_NEW*). hajiz pose son propre filtre, donc on désactive.
# - apparmor=unconfined : la profile docker-default bloque mount() et
#   /proc/*/attr writes nécessaires à hajiz. hajiz a son propre profil
#   AppArmor (packaging/apparmor) — utiliser celui-là sur l'hôte hors
#   container, ou le charger explicitement ici.
DOCKER_FLAGS=(
    --rm
    --network none
    --read-only
    --tmpfs /tmp:exec,size=64m
    --tmpfs /home/sandbox:exec,size=16m
    --cap-drop ALL
    --cap-add SYS_ADMIN
    --cap-add SETUID
    --cap-add SETGID
    --security-opt seccomp=unconfined
    --security-opt apparmor=unconfined
    --security-opt no-new-privileges=true
    -v "$HAJIZ_BIN:/usr/local/bin/hajiz:ro"
    "$IMAGE"
)

build() {
    if [[ ! -x "$HAJIZ_BIN" ]]; then
        echo ">> binaire hajiz absent : $HAJIZ_BIN"
        echo ">> exécute : cargo build --release"
        exit 1
    fi
    docker build -t "$IMAGE" "$(dirname "$0")"
}

ensure_image() {
    docker image inspect "$IMAGE" >/dev/null 2>&1 || build
}

run_probe() {
    local name="$1"
    shift
    ensure_image
    echo "=== $name ==="
    docker run "${DOCKER_FLAGS[@]}" -c "hajiz $* /probes/$name; echo \"exit=\$?\""
}

# Allowlist Landlock partagée par les tests atomics. /dev:ro est requis pour
# que les redirections shell (`2>/dev/null`) fonctionnent — Landlock ABI 3+
# intercepte aussi les opens sur les char devices.
ATOMIC_FS=(--fs /usr:ro --fs /probes:ro --fs /tmp:rw --fs /dev:rw)

case "${1:-all}" in
    build)
        build
        ;;
    net)
        # hajiz --net none doit déjà bloquer ; le container --network none
        # est la double-ceinture.
        run_probe net_probe --net none
        ;;
    fs)
        # Allowlist Landlock : /usr ro pour libc, /probes ro pour exec du
        # binaire de test, /tmp rw pour les écritures volatiles. /etc, /root
        # et / NE sont PAS whitelisted — le probe doit échouer sur tous ses
        # essais de lecture/écriture sensibles.
        run_probe fs_probe --net none --fs /usr:ro --fs /probes:ro --fs /tmp:rw
        ;;
    syscall)
        # Hardening seccomp actif par défaut : unshare/bpf/keyctl interdits.
        run_probe syscall_probe --net none
        ;;
    cve-tiocsti)
        # CVE-2017-5226 : injection de frappes via TIOCSTI sur le TTY parent.
        # hajiz doit refuser l'ioctl TIOCSTI (ajout au denylist seccomp).
        run_probe cve_2017_5226_tiocsti --net none
        ;;
    cve-cgroup)
        # CVE-2022-0492 : escape via cgroups v1 release_agent.
        # Mitigation : Landlock refuse l'open RW de /sys/fs/cgroup,
        # cgroups v2 n'a pas de release_agent, mnt namespace re-mount /sys ro.
        run_probe cve_2022_0492_cgroup_release \
            --net none --fs /usr:ro --fs /probes:ro --fs /tmp:rw
        ;;
    cve-procexe)
        # CVE-2019-5736 : overwrite de /proc/self/exe (binaire runtime).
        # Mitigation : Landlock refuse l'open O_WRONLY hors allowlist RW.
        run_probe cve_2019_5736_procselfexe \
            --net none --fs /usr:ro --fs /probes:ro --fs /tmp:rw
        ;;
    cve-userns)
        # User namespace imbriqué (CVE-2022-0185 et famille).
        # Mitigation : seccomp hardening refuse unshare/setns/clone3.
        run_probe nested_userns --net none
        ;;
    cve)
        "$0" cve-tiocsti  || true
        "$0" cve-cgroup   || true
        "$0" cve-procexe  || true
        "$0" cve-userns   || true
        ;;
    atomic-procmaps)
        # T1003.007 — Lecture de /proc/<pid>/maps. Landlock /proc hors allowlist.
        run_probe atomics/T1003.007_proc_maps_read.sh --net none "${ATOMIC_FS[@]}"
        ;;
    atomic-destruct)
        # T1485 — Écrasement destructif. Landlock RW limité à /tmp.
        run_probe atomics/T1485_destructive_overwrite.sh --net none "${ATOMIC_FS[@]}"
        ;;
    atomic-procroot)
        # T1611 — Traversée /proc/1/root. mnt namespace + Landlock.
        run_probe atomics/T1611_proc_root_traversal.sh --net none "${ATOMIC_FS[@]}"
        ;;
    atomic-ptrace)
        # T1055.008 — Injection via ptrace.
        # Constat actuel : ptrace n'est PAS dans hardened_denied_syscalls
        # (cf. src/isolation/seccomp.rs) et hajiz n'expose pas de denylist
        # extensible côté CLI. Les groupes whitelist (io/memory/threading/
        # network/process) ne couvrent pas non plus les syscalls de
        # signal/temps requis par bash → un --seccomp-whitelist strict
        # empêche le shell de démarrer (exit 127) avant même de tester ptrace.
        # Ce test documente donc la lacune : ptrace doit être ajouté au
        # hardening denylist pour bloquer l'injection ptrace par défaut.
        # Sortie actuelle attendue : exit=0 (ESCAPE) sous mode hardening.
        run_probe atomics/T1055_ptrace_injection.sh --net none "${ATOMIC_FS[@]}"
        ;;
    atomic-discovery)
        # T1083 — Énumération de fichiers. Landlock allowlist restrictive.
        run_probe atomics/T1083_file_discovery.sh --net none "${ATOMIC_FS[@]}"
        ;;
    atomic)
        "$0" atomic-procmaps   || true
        "$0" atomic-destruct   || true
        "$0" atomic-procroot   || true
        "$0" atomic-ptrace     || true
        "$0" atomic-discovery  || true
        ;;
    shell)
        ensure_image
        docker run -it "${DOCKER_FLAGS[@]}"
        ;;
    all)
        "$0" net      || true
        "$0" fs       || true
        "$0" syscall  || true
        "$0" cve      || true
        "$0" atomic   || true
        ;;
    *)
        echo "Usage: $0 {build|net|fs|syscall|cve[-*]|atomic[-*]|shell|all}" >&2
        exit 2
        ;;
esac
