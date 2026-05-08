# Image jetable pour tester hajiz en environnement double-isolé.
# Le binaire hajiz est monté en bind-mount à l'exécution (cf. run.sh) ;
# l'image n'embarque que les probes compilés et leurs dépendances runtime.
FROM archlinux:base

RUN pacman -Sy --noconfirm gcc glibc libseccomp strace \
    && pacman -Scc --noconfirm

WORKDIR /probes
COPY probes/         /probes/src/
COPY known_escapes/  /probes/cve_src/
RUN set -e; \
    for src in /probes/src/*.c; do \
        out="/probes/$(basename "$src" .c)"; \
        gcc -O2 -static-pie -o "$out" "$src"; \
    done; \
    for src in /probes/cve_src/*.c; do \
        out="/probes/$(basename "$src" .c)"; \
        gcc -O2 -static-pie -o "$out" "$src"; \
    done; \
    rm -rf /probes/src /probes/cve_src

# Atomics MITRE ATT&CK — scripts shell, pas de compilation.
COPY atomics/ /probes/atomics/
RUN chmod +x /probes/atomics/*.sh

# Utilisateur non-root par défaut. hajiz s'exécutera sous cet UID dans le
# container ; les caps additionnelles (cf. run.sh) restent indispensables
# pour que hajiz puisse poser ses propres namespaces.
RUN useradd -m -s /bin/bash sandbox
USER sandbox
WORKDIR /home/sandbox

ENTRYPOINT ["/bin/bash"]
