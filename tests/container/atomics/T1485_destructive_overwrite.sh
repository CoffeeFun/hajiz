#!/bin/sh
# MITRE ATT&CK T1485 — Data Destruction
# Réf : Atomic Red Team T1485#1 (Overwrite files with /dev/zero)
#
# Tente d'écraser des fichiers système avec /dev/zero. Sans isolation et
# avec privilèges, ça vandalise le système hôte. Sous hajiz : Landlock
# avec /etc hors allowlist RW doit refuser le open(O_WRONLY).
#
# Cibles testées : /etc/hostname (système), /etc/passwd (auth), /usr/bin/ls
# (binaire critique). Tous doivent échouer.
#
# Sortie : 0 si une écriture a réussi (= destruction), 1 si toutes refusées.

set -u
escapes=0
for target in /etc/hostname /etc/passwd /usr/bin/ls; do
    if dd if=/dev/zero of="$target" bs=1 count=1 conv=notrunc 2>/dev/null; then
        echo "ESCAPE: overwrote $target"
        escapes=$((escapes + 1))
    else
        echo "blocked: $target write refused"
    fi
done
[ "$escapes" -gt 0 ] && exit 0 || exit 1
