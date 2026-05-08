#!/bin/sh
# MITRE ATT&CK T1611 — Escape to Host
# Réf : Atomic Red Team T1611#7 (Container escape via proc/1/root)
#
# Dans un container mal isolé, /proc/1/root pointe vers la racine de l'hôte
# (ou du container parent). Lire des fichiers via /proc/1/root/<path>
# contourne le chroot et accède au filesystem hôte.
#
# Sous hajiz : mnt namespace recrée /proc dans un nouveau pidns, donc
# /proc/1/root dans le sandbox pointe vers le sandbox lui-même, pas l'hôte.
# Et Landlock refuse de toute façon /proc en dehors de l'allowlist.
#
# Sortie : 0 si une lecture sensible a réussi (= évasion vers l'hôte).

set -u
escapes=0
for target in /proc/1/root/etc/shadow /proc/1/root/etc/hostname /proc/1/root/root/.bash_history; do
    if cat "$target" 2>/dev/null | head -1 | grep -q "."; then
        echo "ESCAPE: read $target"
        escapes=$((escapes + 1))
    else
        echo "blocked: $target unreadable"
    fi
done
[ "$escapes" -gt 0 ] && exit 0 || exit 1
