#!/bin/sh
# MITRE ATT&CK T1003.007 — OS Credential Dumping: Proc Filesystem
# Réf : Atomic Red Team T1003.007#1 (Linux)
#
# Lit /proc/<pid>/maps puis /proc/<pid>/mem pour dumper la mémoire d'un autre
# processus (pid 1 ici). Sans isolation, /proc expose la carte mémoire de
# init. Avec hajiz : Landlock + mnt namespace doivent refuser la lecture.
#
# Sortie : 0 si lecture réussie (= fuite mémoire), 1 si refusée.

set -u
target=/proc/1/maps
if cat "$target" 2>/dev/null | head -1 | grep -q "."; then
    echo "ESCAPE: read $target successfully"
    exit 0
fi
echo "blocked: $target unreadable"
exit 1
