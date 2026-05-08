#!/bin/sh
# MITRE ATT&CK T1083 — File and Directory Discovery
# Réf : Atomic Red Team T1083#3 (Linux: enumerate sensitive locations)
#
# Énumération de fichiers sensibles : credentials, clés SSH, history.
# Phase de reconnaissance typique d'un malware ou d'un implant. Sous hajiz
# avec Landlock allowlist /usr+/probes+/tmp, l'énumération de /etc, /root,
# /home/*/.ssh doit échouer.
#
# Le test compte les chemins listables. Plus de 0 = leak de surface
# d'attaque (l'attaquant connaît au moins l'existence des cibles).
#
# Sortie : 0 si au moins un répertoire a été listé, 1 si tous refusés.

set -u
escapes=0
for dir in /etc /root /home /var/log; do
    if ls -la "$dir" 2>/dev/null | head -1 | grep -q "."; then
        echo "ESCAPE: listed $dir"
        escapes=$((escapes + 1))
    else
        echo "blocked: $dir unlisted"
    fi
done
[ "$escapes" -gt 0 ] && exit 0 || exit 1
