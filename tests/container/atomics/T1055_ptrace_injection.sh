#!/bin/sh
# MITRE ATT&CK T1055.008 — Process Injection: Ptrace System Calls
# Réf : Atomic Red Team T1055.008
#
# strace utilise ptrace(PTRACE_TRACEME / PTRACE_ATTACH). Si seccomp refuse
# ptrace, strace échoue immédiatement. Test indirect mais fiable de
# l'interdiction du syscall ptrace.
#
# Hajiz hardening : ptrace n'est pas dans la denylist par défaut (cf.
# isolation/seccomp.rs hardened_denied_syscalls), à vérifier. Si autorisé,
# ce test passe (= évasion attendue par défaut, sauf en mode whitelist
# strict). En mode whitelist sans allow-group debug, ptrace doit être bloqué.
#
# Sortie : 0 si strace a réussi (= ptrace autorisé), 1 si refusé.

set -u
if ! command -v strace >/dev/null 2>&1; then
    echo "skip: strace absent (ne peut pas tester ptrace)"
    exit 1
fi

if strace -e trace=none /bin/true >/dev/null 2>&1; then
    echo "ESCAPE: strace/ptrace succeeded"
    exit 0
fi
echo "blocked: ptrace refused"
exit 1
