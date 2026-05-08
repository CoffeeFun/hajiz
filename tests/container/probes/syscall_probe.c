/* syscall_probe — invoque des syscalls que le hardening seccomp doit refuser.
 *
 * - unshare(CLONE_NEWUSER) : créer un nouveau user namespace (escalade).
 * - bpf(0,0,0)             : charger un programme BPF.
 * - keyctl(0,0,0,0,0)      : manipuler le keyring.
 *
 * Sous hajiz hardening : tous EPERM (ou SIGSYS si --kill-on-deny).
 * Sortie : 0 si AU MOINS UN syscall a réussi à passer le filtre seccomp.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/keyctl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef SYS_bpf
#define SYS_bpf 321
#endif
#ifndef SYS_keyctl
#define SYS_keyctl 250
#endif

static int probe(const char *name, long ret, int err) {
    if (ret >= 0) {
        fprintf(stderr, "ESCAPE: %s succeeded (ret=%ld)\n", name, ret);
        return 1;
    }
    fprintf(stderr, "%s: %s\n", name, strerror(err));
    return 0;
}

int main(void) {
    int escapes = 0;

    long r1 = syscall(SYS_unshare, CLONE_NEWUSER);
    escapes += probe("unshare(CLONE_NEWUSER)", r1, errno);

    long r2 = syscall(SYS_bpf, 0, 0, 0);
    escapes += probe("bpf()", r2, errno);

    long r3 = syscall(SYS_keyctl, 0, 0, 0, 0, 0);
    escapes += probe("keyctl()", r3, errno);

    return escapes > 0 ? 0 : 1;
}
