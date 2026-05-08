/* Abus user namespace imbriqué — pattern classique d'escalade sandbox.
 *
 * Sans isolation : un processus non-root peut faire unshare(CLONE_NEWUSER),
 * devenir root dans le nouveau userns, puis monter, faire des chroots, et
 * exploiter des vulnérabilités kernel non-atteignables autrement.
 *
 * Référence : CVE-2022-0185 (FUSE fsconfig overflow) et toute la classe
 * d'exploits qui passent par un userns non privilégié.
 *
 * hajiz doit bloquer ça via le hardening seccomp :
 *   - unshare → EPERM
 *   - clone3(flags=CLONE_NEWUSER) → EPERM
 *   - setns → EPERM
 *
 * Sortie : 0 si un userns a été créé (= évasion seccomp), 1 sinon.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    /* unshare direct */
    if (unshare(CLONE_NEWUSER) == 0) {
        fprintf(stderr, "ESCAPE: unshare(CLONE_NEWUSER) succeeded\n");
        return 0;
    }
    fprintf(stderr, "unshare(CLONE_NEWUSER) blocked: %s\n", strerror(errno));

    /* unshare(NEWUSER|NEWNS) — combo souvent utilisé pour mount-after */
    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) == 0) {
        fprintf(stderr, "ESCAPE: unshare(NEWUSER|NEWNS) succeeded\n");
        return 0;
    }
    fprintf(stderr, "unshare(NEWUSER|NEWNS) blocked: %s\n", strerror(errno));

    /* setns(/proc/1/ns/user) — réutiliser le ns user du PID 1 host */
    int fd = open("/proc/1/ns/user", 0);
    if (fd >= 0) {
        if (syscall(SYS_setns, fd, CLONE_NEWUSER) == 0) {
            fprintf(stderr, "ESCAPE: setns to /proc/1/ns/user succeeded\n");
            close(fd);
            return 0;
        }
        fprintf(stderr, "setns blocked: %s\n", strerror(errno));
        close(fd);
    } else {
        fprintf(stderr, "open /proc/1/ns/user blocked: %s\n", strerror(errno));
    }

    return 1;
}
