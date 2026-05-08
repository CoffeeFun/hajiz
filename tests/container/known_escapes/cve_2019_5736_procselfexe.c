/* CVE-2019-5736 — runC /proc/self/exe overwrite.
 *
 * Quand `runc exec` lance un binaire dans un container, runc se ré-exec via
 * /proc/self/exe pour entrer dans le namespace de la cible. Si le binaire
 * exécuté dans le container ouvre /proc/self/exe en écriture, il écrase
 * runc sur l'hôte → prochain `runc exec` exécute le payload comme root host.
 *
 * Adapté à hajiz : on tente d'ouvrir /proc/self/exe en écriture. Sous une
 * allowlist Landlock qui ne whiteliste PAS le chemin du binaire en RW,
 * l'open(O_WRONLY) doit échouer. On essaie aussi /proc/<ppid>/exe pour
 * cibler le parent (hajiz).
 *
 * Sortie : 0 si une ouverture en écriture réussit (= évasion), 1 sinon.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int try_open_w(const char *path) {
    int fd = open(path, O_WRONLY);
    if (fd >= 0) {
        fprintf(stderr, "ESCAPE: opened %s O_WRONLY\n", path);
        close(fd);
        return 1;
    }
    fprintf(stderr, "%s O_WRONLY blocked: %s\n", path, strerror(errno));

    fd = open(path, O_RDWR);
    if (fd >= 0) {
        fprintf(stderr, "ESCAPE: opened %s O_RDWR\n", path);
        close(fd);
        return 1;
    }
    fprintf(stderr, "%s O_RDWR blocked: %s\n", path, strerror(errno));
    return 0;
}

int main(void) {
    int escapes = 0;
    char ppid_path[64];
    snprintf(ppid_path, sizeof(ppid_path), "/proc/%d/exe", getppid());

    escapes += try_open_w("/proc/self/exe");
    escapes += try_open_w(ppid_path);
    escapes += try_open_w("/proc/1/exe");

    return escapes > 0 ? 0 : 1;
}
