/* CVE-2022-0492 — runC cgroups v1 release_agent escape.
 *
 * Dans un container avec cgroups v1 et /sys/fs/cgroup writable + caps
 * SYS_ADMIN, écrire un chemin dans `release_agent` et déclencher la
 * libération du cgroup fait exécuter le binaire pointé par `release_agent`
 * sur l'hôte avec les privilèges du kernel.
 *
 * Mitigations qui doivent l'empêcher dans hajiz :
 *   - Landlock : /sys/fs/cgroup hors allowlist → open RW refusé.
 *   - cgroups v2 : pas de release_agent du tout sur l'arbre unifié.
 *   - mount namespace : /sys est remonté ro ou recréé.
 *
 * Sortie : 0 si on a réussi à OUVRIR release_agent en écriture
 * (≠ exécuter — on ne déclenche pas la libération, on prouve juste l'accès
 * au primitive). 1 sinon.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *targets[] = {
    "/sys/fs/cgroup/release_agent",
    "/sys/fs/cgroup/memory/release_agent",
    "/sys/fs/cgroup/cpu/release_agent",
    "/sys/fs/cgroup/systemd/release_agent",
    "/sys/fs/cgroup/rdma/release_agent",
    NULL,
};

int main(void) {
    for (const char **t = targets; *t; t++) {
        int fd = open(*t, O_WRONLY);
        if (fd >= 0) {
            fprintf(stderr, "ESCAPE: opened %s for writing\n", *t);
            close(fd);
            return 0;
        }
        fprintf(stderr, "%s blocked: %s\n", *t, strerror(errno));
    }
    return 1;
}
