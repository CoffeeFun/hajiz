/* CVE-2017-5226 — Bubblewrap TIOCSTI keystroke injection.
 *
 * Technique : un processus dans le sandbox ouvre un TTY (le contrôleur
 * hérité, ou bien il en alloue un via posix_openpt) et injecte des
 * caractères dans le buffer d'entrée via ioctl(TIOCSTI). Si le TTY est
 * partagé avec le shell parent, ces caractères sont exécutés comme frappes
 * clavier après la sortie du sandbox.
 *
 * Mitigation hajiz : ajouter TIOCSTI au denylist seccomp (refuser le
 * syscall ioctl quand request == TIOCSTI, ou refuser ioctl tout court dans
 * le mode whitelist).
 *
 * Pour rendre le test indépendant de l'environnement (pas de TTY contrôleur
 * dans `docker run` sans -t), on alloue notre propre couple master/slave
 * via posix_openpt(). L'ioctl s'exécute sur un vrai TTY → si seccomp ne
 * filtre pas TIOCSTI, l'injection réussit.
 *
 * Sortie : 0 si TIOCSTI a réussi (= évasion), 1 si refusé.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int main(void) {
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0) {
        fprintf(stderr, "posix_openpt failed: %s (env limitation, test inconclusive)\n",
                strerror(errno));
        return 1;
    }
    if (grantpt(master) < 0 || unlockpt(master) < 0) {
        fprintf(stderr, "grant/unlock pt failed: %s\n", strerror(errno));
        close(master);
        return 1;
    }
    const char *slave_name = ptsname(master);
    if (!slave_name) {
        fprintf(stderr, "ptsname failed: %s\n", strerror(errno));
        close(master);
        return 1;
    }
    int slave = open(slave_name, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        fprintf(stderr, "open slave %s failed: %s\n", slave_name, strerror(errno));
        close(master);
        return 1;
    }

    /* TIOCSTI sur le slave : un seul caractère pour prouver le primitive. */
    char c = 'X';
    if (ioctl(slave, TIOCSTI, &c) == 0) {
        fprintf(stderr, "ESCAPE: TIOCSTI succeeded on self-allocated pty\n");
        close(slave);
        close(master);
        return 0;
    }
    fprintf(stderr, "TIOCSTI blocked: %s\n", strerror(errno));
    close(slave);
    close(master);
    return 1;
}
