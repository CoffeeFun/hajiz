/* fs_probe — tente de lire des chemins sensibles hors allowlist Landlock.
 *
 * Cibles : /etc/shadow (lecture interdite UNIX par défaut), /proc/1/root
 * (traversée vers la racine de PID 1 — bloquée par mnt namespace),
 * et création d'un fichier dans / (impossible sous Landlock + ro).
 *
 * Sortie : 0 si une lecture/écriture sensible a réussi (= évasion).
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int try_read(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "read %s: %s\n", path, strerror(errno));
        return 0;
    }
    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n > 0) {
        fprintf(stderr, "ESCAPE: read %zd bytes from %s\n", n, path);
        return 1;
    }
    return 0;
}

static int try_write(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "write %s: %s\n", path, strerror(errno));
        return 0;
    }
    const char *msg = "hajiz_escape\n";
    ssize_t n = write(fd, msg, strlen(msg));
    close(fd);
    if (n > 0) {
        fprintf(stderr, "ESCAPE: wrote %zd bytes to %s\n", n, path);
        unlink(path);
        return 1;
    }
    return 0;
}

int main(void) {
    int escapes = 0;
    escapes += try_read("/etc/shadow");
    escapes += try_read("/proc/1/root/etc/hostname");
    escapes += try_read("/root/.bash_history");
    escapes += try_write("/escape_marker");
    escapes += try_write("/etc/hajiz_escape");
    return escapes > 0 ? 0 : 1;
}
