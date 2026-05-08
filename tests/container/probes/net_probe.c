/* net_probe — tente une connexion TCP sortante.
 *
 * Sans isolation : succès (ou ECONNREFUSED) selon la cible.
 * Sous hajiz --net none : le netns enfant n'a pas d'interface, EHOSTUNREACH.
 * Sous hajiz --net loopback : seul 127.0.0.1 répond.
 * Dans Docker --network none : aucune route, EHOSTUNREACH/ENETUNREACH.
 *
 * Sortie : 0 si la connexion a réussi (= évasion), 1 si elle a échoué.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *host = argc > 1 ? argv[1] : "1.1.1.1";
    int port = argc > 2 ? atoi(argv[2]) : 80;

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        fprintf(stderr, "socket: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host, &addr.sin_addr);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
        fprintf(stderr, "ESCAPE: connected to %s:%d\n", host, port);
        close(s);
        return 0;
    }
    fprintf(stderr, "blocked: %s\n", strerror(errno));
    close(s);
    return 1;
}
