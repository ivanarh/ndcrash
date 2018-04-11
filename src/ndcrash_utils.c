#include "ndcrash_utils.h"
#include <string.h>
#include <sys/socket.h>

void ndcrash_out_fill_sockaddr(const char *socket_name, struct sockaddr_un *out_addr) {
    size_t socket_name_length = strlen(socket_name);
    // Discarding exceeding characters.
    if (socket_name_length > UNIX_PATH_MAX - 1) {
        socket_name_length = UNIX_PATH_MAX - 1;
    }
    memset(out_addr, 0, sizeof(struct sockaddr_un));
    out_addr->sun_family = PF_UNIX;
    // The socket is abstract, the first byte should be 0. See "man 7 unix" for details.
    out_addr->sun_path[0] = '\0';
    memcpy(out_addr->sun_path + 1, socket_name, socket_name_length);
}