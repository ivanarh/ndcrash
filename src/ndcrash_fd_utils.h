#ifndef NDCRASH_FD_UTILS_H
#define NDCRASH_FD_UTILS_H
#include <stdbool.h>

/**
 * Enables non-blocking mode for a passed file descriptor. It's a wrapper around fcntl function.
 * @param fd File descriptor.
 * @return Flag whether setting non-blocking mode is successful.
 */
bool ndcrash_set_nonblock(int fd);

/**
 * Disable signal capabilities of a socket.
 * @param socket Socket descriptor
 * @return Flag if disabling was successful.
 */
bool ndcrash_set_nosignal(int socket);

#endif //NDCRASH_FD_UTILS_H
