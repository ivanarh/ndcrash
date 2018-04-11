#ifndef NDCRASH_UTILS_H
#define NDCRASH_UTILS_H
#include <stdbool.h>
#include <linux/un.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fills in sockaddr_un struct with passed socket name.
 * @param socket_name Null-terminated socket name string.
 * @param out_addr Pointer to sockaddr_un structure to fill.
 */
void ndcrash_out_fill_sockaddr(const char *socket_name, struct sockaddr_un *out_addr);

#ifdef __cplusplus
}
#endif

#endif //NDCRASH_UTILS_H
