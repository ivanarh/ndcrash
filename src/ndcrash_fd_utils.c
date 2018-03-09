#include "ndcrash_fd_utils.h"
#include "ndcrash_log.h"
#include <fcntl.h>
#include <android/log.h>
#include <string.h>
#include <errno.h>

bool ndcrash_set_nonblock(int sock) {
    int socket_flags = fcntl(sock, F_GETFL);
    if (socket_flags==-1) {
        __android_log_print(ANDROID_LOG_ERROR, NDCRASH_LOG_TAG, "Couldn't get fcntl flags, error: %s (%d)", strerror(errno), errno);
        return false;
    }
    if (socket_flags & O_NONBLOCK) return true;
    socket_flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, socket_flags)==-1) {
        __android_log_print(ANDROID_LOG_ERROR, NDCRASH_LOG_TAG, "Couldn't set fcntl flags, error: %s (%d)", strerror(errno), errno);
        return false;
    }
    return true;
}