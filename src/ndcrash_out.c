#include "ndcrash.h"
#include "ndcrash_private.h"
#include "ndcrash_signal_utils.h"
#include "ndcrash_log.h"
#include <signal.h>
#include <malloc.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <android/log.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <string.h>
#include <errno.h>

#ifdef ENABLE_OUTOFPROCESS

struct ndcrash_out_context {

    /// Old handlers of signals that we restore on de-initialization. Keep values for all possible
    /// signals, for unused signals NULL value is stored.
    struct sigaction old_handlers[NSIG];
};

/// Global instance of out-of-process context.
struct ndcrash_out_context *ndcrash_out_context_instance = NULL;

/// Signal handling function for out-of-process architecture.
void ndcrash_out_signal_handler(int signo, struct siginfo *siginfo, void *ctxvoid) {
    // Restoring an old handler to make built-in Android crash mechanism work.
    sigaction(signo, &ndcrash_out_context_instance->old_handlers[signo], NULL);

    // Filling message fields.
    struct ndcrash_out_message msg;
    msg.pid = getpid();
    msg.tid = gettid();
    msg.signo = signo;
    msg.si_code = siginfo->si_code;
    msg.faultaddr = siginfo->si_addr;
    memcpy(&msg.context, ctxvoid, sizeof(struct ucontext));

    NDCRASHLOG(
            ERROR,
            "Signal caught: %d (%s), code %d (%s) pid: %d, tid: %d",
            signo,
            ndcrash_get_signame(signo),
            siginfo->si_code,
            ndcrash_get_sigcode(signo, siginfo->si_code),
            msg.pid,
            msg.tid);

    // Connecting to service using UNIX domain socket, sending message to it.
    // Using blocking sockets!
    const int sock = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (sock < 0) {
        NDCRASHLOG(ERROR,"Couldn't create socket, error: %s (%d)", strerror(errno), errno);
        return;
    }

    // Discarding terminating \0 char.
    const size_t socket_name_size = sizeofa(NDCRASH_SOCKET_NAME) - 1;

    // Setting socket address.
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = PF_LOCAL;
    addr.sun_path[0] = 0;
    memcpy(addr.sun_path + 1, NDCRASH_SOCKET_NAME, socket_name_size); //Discarding terminating \0 char.

    // Connecting.
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr.sun_family) + 1 + socket_name_size)) {
        NDCRASHLOG(ERROR,"Couldn't connect socket, error: %s (%d)", strerror(errno), errno);
        close(sock);
        return;
    }

    // Sending.
    const ssize_t sent = send(sock, &msg, sizeof(msg), MSG_NOSIGNAL);
    if (sent < 0) {
        NDCRASHLOG(ERROR,"Send error: %s (%d)", strerror(errno), errno);
    } else if (sent != sizeof(msg)) {
        NDCRASHLOG(ERROR,"Error: couldn't send whole message, sent bytes: %d, message size: %d", (int)sent, (int)sizeof(msg));
    } else {
        NDCRASHLOG(INFO, "Successfuly sent data to crash service.");
    }

    // Blocking read.
    char c = 0;
    if (recv(sock, &c, 1, MSG_NOSIGNAL) < 0) {
        NDCRASHLOG(ERROR,"Recv error: %s (%d)", strerror(errno), errno);
    }

    close(sock);

    // In some cases we need to re-send a signal to run standard bionic handler.
    if (siginfo->si_code <= 0 || signo == SIGABRT) {
        if (syscall(__NR_tgkill, getpid(), gettid(), signo) < 0) {
            _exit(1);
        }
    }
}

enum ndcrash_error ndcrash_out_init() {
    if (ndcrash_out_context_instance) {
        return ndcrash_error_already_initialized;
    }

    // Initializing context instance.
    ndcrash_out_context_instance = (struct ndcrash_out_context *) malloc(sizeof(struct ndcrash_out_context));
    memset(ndcrash_out_context_instance, 0, sizeof(struct ndcrash_out_context));

    // Trying to register signal handler.
    if (!ndcrash_register_signal_handler(&ndcrash_out_signal_handler, ndcrash_out_context_instance->old_handlers)) {
        ndcrash_in_deinit();
        return ndcrash_error_signal;
    }

    return ndcrash_ok;
}

void ndcrash_out_deinit() {
    if (!ndcrash_out_context_instance) return;
    ndcrash_unregister_signal_handler(ndcrash_out_context_instance->old_handlers);
    free(ndcrash_out_context_instance);
    ndcrash_out_context_instance = NULL;
}

#endif //ENABLE_OUTOFPROCESS