#include "ndcrash.h"
#include "ndcrash_private.h"
#include "ndcrash_signal_utils.h"
#include "ndcrash_log.h"
#include "ndcrash_utils.h"
#include <signal.h>
#include <malloc.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <string.h>
#include <errno.h>
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/types.h>
#ifdef ENABLE_OUTOFPROCESS

struct ndcrash_out_context {

    /// Old handlers of signals that we restore on de-initialization. Keep values for all possible
    /// signals, for unused signals NULL value is stored.
    struct sigaction old_handlers[NSIG];

    /// Socket address that we use to communicate with debugger.
    struct sockaddr_un socket_address;

    /// Old state of dumpable flag. Restoring it when a signal handler is de-initialized.
    int old_dumpable;
};

/// Global instance of out-of-process context.
struct ndcrash_out_context *ndcrash_out_context_instance = NULL;

/// Send message
int ndcrash_out_send_message(struct ndcrash_out_message *msg) {
    // Connecting to service using UNIX domain socket, sending message to it.
    int r = 0;
    // Using blocking sockets!
    const int sock = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (sock < 0) {
        NDCRASHLOG(ERROR,"Couldn't create socket, error: %s (%d)", strerror(errno), errno);
        r = -1;
    } else {
        // Connecting.
        if (connect(
                sock,
                (struct sockaddr *) &ndcrash_out_context_instance->socket_address,
                sizeof(struct sockaddr_un))) {
            NDCRASHLOG(ERROR, "Couldn't connect socket, error: %s (%d)", strerror(errno), errno);
            r = -2;
        } else {
            // Sending.
            const ssize_t sent = send(sock, msg, sizeof(*msg), MSG_NOSIGNAL);
            if (sent < 0) {
                NDCRASHLOG(ERROR, "Send error: %s (%d)", strerror(errno), errno);
                r = -3;
            } else if (sent != sizeof(*msg)) {
                NDCRASHLOG(
                        ERROR,
                        "Error: couldn't send whole message, sent bytes: %d, message size: %d",
                        (int) sent,
                        (int) sizeof(*msg));
                r = -4;
            } else {
                NDCRASHLOG(INFO, "Successfuly sent data to crash service.");
            }

            // Blocking read.
            char c = 0;
            if (recv(sock, &c, 1, MSG_NOSIGNAL) < 0) {
                NDCRASHLOG(ERROR, "Recv error: %s (%d)", strerror(errno), errno);
                r = -5;
            }
        }

        // Closing a socket.
        close(sock);
    }
    return r;
}

/// Signal handling function for out-of-process architecture.
void ndcrash_out_signal_handler(int signo, siginfo_t *siginfo, void *ctxvoid) {
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

    // Send message on socket
    ndcrash_out_send_message(&msg);

    // In some cases we need to re-send a signal to run standard bionic handler.
    if (siginfo->si_code <= 0 || signo == SIGABRT) {
        if (syscall(__NR_tgkill, getpid(), gettid(), signo) < 0) {
            _exit(1);
        }
    }
}

enum ndcrash_error ndcrash_out_trigger_dump() {
    // Filling message fields.
    struct ndcrash_out_message msg;
    msg.pid = getpid();
    msg.tid = gettid();
    msg.signo = 0;

    NDCRASHLOG(
            ERROR,
            "Dump: pid: %d, tid: %d",
            msg.pid,
            msg.tid);

    // Send message on socket
    if (ndcrash_out_send_message(&msg) < 0) {
        return ndcrash_error_service_communication_failed;
    }
    return ndcrash_ok;
}

enum ndcrash_error ndcrash_out_init(const char *socket_name) {
    if (ndcrash_out_context_instance) {
        return ndcrash_error_already_initialized;
    }

    // Socket name can't be null or empty.
    if (!socket_name || !*socket_name) {
        return ndcrash_error_socket_name;
    }

    // Initializing context instance.
    ndcrash_out_context_instance = (struct ndcrash_out_context *) malloc(sizeof(struct ndcrash_out_context));
    memset(ndcrash_out_context_instance, 0, sizeof(struct ndcrash_out_context));

    // Saving old dumpable flag. Not checking for error.
    ndcrash_out_context_instance->old_dumpable = prctl(PR_GET_DUMPABLE);

    // Setting dumpable flag. Required for ptrace.
    prctl(PR_SET_DUMPABLE, 1);

    // Filling in socket address.
    ndcrash_out_fill_sockaddr(socket_name, &ndcrash_out_context_instance->socket_address);

    // Trying to register signal handler.
    if (!ndcrash_register_signal_handler(&ndcrash_out_signal_handler, ndcrash_out_context_instance->old_handlers)) {
        ndcrash_out_deinit();
        return ndcrash_error_signal;
    }

    return ndcrash_ok;
}

bool ndcrash_out_deinit() {
    if (!ndcrash_out_context_instance) return false;

    // Restoring old signal handlers.
    ndcrash_unregister_signal_handler(ndcrash_out_context_instance->old_handlers);

    // Restoring old dumpable state. Note that PR_GET_DUMPABLE might fail.
    if (ndcrash_out_context_instance->old_dumpable >= 0) {
        prctl(PR_SET_DUMPABLE, ndcrash_out_context_instance->old_dumpable);
    }

    // Freeing memory.
    free(ndcrash_out_context_instance);
    ndcrash_out_context_instance = NULL;
    return true;
}

#endif //ENABLE_OUTOFPROCESS
