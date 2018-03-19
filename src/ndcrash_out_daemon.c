#include "ndcrash.h"
#include "ndcrash_backends.h"
#include "ndcrash_dump.h"
#include "ndcrash_private.h"
#include "ndcrash_log.h"
#include "ndcrash_fd_utils.h"
#include <malloc.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <android/log.h>
#include <linux/un.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

#ifdef ENABLE_OUTOFPROCESS

struct ndcrash_out_daemon_context {

    /// Pointer to unwinding function.
    ndcrash_out_unwind_func_ptr unwind_function;

    /// Path to a log file. Null if not set.
    char *log_file;

    /// Pipes that we use to stop a daemon.
    int interruptor[2];

    /// Daemon thread.
    pthread_t daemon_thread;
};

/// Global instance of out-of-process daemon context.
struct ndcrash_out_daemon_context *ndcrash_out_daemon_context_instance = NULL;

/// Constant for listening socket backlog argument.
static const int SOCKET_BACKLOG = 1;

void ndcrash_out_daemon_do_unwinding(struct ndcrash_out_message *message) {
    const bool attached = ptrace(PTRACE_ATTACH, message->tid, NULL, NULL) != -1;
    if (!attached) {
        NDCRASHLOG(INFO, "Ptrace attach failed");
        return;
    }
    NDCRASHLOG(INFO, "Ptrace attach successful");

    int status = 0;
    if (waitpid(message->tid, &status, WUNTRACED) < 0) {
        NDCRASHLOG(INFO,  "Waitpid failed, error: %s (%d)", strerror(errno), errno);
    } else {
        //Opening output file
        int outfile = -1;
        if (ndcrash_out_daemon_context_instance->log_file) {
            outfile = ndcrash_dump_create_file(ndcrash_out_daemon_context_instance->log_file);
        }

        // Writing a crash dump header
        ndcrash_dump_header(
                outfile,
                message->pid,
                message->tid,
                message->signo,
                message->si_code,
                message->faultaddr,
                &message->context);

        // Stack unwinding.
        if (ndcrash_out_daemon_context_instance->unwind_function) {
            ndcrash_out_daemon_context_instance->unwind_function(outfile, message);
        }

        // Final line of crash dump.
        ndcrash_dump_write_line(outfile, " ");

        // Closing output file.
        if (outfile >= 0) {
            //Closing file
            close(outfile);
        }
    }

    ptrace(PTRACE_DETACH, message->tid, NULL, NULL);
}

void ndcrash_out_daemon_process_client(int clientsock)
{
    struct ndcrash_out_message message = { 0, 0 };
    ssize_t overall_read = 0;
    do {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(clientsock, &fdset);
        FD_SET(ndcrash_out_daemon_context_instance->interruptor[0], &fdset);
        const int select_result = select(MAX(clientsock, ndcrash_out_daemon_context_instance->interruptor[0]) + 1, &fdset, NULL, NULL, NULL);
        if (select_result < 0) {
            NDCRASHLOG(ERROR,"Select on recv error: %s (%d)", strerror(errno), errno);
            close(clientsock);
            return;
        }
        if (FD_ISSET(ndcrash_out_daemon_context_instance->interruptor[0], &fdset)) {
            // Interrupting by pipe.
            close(clientsock);
            return;
        }
        const int bytes_read = recv(clientsock, (char *)&message + overall_read, sizeof(struct ndcrash_out_message) - overall_read, 0);
        if (bytes_read < 0) {
            NDCRASHLOG(ERROR,"Recv error: %s (%d)", strerror(errno), errno);
            close(clientsock);
            return;
        }
        overall_read += bytes_read;
    } while (overall_read < sizeof(struct ndcrash_out_message));

    NDCRASHLOG(INFO, "Client info received, pid: %d tid: %d", message.pid, message.tid);

    ndcrash_out_daemon_do_unwinding(&message);

    //Write 1 byte as a response.
    write(clientsock, "\0", 1);

    close(clientsock);
}

void *ndcrash_out_daemon_function(void *arg) {
    // Creating socket
    const int listensock = socket(PF_LOCAL, SOCK_STREAM, 0);
    if (listensock < 0) {
        NDCRASHLOG(ERROR,"Couldn't create socket, error: %s (%d)", strerror(errno), errno);
        return NULL;
    }

    // Setting options
    {
        int n = 1;
        setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));
    }

    // Discarding terminating \0 char.
    const size_t socket_name_size = sizeofa(SOCKET_NAME) - 1;

    // Binding to an address.
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = PF_LOCAL;
    addr.sun_path[0] = 0;
    memcpy(addr.sun_path + 1, SOCKET_NAME, socket_name_size);
    int addrlen = sizeof(sa_family_t) + 1 + socket_name_size;
    if (bind(listensock, (struct sockaddr *)&addr, addrlen) < 0) {
        NDCRASHLOG(ERROR,"Couldn't bind socket, error: %s (%d)", strerror(errno), errno);
        return NULL;
    }

    // Listening
    if (listen(listensock, SOCKET_BACKLOG) < 0) {
        NDCRASHLOG(ERROR,"Couldn't listen socket, error: %s (%d)", strerror(errno), errno);
        return NULL;
    }

    NDCRASHLOG(INFO, "Daemon is successfuly started, accepting connections...");

    // Accepting connections in a cycle.
    for (;;) {
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(listensock, &fdset);
        FD_SET(ndcrash_out_daemon_context_instance->interruptor[0], &fdset);
        const int select_result = select(MAX(listensock, ndcrash_out_daemon_context_instance->interruptor[0]) + 1, &fdset, NULL, NULL, NULL);
        if (select_result < 0) {
            NDCRASHLOG(ERROR,"Select on accept error: %s (%d)", strerror(errno), errno);
            break;
        }
        if (FD_ISSET(ndcrash_out_daemon_context_instance->interruptor[0], &fdset)) {
            // Interrupting by pipe.
            break;
        }

        struct sockaddr_storage ss;
        struct sockaddr *addrp = (struct sockaddr *)&ss;
        socklen_t alen = sizeof(ss);
        int clientsock = accept(listensock, addrp, &alen);
        if (clientsock == -1) {
            NDCRASHLOG(ERROR,"Accept failed, error: %s (%d)", strerror(errno), errno);
            continue;
        }

        NDCRASHLOG(INFO, "Client connected, socket: %d", clientsock);
        ndcrash_out_daemon_process_client(clientsock);
    }

    return NULL;
}

enum ndcrash_error ndcrash_out_start_daemon(const enum ndcrash_backend backend, const char *log_file) {
    if (ndcrash_out_daemon_context_instance) {
        return ndcrash_error_already_initialized;
    }

    // Creating a new struct instance.
    ndcrash_out_daemon_context_instance = (struct ndcrash_out_daemon_context *) malloc(sizeof(struct ndcrash_out_daemon_context));
    memset(ndcrash_out_daemon_context_instance, 0, sizeof(struct ndcrash_out_daemon_context));

    // Checking if backend is supported. Setting unwind function.
    switch (backend) {
#ifdef ENABLE_LIBCORKSCREW
        case ndcrash_backend_libcorkscrew:
            ndcrash_out_daemon_context_instance->unwind_function = &ndcrash_out_unwind_libcorkscrew;
            break;
#endif
#ifdef ENABLE_LIBUNWIND
        case ndcrash_backend_libunwind:
            ndcrash_out_daemon_context_instance->unwind_function = &ndcrash_out_unwind_libunwind;
            break;
#endif
#ifdef ENABLE_LIBUNWINDSTACK
        case ndcrash_backend_libunwindstack:
            ndcrash_out_daemon_context_instance->unwind_function = &ndcrash_out_unwind_libunwindstack;
            break;
#endif
    }
    if (!ndcrash_out_daemon_context_instance->unwind_function) {
        ndcrash_out_deinit();
        return ndcrash_error_not_supported;
    }


    // Copying log file path if set.
    if (log_file) {
        size_t log_file_size = strlen(log_file);
        if (log_file_size) {
            ndcrash_out_daemon_context_instance->log_file = malloc(++log_file_size);
            memcpy(ndcrash_out_daemon_context_instance->log_file, log_file, log_file_size);
        }
    }

    // Creating interruption pipes.
    if (pipe(ndcrash_out_daemon_context_instance->interruptor) < 0 ||
            !ndcrash_set_nonblock(ndcrash_out_daemon_context_instance->interruptor[0] ||
            !ndcrash_set_nonblock(ndcrash_out_daemon_context_instance->interruptor[1]))) {
        ndcrash_out_stop_daemon();
        return ndcrash_error_pipe;
    }

    // Creating a daemon thread.
    const int res = pthread_create(&ndcrash_out_daemon_context_instance->daemon_thread, NULL, ndcrash_out_daemon_function, NULL);
    if (res) {
        return ndcrash_error_thread;
    }

    return ndcrash_ok;
}

bool ndcrash_out_stop_daemon() {
    if (!ndcrash_out_daemon_context_instance) return false;
    if (ndcrash_out_daemon_context_instance->daemon_thread) {
        // Writing to pipe in order to interrupt select.
        write(ndcrash_out_daemon_context_instance->interruptor[1], (void *)'\0', 1);
        pthread_join(ndcrash_out_daemon_context_instance->daemon_thread, NULL);
        close(ndcrash_out_daemon_context_instance->interruptor[0]);
        close(ndcrash_out_daemon_context_instance->interruptor[1]);
    }
    if (ndcrash_out_daemon_context_instance->log_file) {
        free(ndcrash_out_daemon_context_instance->log_file);
    }
    free(ndcrash_out_daemon_context_instance);
    ndcrash_out_daemon_context_instance = NULL;
    return true;
}

#endif //ENABLE_OUTOFPROCESS
