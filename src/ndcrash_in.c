#include "ndcrash.h"
#include "ndcrash_backends.h"
#include "ndcrash_dump.h"
#include "ndcrash_private.h"
#include "ndcrash_log.h"
#include <malloc.h>
#include <signal.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

struct ndcrash_in_context {

    /// Old handlers of signals that we restore on de-initialization. Keep values for all possible
    /// signals, for unused signals NULL value is stored.
    struct sigaction old_handlers[NSIG];

    /// Pointer to unwinding function.
    ndcrash_unwind_func_ptr unwind_function;

    /// Path to a log file. Null if not set.
    char *log_file;
};

struct ndcrash_in_context *ndcrash_in_context_instance = NULL;

/// Main signal handling function.
void ndcrash_in_signal_handler(int signo, struct siginfo *siginfo, void *ctxvoid) {
    // Restoring an old handler to make built-in Android crash mechanism work.
    sigaction(signo, &ndcrash_in_context_instance->old_handlers[signo], NULL);

    struct ucontext *context = (struct ucontext *)ctxvoid;
    int outfile = 0;
    if (ndcrash_in_context_instance->log_file) {
        outfile = ndcrash_dump_create_file(ndcrash_in_context_instance->log_file);
    }

    // Dumping header of a crash dump.
    ndcrash_dump_header(outfile, getpid(), gettid(), signo, siginfo->si_code, siginfo->si_addr, context);


    if (ndcrash_in_context_instance->unwind_function) {
        ndcrash_in_context_instance->unwind_function(outfile, context);
    }

    // Final new line of crash dump.
    ndcrash_log_write_line(outfile, " ");

    // Closing an output file.
    if (outfile) {
        close(outfile);
    }
}

enum ndcrash_error ndcrash_in_init(const enum ndcrash_backend backend, const char *log_file) {
    if (ndcrash_in_context_instance) {
        return ndcrash_error_already_initialized;
    }
    ndcrash_in_context_instance = (struct ndcrash_in_context *) malloc(sizeof(struct ndcrash_in_context));
    memset(ndcrash_in_context_instance, 0, sizeof(struct ndcrash_in_context));

    // Checking if backend is supported. Setting unwind function.
    switch (backend) {
#ifdef ENABLE_LIBCORKSCREW
        case ndcrash_backend_libcorkscrew:
            ndcrash_in_context_instance->unwind_function = &ndcrash_in_unwind_libcorkscrew;
            break;
#endif
#ifdef ENABLE_LIBUNWIND
        case ndcrash_backend_libunwind:
            ndcrash_in_context_instance->unwind_function = &ndcrash_in_unwind_libunwind;
            break;
#endif
#ifdef ENABLE_LIBUNWINDSTACK
        case ndcrash_backend_libunwindstack:
            ndcrash_in_context_instance->unwind_function = &ndcrash_in_unwind_libunwindstack;
            break;
#endif
    }
    if (!ndcrash_in_context_instance->unwind_function) {
        ndcrash_in_deinit();
        return ndcrash_error_not_supported;
    }

    // Trying to register signal handler.
    struct sigaction sigactionstruct;
    memset(&sigactionstruct, 0, sizeof(sigactionstruct));
    sigactionstruct.sa_flags = SA_SIGINFO;
    sigactionstruct.sa_sigaction = &ndcrash_in_signal_handler;
    for (int index = 0; index < NUM_SIGNALS_TO_CATCH; ++index) {
        const int signo = SIGNALS_TO_CATCH[index];
        if (sigaction(signo, &sigactionstruct, &ndcrash_in_context_instance->old_handlers[signo])) {
            ndcrash_in_deinit();
            return ndcrash_error_signal;
        }
    }

    if (log_file) {
        size_t log_file_size = strlen(log_file);
        if (log_file_size) {
            ndcrash_in_context_instance->log_file = malloc(++log_file_size);
            memcpy(ndcrash_in_context_instance->log_file, log_file, log_file_size);
        }
    }

    return ndcrash_ok;
}

void ndcrash_in_deinit() {
    if (!ndcrash_in_context_instance) return;
    for (int signo = 0; signo < NSIG; ++signo) {
        const struct sigaction *old_handler = &ndcrash_in_context_instance->old_handlers[signo];
        if (!old_handler->sa_handler) continue;
        sigaction(signo, old_handler, NULL);
    }
    if (ndcrash_in_context_instance->log_file) {
        free(ndcrash_in_context_instance->log_file);
    }
    free(ndcrash_in_context_instance);
    ndcrash_in_context_instance = NULL;
}