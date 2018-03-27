#ifndef NDCRASH_PRIVATE_H
#define NDCRASH_PRIVATE_H
#include "sizeofa.h"
#include <signal.h>
#include <ucontext.h>

/// Array of constants with signal numbers to catch.
static const int SIGNALS_TO_CATCH[] = {
        SIGABRT,
        SIGBUS,
        SIGFPE,
        SIGSEGV,
        SIGILL,
#if defined(SIGSTKFLT)
        SIGSTKFLT,
#endif
};

/// Count of signals to catch
static const int NUM_SIGNALS_TO_CATCH = sizeofa(SIGNALS_TO_CATCH);

/// Struct for message that is sent from signal handler to daemon in out-of-process architecture.
struct ndcrash_out_message
{
    pid_t pid;
    pid_t tid;
    int signo, si_code;
    void *faultaddr;
    struct ucontext context;
};

/**
 * Type of pointer to unwinding function for in-process unwinding.
 * @param outfile Output file descriptor for a crash dump.
 * @param context processor state at a moment of crash.
 */
typedef void (*ndcrash_in_unwind_func_ptr)(int outfile, struct ucontext *context);

/**
 * Type of pointer to unwinding function for out-of-process unwinding.
 * @param outfile Output file descriptor for a crash dump.
 * @param message Message instance that is sent to a daemon. Contains source data for a crash report.
 */
typedef void (*ndcrash_out_unwind_func_ptr)(int outfile, struct ndcrash_out_message *message);

#define NDCRASH_TOSTRING(arg) #arg

#ifndef SOCKET_NAME
#error SOCKET_NAME macro MUST be defined.
#endif

/// Socket for out-of-process architecture communication.
static const char NDCRASH_SOCKET_NAME[] = NDCRASH_TOSTRING(SOCKET_NAME);

/// This macro allows us to configure maximum lines count in backtrace.
#ifndef NDCRASH_MAX_FRAMES
#define NDCRASH_MAX_FRAMES 128
#endif

/// This macro allows us to configure maximum function name length. Used for buffer size.
#ifndef NDCRASH_MAX_FUNCTION_NAME_LENGTH
#define NDCRASH_MAX_FUNCTION_NAME_LENGTH 64
#endif

#endif //NDCRASH_PRIVATE_H
