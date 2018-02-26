#ifndef NDCRASH_PRIVATE_H
#define NDCRASH_PRIVATE_H
#include "sizeofa.h"
#include <signal.h>

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

/// Forward declaration.
struct ucontext;

/// Type of pointer to unwinding function.
/// Parameter is processor state at a moment of crash.
typedef void (*ndcrash_unwind_func_ptr)(int outfile, struct ucontext *);

/// Forward declaration.
struct ndcrash_in_context;

#endif //NDCRASH_PRIVATE_H
