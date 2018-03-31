#include "ndcrash_unwinders.h"
#include "ndcrash_dump.h"
#include "ndcrash_private.h"
#include <corkscrew/backtrace.h>
#include <corkscrew/backtrace-arch.h>

#if defined(__arm__) || defined(__i386__)

/**
 * We limit count of frames by 32 for in-process mode because we have a very limited stack size.
 */
static const int LIBCORKSCREW_IN_MAX_FRAMES =
#if NDCRASH_MAX_FRAMES > 32
        32;
#else
        NDCRASH_MAX_FRAMES;
#endif

void ndcrash_common_unwind_libcorkscrew(int outfile, backtrace_symbol_t *backtrace_symbols, ssize_t frame_count) {
    for (ssize_t i = 0; i < frame_count; ++i) {
        const backtrace_symbol_t *symbol = backtrace_symbols + i;
        const char * const symbol_name = symbol->demangled_name ? symbol->demangled_name : symbol->symbol_name;
        ndcrash_dump_backtrace_line(
                outfile,
                i,
                symbol->relative_pc,
                symbol->map_name,
                symbol_name,
                symbol->relative_pc - symbol->relative_symbol_addr);
    }
}

#ifdef ENABLE_INPROCESS

void ndcrash_in_unwind_libcorkscrew(int outfile, struct ucontext *context) {
    map_info_t *map_info = acquire_my_map_info_list();
    backtrace_frame_t frames[LIBCORKSCREW_IN_MAX_FRAMES] = { { 0, 0, 0 } };

    // Unwinding stack.
    const ssize_t frame_count = unwind_backtrace_signal_arch(NULL, context, map_info, frames, 0, LIBCORKSCREW_IN_MAX_FRAMES);

    //Getting symbols information.
    backtrace_symbol_t backtrace_symbols[LIBCORKSCREW_IN_MAX_FRAMES] = { { 0, 0, NULL, NULL, NULL } };
    get_backtrace_symbols(frames, (size_t)frame_count, backtrace_symbols);

    ndcrash_common_unwind_libcorkscrew(outfile, backtrace_symbols, frame_count);

    free_backtrace_symbols(backtrace_symbols, (size_t)frame_count);
    release_my_map_info_list(map_info);
}

#endif //ENABLE_INPROCESS

#ifdef ENABLE_OUTOFPROCESS

void ndcrash_out_unwind_libcorkscrew(int outfile, struct ndcrash_out_message *message) {
    ptrace_context_t *ptrace_context = load_ptrace_context(message->tid);
    backtrace_frame_t frames[NDCRASH_MAX_FRAMES] = { { 0, 0, 0 } };

    // Collecting backtrace
    const ssize_t frame_count = unwind_backtrace_ptrace_context_arch(
            message->tid,
            (void *)&message->context,
            ptrace_context,
            frames,
            0,
            NDCRASH_MAX_FRAMES);

    //Getting symbols information.
    backtrace_symbol_t backtrace_symbols[NDCRASH_MAX_FRAMES] = { { 0, 0, NULL, NULL, NULL } };
    get_backtrace_symbols_ptrace(ptrace_context, frames, (size_t)frame_count, backtrace_symbols);

    ndcrash_common_unwind_libcorkscrew(outfile, backtrace_symbols, frame_count);

    free_backtrace_symbols(backtrace_symbols, (size_t)frame_count);
    free_ptrace_context(ptrace_context);
}

#endif //ENABLE_OUTOFPROCESS

#else //defined(__arm__) || defined(__i386__)
#error Architecture is not supported, libcorkscrew supports only arm and x86.
#endif