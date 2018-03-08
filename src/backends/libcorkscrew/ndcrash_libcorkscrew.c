#include "ndcrash_backends.h"
#include "ndcrash_dump.h"
#include <corkscrew/backtrace.h>
#include <corkscrew/backtrace-arch.h>

enum { MAX_DEPTH = 32 };

void ndcrash_in_unwind_libcorkscrew(int outfile, struct ucontext *context) {
    map_info_t *map_info = acquire_my_map_info_list();
    backtrace_frame_t frames[MAX_DEPTH] = { { 0, 0, 0 } };
    backtrace_symbol_t backtrace_symbols[MAX_DEPTH] = { { 0, 0, NULL, NULL, NULL } };

    // Unwinding stack.
    const ssize_t frame_count = unwind_backtrace_signal_arch(NULL, context, map_info, frames, 0, MAX_DEPTH);

    //Getting symbols information.
    get_backtrace_symbols(frames, (size_t)frame_count, backtrace_symbols);

    for (ssize_t i = 0; i < frame_count; ++i) {
        const backtrace_symbol_t *symbol = backtrace_symbols + i;
        const char * const symbol_name = symbol->demangled_name ? symbol->demangled_name : symbol->symbol_name;
        if (symbol_name) {
            ndcrash_dump_backtrace_line_full(
                    outfile,
                     i,
                     symbol->relative_pc,
                     symbol->map_name,
                     symbol->symbol_name,
                     symbol->relative_pc - symbol->relative_symbol_addr
            );
        } else {
            ndcrash_dump_backtrace_line_part(
                    outfile,
                     i,
                     symbol->relative_pc,
                     symbol->map_name
            );
        }
    }
    free_backtrace_symbols(backtrace_symbols, (size_t)frame_count);
    release_my_map_info_list(map_info);
}