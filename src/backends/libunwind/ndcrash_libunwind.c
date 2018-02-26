#include "ndcrash_backends.h"
#include "ndcrash_dump.h"
#include "sizeofa.h"
#include <libunwind.h>
#include <string.h>
#include <ucontext.h>

void ndcrash_in_unwind_libunwind(int outfile, struct ucontext *context) {

    // Unwinding stack.
    unw_cursor_t unw_cursor;
    char unw_function_name[64];
    unw_context_t uc;
    int result;
#if defined(__arm__)
    unw_tdep_context_t *unw_ctx = (unw_tdep_context_t*)&uc;
    struct sigcontext *sig_ctx = &context->uc_mcontext;
    memcpy(unw_ctx->regs, &sig_ctx->arm_r0, sizeof(unw_ctx->regs));
#elif defined(__i386__)
    uc = *((unw_context_t*)context);
#else
#error Architecture is not supported.
#endif

    //Getting cursor for unwinding
    result = unw_init_local(&unw_cursor, &uc);
    if (!result) {
        //Arguments for unw_get_proc_name
        unw_word_t regip, offset;
        //Maximum stack size, to prevent infinite loop
        static const int max_stack_size = 128;
        int i = 0;
        for (; i<max_stack_size; ++i) {
            // Getting function data and name.
            unw_get_reg(&unw_cursor, UNW_REG_IP, &regip);

            unw_map_cursor_t proc_map_cursor;
            unw_map_local_cursor_get(&proc_map_cursor);
            unw_map_t proc_map_item = { 0, 0, 0, 0, "", 0 };
            while (unw_map_cursor_get_next(&proc_map_cursor, &proc_map_item) > 0) {
                if (regip >= proc_map_item.start && regip < proc_map_item.end) break;
            }

            if (unw_get_proc_name(&unw_cursor, unw_function_name, sizeofa(unw_function_name), &offset) > 0) {
                ndcrash_dump_backtrace_line_full(
                        outfile,
                         i,
                         regip - proc_map_item.start,
                         proc_map_item.path,
                         unw_function_name,
                         offset
                );
            } else {
                ndcrash_dump_backtrace_line_part(
                        outfile,
                         i,
                         regip - proc_map_item.start,
                         proc_map_item.path
                );
            }
            if (unw_step(&unw_cursor) <= 0) break;
        }
    }

}