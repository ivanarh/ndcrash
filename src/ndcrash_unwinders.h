#ifndef NDCRASH_UNWINDERS_H
#define NDCRASH_UNWINDERS_H
#include "ndcrash_private.h"

#ifdef __cplusplus
extern "C" {
#endif

struct ucontext;

// See ndcrash_in_unwind_func_ptr for arguments description.
void ndcrash_in_unwind_libcorkscrew(int outfile, struct ucontext *context);
void ndcrash_in_unwind_libunwind(int outfile, struct ucontext *context);
void ndcrash_in_unwind_libunwindstack(int outfile, struct ucontext *context);
void ndcrash_in_unwind_cxxabi(int outfile, struct ucontext *context);
void ndcrash_in_unwind_stackscan(int outfile, struct ucontext *context);

// See ndcrash_out_unwind_func_ptr for arguments description.
void ndcrash_out_unwind_libcorkscrew(int outfile, struct ndcrash_out_message *message);
void ndcrash_out_unwind_libunwind(int outfile, struct ndcrash_out_message *message);
void ndcrash_out_unwind_libunwindstack(int outfile, struct ndcrash_out_message *message);

#ifdef __cplusplus
}
#endif


#endif //NDCRASH_UNWINDERS_H
