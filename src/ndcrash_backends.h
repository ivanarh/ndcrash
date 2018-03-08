#ifndef NDCRASH_BACKENDS_H
#define NDCRASH_BACKENDS_H

#ifdef __cplusplus
extern "C" {
#endif

struct ucontext;

void ndcrash_in_unwind_libcorkscrew(int outfile, struct ucontext *context);
void ndcrash_in_unwind_libunwind(int outfile, struct ucontext *context);
void ndcrash_in_unwind_libunwindstack(int outfile, struct ucontext *context);

#ifdef __cplusplus
}
#endif


#endif //NDCRASH_BACKENDS_H
