#ifndef NDCRASH_BACKENDS_H
#define NDCRASH_BACKENDS_H

struct ucontext;

void ndcrash_unwind_libcorkscrew(struct ucontext *context);
void ndcrash_unwind_libunwind(struct ucontext *context);
void ndcrash_unwind_libunwindstack(struct ucontext *context);

#endif //NDCRASH_BACKENDS_H
