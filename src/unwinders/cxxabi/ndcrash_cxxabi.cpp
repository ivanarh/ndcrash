#include "ndcrash_unwinders.h"
#include "ndcrash_dump.h"
#include "ndcrash_private.h"
#include <unwind.h>
#include <dlfcn.h>

enum {
    MAX_DEPTH = 64
};

#ifdef ENABLE_INPROCESS

typedef struct {
    int outfile;
    int frameno;
} ndcrash_cxxabi_unwind_data;

extern "C" {

_Unwind_Reason_Code callback(struct _Unwind_Context *context, void *data) {
    ndcrash_cxxabi_unwind_data * const ud = (ndcrash_cxxabi_unwind_data *) data;
    const uintptr_t pc = _Unwind_GetIP(context);
    Dl_info info;
    if (pc && dladdr((void *) pc, &info)) {
        ndcrash_dump_backtrace_line(
                ud->outfile,
                ud->frameno,
                (intptr_t) pc - (intptr_t) info.dli_fbase,
                info.dli_fname,
                info.dli_sname,
                (intptr_t) pc - (intptr_t) info.dli_saddr
        );
    } else {
        ndcrash_dump_backtrace_line(ud->outfile, ud->frameno, pc, NULL, NULL, 0);
    }
    return ++ud->frameno >= MAX_DEPTH ? _URC_END_OF_STACK : _URC_NO_REASON;
}

void ndcrash_in_unwind_cxxabi(int outfile, struct ucontext *context) {
    ndcrash_cxxabi_unwind_data unwdata;
    unwdata.frameno = 0;
    unwdata.outfile = outfile;
    _Unwind_Backtrace(callback, &unwdata);
}

} //extern "C"

#endif //ENABLE_INPROCESS
