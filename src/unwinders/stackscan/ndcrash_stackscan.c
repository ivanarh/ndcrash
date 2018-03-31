#include "ndcrash_unwinders.h"
#include "ndcrash_dump.h"
#include "ndcrash_private.h"
#include "ndcrash_memory_map.h"
#include <unwind.h>
#include <dlfcn.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef ENABLE_INPROCESS

/**
 * Extracts program counter (instruction pointer) value from passed ucontext structure.
 * @param uc Pointer to ucontext structure.
 * @return Program counter value.
 */
static uintptr_t ndcrash_pc_from_ucontext(const ucontext_t *uc) {
#if defined(__arm__)
    return uc->uc_mcontext.arm_pc;
#elif defined(__aarch64__)
    return uc->uc_mcontext.pc;
#elif defined(__i386__)
    return uc->uc_mcontext.gregs[REG_EIP];
#elif defined(__x86_64__)
    return uc->uc_mcontext.gregs[REG_RIP];
#endif
}

/**
 * Extracts stack pointer value from passed ucontext structure.
 * @param uc Pointer to ucontext structure.
 * @return Stack pointer value.
 */
static uintptr_t ndcrash_sp_from_ucontext(const ucontext_t *uc) {
#if defined(__arm__)
    return uc->uc_mcontext.arm_sp;
#elif defined(__aarch64__)
    return uc->uc_mcontext.sp;
#elif defined(__i386__)
    return uc->uc_mcontext.gregs[REG_ESP];
#elif defined(__x86_64__)
    return uc->uc_mcontext.gregs[REG_RSP];
#endif
}

/**
 * Rewinds program counter value to an address of a previous instruction.
 * @param pc Program counter value to rewind.
 * @return Rewound program counter value.
 */
static uintptr_t ndcrash_rewind_pc(uintptr_t pc) {
#ifdef __arm__
    if (pc & 1) {
        // Thumb mode.
        const uintptr_t value = *((uintptr_t *)(pc - 5));
        if ((value & 0xe000f000) != 0xe000f000) {
            return pc - 2;
        }
    }
    return pc - 4;
#elif defined(__aarch64__)
    return pc < 4 ? pc : pc - 4;
#elif defined(__i386__) || defined(__x86_64__)
    return pc - 1;
#endif
}

/**
 * Looks for a function containing specified address and adds it to a backtrace if found.
 * @param addr Address value to search a function. This may be a program counter value (for the
 * first frame) or any value from a stack.
 * @param outfile A file descriptor where to write a crash dump.
 * @param frameno A pointer to frame number which is incremented when a function is found.
 * @param rewind A flag whether to perform addr rewinding to a previous instruction. Typically it's
 * not required for program counter value but required for values from stack.
 */
static void ndcrash_try_unwind_frame(uintptr_t addr, int outfile, int *frameno, bool rewind) {
    Dl_info info;
    if (addr && dladdr((void *)addr, &info)) {
        if (rewind) {
            addr = ndcrash_rewind_pc(addr);
        }
        ndcrash_dump_backtrace_line(
                outfile,
                 *frameno,
                 (uintptr_t)addr - (uintptr_t)info.dli_fbase,
                 info.dli_fname,
                 info.dli_sname, // May be null.
                 addr - (uintptr_t)info.dli_saddr
        );
        ++(*frameno);
    }
}

/**
 * Contains bounds of scanned stack.
 */
typedef struct {

    /// Top of stack, an address where we start scanning. This is stack pointer value.
    uintptr_t sp;

    /// End of stack, an address after a final stack byte.
    uintptr_t end;

} ndcrash_stackscan_stack_t;

/**
 * Callback for a memory map parsing function. We use it to make sure that used stack bounds don't
 * run out of stack memory area to prevent a crash. For arguments description see
 * ndcrash_memory_map_entry_callback type definition.
 */
static void ndcrash_stackscan_maps_callback(uintptr_t start, uintptr_t end, void *data, bool *stop) {
    ndcrash_stackscan_stack_t *stack = (ndcrash_stackscan_stack_t *)data;
    if (start <= stack->sp && stack->sp < end) {
        if (stack->end > end) {
            stack->end = end;
        }
        *stop = true;
    }
}

void ndcrash_in_unwind_stackscan(int outfile, struct ucontext *context) {

    // Program counter is always the first element
    int frameno = 0;
    ndcrash_try_unwind_frame(ndcrash_pc_from_ucontext(context), outfile, &frameno, false);
#ifdef __arm__
    // For 32-bit arm architecture the second backtrace element is always lr register.
    // Third and following are obtained from stack.
    ndcrash_try_unwind_frame(context->uc_mcontext.arm_lr, outfile, &frameno, true);
#endif

    // Filling in initial stack bounds to scan.
    ndcrash_stackscan_stack_t stack;
    stack.sp = ndcrash_sp_from_ucontext(context);
    stack.end = stack.sp + getpagesize();

    // Searching sp value in memory map in order to avoid walking out of stack bounds.
    ndcrash_parse_memory_map(getpid(), &ndcrash_stackscan_maps_callback, &stack);

    // Scanning a stack by simple iteration of each stack element.
    uintptr_t *stack_content = (uintptr_t *) stack.sp;
    uintptr_t * const stack_end = (uintptr_t *) stack.end;
    for (; stack_content != stack_end && frameno < NDCRASH_MAX_FRAMES; ++stack_content) {
        ndcrash_try_unwind_frame(*stack_content, outfile, &frameno, true);
    }
}

#endif //ENABLE_INPROCESS
