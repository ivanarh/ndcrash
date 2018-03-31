#include "ndcrash_unwinders.h"
#include "ndcrash_dump.h"
#include "ndcrash_log.h"
#include "ndcrash_private.h"
#include "sizeofa.h"
#include <libunwind.h>
#include <libunwind-ptrace.h>
#include <libunwind_i.h>
#include <mempool.h>
#include <string.h>
#include <ucontext.h>
#include <android/log.h>
#include <stdbool.h>
#include <malloc.h>

#ifdef ENABLE_INPROCESS

/**
 * Initializes unw_context_t structure by specified ucontext structure.
 *
 * @param context Source data.
 * @param unw_ctx Pointer to destination structure.
 */
void ndcrash_in_unwind_libunwind_get_context(struct ucontext *context, unw_context_t *unw_ctx) {
#if defined(__arm__)
    struct sigcontext *sig_ctx = &context->uc_mcontext;
    memcpy(unw_ctx->regs, &sig_ctx->arm_r0, sizeof(unw_ctx->regs));
#elif defined(__i386__) || defined(__x86_64__) || defined(__aarch64__)
    *unw_ctx = *context;
#else
#error Architecture is not supported.
#endif
}

void ndcrash_in_unwind_libunwind(int outfile, struct ucontext *context) {
    // Parsing local /proc/pid/maps
    unw_map_local_create();

    // Cursor - the main structure used for unwinding with a huge size. Allocating on stack is undesirable
    // due to limited alternate stack size. malloc isn't signal safe. Using libunwind memory pools.
    struct mempool cursor_pool;
    mempool_init(&cursor_pool, sizeof(unw_cursor_t), 0);
    unw_cursor_t * const unw_cursor = mempool_alloc(&cursor_pool);

    // Buffer for function name.
    char unw_function_name[NDCRASH_MAX_FUNCTION_NAME_LENGTH];

    // Initializing context instance (processor state).
    unw_context_t unw_ctx;
    ndcrash_in_unwind_libunwind_get_context(context, &unw_ctx);

    // Initializing cursor for unwinding from passed processor context.
    if (!unw_init_local(unw_cursor, &unw_ctx)) {

        for (int i = 0; i < NDCRASH_MAX_FRAMES; ++i) {
            // Getting program counter value for the a current stack frame.
            unw_word_t regip;
            unw_get_reg(unw_cursor, UNW_REG_IP, &regip);

            // Looking for a function name.
            unw_word_t func_offset;
            const bool func_name_found = unw_get_proc_name(
                    unw_cursor, unw_function_name, sizeofa(unw_function_name), &func_offset) > 0;

            // Looking for a object (shared library) where a function is located.
            unw_map_cursor_t proc_map_cursor;
            unw_map_local_cursor_get(&proc_map_cursor);
            bool maps_found = false;
            unw_map_t proc_map_item;
            while (unw_map_cursor_get_next(&proc_map_cursor, &proc_map_item) > 0) {
                if (regip >= proc_map_item.start && regip < proc_map_item.end) {
                    maps_found = true;
                    regip -= proc_map_item.start; // Making relative.
                    break;
                }
            }

            // Writing a backtrace line.
            ndcrash_dump_backtrace_line(
                    outfile,
                    i,
                    regip, // Relative if maps is found
                    maps_found ? proc_map_item.path : NULL,
                    func_name_found ? unw_function_name : NULL,
                    (int) func_offset);

            // Trying to switch to a previous stack frame.
            if (unw_step(unw_cursor) <= 0) break;
        }
    }

    // Freeing a memory for cursor.
    mempool_free(&cursor_pool, unw_cursor);

    // Destroying local /proc/pid/maps
    unw_map_local_destroy();

}

#endif //ENABLE_INPROCESS

#ifdef ENABLE_OUTOFPROCESS

struct ndcrash_out_libunwind_as_arg {
    void *upt_info;
    unw_context_t unw_ctx;
};

static int ndcrash_out_libunwind_find_proc_info(unw_addr_space_t as, unw_word_t ip, unw_proc_info_t *pi,
                                         int need_unwind_info, void *arg) {
    const unw_accessors_t old_acc = as->acc;
    as->acc = _UPT_accessors;
    const int result = _UPT_find_proc_info(as, ip, pi, need_unwind_info, ((struct ndcrash_out_libunwind_as_arg *) arg)->upt_info);
    as->acc = old_acc;
    return result;
}

static void ndcrash_out_libunwind_put_unwind_info(unw_addr_space_t as, unw_proc_info_t *pi, void *arg) {
    const unw_accessors_t old_acc = as->acc;
    as->acc = _UPT_accessors;
    _UPT_put_unwind_info(as, pi, ((struct ndcrash_out_libunwind_as_arg *) arg)->upt_info);
    as->acc = old_acc;
}

static int ndcrash_out_libunwind_get_dyn_info_list_addr(unw_addr_space_t as, unw_word_t *dil_addr, void *arg) {
    const unw_accessors_t old_acc = as->acc;
    as->acc = _UPT_accessors;
    const int result = _UPT_get_dyn_info_list_addr(as, dil_addr, ((struct ndcrash_out_libunwind_as_arg *) arg)->upt_info);
    as->acc = old_acc;
    return result;
}

static int ndcrash_out_libunwind_access_mem(unw_addr_space_t as, unw_word_t addr, unw_word_t *val, int write, void *arg) {
    const unw_accessors_t old_acc = as->acc;
    as->acc = _UPT_accessors;
    const int result = _UPT_access_mem(as, addr, val, write, ((struct ndcrash_out_libunwind_as_arg *) arg)->upt_info);
    as->acc = old_acc;
    return result;
}


static inline void *ndcrash_out_libunwind_uc_addr(unw_tdep_context_t *uc, int reg) {
#ifdef __arm__
    if (reg >= UNW_ARM_R0 && reg < UNW_ARM_R0 + 16) {
        return &uc->regs[reg - UNW_ARM_R0];
    } else {
        return NULL;
    }
#elif defined(__aarch64__)
    if (reg >= UNW_AARCH64_X0 && reg <= UNW_AARCH64_V31) {
        return &uc->uc_mcontext.regs[reg];
    } else {
        return NULL;
    }
#elif defined(__i386__)
    void *addr;
    switch (reg) {
        case UNW_X86_GS:  addr = &uc->uc_mcontext.gregs[REG_GS]; break;
        case UNW_X86_FS:  addr = &uc->uc_mcontext.gregs[REG_FS]; break;
        case UNW_X86_ES:  addr = &uc->uc_mcontext.gregs[REG_ES]; break;
        case UNW_X86_DS:  addr = &uc->uc_mcontext.gregs[REG_DS]; break;
        case UNW_X86_EAX: addr = &uc->uc_mcontext.gregs[REG_EAX]; break;
        case UNW_X86_EBX: addr = &uc->uc_mcontext.gregs[REG_EBX]; break;
        case UNW_X86_ECX: addr = &uc->uc_mcontext.gregs[REG_ECX]; break;
        case UNW_X86_EDX: addr = &uc->uc_mcontext.gregs[REG_EDX]; break;
        case UNW_X86_ESI: addr = &uc->uc_mcontext.gregs[REG_ESI]; break;
        case UNW_X86_EDI: addr = &uc->uc_mcontext.gregs[REG_EDI]; break;
        case UNW_X86_EBP: addr = &uc->uc_mcontext.gregs[REG_EBP]; break;
        case UNW_X86_EIP: addr = &uc->uc_mcontext.gregs[REG_EIP]; break;
        case UNW_X86_ESP: addr = &uc->uc_mcontext.gregs[REG_ESP]; break;
        case UNW_X86_TRAPNO:  addr = &uc->uc_mcontext.gregs[REG_TRAPNO]; break;
        case UNW_X86_CS:  addr = &uc->uc_mcontext.gregs[REG_CS]; break;
        case UNW_X86_EFLAGS:  addr = &uc->uc_mcontext.gregs[REG_EFL]; break;
        case UNW_X86_SS:  addr = &uc->uc_mcontext.gregs[REG_SS]; break;
        default: addr = NULL;
    }
    return addr;

#elif defined(__x86_64__)
    void *addr;
    switch (reg) {
        case UNW_X86_64_R8: addr = &uc->uc_mcontext.gregs[REG_R8]; break;
        case UNW_X86_64_R9: addr = &uc->uc_mcontext.gregs[REG_R9]; break;
        case UNW_X86_64_R10: addr = &uc->uc_mcontext.gregs[REG_R10]; break;
        case UNW_X86_64_R11: addr = &uc->uc_mcontext.gregs[REG_R11]; break;
        case UNW_X86_64_R12: addr = &uc->uc_mcontext.gregs[REG_R12]; break;
        case UNW_X86_64_R13: addr = &uc->uc_mcontext.gregs[REG_R13]; break;
        case UNW_X86_64_R14: addr = &uc->uc_mcontext.gregs[REG_R14]; break;
        case UNW_X86_64_R15: addr = &uc->uc_mcontext.gregs[REG_R15]; break;
        case UNW_X86_64_RDI: addr = &uc->uc_mcontext.gregs[REG_RDI]; break;
        case UNW_X86_64_RSI: addr = &uc->uc_mcontext.gregs[REG_RSI]; break;
        case UNW_X86_64_RBP: addr = &uc->uc_mcontext.gregs[REG_RBP]; break;
        case UNW_X86_64_RBX: addr = &uc->uc_mcontext.gregs[REG_RBX]; break;
        case UNW_X86_64_RDX: addr = &uc->uc_mcontext.gregs[REG_RDX]; break;
        case UNW_X86_64_RAX: addr = &uc->uc_mcontext.gregs[REG_RAX]; break;
        case UNW_X86_64_RCX: addr = &uc->uc_mcontext.gregs[REG_RCX]; break;
        case UNW_X86_64_RSP: addr = &uc->uc_mcontext.gregs[REG_RSP]; break;
        case UNW_X86_64_RIP: addr = &uc->uc_mcontext.gregs[REG_RIP]; break;
        default: addr = NULL;
    }
    return addr;
#else
#error Architecture is not supported.
#endif
}

static int ndcrash_out_libunwind_access_reg(unw_addr_space_t as, unw_regnum_t reg, unw_word_t *val, int write, void *arg) {
    unw_word_t *addr;
    if (unw_is_fpreg(reg)) goto badreg;
    unw_tdep_context_t * const uc = &((struct ndcrash_out_libunwind_as_arg *) arg)->unw_ctx;
    if (!(addr = ndcrash_out_libunwind_uc_addr(uc, reg))) goto badreg;
    if (write) {
        *addr = *val;
    } else {
        *val = *addr;
    }
    return 0;
badreg:
    return -UNW_EBADREG;
}

static int ndcrash_out_libunwind_access_fpreg(unw_addr_space_t as, unw_regnum_t reg, unw_fpreg_t *val, int write, void *arg) {
    const unw_accessors_t old_acc = as->acc;
    as->acc = _UPT_accessors;
    const int result = _UPT_access_fpreg(as, reg, val, write, ((struct ndcrash_out_libunwind_as_arg *) arg)->upt_info);
    as->acc = old_acc;
    return result;
}

static int ndcrash_out_libunwind_get_proc_name(unw_addr_space_t as, unw_word_t ip, char *buf, size_t buf_len, unw_word_t *offp, void *arg) {
    const unw_accessors_t old_acc = as->acc;
    as->acc = _UPT_accessors;
    const int result = _UPT_get_proc_name(as, ip, buf, buf_len, offp, ((struct ndcrash_out_libunwind_as_arg *) arg)->upt_info);
    as->acc = old_acc;
    return result;
}

static int ndcrash_out_libunwind_resume(unw_addr_space_t as, unw_cursor_t *c, void *arg) {
    const unw_accessors_t old_acc = as->acc;
    as->acc = _UPT_accessors;
    const int result = _UPT_resume(as, c, ((struct ndcrash_out_libunwind_as_arg *) arg)->upt_info);
    as->acc = old_acc;
    return result;
}

void ndcrash_out_unwind_libunwind(int outfile, struct ndcrash_out_message *message) {
    unw_accessors_t accessors;
    accessors.find_proc_info = ndcrash_out_libunwind_find_proc_info;
    accessors.put_unwind_info = ndcrash_out_libunwind_put_unwind_info;
    accessors.get_dyn_info_list_addr = ndcrash_out_libunwind_get_dyn_info_list_addr;
    accessors.access_mem = ndcrash_out_libunwind_access_mem;
    accessors.access_reg = ndcrash_out_libunwind_access_reg;
    accessors.access_fpreg = ndcrash_out_libunwind_access_fpreg;
    accessors.get_proc_name = ndcrash_out_libunwind_get_proc_name;
    accessors.resume = ndcrash_out_libunwind_resume;

    const unw_addr_space_t addr_space = unw_create_addr_space(&accessors, 0);
    if (addr_space) {
        unw_map_cursor_t proc_map_cursor;
        if (!unw_map_cursor_create(&proc_map_cursor, message->tid)) {
            unw_map_set(addr_space, &proc_map_cursor);

            struct ndcrash_out_libunwind_as_arg ndcrash_as_arg;
            ndcrash_as_arg.upt_info = _UPT_create(message->tid);
            ndcrash_in_unwind_libunwind_get_context(&message->context, &ndcrash_as_arg.unw_ctx);

            if (ndcrash_as_arg.upt_info) {
                unw_cursor_t unw_cursor;
                char unw_function_name[NDCRASH_MAX_FUNCTION_NAME_LENGTH];
                if (unw_init_remote(&unw_cursor, addr_space, &ndcrash_as_arg) >= 0) {
                    for (int i = 0; i < NDCRASH_MAX_FRAMES; ++i) {
                        // Getting function data and name.
                        unw_word_t regip;
                        unw_get_reg(&unw_cursor, UNW_REG_IP, &regip);
                        unw_map_t proc_map_item = {0, 0, 0, 0, "", 0};
                        unw_map_cursor_reset(&proc_map_cursor);

                        // Looking for a function name.
                        unw_word_t func_offset;
                        const bool func_name_found = unw_get_proc_name_by_ip(
                                addr_space,
                                regip,
                                unw_function_name,
                                sizeofa(unw_function_name),
                                &func_offset,
                                &ndcrash_as_arg) >= 0 && unw_function_name[0] != '\0';

                        // Looking for a object (shared library) where a function is located.
                        bool maps_found = false;
                        while (unw_map_cursor_get_next(&proc_map_cursor, &proc_map_item) > 0) {
                            if (regip >= proc_map_item.start && regip < proc_map_item.end) {
                                maps_found = true;
                                regip -= proc_map_item.start; // Making relative.
                                break;
                            }
                        }

                        // Writing a backtrace line.
                        ndcrash_dump_backtrace_line(
                                outfile,
                                i,
                                regip, // Relative if maps is found
                                maps_found ? proc_map_item.path : NULL,
                                func_name_found ? unw_function_name : NULL,
                                func_offset);

                        // Trying to switch to a previous stack frame.
                        if (unw_step(&unw_cursor) <= 0) break;
                    }
                } else {
                    NDCRASHLOG(ERROR, "Failed to initialize libunwind.");
                }
                _UPT_destroy(ndcrash_as_arg.upt_info);
            } else {
                NDCRASHLOG(ERROR, "Failed to create upt.");
            }
            unw_map_cursor_destroy(&proc_map_cursor);
        } else {
            NDCRASHLOG(ERROR, "Call unw_map_cursor_create failed.");
        }
        // Remove the map from the address space before destroying it.
        // It will be freed in the UnwindMap destructor.
        unw_map_set(addr_space, NULL);
        unw_destroy_addr_space(addr_space);
    } else {
        NDCRASHLOG(ERROR, "Failed to create addr space.");
    }
}

#endif
