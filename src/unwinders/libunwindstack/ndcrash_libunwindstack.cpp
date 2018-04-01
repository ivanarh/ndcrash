#include "ndcrash_unwinders.h"
#include "ndcrash_log.h"
#include "ndcrash_dump.h"
#include "ndcrash_private.h"
#include <android/log.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>


extern "C" {

using namespace unwindstack;

#if defined(ENABLE_INPROCESS) || defined(ENABLE_OUTOFPROCESS)

static void ndcrash_common_unwind_libunwindstack(int outfile, struct ucontext *context, Maps &maps, const std::shared_ptr<Memory> &memory) {
    // String for function name.
    std::string unw_function_name;

    // Initializing registers value from ucontext.
    const std::unique_ptr<Regs> regs(Regs::CreateFromUcontext(Regs::CurrentArch(), context));

    for (size_t frame_num = 0; frame_num < NDCRASH_MAX_FRAMES; frame_num++) {
        // Looking for a map info item for pc on this unwinding step.
        MapInfo * const map_info = maps.Find(regs->pc());
        if (!map_info) {
            ndcrash_dump_backtrace_line(
                    outfile,
                    (int)frame_num,
                    (intptr_t)regs->pc(),
                    NULL,
                    NULL,
                    0);
            break;
        }

        // Loading data from ELF
        Elf * const elf = map_info->GetElf(memory, true);
        if (!elf) {
            ndcrash_dump_backtrace_line(
                    outfile,
                    (int)frame_num,
                    (intptr_t)regs->pc(),
                    map_info->name.c_str(),
                    NULL,
                    0);
            break;
        }

        // Getting value of program counter relative module where a function is located.
        const uint64_t rel_pc = elf->GetRelPc(regs->pc(), map_info);
        uint64_t adjusted_rel_pc = rel_pc;
        if (frame_num != 0) {
            // If it's not a first frame we need to rewind program counter value to previous instruction.
            // For the first frame pc from ucontext points exactly to a failed instruction, for other
            // frames rel_pc will contain return address after function call instruction.
            adjusted_rel_pc -= regs->GetPcAdjustment(rel_pc, elf);
        }

        // Getting function name and writing value to a log.
        uint64_t func_offset = 0;
        if (elf->GetFunctionName(rel_pc, &unw_function_name, &func_offset)) {
            ndcrash_dump_backtrace_line(
                    outfile,
                    (int)frame_num,
                    (intptr_t)rel_pc,
                    map_info->name.c_str(),
                    unw_function_name.c_str(),
                    (intptr_t) func_offset);
        } else {
            unw_function_name.clear();
            ndcrash_dump_backtrace_line(
                    outfile,
                    (int)frame_num,
                    (intptr_t)rel_pc,
                    map_info->name.c_str(),
                    NULL,
                    0);
        }

        // Trying to switch to a next frame.
        bool finished = false;
        if (!elf->Step(rel_pc, adjusted_rel_pc, map_info->elf_offset, regs.get(), memory.get(), &finished)) {
            break;
        }
    }
}

#endif //defined(ENABLE_INPROCESS) || defined(ENABLE_OUTOFPROCESS)

#ifdef ENABLE_INPROCESS

void ndcrash_in_unwind_libunwindstack(int outfile, struct ucontext *context) {
    // Initializing /proc/self/maps cache.
    LocalMaps maps;
    if (!maps.Parse()) {
        NDCRASHLOG(ERROR, "libunwindstack: failed to parse local /proc/pid/maps.");
        return;
    }
    // Unwinding stack.
    const std::shared_ptr<Memory> memory(new MemoryLocal);
    ndcrash_common_unwind_libunwindstack(outfile, context, maps, memory);
}

#endif //ENABLE_INPROCESS

#ifdef ENABLE_OUTOFPROCESS

void ndcrash_out_unwind_libunwindstack(int outfile, struct ndcrash_out_message *message) {
    RemoteMaps maps(message->tid);
    if (!maps.Parse()) {
        NDCRASHLOG(ERROR, "libunwindstack: failed to parse remote /proc/pid/maps.");
        return;
    }
    // Unwinding stack.
    const std::shared_ptr<Memory> memory(new MemoryRemote(message->tid));
    ndcrash_common_unwind_libunwindstack(outfile, &message->context, maps, memory);
}

#endif //ENABLE_OUTOFPROCESS

}