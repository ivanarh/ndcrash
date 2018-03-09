#include "ndcrash_backends.h"
#include "ndcrash_log.h"
#include "ndcrash_dump.h"
#include <android/log.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>


extern "C" {

using namespace unwindstack;

void ndcrash_common_unwind_libunwindstack(int outfile, struct ucontext *context, Maps &maps, Memory &memory) {
    std::string unw_function_name;
    const std::unique_ptr<Regs> regs(Regs::CreateFromUcontext(Regs::GetMachineType(), context));
    for (size_t frame_num = 0; frame_num < 128; frame_num++) {
        MapInfo * const map_info = maps.Find(regs->pc());
        if (!map_info) {
            __android_log_write(ANDROID_LOG_ERROR, NDCRASH_LOG_TAG, "MapInfo.Find error");
            break;
        }
        Elf *elf = map_info->GetElf(getpid(), true);
        if (!elf) {
            __android_log_write(ANDROID_LOG_ERROR, NDCRASH_LOG_TAG, "MapInfo.GetElf error");
            break;
        }
        uint64_t rel_pc = elf->GetRelPc(regs->pc(), map_info);
        uint64_t adjusted_rel_pc = rel_pc;
        if (frame_num != 0) {
            adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
        }
        uint64_t func_offset = 0;
        if (elf->GetFunctionName(adjusted_rel_pc, &unw_function_name, &func_offset)) {
            ndcrash_dump_backtrace_line_full(
                    outfile,
                    (int)frame_num,
                    (intptr_t)adjusted_rel_pc,
                    map_info->name.c_str(),
                    unw_function_name.c_str(),
                    (int)func_offset);

        } else {
            unw_function_name.clear();
            ndcrash_dump_backtrace_line_part(
                    outfile,
                    (int)frame_num,
                    (intptr_t)adjusted_rel_pc,
                    map_info->name.c_str());
        }
        if (!elf->Step(rel_pc + map_info->elf_offset, regs.get(), &memory)) {
            break;
        }
    }
}

#ifdef ENABLE_INPROCESS

void ndcrash_in_unwind_libunwindstack(int outfile, struct ucontext *context) {
    // Initializing /proc/self/maps cache.
    LocalMaps maps;
    if (!maps.Parse()) {
        __android_log_write(ANDROID_LOG_ERROR, NDCRASH_LOG_TAG, "/proc/self/maps parsing error.");
    }

    // Unwinding stack.
    MemoryLocal memory;
    ndcrash_common_unwind_libunwindstack(outfile, context, maps, memory);
}

#endif

#ifdef ENABLE_OUTOFPROCESS

void ndcrash_out_unwind_libunwindstack(int outfile, struct ndcrash_out_message *message) {
    RemoteMaps maps(message->tid);
    if (!maps.Parse()) {
        __android_log_print(ANDROID_LOG_ERROR, NDCRASH_LOG_TAG, "Failed to parse map data.");
        return;
    }

    // Unwinding stack.
    MemoryRemote memory(message->tid);
    ndcrash_common_unwind_libunwindstack(outfile, &message->context, maps, memory);
}

#endif

}