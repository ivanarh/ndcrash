#include "ndcrash_dump.h"
#include "ndcrash_log.h"
#include "ndcrash_signal_utils.h"
#include "sizeofa.h"
#include <ucontext.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <android/log.h>

ssize_t ndcrash_read_file(const char *filename, char *outbuffer, size_t buffersize) {
    const int fd = open(filename, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t bytes_read;
    ssize_t overall_read = 0;
    while ((bytes_read = read(fd, outbuffer + overall_read, buffersize - overall_read - 1)) > 0) {
        overall_read += bytes_read;
    }
    if (bytes_read < 0) return -1;
    outbuffer[overall_read] = '\0';
    return overall_read;
}

int ndcrash_dump_create_file(const char *path) {
    const int result = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (result < 0) {
        __android_log_print(
                ANDROID_LOG_ERROR,
                NDCRASH_LOG_TAG,
                "Error creating dump file %s: %s (%d)",
                path,
                strerror(errno),
                errno);
    }
    return result;
}

void ndcrash_dump_header(int outfile, pid_t pid, pid_t tid, int signo, int si_code, void *faultaddr,
                         struct ucontext *context) {
    ndcrash_log_write_line(outfile,
                           "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***");
    ndcrash_log_write_line(outfile, "Build fingerprint: ''");
    ndcrash_log_write_line(outfile, "Revision: '0'");
#ifdef __arm__
    ndcrash_log_write_line(outfile, "ABI: 'arm'");
#elif defined(__i386__)
    ndcrash_log_write_line(outfile, "ABI: 'x86'");
#endif

    {
        // Buffer used for file path formatting.
        char proc_file_path[32];

        // Buffers for process and thread name.
        char proc_cmdline_content[64], proc_comm_content[32];
        proc_cmdline_content[0] = '\0';
        proc_comm_content[0] = '\0';

        if (snprintf(proc_file_path, sizeofa(proc_file_path), "proc/%d/cmdline", pid) >= 0) {
            ndcrash_read_file(proc_file_path, proc_cmdline_content, sizeofa(proc_cmdline_content));
        }

        if (snprintf(proc_file_path, sizeofa(proc_file_path), "proc/%d/comm", pid) >= 0) {
            const ssize_t bytes_read = ndcrash_read_file(proc_file_path, proc_comm_content,
                                                         sizeofa(proc_comm_content));
            // comm usually contains newline character on the end. We don't need it.
            if (bytes_read > 0 && proc_comm_content[bytes_read - 1] == '\n') {
                proc_comm_content[bytes_read - 1] = '\0';
            }
        }

        ndcrash_log_write_line(
                outfile,
                "pid: %d, tid: %d, name: %s  >>> %s <<<",
                pid,
                tid,
                proc_cmdline_content,
                proc_comm_content);
    }
    {
        char addr_buffer[11]; // TODO: Add 64 bit support.
        if (ndcrash_signal_has_si_addr(signo, si_code)) {
            snprintf(addr_buffer, sizeof(addr_buffer), "%p", faultaddr);
        } else {
            snprintf(addr_buffer, sizeof(addr_buffer), "--------");
        }
        ndcrash_log_write_line(
                outfile,
                "signal %d (%s), code %d (%s), fault addr %s",
                signo,
                ndcrash_get_signame(signo),
                si_code,
                ndcrash_get_sigcode(signo, si_code),
                addr_buffer);
    }

    const mcontext_t *const ctx = &context->uc_mcontext;
#if defined(__arm__)
    ndcrash_log_write_line(outfile, "    r0 %08x  r1 %08x  r2 %08x  r3 %08x",
                           ctx->arm_r0, ctx->arm_r1, ctx->arm_r2, ctx->arm_r3);
    ndcrash_log_write_line(outfile, "    r4 %08x  r5 %08x  r6 %08x  r7 %08x",
                           ctx->arm_r4, ctx->arm_r5, ctx->arm_r6, ctx->arm_r7);
    ndcrash_log_write_line(outfile, "    r8 %08x  r9 %08x  sl %08x  fp %08x",
                           ctx->arm_r8, ctx->arm_r9, ctx->arm_r10, ctx->arm_fp);
    ndcrash_log_write_line(outfile, "    ip %08x  sp %08x  lr %08x  pc %08x  cpsr %08x",
                           ctx->arm_ip, ctx->arm_sp, ctx->arm_lr, ctx->arm_pc, ctx->arm_cpsr);
#elif defined(__i386__)
    ndcrash_log_write_line(outfile, "    eax %08lx  ebx %08lx  ecx %08lx  edx %08lx",
            ctx->gregs[REG_EAX], ctx->gregs[REG_EBX], ctx->gregs[REG_ECX], ctx->gregs[REG_EDX]);
    ndcrash_log_write_line(outfile, "    esi %08lx  edi %08lx",
            ctx->gregs[REG_ESI], ctx->gregs[REG_EDI]);
    ndcrash_log_write_line(outfile, "    xcs %08x  xds %08x  xes %08x  xfs %08x  xss %08x",
            ctx->gregs[REG_CS], ctx->gregs[REG_DS], ctx->gregs[REG_ES], ctx->gregs[REG_FS], ctx->gregs[REG_SS]);
    ndcrash_log_write_line(outfile, "    eip %08lx  ebp %08lx  esp %08lx  flags %08lx",
            ctx->gregs[REG_EIP], ctx->gregs[REG_EBP], ctx->gregs[REG_ESP], ctx->gregs[REG_EFL]);
#endif

    ndcrash_log_write_line(outfile, " ");
    ndcrash_log_write_line(outfile, "backtrace:");
}

void ndcrash_dump_backtrace_line_full(int outfile, int counter, intptr_t pc, const char *path,
                                      const char *funcname, int offset) {
    ndcrash_log_write_line(outfile,
                           "    #%02d pc %08lx  %s (%s+%d)",
                           counter,
                           pc,
                           path,
                           funcname,
                           offset
    );
}

void ndcrash_dump_backtrace_line_part(int outfile, int counter, intptr_t pc, const char *path) {
    ndcrash_log_write_line(outfile,
                           "    #%02d pc %08lx  %s",
                           counter,
                           pc,
                           path
    );
}