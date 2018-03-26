#include "ndcrash_dump.h"
#include "ndcrash_log.h"
#include "ndcrash_signal_utils.h"
#include "sizeofa.h"
#include <ucontext.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <android/log.h>

/**
 * Reads a file contents from passed filename to output buffer with specified size. Appends '\0'
 * character after file data that has been read.
 * @param filename File name to read.
 * @param outbuffer Buffer where to read a file
 * @param buffersize Size of buffer in bytes.
 * @return Count of read bytes not including terminating '\0' character or -1 or error.
 */
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
        NDCRASHLOG(
                ERROR,
                "Error creating dump file %s: %s (%d)",
                path,
                strerror(errno),
                errno);
    }
    return result;
}

#ifndef NDCRASH_LOG_BUFFER_SIZE
#define NDCRASH_LOG_BUFFER_SIZE 256
#endif

void ndcrash_dump_write_line(int fd, const char *format, ...) {
    char buffer[NDCRASH_LOG_BUFFER_SIZE];
    va_list args;
    va_start(args, format);

    // First writing to a log as is.
    __android_log_vprint(ANDROID_LOG_ERROR, NDCRASH_LOG_TAG, format, args);

    // Writing file to log may be disabled.
    if (fd <= 0) return;

    // Writing to a buffer.
    int printed = vsnprintf(buffer, NDCRASH_LOG_BUFFER_SIZE, format, args);

    va_end(args);

    // printed contains the number of characters that would have been written if n had been sufficiently
    // large, not counting the terminating null character.
    if (printed > 0) {
        if (printed >= NDCRASH_LOG_BUFFER_SIZE) {
            printed = NDCRASH_LOG_BUFFER_SIZE - 1;
        }
        // Replacing last buffer character with new line.
        buffer[printed] = '\n';

        // Writing to a file including \n character.
        write(fd, buffer, (size_t)printed + 1);
    }
}

void ndcrash_dump_header(int outfile, pid_t pid, pid_t tid, int signo, int si_code, void *faultaddr,
                         struct ucontext *context) {
    ndcrash_dump_write_line(outfile, "*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***");
    ndcrash_dump_write_line(outfile, "Build fingerprint: ''");
    ndcrash_dump_write_line(outfile, "Revision: '0'");
#ifdef __arm__
    ndcrash_dump_write_line(outfile, "ABI: 'arm'");
#elif defined(__i386__)
    ndcrash_dump_write_line(outfile, "ABI: 'x86'");
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

        ndcrash_dump_write_line(
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
        ndcrash_dump_write_line(
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
    ndcrash_dump_write_line(outfile, "    r0 %08x  r1 %08x  r2 %08x  r3 %08x",
                            ctx->arm_r0, ctx->arm_r1, ctx->arm_r2, ctx->arm_r3);
    ndcrash_dump_write_line(outfile, "    r4 %08x  r5 %08x  r6 %08x  r7 %08x",
                            ctx->arm_r4, ctx->arm_r5, ctx->arm_r6, ctx->arm_r7);
    ndcrash_dump_write_line(outfile, "    r8 %08x  r9 %08x  sl %08x  fp %08x",
                            ctx->arm_r8, ctx->arm_r9, ctx->arm_r10, ctx->arm_fp);
    ndcrash_dump_write_line(outfile, "    ip %08x  sp %08x  lr %08x  pc %08x  cpsr %08x",
                            ctx->arm_ip, ctx->arm_sp, ctx->arm_lr, ctx->arm_pc, ctx->arm_cpsr);
#elif defined(__i386__)
    ndcrash_dump_write_line(outfile, "    eax %08lx  ebx %08lx  ecx %08lx  edx %08lx",
            ctx->gregs[REG_EAX], ctx->gregs[REG_EBX], ctx->gregs[REG_ECX], ctx->gregs[REG_EDX]);
    ndcrash_dump_write_line(outfile, "    esi %08lx  edi %08lx",
            ctx->gregs[REG_ESI], ctx->gregs[REG_EDI]);
    ndcrash_dump_write_line(outfile, "    xcs %08x  xds %08x  xes %08x  xfs %08x  xss %08x",
            ctx->gregs[REG_CS], ctx->gregs[REG_DS], ctx->gregs[REG_ES], ctx->gregs[REG_FS], ctx->gregs[REG_SS]);
    ndcrash_dump_write_line(outfile, "    eip %08lx  ebp %08lx  esp %08lx  flags %08lx",
            ctx->gregs[REG_EIP], ctx->gregs[REG_EBP], ctx->gregs[REG_ESP], ctx->gregs[REG_EFL]);
#endif

    ndcrash_dump_write_line(outfile, " ");
    ndcrash_dump_write_line(outfile, "backtrace:");
}

void ndcrash_dump_backtrace_line_full(int outfile, int counter, intptr_t pc, const char *path,
                                      const char *funcname, int offset) {
    ndcrash_dump_write_line(outfile,
                            "    #%02d pc %08lx  %s (%s+%d)",
                            counter,
                            pc,
                            path,
                            funcname,
                            offset
    );
}

void ndcrash_dump_backtrace_line_part(int outfile, int counter, intptr_t pc, const char *path) {
    ndcrash_dump_write_line(outfile,
                            "    #%02d pc %08lx  %s",
                            counter,
                            pc,
                            path
    );
}

void ndcrash_dump_backtrace_line_func_name(int outfile, int counter, const char *funcname, int offset) {
    ndcrash_dump_write_line(
            outfile,
            "    #%02d  (%s+%d)",
            counter,
            funcname,
            offset
    );
}

void ndcrash_dump_backtrace_line_no_data(int outfile, int counter) {
    ndcrash_dump_write_line(
            outfile,
            "    #%02d",
            counter
    );
}