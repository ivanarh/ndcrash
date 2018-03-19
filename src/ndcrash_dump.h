#ifndef NDCRASH_DUMP_H
#define NDCRASH_DUMP_H
#include <sys/types.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct siginfo;
struct ucontext;

/**
 * Creates an output file for a crash report. Wrapper around open() system call.
 * @param path Path to an output file.
 * @return Result of open() system call (file descriptor on success), see its documentation.
 */
int ndcrash_dump_create_file(const char *path);

/**
 * Write an arbitrary line to a crash dump.
 * @param fd Crash dump file descriptor.
 * @param format Dump line format.
 * @param ... Format arguments.
 */
void ndcrash_dump_write_line(int fd, const char *format, ...);

/**
 * Write a crash report header to a file and to log.
 * @param outfile Output file descriptor for a crash report.
 * @param pid Crashed process identifier.
 * @param tid Crashed thread identifier.
 * @param signo Number of signal that was caught on crash.
 * @param si_code Code of signal that was caught on crash (from siginfo structure).
 * @param faultaddr Optional fault address (from siginfo structure).
 * @param context Execution context a moment of crash.
 */
void ndcrash_dump_header(int outfile, pid_t pid, pid_t tid, int signo, int si_code, void *faultaddr,
                         struct ucontext *context);

/**
 * Write a full line of backtrace to a crash report. Full means that we have all data including
 * function name and instruction offset within a function.
 * @param outfile Output file descriptor for a crash report.
 * @param counter Number of backtrace element.
 * @param pc Program counter value (address of instruction). Relative.
 * @param path Path of object containing a function.
 * @param funcname Name of function.
 * @param offset Offset of instruction from function start. In bytes.
 */
void ndcrash_dump_backtrace_line_full(int outfile, int counter, intptr_t pc, const char *path,
                                      const char *funcname, int offset);

/**
 * Writes a partial line of backtrace to a crash report. Used when we didn't manage to determine
 * a function name and offset within it.
 * @param outfile Output file descriptor for a crash report.
 * @param counter Number of backtrace element.
 * @param pc Program counter value (address of instruction). Relative.
 * @param path Path of object containing a function.
 */
void ndcrash_dump_backtrace_line_part(int outfile, int counter, intptr_t pc, const char *path);

#ifdef __cplusplus
}
#endif

#endif //NDCRASH_DUMP_H
