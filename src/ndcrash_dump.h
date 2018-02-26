#ifndef NDCRASH_DUMP_H
#define NDCRASH_DUMP_H
#include <sys/types.h>
#include <stdint.h>

struct siginfo;
struct ucontext;

int ndcrash_dump_create_file(const char *path);

void ndcrash_dump_header(int outfile, pid_t pid, pid_t tid, int signo, int si_code, void *faultaddr, struct ucontext *context);

void ndcrash_dump_backtrace_line_full(int outfile, int counter, intptr_t pc, const char *path, const char *funcname, int offset);

void ndcrash_dump_backtrace_line_part(int outfile, int counter, intptr_t pc, const char *path);

#endif //NDCRASH_DUMP_H
