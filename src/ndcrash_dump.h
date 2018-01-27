#ifndef NDCRASH_DUMP_H
#define NDCRASH_DUMP_H
#include <sys/types.h>

struct siginfo;
struct ucontext;

void ndcrash_dump_header(int outfile, pid_t pid, pid_t tid, int signo, int si_code, void *faultaddr, struct ucontext *context);

#endif //NDCRASH_DUMP_H
