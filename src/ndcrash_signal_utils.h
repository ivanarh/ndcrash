#ifndef NDCRASH_SIGNAL_UTILS_H
#define NDCRASH_SIGNAL_UTILS_H
#include <stdbool.h>

bool ndcrash_signal_has_si_addr(int si_signo, int si_code);
const char *ndcrash_get_signame(int sig);
const char *ndcrash_get_sigcode(int signo, int code);

#endif //NDCRASH_SIGNAL_UTILS_H
