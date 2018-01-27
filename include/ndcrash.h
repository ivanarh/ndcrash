#ifndef NDCRASHDEMO_NDCRASH_H
#define NDCRASHDEMO_NDCRASH_H
#include <stdint.h>

/**
 * Enum representing supported backends for stack unwinding.
 */
enum ndcrash_backend {
    ndcrash_backend_libcorkscrew,
    ndcrash_backend_libunwind,
    ndcrash_backend_libunwindstack,
};

enum ndcrash_error {
    ndcrash_ok,
    ndcrash_error_already_initialized,
    ndcrash_error_not_supported,
    ndcrash_error_signal,
};

/**
 * Initialize crash reporting library in in-process mode.
 *
 * @param pcontext
 * @param backend
 * @return
 */
enum ndcrash_error ndcrash_in_init(const enum ndcrash_backend backend, const char *log_file);

/**
 * De-initialize crash reporting library in in-process mode.
 *
 * @param context
 */
void ndcrash_in_deinit();

#endif //NDCRASHDEMO_NDCRASH_H
