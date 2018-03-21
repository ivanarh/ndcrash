#ifndef NDCRASHDEMO_NDCRASH_H
#define NDCRASHDEMO_NDCRASH_H
#include <stdint.h>
#include <stdbool.h>

/**
 * Enum representing supported backends for stack unwinding.
 */
enum ndcrash_backend {                      // Supported architectures
    ndcrash_backend_libcorkscrew,           // Both
    ndcrash_backend_libunwind,              // Both
    ndcrash_backend_libunwindstack,         // Both
    ndcrash_backend_cxxabi                  // In-process
};

/**
 * Represents a result of ndcrash initialization.
 */
enum ndcrash_error {
    ndcrash_ok,
    ndcrash_error_already_initialized,
    ndcrash_error_not_supported,
    ndcrash_error_signal,
    ndcrash_error_pipe,
    ndcrash_error_thread,
};

/**
 * Initializes crash reporting library in in-process mode.
 *
 * @param backend What backend to use for unwinding.
 * @param log_file Path to crash report file where to write it.
 * @return Initialization result.
 */
enum ndcrash_error ndcrash_in_init(const enum ndcrash_backend backend, const char *log_file);

/**
 * De-initialize crash reporting library in in-process mode.
 */
void ndcrash_in_deinit();

/**
 * Initializes crash reporting library in out-of-process mode. This method should be called from
 * the main process of an application.
 */
enum ndcrash_error ndcrash_out_init();

/**
 * De-initialize crash reporting library in out-of-process mode.
 */
void ndcrash_out_deinit();

/**
 * Start an unwinding daemon for out-of-process crash reporting. In out-of-process architecture
 * a daemon performs stack crash report creation, does stack unwinding using ptrace mechanism and
 * saves a crash report to file. This method should be called from a separate process, for example,
 * background service that has android:process attribute.
 *
 * @param backend What backend to use for unwinding.
 * @param log_file Path to crash report file where to write it.
 * @return Initialization result.
 */
enum ndcrash_error ndcrash_out_start_daemon(const enum ndcrash_backend backend, const char *log_file);

/**
 * Stops an unwinding daemon for out-of-process crash reporting.
 *
 * @return Flag whether a daemon has been successfully stopped.
 */
bool ndcrash_out_stop_daemon();

#endif //NDCRASHDEMO_NDCRASH_H
