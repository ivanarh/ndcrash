#ifndef NDCRASH_UTILS_H
#define NDCRASH_UTILS_H
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Check whether a specified library is a system library by its path.
 * @param library_path Path to a library.
 * @return Flag value.
 */
bool ndcrash_is_system_lib(const char *library_path);

#ifdef __cplusplus
}
#endif

#endif //NDCRASH_UTILS_H
