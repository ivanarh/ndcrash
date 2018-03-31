#include "ndcrash_utils.h"
#include <string.h>

bool ndcrash_is_system_lib(const char *library_path) {
    if (!library_path) return false;
    return strstr(library_path, "/system/") != NULL ||
           strstr(library_path, "libc.so") != NULL ||
           strstr(library_path, "libart.so") != NULL ||
           strstr(library_path, "libdvm.so") != NULL;
}