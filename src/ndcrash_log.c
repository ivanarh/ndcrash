#include "ndcrash_log.h"
#include <stdio.h>
#include <stdarg.h>
#include <android/log.h>
#include <unistd.h>

#ifndef NDCRASH_LOG_BUFFER_SIZE
#define NDCRASH_LOG_BUFFER_SIZE 256
#endif

#ifndef NDCRASH_LOG_TAG
#define NDCRASH_LOG_TAG "NDCRASH"
#endif

void ndcrash_log_write_line(int fd, const char *format, ...) {
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

        // Writing to a file.
        write(fd, buffer, (size_t)printed);
    }
}