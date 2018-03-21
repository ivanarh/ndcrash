#include "ndcrash_memory_map.h"
#include "sizeofa.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

void ndcrash_parse_memory_map(pid_t pid, ndcrash_memory_map_entry_callback callback, void *data) {
    char buffer[128];

    // Opening input file.
    snprintf(buffer, sizeofa(buffer), "/proc/%d/maps", (int)pid);
    const int fd = open(buffer, O_RDONLY);
    if (fd < 0) return;

    ssize_t bytes_read;
    bool new_line = true;
    while ((bytes_read = read(fd, buffer, sizeofa(buffer) - 1)) != 0) {
        if (bytes_read <= 0) {
            close(fd);
            return;
        }
        buffer[bytes_read] = '\0';
        if (new_line) {
            // Obtaining start and end addresses
            unsigned long int start;
            unsigned long int end;
            if (sscanf(buffer, "%lx-%lx", &start, &end) != 2) {
                close(fd);
                return;
            }
            bool stop = false;
            callback(start, end, data, &stop);
            if (stop) {
                close(fd);
                return;
            }
        }
        // Searching for a new line.
        ssize_t newline_pos = 0;
        for (; newline_pos != bytes_read; ++newline_pos) {
            if (buffer[newline_pos] == '\n') break;
        }
        if (newline_pos != bytes_read) {
            // Seeking to the next byte after newline_pos.
            if (lseek(fd, newline_pos + 1 - bytes_read, SEEK_CUR) < 0) {
                close(fd);
                return;
            }
            new_line = true;
        } else {
            new_line = false;
        }
    }

    close(fd);
}