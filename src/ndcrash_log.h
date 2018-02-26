#ifndef NDCRASHDEMO_NDCRASH_LOG_H
#define NDCRASHDEMO_NDCRASH_LOG_H

#ifndef NDCRASH_LOG_TAG
#define NDCRASH_LOG_TAG "NDCRASH"
#endif

void ndcrash_log_write_line(int fd, const char *format, ...);

#endif //NDCRASHDEMO_NDCRASH_LOG_H
