#ifndef NDCRASHDEMO_NDCRASH_LOG_H
#define NDCRASHDEMO_NDCRASH_LOG_H

#ifndef NDCRASH_LOG_TAG
#define NDCRASH_LOG_TAG "NDCRASH"
#endif

#ifdef __cplusplus
extern "C" {
#endif

void ndcrash_log_write_line(int fd, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif //NDCRASHDEMO_NDCRASH_LOG_H
