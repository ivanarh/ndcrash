#ifndef NDCRASHDEMO_NDCRASH_LOG_H
#define NDCRASHDEMO_NDCRASH_LOG_H

#ifndef NDCRASH_LOG_TAG
#define NDCRASH_LOG_TAG "NDCRASH"
#endif

#ifdef NDCRASH_NO_LOG
#define NDCRASHLOG(level, ...)
#else
#ifdef ANDROID
#include <android/log.h>
#define NDCRASHLOG(level, ...) __android_log_print(ANDROID_LOG_##level, NDCRASH_LOG_TAG, __VA_ARGS__)
#else
#include <stdio.h>
#define NDCRASHLOG(level, ...) do { \
    fprintf(stderr, NDCRASH_LOG_TAG": "); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while (0)
#endif
#endif

#endif //NDCRASHDEMO_NDCRASH_LOG_H
