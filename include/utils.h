/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef _LIBVHOST_UTILS_H_
#define _LIBVHOST_UTILS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#define CHECK(cond)                                                      \
    do {                                                                 \
        if (!(cond)) {                                                   \
            fprintf(stderr, "[%s] Check failed: %s\n", __func__, #cond); \
            exit(1);                                                     \
        }                                                                \
    } while (0)

enum LOG_LEVEL {
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARN,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL,
};

#ifndef NDEBUG
#define DEBUG(...) __vhost_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)
#else
#define DEBUG(...)
#endif
#define INFO(...) __vhost_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define WARN(...) __vhost_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define ERROR(...) __vhost_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)
#define FALTA(...) __vhost_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__)

void DumpHex(const void* data, size_t size);

void __vhost_log(enum LOG_LEVEL level, const char* file, const int line, const char* func, const char* fmt, ...);

#define AlignUp(x, a) (((x) + (a)-1) & ~((a)-1))

#ifdef __cplusplus
}
#endif

#endif
