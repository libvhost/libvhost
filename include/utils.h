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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>  // For getenv
#include <string.h>  // For strcmp
#include <sys/uio.h>

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

// Function to determine if logging should occur based on log level
static inline int should_log(enum LOG_LEVEL level) {
    static enum LOG_LEVEL env_level = -1;  // Cache for environment log level priority

    // Check if the environment log level has been cached
    if (env_level == -1) {
        // Initialize log level priorities and default to INFO level if not set
        const char *log_level_env = getenv("LOG_LEVEL");
        if (log_level_env == NULL) {
            env_level = LOG_LEVEL_INFO;  // Default to INFO if environment variable is not set
        } else {
            // Determine the priority of the environment log level
            if (strcmp(log_level_env, "DEBUG") == 0) {
                env_level = LOG_LEVEL_DEBUG;
            } else if (strcmp(log_level_env, "INFO") == 0) {
                env_level = LOG_LEVEL_INFO;
            } else if (strcmp(log_level_env, "WARN") == 0) {
                env_level = LOG_LEVEL_WARN;
            } else if (strcmp(log_level_env, "ERROR") == 0) {
                env_level = LOG_LEVEL_ERROR;
            } else if (strcmp(log_level_env, "FATAL") == 0) {
                env_level = LOG_LEVEL_FATAL;
            } else {
                env_level = LOG_LEVEL_INFO;  // Default to INFO if the value is invalid
            }
        }
    }

    // Check if the current log level should be logged based on priority
    return level >= env_level;
}

// Logging macros
#define DEBUG(...)                                                                                                \
    do {                                                                                                          \
        if (should_log(LOG_LEVEL_DEBUG)) __vhost_log(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__); \
    } while (0)

#define INFO(...)                                                                                               \
    do {                                                                                                        \
        if (should_log(LOG_LEVEL_INFO)) __vhost_log(LOG_LEVEL_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__); \
    } while (0)

#define WARN(...)                                                                                               \
    do {                                                                                                        \
        if (should_log(LOG_LEVEL_WARN)) __vhost_log(LOG_LEVEL_WARN, __FILE__, __LINE__, __func__, __VA_ARGS__); \
    } while (0)

#define ERROR(...)                                                                                                \
    do {                                                                                                          \
        if (should_log(LOG_LEVEL_ERROR)) __vhost_log(LOG_LEVEL_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__); \
    } while (0)

#define FATAL(...)                                                                                                \
    do {                                                                                                          \
        if (should_log(LOG_LEVEL_FATAL)) __vhost_log(LOG_LEVEL_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__); \
    } while (0)

void DumpHex(const void* data, size_t size);

void __vhost_log(enum LOG_LEVEL level, const char* file, const int line, const char* func, const char* fmt, ...);

#define AlignUp(x, a) (((x) + (a)-1) & ~((a)-1))

static inline uint16_t
from_be16(const void *ptr)
{
	const uint8_t *tmp = (const uint8_t *)ptr;
	return (((uint16_t)tmp[0] << 8) | tmp[1]);
}

static inline void
to_be16(void *out, uint16_t in)
{
	uint8_t *tmp = (uint8_t *)out;
	tmp[0] = (in >> 8) & 0xFF;
	tmp[1] = in & 0xFF;
}

static inline uint32_t
from_be32(const void *ptr)
{
	const uint8_t *tmp = (const uint8_t *)ptr;
	return (((uint32_t)tmp[0] << 24) |
		((uint32_t)tmp[1] << 16) |
		((uint32_t)tmp[2] << 8) |
		((uint32_t)tmp[3]));
}

static inline void
to_be32(void *out, uint32_t in)
{
	uint8_t *tmp = (uint8_t *)out;
	tmp[0] = (in >> 24) & 0xFF;
	tmp[1] = (in >> 16) & 0xFF;
	tmp[2] = (in >> 8) & 0xFF;
	tmp[3] = in & 0xFF;
}

static inline int
iovec_init(struct iovec* iov, void* buf, size_t len) {
    iov->iov_base = buf;
    iov->iov_len = len;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif
