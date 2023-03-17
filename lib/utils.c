/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "utils.h"

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

pid_t gettid(void) {
    return syscall(__NR_gettid);
}

void DumpHex(const void* data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char*)data)[i]);
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

static const char* gettimestr(char* buff, int size) {
    int time_len = 0, n;
    struct tm* tm_info;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);
    time_len += strftime(buff, size, "%m%d %H:%M:%S", tm_info);
    time_len += snprintf(buff + time_len, size - time_len, ".%06ld", tv.tv_usec);
    return buff;
}

const char* level_names[] = {"D", "I", "W", "E", "F"};

static char* basename(char const* path) {
    char* s = strrchr(path, '/');
    if (!s)
        return (char*)path;
    else
        return s + 1;
}

void __vhost_log(enum LOG_LEVEL level, const char* file, const int line, const char* func, const char* fmt, ...) {
    char buf[1024];
    char timestamp[64];

    va_list ap;
    va_start(ap, fmt);
    va_end(ap);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    gettimestr(timestamp, sizeof(timestamp));
    // I1201 17:40:48.639746 14188 thread.cc:114]
    fprintf(stderr, "%s%s %d %s:%d] %s", level_names[level], timestamp, gettid(), basename(file), line, buf);
}
