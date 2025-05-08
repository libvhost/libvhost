/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "libvhost.h"
#include "utils.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void random_buf(char* buf, size_t size) {
    int rnd = open("/dev/urandom", O_RDONLY);
    read(rnd, buf, size);
    close(rnd);
}

int my_memcmp(const void* s1, const void* s2, size_t n) {
    const uint8_t* p1 = s1;
    const uint8_t* p2 = s2;
    size_t i;
    for (i = 0; i < n; i++) {
        if (p1[i] != p2[i]) {
            printf("i: %d [0x%x] != [0x%x]\n", i, p1[i], p2[i]);
            return p1[i] - p2[i];
        }
    }
    return 0;
}

int test_sync_io(struct libvhost_ctrl* ctrl) {
    int i;
    int ret = 0;
    int buf_size = 4 << 10;
    char* rbuf;
    char* wbuf;
    wbuf = (char*)libvhost_malloc(ctrl, buf_size);
    rbuf = (char*)libvhost_malloc(ctrl, buf_size);

    for (i = 0; i < (1 << 16) + 10; ++i) {
        printf("============== %d ==================\n", i);
        random_buf(wbuf, buf_size);
        // libvhost_write(conn, 0, i << 9, wbuf, buf_size);
        libvhost_read(ctrl, 0, i << 9, rbuf, buf_size);
        if (0 != my_memcmp(wbuf, rbuf, buf_size)) {
            printf("miscompare failed: %d\n", memcmp(wbuf, rbuf, buf_size));
            ret = -1;
            printf("wbuf: \n");
            DumpHex((void*)wbuf, 16);
            printf("rbuf: \n");
            DumpHex((void*)rbuf, 16);
            break;
        }
    }
fail:
    libvhost_free(ctrl, wbuf);
    libvhost_free(ctrl, rbuf);
    return ret;
}

int test_discard(struct libvhost_ctrl* ctrl) {
    int i;
    int ret = 0;
    int buf_size = 1 << 20;
    char* rbuf;
    char* zero_buff;
    rbuf = (char*)libvhost_malloc(ctrl, buf_size);
    CHECK(rbuf);
    zero_buff = (char*)libvhost_malloc(ctrl, buf_size);
    CHECK(zero_buff);
    memset((void*)zero_buff, 0, buf_size);
    char* wbuf;
    wbuf = (char*)libvhost_malloc(ctrl, buf_size);
    CHECK(wbuf);

    for (i = 0; i < 1; ++i) {
        printf("============== %d ==================\n", i);
        random_buf(wbuf, buf_size);
        libvhost_write(ctrl, 0, i << 9, wbuf, buf_size);
        if (libvhost_discard(ctrl, 0, i << 9, buf_size) != 0) {
            printf("discard fail\n");
            goto fail;
        }
        libvhost_read(ctrl, 0, i << 9, rbuf, buf_size);
        if (0 != my_memcmp(zero_buff, rbuf, buf_size)) {
            printf("miscompare failed: %d\n", memcmp(zero_buff, rbuf, buf_size));
            ret = -1;
            printf("wbuf: \n");
            DumpHex((void*)zero_buff, 16);
            printf("rbuf: \n");
            DumpHex((void*)rbuf, 16);
            break;
        }
        printf("discard success\n");
    }

fail:
    libvhost_free(ctrl, rbuf);
    libvhost_free(ctrl, wbuf);
    libvhost_free(ctrl, zero_buff);

    return ret;
}

int test_sync_big_io(struct libvhost_ctrl* ctrl) {
    int i;
    int ret = 0;
    int buf_size = 8 << 20;
    char* rbuf;
    char* wbuf;
    wbuf = (char*)libvhost_malloc(ctrl, buf_size);
    CHECK(wbuf);
    rbuf = (char*)libvhost_malloc(ctrl, buf_size);
    CHECK(rbuf);

    for (i = 0; i < 1; ++i) {
        printf("============== %d ==================\n", i);
        random_buf(wbuf, buf_size);
        libvhost_write(ctrl, 0, i << 9, wbuf, buf_size);
        libvhost_read(ctrl, 0, i << 9, rbuf, buf_size);
        if (0 != my_memcmp(wbuf, rbuf, buf_size)) {
            printf("miscompare failed: %d\n", memcmp(wbuf, rbuf, buf_size));
            ret = -1;
            printf("wbuf: \n");
            DumpHex((void*)wbuf, 16);
            printf("rbuf: \n");
            DumpHex((void*)rbuf, 16);
            break;
        }
    }
fail:
    libvhost_free(ctrl, wbuf);
    libvhost_free(ctrl, rbuf);
    return ret;
}

struct test_iov {
    struct iovec iov;
    char* buf;
};

int test_async_io(struct libvhost_ctrl* ctrl) {
    int round;
    int idx;
    int ret = 0;
    int buf_size = 1024;
    const int depth = 1024;
    const int max_round = 100;
    struct test_iov r_iov[depth];
    struct test_iov w_iov[depth];
    VhostEvent events[depth];
    for (idx = 0; idx < depth; ++idx) {
        w_iov[idx].buf = (char*)libvhost_malloc(ctrl, buf_size);
        r_iov[idx].buf = (char*)libvhost_malloc(ctrl, buf_size);

        w_iov[idx].iov.iov_base = w_iov[idx].buf;
        w_iov[idx].iov.iov_len = buf_size;
        r_iov[idx].iov.iov_base = r_iov[idx].buf;
        r_iov[idx].iov.iov_len = buf_size;
    }

    for (round = 0; round < max_round; ++round) {
        printf("============== %d ==================\n", round);
        for (idx = 0; idx < depth; ++idx) {
            random_buf(w_iov[idx].buf, buf_size);
            libvhost_submit(ctrl, 0, (round * depth + idx) << 10, &w_iov[idx].iov, 1, true, NULL);
        }
        libvhost_getevents(ctrl, 0, depth, depth, events);
        for (idx = 0; idx < depth; ++idx) {
            libvhost_submit(ctrl, 0, (round * depth + idx) << 10, &r_iov[idx].iov, 1, false, NULL);
        }
        libvhost_getevents(ctrl, 0, depth, depth, events);
        for (idx = 0; idx < depth; ++idx) {
            if (0 != my_memcmp(w_iov[idx].buf, r_iov[idx].buf, buf_size)) {
                printf("req %d miscompare failed\n", idx);
                ret = -1;
                printf("wbuf: \n");
                DumpHex((void*)w_iov[idx].buf, 520);
                printf("rbuf: \n");
                DumpHex((void*)r_iov[idx].buf, 520);
                break;
            }
        }
    }
    for (idx = 0; idx < depth; ++idx) {
        libvhost_free(ctrl, w_iov[idx].buf);
        libvhost_free(ctrl, r_iov[idx].buf);
    }
    return ret;
}

static int test_blk(struct libvhost_ctrl* ctrl) {
    int ret;

    ret = test_sync_big_io(ctrl);
    if (ret != 0) {
        printf("test_sync_big_io failed: %d\n", ret);
        return ret;
    }

    ret = test_async_io(ctrl);
    if (ret != 0) {
        printf("vhost-blk async io failed\n");
        return ret;
    }

    ret = test_discard(ctrl);
    if (ret != 0) {
        printf("test_discard failed: %d\n", ret);
        return ret;
    }

    return 0;
}

static int test_scsi(struct libvhost_ctrl* ctrl) {
    int i;
    char *rbuf, *wbuf;
    int ret = 0;
    int buf_size = 4 << 20; // SPDK limits the io size to (4 << 20) / bdev_number_blocks

    wbuf = (char*)libvhost_malloc(ctrl, buf_size);
    CHECK(wbuf);
    rbuf = (char*)libvhost_malloc(ctrl, buf_size);
    CHECK(rbuf);

    random_buf(wbuf, buf_size);
    libvhost_write(ctrl, 0, 0 << 9, wbuf, buf_size);
    libvhost_read(ctrl, 0, 0 << 9, rbuf, buf_size);
    if (0 != my_memcmp(wbuf, rbuf, buf_size)) {
        printf("miscompare failed: %d\n", memcmp(wbuf, rbuf, buf_size));
        ret = -1;
        printf("wbuf: \n");
        DumpHex((void*)wbuf, 16);
        printf("rbuf: \n");
        DumpHex((void*)rbuf, 16);
        goto fail;
    }
    printf("vhost-scsi sync read write ok\n");

    ret = test_async_io(ctrl);
    if (ret != 0) {
        printf("vhost-scsi async io failed\n");
        goto fail;
    }
    printf("vhost-scsi async io ok\n");

fail:
    libvhost_free(ctrl, wbuf);
    libvhost_free(ctrl, rbuf);
    return ret;
}

static void print_usage() {
    printf("Usage: main -p <socket_path> [-s] [-t <target>] [-h]\n");
    printf("Options:\n");
    printf("  -p, Vhost controller socket path, required\n");
    printf("  -s, Create vhost scsi libvhost controller\n");
    printf("  -t, Specify the vhost scsi target number\n");
    printf("  -h, Display this help message\n");
}

#define PARSE_ARGS_EXIT(succ) \
    print_usage();  \
    exit(succ)

int main(int argc, char** argv) {
    struct libvhost_ctrl* ctrl;
    char *socket_path = NULL;
    int scsi = 0, target;
    int ret = 0;
    int opt;

    while ((opt = getopt(argc, argv, "p:st:h")) != -1) {
        switch (opt) {
            case 'p':
                socket_path = optarg;
                break;
            case 's':
                scsi = 1;
                break;
            case 't':
                target = atoi(optarg);
                break;
            case 'h':
                PARSE_ARGS_EXIT(EXIT_SUCCESS);
            case '?':
                fprintf(stderr, "Unknown option `-%c'.\n", optopt);
                PARSE_ARGS_EXIT(EXIT_FAILURE);
            default:
                PARSE_ARGS_EXIT(EXIT_FAILURE);
        }
    }
    if (socket_path == NULL) {
        fprintf(stderr, "Error: Socket path is required.\n");
        PARSE_ARGS_EXIT(EXIT_FAILURE);
    }

    ctrl = scsi ? libvhost_scsi_ctrl_create(socket_path, target) :
                  libvhost_ctrl_create(socket_path);
    if (!ctrl) {
        return 1;
    }

    if (!libvhost_ctrl_init_memory(ctrl, 1ULL << 30)) {
        printf("init memory failed\n");
        goto fail_ctrl;
    }
    ret = libvhost_ctrl_connect(ctrl);
    if (ret != 0) {
        printf("libvhost_ctrl_connect failed: %d\n", ret);
        goto fail_ctrl;
    }
    ret = libvhost_ctrl_setup(ctrl);
    if (ret != 0) {
        printf("libvhost_ctrl_setup failed: %d\n", ret);
        goto fail_ctrl;
    }

    ret = libvhost_ctrl_add_virtqueue(ctrl, 4, 1024);
    if (ret != 0) {
        printf("libvhost_ctrl_add_virtqueue failed: %d\n", ret);
        goto fail_ctrl;
    }

    ret = scsi ? test_scsi(ctrl) : test_blk(ctrl);

fail_ctrl:
    libvhost_ctrl_stop(ctrl);
    libvhost_ctrl_destroy(ctrl);
    return ret;
}
