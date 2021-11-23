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
    const int depth = 128;
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
        libvhost_getevents(ctrl, 0, depth, events);
        for (idx = 0; idx < depth; ++idx) {
            libvhost_submit(ctrl, 0, (round * depth + idx) << 10, &r_iov[idx].iov, 1, false, NULL);
        }
        libvhost_getevents(ctrl, 0, depth, events);
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

int main(int argc, char** argv) {
    int ret = 0;
    int i;
    if (argc != 2) {
        printf("Usage: %s <socket_path>\n", argv[0]);
        return 1;
    }

    struct libvhost_ctrl* ctrl = libvhost_ctrl_create(argv[1]);
    if (!ctrl) {
        goto fail_ctrl;
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

    ret = libvhost_ctrl_add_virtqueue(ctrl, 1024);
    if (ret != 0) {
        printf("libvhost_ctrl_add_virtqueue failed: %d\n", ret);
        goto fail_ctrl;
    }
    // ret = vhost_ctrl_add_vq(conn, 32);
    // if (ret != 0) {
    //   printf("vhost_ctrl_add_vq failed: %d\n", ret);
    //   return -1;
    // }

    // ret = test_sync_io(conn);
    // if (ret != 0) {
    //   printf("test_sync_io failed: %d\n", ret);
    //   goto fail_conn;
    // }

    ret = test_sync_big_io(ctrl);
    if (ret != 0) {
        printf("test_sync_big_io failed: %d\n", ret);
        goto fail_ctrl;
    }

fail_ctrl:
    libvhost_ctrl_destroy(ctrl);
    return ret;
}
