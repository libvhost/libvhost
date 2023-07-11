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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/virtio_blk.h>
#include "libvhost.h"
#include "libvhost_internal.h"

static char* get_virtio_task_status(int status) {
    switch (status) {
        case VIRTIO_BLK_S_OK:
            return "OK";
        case VIRTIO_BLK_S_IOERR:
            return "IOERR";
        case VIRTIO_BLK_S_UNSUPP:
            return "UNSUPP";
        default:
            return "UNKNOWN";
    }
}

static int task_done(void* opaque) {
    struct libvhost_io_task* task = opaque;
    task->finished = true;

    struct libvhost_virtio_blk_req* req = task->priv;

    DEBUG("[TASK DONE] offset: 0x%" PRIx64
          ", type: %d, iovcnt: %d, queue index: %d, used: %d, priv: %p status: "
          "%s task: %p\n",
          task->offset, task->type, task->iovcnt, task->q_idx, task->used, task->priv,
          get_virtio_task_status(req->status), task);
    return 0;
}

static int libvhost_readwritev(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt,
                               bool write, bool async, void* opaque) {
    struct libvhost_io_task* task;
    struct libvhost_io_task* out_task;
    struct libvhost_virt_queue* vq = &ctrl->vqs[q_idx];
    task = virtring_get_free_task(vq);
    if (!task) {
        printf("NO MORE TASK\n");
        exit(EXIT_FAILURE);
        return -1;
    }
    CHECK(task->used == true);
    CHECK(task->finished == false);
    task->cb = task_done;
    task->opaque = opaque;
    // TODO: check the offset, len that should be aligned to 512/4k block size.
    task->offset = offset;
    memcpy(task->iovs, iov, sizeof(struct iovec) * iovcnt);
    task->iovcnt = iovcnt;
    task->q_idx = q_idx;
    if (write) {
        task->type = VHOST_IO_WRITE;
    } else {
        task->type = VHOST_IO_READ;
    }
    blk_task_submit(vq, task);
    if (async) {
        return 0;
    }

    while (!task->finished) {
        if (blk_task_getevents(vq, &out_task) == 0) {
            continue;
        }
        if (task != out_task) {
            virtring_free_task(out_task);
            printf("[WARN] io is out-of-order, task: %p, out_task: %p\n", task, out_task);
        }
    }
    virtring_free_task(task);
    return 0;
}


static int libvhost_discard_write_zeroes(struct libvhost_ctrl* ctrl, int q_idx,
                                         uint64_t offset, struct iovec* iov, int iovcnt,
                                         enum libvhost_io_type type, void* opaque) {
    struct libvhost_io_task* task;
    struct libvhost_io_task* out_task;
    struct libvhost_virt_queue* vq = &ctrl->vqs[q_idx];
    task = virtring_get_free_task(vq);
    if (!task) {
        printf("NO MORE TASK\n");
        exit(EXIT_FAILURE);
        return -1;
    }
    CHECK(task->used == true);
    CHECK(task->finished == false);
    task->cb = task_done;
    task->opaque = opaque;
    // TODO: check the offset, len that should be aligned to 512/4k block size.
    task->offset = offset;
    memcpy(task->iovs, iov, sizeof(struct iovec) * iovcnt);
    task->iovcnt = iovcnt;
    task->q_idx = q_idx;
    task->type = type;

    blk_task_submit(vq, task);

    while (!task->finished) {
        if (blk_task_getevents(vq, &out_task) == 0) {
            continue;
        }
        if (task != out_task) {
            virtring_free_task(out_task);
            printf("[WARN] io is out-of-order, task: %p, out_task: %p\n", task, out_task);
        }
    }
    virtring_free_task(task);
    return 0;
}

typedef struct virtio_blk_discard_write_zeroes vb_dwz;

int libvhost_discard(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, int len) {
    vb_dwz* discard_buf = (vb_dwz*)libvhost_malloc(ctrl, sizeof(vb_dwz));
    CHECK(discard_buf);
    discard_buf->sector = offset >> 9;
    discard_buf->num_sectors = len >> 9;
    discard_buf->flags = 0;

    struct iovec iov = {.iov_base = discard_buf, .iov_len = sizeof(vb_dwz)};
    return libvhost_discard_write_zeroes(ctrl, q_idx, offset, &iov, 1, VHOST_IO_DISCARD, NULL);
}

int libvhost_write_zeroes(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, int len, bool unmap) {
    vb_dwz* discard_buf = (vb_dwz*)libvhost_malloc(ctrl, sizeof(vb_dwz));
    CHECK(discard_buf);
    discard_buf->sector = offset >> 9;
    discard_buf->num_sectors = len >> 9;
    discard_buf->flags = (unmap ? VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP : 0);

    struct iovec iov = {.iov_base = discard_buf, .iov_len = sizeof(vb_dwz)};
    return libvhost_discard_write_zeroes(ctrl, q_idx, offset, &iov, 1, VHOST_IO_WRITE_ZEROES, NULL);
}

int libvhost_read(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, char* buf, int len) {
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    return libvhost_readwritev(ctrl, q_idx, offset, &iov, 1, false, false, NULL);
}

int libvhost_write(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, char* buf, int len) {
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    return libvhost_readwritev(ctrl, q_idx, offset, &iov, 1, true, false, NULL);
}

int libvhost_readv(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt) {
    return libvhost_readwritev(ctrl, q_idx, offset, iov, iovcnt, false, false, NULL);
}

int libvhost_writev(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt) {
    return libvhost_readwritev(ctrl, q_idx, offset, iov, iovcnt, true, false, NULL);
}

int libvhost_submit(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt, bool write,
                    void* opaque) {
    return libvhost_readwritev(ctrl, q_idx, offset, iov, iovcnt, write, true, opaque);
}

int libvhost_getevents(struct libvhost_ctrl* ctrl, int q_idx, int nr, VhostEvent* events) {
    int done = 0;
    int ret = 0;
    int i;
    struct libvhost_io_task* done_tasks[VIRTIO_MAX_IODEPTH];
    while (done < nr) {
        ret = blk_task_getevents(&ctrl->vqs[q_idx], &done_tasks[done]);
        if (ret == 0) {
            continue;
        }
        done += ret;
        CHECK(done_tasks[done - 1]->used == true);
        CHECK(done_tasks[done - 1]->finished == true);
    }
    for (i = 0; i < done; i++) {
        events[i].data = done_tasks[i]->opaque;
        events[i].res = ((struct libvhost_virtio_blk_req*)done_tasks[i]->priv)->status;
        virtring_free_task(done_tasks[i]);
    }
    return done;
}
