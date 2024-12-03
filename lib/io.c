/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/virtio_blk.h>

#include "libvhost.h"
#include "libvhost_internal.h"
#include "scsi.h"
#include "utils.h"

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

#define SENSE_STRING(sense_key) \
    case sense_key: \
        return #sense_key

static char* get_virtio_scsi_task_resp(struct virtio_scsi_cmd_resp* resp) {
    if (resp->response == VIRTIO_SCSI_S_OK && resp->status == CDB_STATUS_GOOD) {
        return "OK";
    }
    CHECK(resp->sense_len > 2);
    switch (resp->sense[2] & SCSI_SENSE_KEY_MASK) {
        SENSE_STRING(SCSI_SENSE_RECOVERED_ERROR);
        SENSE_STRING(SCSI_SENSE_NOT_READY);
        SENSE_STRING(SCSI_SENSE_MEDIUM_ERROR);
        SENSE_STRING(SCSI_SENSE_HARDWARE_ERROR);
        SENSE_STRING(SCSI_SENSE_ILLEGAL_REQUEST);
        SENSE_STRING(SCSI_SENSE_UNIT_ATTENTION);
        SENSE_STRING(SCSI_SENSE_DATA_PROTECT);
        SENSE_STRING(SCSI_SENSE_BLANK_CHECK);
        SENSE_STRING(SCSI_SENSE_VENDOR_SPECIFIC);
        SENSE_STRING(SCSI_SENSE_COPY_ABORTED);
        SENSE_STRING(SCSI_SENSE_ABORTED_COMMAND);
        SENSE_STRING(SCSI_SENSE_VOLUME_OVERFLOW);
        SENSE_STRING(SCSI_SENSE_MISCOMPARE);
        default:
            ERROR("UNKNOWN response: %d\n", resp->sense[2] & SCSI_SENSE_KEY_MASK);
            return "UNKNOWN";
    }
}

static int task_done(void* opaque) {
    struct libvhost_io_task* task = opaque;

    task->finished = true;

    if (task->vq->ctrl->type == DEVICE_TYPE_BLK) {
        struct libvhost_virtio_blk_req* req = task->priv;
        DEBUG("[TASK DONE] offset: 0x%" PRIx64
            ", type: %d, iovcnt: %d, queue index: %d, priv: %p status: "
            "%s task: %p\n",
            task->offset, task->type, task->iovcnt, task->q_idx, task->priv,
            get_virtio_task_status(req->status), task);
    } else if (task->vq->ctrl->type == DEVICE_TYPE_SCSI) {
        struct libvhost_virtio_scsi_req* req = task->priv;
        DEBUG("[TASK DONE] offset: 0x%" PRIx64
            ", type: %d, iovcnt: %d, queue index: %d, priv: %p, "
            "response: %s, task: %p\n",
            task->offset, task->type, task->iovcnt, task->q_idx, task->priv,
            get_virtio_scsi_task_resp(&req->resp), task);
    }

    return 0;
}

static int task_getevents(struct libvhost_virt_queue* vq, struct libvhost_io_task** out_task) {
    return virtqueue_get(vq, out_task);
}

static int libvhost_readwritev(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt,
                               enum libvhost_io_type type, bool async, void* opaque) {
    struct libvhost_io_task* task;
    struct libvhost_io_task* out_task;
    struct libvhost_virt_queue* vq;

    if (ctrl->type == DEVICE_TYPE_SCSI) {
        /* spdk use at least the 3rd vq for scsi */
        q_idx = q_idx + 2;
    }

    vq = &ctrl->vqs[q_idx];
    task = virtqueue_get_task(vq);
    if (!task) {
        printf("NO MORE TASK\n");
        exit(EXIT_FAILURE);
        return -1;
    }
    CHECK(task->finished == false);
    task->cb = task_done;
    task->opaque = opaque;
    // TODO: check the offset, len that should be aligned to 512/4k block size.
    task->offset = offset;
    memcpy(task->iovs, iov, sizeof(struct iovec) * iovcnt);
    task->iovcnt = iovcnt;
    task->q_idx = q_idx;
    task->type = type;

    if (ctrl->type == DEVICE_TYPE_BLK) {
        blk_task_submit(vq, task);
    } else if (ctrl->type == DEVICE_TYPE_SCSI) {
        scsi_task_submit(vq, task, iov->iov_len, ctrl->scsi_config->target);
    } else {
        ERROR("UNKNOWN DEVICE TYPE\n");
        return -1;
    }

    if (async) {
        return 0;
    }

    while (!task->finished) {
        if (task_getevents(vq, &out_task) == 0) {
            continue;
        }
        if (task != out_task) {
            virtqueue_free_task(out_task);
            printf("[WARN] io is out-of-order, task: %p, out_task: %p\n", task, out_task);
        }
    }
    virtqueue_free_task(task);
    return 0;
}


static int libvhost_discard_write_zeroes(struct libvhost_ctrl* ctrl, int q_idx,
                                         uint64_t offset, struct iovec* iov, int iovcnt,
                                         enum libvhost_io_type type, void* opaque) {
    struct libvhost_io_task* task;
    struct libvhost_io_task* out_task;
    struct libvhost_virt_queue* vq = &ctrl->vqs[q_idx];
    task = virtqueue_get_task(vq);
    if (!task) {
        printf("NO MORE TASK\n");
        exit(EXIT_FAILURE);
        return -1;
    }
    CHECK(type <= 4);
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
        if (task_getevents(vq, &out_task) == 0) {
            continue;
        }
        if (task != out_task) {
            virtqueue_free_task(out_task);
            printf("[WARN] io is out-of-order, task: %p, out_task: %p\n", task, out_task);
        }
    }
    virtqueue_free_task(task);
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
    return libvhost_readwritev(ctrl, q_idx, offset, &iov, 1, VHOST_IO_READ, false, NULL);
}

int libvhost_write(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, char* buf, int len) {
    struct iovec iov = {.iov_base = buf, .iov_len = len};
    return libvhost_readwritev(ctrl, q_idx, offset, &iov, 1, VHOST_IO_WRITE, false, NULL);
}

int libvhost_readv(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt) {
    return libvhost_readwritev(ctrl, q_idx, offset, iov, iovcnt, VHOST_IO_READ, false, NULL);
}

int libvhost_writev(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt) {
    return libvhost_readwritev(ctrl, q_idx, offset, iov, iovcnt, VHOST_IO_WRITE, false, NULL);
}

int libvhost_submit(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt, bool write,
                    void* opaque) {
    return libvhost_readwritev(ctrl, q_idx, offset, iov, iovcnt, write ? VHOST_IO_WRITE : VHOST_IO_READ, true, opaque);
}

int libvhost_getevents(struct libvhost_ctrl* ctrl, int q_idx, int nr, VhostEvent* events) {
    int done = 0;
    int ret = 0;
    int i;
    struct libvhost_io_task* done_tasks[VIRTIO_MAX_IODEPTH];

    q_idx = ctrl->type == DEVICE_TYPE_BLK ? q_idx : q_idx + 2;

    while (done < nr) {
        ret = task_getevents(&ctrl->vqs[q_idx], &done_tasks[done]);
        if (ret == 0) {
            continue;
        }
        done += ret;
        CHECK(done_tasks[done - 1]->finished == true);
    }
    for (i = 0; i < done; i++) {
        events[i].data = done_tasks[i]->opaque;
        events[i].res = (ctrl->type == DEVICE_TYPE_BLK ?
                         ((struct libvhost_virtio_blk_req*)done_tasks[i]->priv)->status :
                         ((struct libvhost_virtio_scsi_req*)done_tasks[i]->priv)->resp.status);
        virtqueue_free_task(done_tasks[i]);
    }
    return done;
}

void libvhost_scsi_read_capacity(struct libvhost_ctrl* ctrl) {
    struct iovec iov;
    char *rcap_buf = NULL;

    rcap_buf = (char*)libvhost_malloc(ctrl, 8);
    CHECK(rcap_buf);
    memset(rcap_buf, 0, 8);

    iov.iov_base = rcap_buf;
    iov.iov_len = 8;
    libvhost_readwritev(ctrl, 0, 0, &iov, 1, VHOST_IO_READ_CAPACITY, false, NULL);
    ctrl->scsi_config->num_blocks = from_be32(rcap_buf) + 1;
    ctrl->scsi_config->block_size = from_be32(rcap_buf + 4);

    DEBUG("scsi device(%s) num blocks(%u), block size(%u)\n",
          ctrl->sock_path, ctrl->scsi_config->num_blocks, ctrl->scsi_config->block_size);
}
