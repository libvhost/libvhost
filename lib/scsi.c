/*
 * Copyright 2023 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "libvhost.h"
#include "libvhost_internal.h"
#include "scsi.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int scsi_add_req(struct libvhost_virt_queue* vq, struct libvhost_virtio_scsi_req* vbr,
                        struct iovec* data_iovs, int data_iovcnt, void* data, bool write) {
    int num_out = 0;
    int num_in = 0;
    int i;
    struct vring_desc* desc;
    struct iovec iovs[128];

    if (data_iovcnt > 128 - 2) {
        printf("Too many iovec in req: %d\n", data_iovcnt);
        exit(EXIT_FAILURE);
        return -1;
    }
    // put header.
    iovec_init(&iovs[num_out++], &vbr->out_hdr, sizeof(vbr->out_hdr));

    /* WRITE:[RD_req][RD_buf0]...[RD_bufN][WR_resp]
     * READ: [RD_req][WR_resp][WR_buf0]...[WR_bufN]
     */
    if (write) {
        for (i = 0; i < data_iovcnt; ++i) {
            iovs[num_out++] = data_iovs[i];
        }
        iovec_init(&iovs[num_out + num_in++], &vbr->resp, sizeof(vbr->resp));
    } else {
        iovec_init(&iovs[num_out + num_in++], &vbr->resp, sizeof(vbr->resp));
        for (i = 0; i < data_iovcnt; ++i) {
            iovs[num_out + num_in++] = data_iovs[i];
        }
    }

    virtring_add(vq, iovs, num_out, num_in, data);
    return 0;
}

void scsi_task_submit(struct libvhost_virt_queue* vq, struct libvhost_io_task* task, uint32_t len, uint16_t target) {
    struct libvhost_virtio_scsi_req* req = libvhost_malloc(task->vq->ctrl, sizeof(struct libvhost_virtio_scsi_req));
    bool is_write;

    task->priv = req;
    memset(req, 0, sizeof(struct virtio_scsi_cmd_req));
    make_lun(req->out_hdr.lun, target, 0);
    switch (task->type) {
        case VHOST_IO_READ_CAPACITY: {
            scsi_cdb_read_capacity_10 read_cap_cdb = {
                .command = 0x25,
                .lba = 0, /* LBA field shall be set to zero if the PMI bit is set to 0 and we always set 0 */
            };
            memcpy(req->out_hdr.cdb, &read_cap_cdb, sizeof(struct scsi_cdb_read_capacity_10));
            is_write = false;
            break;
        }
        case VHOST_IO_WRITE: {
            scsi_cdb_write_10 write10_cbd = { .command = 0x2a };
            to_be32(&write10_cbd.lba, task->offset >> 9);
            to_be16(&write10_cbd.xfer_length, len >> 9);
            memcpy(req->out_hdr.cdb, &write10_cbd, sizeof(struct scsi_cdb_write_10));
            is_write = true;
            break;
        }
        case VHOST_IO_READ: {
            scsi_cdb_read_10 read10cdb = { .command = 0x28 };
            to_be32(&read10cdb.lba, task->offset >> 9);
            to_be16(&read10cdb.xfer_length, len >> 9);
            memcpy(req->out_hdr.cdb, &read10cdb , sizeof(struct scsi_cdb_read_10));
            is_write = false;
            break;
        }
        default:
            printf("scsi_task_submit unknow io type\n");
            exit(EXIT_FAILURE);
    }
    scsi_add_req(vq, req, task->iovs, task->iovcnt, task, is_write);
}
