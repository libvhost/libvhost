/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef __LIBVHOST_H__
#define __LIBVHOST_H__

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>
#include <linux/virtio_blk.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

enum device_type {
    DEVICE_TYPE_BLK,
    DEVICE_TYPE_SCSI
};

struct libvhost_mem;
struct libvhost_ctrl;

/* vhost controller */
struct libvhost_ctrl* libvhost_ctrl_create(const char* path);
struct libvhost_ctrl* libvhost_scsi_ctrl_create(const char* path, uint16_t target);
void libvhost_ctrl_destroy(struct libvhost_ctrl* ctrl);
int libvhost_ctrl_connect(struct libvhost_ctrl* ctrl);
int libvhost_ctrl_setup(struct libvhost_ctrl* ctrl);
int libvhost_ctrl_stop(struct libvhost_ctrl* ctrl);
bool libvhost_ctrl_init_memory(struct libvhost_ctrl* ctrl, uint64_t mem_size);
int libvhost_ctrl_add_virtqueue(struct libvhost_ctrl* ctrl, int num_io_queues, int size);
// int vhost_ctrl_del_vq(struct libvhost_ctrl* ctrl);

uint64_t libvhost_ctrl_get_blocksize(struct libvhost_ctrl* ctrl);
int libvhost_ctrl_get_numblocks(struct libvhost_ctrl* ctrl);

/* io */
typedef struct VhostEvent {
    void* data;
    int res;
} VhostEvent;

/* sync io, couldn't use with async io. */
int libvhost_read(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, char* buf, int len);
int libvhost_write(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, char* buf, int len);
int libvhost_discard(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, int len);
int libvhost_write_zeroes(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, int len, bool unmap);
int libvhost_readv(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt);
int libvhost_writev(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt);

/* async io, couldn't use with sync io*/
int libvhost_submit(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt, bool write,
                    void* opaque);
int libvhost_getevents(struct libvhost_ctrl* ctrl, int q_idx, int min, int nr, VhostEvent* events);

void* libvhost_malloc(struct libvhost_ctrl* ctrl, uint64_t size);
void libvhost_free(struct libvhost_ctrl* ctrl, void* ptr);

#ifdef __cplusplus
}
#endif

#endif
