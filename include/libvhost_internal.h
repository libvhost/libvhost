/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef _VIRT_QUEUE_H_
#define _VIRT_QUEUE_H_

#include <linux/virtio_blk.h>
#include <linux/virtio_scsi.h>
#include <linux/virtio_ring.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <inttypes.h>

#include "libvhost.h"
#include "vhost_user_spec.h"

#if defined(__x86_64__)
#define rmb() __asm volatile("" ::: "memory")
#define wmb() __asm volatile("" ::: "memory")
#else
#define rmb() asm volatile("dmb ishld" : : : "memory")
#define wmb() asm volatile("dmb ishst" : : : "memory")
#endif

#define VIRTIO_MAX_IODEPTH 256
struct vhost_inflight {
    int fd;
    void* addr;
    uint64_t size;
    uint64_t offset;
    uint16_t queue_size;
};

struct libvhost_scsi_config {
    struct virtio_scsi_config* config;
    uint32_t num_blocks;
    uint32_t block_size;
    uint16_t target;
};

struct libvhost_ctrl {
    char* sock_path;
    int status;
    int sock;
    int epollfd;
    uint64_t features;
    uint64_t protocol_features;
    struct libvhost_virt_queue* vqs;
    int nr_vqs;
    pthread_t thread;
    struct vhost_inflight inflight;
    struct libvhost_mem* mem;
    bool stopped;
    enum device_type type;

    union {
        struct virtio_blk_config* blk_config;
        struct libvhost_scsi_config* scsi_config;
    };
};

enum libvhost_io_type {
    VHOST_IO_READ,
    VHOST_IO_WRITE,
    VHOST_IO_FLUSH,
    VHOST_IO_DISCARD,
    VHOST_IO_WRITE_ZEROES,
    VHOST_IO_READ_CAPACITY,
};

typedef int (*VhostIOCB)(void* task);
struct libvhost_io_task {
    struct libvhost_virt_queue* vq;
    uint64_t offset;  // align to sector size.
    struct iovec iovs[128];
    enum libvhost_io_type type;
    int iovcnt;
    int num_add;
    int q_idx;
    VhostIOCB cb;
    struct vring_packed_desc* indir_desc;

    // struct libvhost_virtio_blk_req or SCSIReq;
    void* priv;

    // user data.
    void* opaque;

    struct libvhost_io_task* next;
};

struct vring_virtqueue_packed {
    struct {
        struct vring_packed_desc* desc;
        struct vring_packed_desc_event* driver;
        struct vring_packed_desc_event* device;
    } vring;

    /* Avail used flags. */
    uint16_t avail_used_flags;

    /* Index of the next avail descriptor. */
    uint16_t next_avail_idx;
};

struct libvhost_virt_queue {
    struct libvhost_ctrl* ctrl;
    int idx;
    int size;

    /* Last used index  we've seen.
     * for split ring, it just contains last used index
     * for packed ring:
     * bits up to VRING_PACKED_EVENT_F_WRAP_CTR include the last used index.
     * bits from VRING_PACKED_EVENT_F_WRAP_CTR include the used wrap counter.
     */
    uint16_t last_used_idx;

    /* Host supports indirect buffers */
    bool indirect;

    /* Is this a packed ring? */
    bool packed_ring;

    int kickfd;
    int callfd;

    union {
        struct vring vring;
        struct vring_virtqueue_packed packed;
    };

    /* next free head in desc table */
    uint16_t free_head;
    uint16_t num_free;

    struct libvhost_io_task free_list;
    void** desc_state;
};

void vhost_create_virtqueue(struct libvhost_virt_queue* vq, struct libvhost_ctrl* ctrl);
void vhost_free_vq(struct libvhost_virt_queue* vq);
struct libvhost_io_task* virtqueue_get_task(struct libvhost_virt_queue* vq);
void virtqueue_free_task(struct libvhost_io_task* task);

void virtring_add(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in, void* data);
void virtring_add_packed(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in, void* data);
void virtqueue_add(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in, void* data);

void virtqueue_kick(struct libvhost_virt_queue* vq);

int virtqueue_get(struct libvhost_virt_queue* vq, VhostEvent* event);
int virtring_get_packed(struct libvhost_virt_queue* vq, VhostEvent* event);
int virtring_get_split(struct libvhost_virt_queue* vq, VhostEvent* event);

int libvhost_mem_get_memory_fds(struct libvhost_ctrl* ctrl, int* fds, int* size);

int vhost_ioctl(struct libvhost_ctrl* ctrl, enum libvhost_user_msg_type req, void* arg);

struct libvhost_virtio_blk_req {
    struct virtio_blk_outhdr out_hdr;
    uint8_t status;
};

struct libvhost_virtio_scsi_req {
    struct virtio_scsi_cmd_req out_hdr;
    struct virtio_scsi_cmd_resp resp;
};

void blk_task_submit(struct libvhost_virt_queue* vq, struct libvhost_io_task* task);
void scsi_task_submit(struct libvhost_virt_queue* vq, struct libvhost_io_task* task, uint32_t len, uint16_t target);

void libvhost_scsi_read_capacity(struct libvhost_ctrl* ctrl);
#endif
