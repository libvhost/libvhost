#ifndef _VIRT_QUEUE_H_
#define _VIRT_QUEUE_H_

#include <linux/virtio_blk.h>
#include <linux/virtio_ring.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <inttypes.h>

#include "vhost_user_spec.h"

#define rmb() __asm volatile("" ::: "memory")
#define wmb() __asm volatile("" ::: "memory")

#define VIRTIO_MAX_IODEPTH 256

enum libvhost_io_type {
    VHOST_IO_READ,
    VHOST_IO_WRITE,
    VHOST_IO_FLUSH,
};

typedef int (*VhostIOCB)(void* task);
struct libvhost_io_task {
    struct libvhost_ctrl* ctrl;
    uint64_t offset;  // align to sector size.
    enum libvhost_io_type type;
    struct iovec iovs[128];
    int iovcnt;
    int q_idx;
    bool used;
    VhostIOCB cb;

    // struct libvhost_virtio_blk_req or SCSIReq;
    void* priv;
    bool finished;

    // user data.
    void* opaque;
};

struct libvhost_virt_queue {
    struct libvhost_ctrl* ctrl;
    int idx;
    int size;
    /* Must be [0, 2^16 - 1] */
    uint16_t last_used_idx;
    int kickfd;
    int callfd;

    struct vring vring;
    /* next free head in desc table */
    uint16_t free_head;
    uint16_t num_free;

    struct libvhost_io_task tasks[VIRTIO_MAX_IODEPTH];
    void* desc_state[VIRTIO_MAX_IODEPTH];
};

void vhost_vq_init(struct libvhost_virt_queue* vq, struct libvhost_ctrl* ctrl);
void virtring_add(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in, void* data);
struct libvhost_io_task* virtring_get_free_task(struct libvhost_virt_queue* vq);
void virtring_free_task(struct libvhost_io_task* task);

void virtqueue_kick(struct libvhost_virt_queue* vq);
int virtqueue_get(struct libvhost_virt_queue* vq, struct libvhost_io_task** out_task);

int libvhost_mem_get_memory_fds(struct libvhost_ctrl* ctrl, int* fds, int* size);

int vhost_ioctl(struct libvhost_ctrl* ctrl, enum libvhost_user_msg_type req, void* arg);

struct libvhost_virtio_blk_req {
    struct virtio_blk_outhdr out_hdr;
    uint8_t status;
};

void blk_task_submit(struct libvhost_virt_queue* vq, struct libvhost_io_task* task);
int blk_task_getevents(struct libvhost_virt_queue* vq, struct libvhost_io_task** out_task);

#endif