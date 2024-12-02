/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "libvhost_internal.h"
#include "libvhost.h"
#include "utils.h"
#include <linux/virtio_blk.h>
#include <linux/virtio_ring.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define VIRTIO_PCI_VRING_ALIGN 4096

void vhost_vq_init(struct libvhost_virt_queue* vq, struct libvhost_ctrl* ctrl) {
    uint64_t desc_table_len;
    uint64_t avail_table_len;
    uint64_t used_table_len;
    uint64_t total_size;
    uint64_t size_aligned;
    void* q_mem;
    int i;

    CHECK(ctrl);

    vq->ctrl = ctrl;

    vq->kickfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    vq->callfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);

    vq->desc_state = calloc(sizeof(void*), vq->size);

    size_aligned = vring_size(vq->size, VIRTIO_PCI_VRING_ALIGN);
    q_mem = libvhost_malloc(ctrl, size_aligned);
    vring_init(&vq->vring, vq->size, q_mem, VIRTIO_PCI_VRING_ALIGN);
    vq->num_free = vq->size;
    vq->free_head = 0;
    /* Set the default next to the slinbling. */
    for (i = 0; i < vq->vring.num - 1; i++) {
        vq->vring.desc[i].next = i + 1;
    }
    vq->vring.desc[i].next = 0;
}


void vhost_vq_free(struct libvhost_virt_queue* vq) {
    free(vq->desc_state);
    close(vq->kickfd);
    close(vq->callfd);
}

static void virtio_get_flags_name(uint16_t flags, char name[16]) {
    int i = 0;
    int j = 0;
    for (; i < 16; ++i) {
        if (flags & (1 << i)) {
            switch (flags & (1 << i)) {
                case VIRTIO_RING_F_INDIRECT_DESC:
                    name[j++] = 'I';
                    break;
                case VRING_DESC_F_NEXT:
                    name[j++] = 'N';
                    break;
                case VRING_DESC_F_WRITE:
                    name[j++] = 'W';
                    break;
                default:
                    name[j++] = 'U';
                    break;
            }
            if (j == 15) {
                break;
            }
        }
    }
    name[j] = '\0';
}

void virtring_add(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in, void* data) {
    struct vring_desc* desc = vq->vring.desc;
    int i;
    int n;
    int last_n;
    uint16_t avail;
    uint16_t head = vq->free_head;
    char flags_name[16] = {0};

    DEBUG("[VIRTIO] avail add idx: %d num_free: %d\n", head, vq->num_free);
    if (vq->num_free < num_out + num_in) {
        ERROR("[VIRTIO] avail add failed: %d\n", vq->num_free);
        exit(EXIT_FAILURE);
        return;
    }

    n = head;
    for (i = 0; i < num_out; ++i) {
        desc[n].flags = VRING_DESC_F_NEXT;
        desc[n].addr = (uint64_t)iovec[i].iov_base;
        desc[n].len = iovec[i].iov_len;
        virtio_get_flags_name(desc[n].flags, flags_name);
        DEBUG("    item %2d addr %p len 0x%-10" PRIx64 " flags %s\n", n, iovec[i].iov_base, iovec[i].iov_len,
              flags_name);
        last_n = n;
        n = desc[n].next;
    }
    for (i = num_out; i < num_out + num_in; ++i) {
        desc[n].flags = VRING_DESC_F_NEXT | VRING_DESC_F_WRITE;
        desc[n].addr = (uint64_t)iovec[i].iov_base;
        desc[n].len = iovec[i].iov_len;

        virtio_get_flags_name(desc[n].flags, flags_name);
        DEBUG("    item %2d addr %p len 0x%-10" PRIx64 " flags %s\n", n, iovec[i].iov_base, iovec[i].iov_len,
              flags_name);
        last_n = n;
        n = desc[n].next;
    }
    desc[last_n].flags &= ~VRING_DESC_F_NEXT;
    vq->num_free -= (num_out + num_in);
    vq->free_head = n;

    vq->desc_state[head] = data;

    // Fill the avail ring.
    avail = vq->vring.avail->idx & (vq->vring.num - 1);
    vq->vring.avail->ring[avail] = head;
    wmb();
    vq->vring.avail->idx++;
    wmb();
}

static inline bool more_used(const struct libvhost_virt_queue* vq) {
    rmb();
    // NOTICE: the shared used->idx range is [0, 2^16 -1], not [0, ring_num - 1];
    return vq->last_used_idx != vq->vring.used->idx;
}

static void reset_desc(struct libvhost_virt_queue* vq, uint16_t head) {
    uint16_t id = head;
    // reset the desc;
    while (vq->vring.desc[id].flags & VRING_DESC_F_NEXT) {
        id = vq->vring.desc[id].next;
        vq->num_free++;
    }
    vq->vring.desc[id].next = vq->free_head;
    vq->free_head = head;

    /* Plus final descriptor */
    vq->num_free++;
}

int virtqueue_get(struct libvhost_virt_queue* vq, struct libvhost_io_task** out_task) {
    uint16_t id;
    uint16_t last_used;
    uint32_t len;
    struct libvhost_io_task* task;
    if (!more_used(vq)) {
        return 0;
    }
    DEBUG("last_used_idx: %d, used->idx: %d\n", vq->last_used_idx, vq->vring.used->idx);
    rmb();
    last_used = vq->last_used_idx & (vq->vring.num - 1);
    id = vq->vring.used->ring[last_used].id;
    len = vq->vring.used->ring[last_used].len;
    task = vq->desc_state[id];
    if (!task) {
        ERROR("task is null, bug here\n");
        exit(EXIT_FAILURE);
    }
    // clear the desc_state to avoid info leak;
    vq->desc_state[id] = NULL;
    DEBUG(
        "[VIRTIO] USED RING last_used_idx: %d, last_used: %d, req id: %d len: "
        "%d task: %p used: %d\n",
        vq->last_used_idx, last_used, id, len, task, task->used);
    task->cb(task);

    reset_desc(vq, id);

    vq->last_used_idx++;
    *out_task = task;
    return 1;
}

struct libvhost_io_task* virtring_get_free_task(struct libvhost_virt_queue* vq) {
    int i;
    for (i = 0; i < sizeof(vq->tasks) / sizeof(vq->tasks[0]); ++i) {
        struct libvhost_io_task* task = &vq->tasks[i];
        if (!task->used) {
            task->used = true;
            task->ctrl = vq->ctrl;
            DEBUG("get free task: %p, id: %d\n", task, i);
            return task;
        }
    }
    return NULL;
}

void virtring_free_task(struct libvhost_io_task* task) {
    libvhost_free(task->ctrl, task->priv);
    memset(task, 0, sizeof(*task));
    // printf("xxx free task: %p\n", task);
}

void virtqueue_kick(struct libvhost_virt_queue* vq) {
    uint64_t kick_value = 1;
    printf("kick vq %d\n", vq->idx);
    write(vq->kickfd, &kick_value, sizeof(kick_value));
}
