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

#define VQ_CALLOC(ctrl, vq, type)                  \
    ({                                             \
        size_t size = (vq)->size * sizeof(type);   \
        void* mem = libvhost_malloc((ctrl), size); \
        CHECK(mem);                                \
        memset(mem, 0, size);                      \
        (type*)mem;                                \
    })

static void virtqueue_init(struct libvhost_virt_queue* vq, struct libvhost_ctrl* ctrl) {
    int i;

    vq->ctrl = ctrl;
    vq->kickfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    vq->callfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    vq->num_free = vq->size;
    vq->free_head = 0;
    vq->desc_state = calloc(sizeof(void*), vq->size);
    vq->indirect = (ctrl->features & (1ULL << VIRTIO_RING_F_INDIRECT_DESC));

    vq->free_list.next = NULL;
    for (i = 0; i < vq->size; ++i) {
        struct libvhost_io_task* task = calloc(1, sizeof(*task));
        task->next = vq->free_list.next;
        vq->free_list.next = task;
    }
}

static void vhost_vq_init_split(struct libvhost_virt_queue* vq, struct libvhost_ctrl* ctrl) {
    uint64_t desc_table_len;
    uint64_t avail_table_len;
    uint64_t used_table_len;
    uint64_t total_size;
    uint64_t size_aligned;
    void* q_mem;
    int i;

    size_aligned = vring_size(vq->size, VIRTIO_PCI_VRING_ALIGN);
    q_mem = libvhost_malloc(ctrl, size_aligned);
    vring_init(&vq->vring, vq->size, q_mem, VIRTIO_PCI_VRING_ALIGN);

    /* Set the default next to the slinbling. */
    for (i = 0; i < vq->vring.num - 1; i++) {
        vq->vring.desc[i].next = i + 1;
    }
    vq->vring.desc[i].next = 0;

    virtqueue_init(vq, ctrl);
}

static void vhost_vq_init_packed(struct libvhost_virt_queue* vq, struct libvhost_ctrl* ctrl) {
    size_t size;
    void* q_mem;

    vq->packed_ring = true;

    // alloc packed ring memory
    vq->packed.vring.desc = VQ_CALLOC(ctrl, vq, struct vring_packed_desc);
    vq->packed.next_avail_idx = 0;
    vq->packed.avail_used_flags = 1 << VRING_PACKED_DESC_F_AVAIL;
    vq->last_used_idx = 0 | (1 << VRING_PACKED_EVENT_F_WRAP_CTR);

    // alloc event memory
    vq->packed.vring.driver = VQ_CALLOC(ctrl, vq, struct vring_packed_desc_event);
    // Tell other side not to bother us
    vq->packed.vring.driver->flags = VRING_PACKED_EVENT_FLAG_DISABLE;

    vq->packed.vring.device = VQ_CALLOC(ctrl, vq, struct vring_packed_desc_event);

    virtqueue_init(vq, ctrl);
}

void vhost_create_virtqueue(struct libvhost_virt_queue* vq, struct libvhost_ctrl* ctrl) {
    CHECK(ctrl);

    if (ctrl->features & (1ULL << VIRTIO_F_RING_PACKED)) {
        vhost_vq_init_packed(vq, ctrl);
    } else {
        vhost_vq_init_split(vq, ctrl);
    }
}

void vhost_free_vq(struct libvhost_virt_queue* vq) {
    int i;
    free(vq->desc_state);
    close(vq->kickfd);
    close(vq->callfd);

    struct libvhost_io_task* task = vq->free_list.next;
    while(task) {
        struct libvhost_io_task* next = task->next;
        free(task);
        task = next;
    }
}

static void virtio_get_flags_name(uint16_t flags, char name[16]) {
    int i = 0;
    int j = 0;

    for (; i < 16; ++i) {
        if (flags & (1 << i)) {
            switch (i) {
                case (VRING_DESC_F_NEXT - 1):
                    name[j++] = 'N';
                    break;
                case (VRING_DESC_F_WRITE - 1):
                    name[j++] = 'W';
                    break;
                case (VRING_DESC_F_INDIRECT - 1):
                    name[j++] = 'I';
                    break;
                case VRING_PACKED_DESC_F_AVAIL:
                    name[j++] = 'A';
                    break;
                case VRING_PACKED_DESC_F_USED:
                    name[j++] = 'U';
                    break;
                default:
                    break;
            }
            if (j == 15) {
                break;
            }
        }
    }
    name[j] = '\0';
}

static struct vring_desc *alloc_indirect_split(struct libvhost_virt_queue* vq, unsigned int size) {
    struct vring_desc *desc;
    unsigned int i;

    desc = libvhost_malloc(vq->ctrl, size * sizeof(struct vring_desc));
    if (!desc)
        return NULL;

    memset(desc, 0, size * sizeof(struct vring_desc));
    for (i = 0; i < size; i++)
        desc[i].next = (__virtio16)(i + 1);
    return desc;
}

void virtring_add(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in, void* data) {
    struct vring_desc* desc;
    int i, j;
    int n;
    int last_n;
    uint16_t avail;
    uint16_t head = vq->free_head;
    char flags_name[16] = {0};
    bool indirect;
    uint16_t descs_used;

    /* Use the indirect vring only if the number of iov greater than 1 */
    if (vq->indirect && num_in + num_out > 1) {
        desc = alloc_indirect_split(vq, num_in + num_out);
    } else {
        desc = NULL;
    }
    if (desc) {
        /* Use a single buffer which doesn't continue */
        indirect = true;
        /* Set up rest to use this indirect table */
        i = 0;
        descs_used = 1;
    } else {
        indirect = false;
        desc = vq->vring.desc;
        i = head;
        descs_used = num_in + num_out;
    }

    DEBUG("[VIRTIO] avail add idx: %d num_free: %d\n", head, vq->num_free);
    if (vq->num_free < descs_used) {
        ERROR("[VIRTIO] avail add failed: %d %d\n", vq->num_free, descs_used);
        exit(EXIT_FAILURE);
        return;
    }

    n = i;
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
    if (indirect) {
    	/* Now that the indirect table is filled in, map it. */
        vq->vring.desc[head].flags = VRING_DESC_F_INDIRECT;
        vq->vring.desc[head].addr = (uint64_t)desc;
        vq->vring.desc[head].len = (num_in + num_out) * sizeof(struct vring_desc);
        virtio_get_flags_name(desc[n].flags, flags_name);
        DEBUG("    item %2d addr %p len 0x%-10" PRIx64 " flags %s\n", head, desc,
              (num_in + num_out) * sizeof(struct vring_desc),
              flags_name);
        n = vq->vring.desc[head].next;
    }
    /* We're using some buffers from the free list. */
    vq->num_free -= descs_used;
    /* Update free pointer */
    vq->free_head = n;

    vq->desc_state[head] = data;

    // Fill the avail ring.
    avail = vq->vring.avail->idx & (vq->vring.num - 1);
    vq->vring.avail->ring[avail] = head;
    wmb();
    vq->vring.avail->idx++;
    wmb();
}

static struct vring_packed_desc* alloc_indirect_packed(struct libvhost_virt_queue* vq, unsigned int size) {
    struct vring_packed_desc* desc;

    desc = (struct vring_packed_desc*)libvhost_malloc(vq->ctrl, size * sizeof(struct vring_packed_desc));
    if (!desc) {
        return NULL;
    }
    memset(desc, 0, size * sizeof(struct vring_packed_desc));
    return desc;
}

static void virtring_add_indirect_packed(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in,
                                         void* data) {
    struct vring_packed_desc* desc;
    struct libvhost_io_task* task = data;
    int i, c;
    uint16_t head, id;
    uint16_t descs_used;

    if (vq->num_free < 1) {
        ERROR("[VIRTIO] add desc failed: %d %d\n", vq->num_free, descs_used);
        exit(EXIT_FAILURE);
    }

    desc = alloc_indirect_packed(vq, num_in + num_out);
    CHECK(desc);

    i = 0;
    id = vq->free_head;
    descs_used = num_out + num_in;
    head = vq->packed.next_avail_idx;
    for (c = 0; c < descs_used; ++c) {
        /*
         * Since SPDK would not use NEXT flag in packed ring when
         * the desc is indirect, we don't need to set NEXT flag
         * for indirect desc.
         */
        desc[i].flags = (c < num_out ? 0 : VRING_DESC_F_WRITE);
        desc[i].addr = (uint64_t)iovec[c].iov_base;
        desc[i].len = iovec[c].iov_len;
        i++;
    }
    vq->packed.vring.desc[head].addr = (uint64_t)desc;
    vq->packed.vring.desc[head].len = descs_used * sizeof(struct vring_packed_desc);
    vq->packed.vring.desc[head].id = id;
    wmb();
    vq->packed.vring.desc[head].flags = VRING_DESC_F_INDIRECT | vq->packed.avail_used_flags;
    wmb();

    /* We're using some buffers from the free list. */
    vq->num_free -= 1;
    c = head + 1;
    if (c >= vq->size) {
        c = 0;
        vq->packed.avail_used_flags ^= (1 << VRING_PACKED_DESC_F_AVAIL | 1 << VRING_PACKED_DESC_F_USED);
        DEBUG("clip avali_used_flags(%x)\n", vq->packed.avail_used_flags);
    }

    vq->packed.next_avail_idx = c;
    vq->free_head = (id + 1 >= vq->size) ? 0 : id + 1;
    task->num_add = 1;
    task->indir_desc = desc;
    vq->desc_state[id] = data;
}

void virtring_add_packed(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in, void* data) {
    struct vring_packed_desc* desc;
    struct libvhost_io_task* task = data;
    int i, n, c;
    int last_n;
    uint16_t head, id, prev, curr;
    uint16_t head_flags, flags;
    uint16_t descs_used;
    char flags_name[16] = {0};

    if (vq->indirect && num_out + num_in > 1) {
        virtring_add_indirect_packed(vq, iovec, num_out, num_in, data);
        return;
    }

    head = vq->packed.next_avail_idx;
    desc = vq->packed.vring.desc;
    descs_used = num_out + num_in;

    if (vq->num_free < descs_used) {
        ERROR("[VIRTIO] add desc failed: %d %d\n", vq->num_free, descs_used);
        exit(EXIT_FAILURE);
        return;
    }

    id = vq->free_head;
    n = head;
    c = 0;
    for (i = 0; i < descs_used; ++i) {
        flags = vq->packed.avail_used_flags | ((++c == descs_used) ? 0 : VRING_DESC_F_NEXT) |
                (i < num_out ? 0 : VRING_DESC_F_WRITE);
        if (n == head) {
            head_flags = flags;
        } else {
            desc[n].flags = flags;
        }
        desc[n].addr = (uint64_t)iovec[i].iov_base;
        desc[n].len = iovec[i].iov_len;
        desc[n].id = id;

        virtio_get_flags_name(flags, flags_name);
        DEBUG("ADD new desc(%d) addr(%llx) len(%d) id(%d) flags(%x %s)\n", n, (vq->packed.vring.desc[n].addr),
              (vq->packed.vring.desc[n].len), (vq->packed.vring.desc[n].id), (flags), flags_name);
        if (++n >= vq->size) {
            n = 0;
            vq->packed.avail_used_flags ^= (1 << VRING_PACKED_DESC_F_AVAIL | 1 << VRING_PACKED_DESC_F_USED);
            DEBUG("clip avali_used_flags(%x)\n", vq->packed.avail_used_flags);
        }
    }

    /* We're using some buffers from the free list. */
    vq->num_free -= descs_used;
    task->num_add = descs_used;

    /* Update free pointer */
    vq->packed.next_avail_idx = n;
    vq->free_head = (id + 1 >= vq->size) ? 0 : id + 1;
    vq->desc_state[id] = data;
    wmb();
    vq->packed.vring.desc[head].flags = head_flags;
    wmb();
}

void virtqueue_add(struct libvhost_virt_queue* vq, struct iovec* iovec, int num_out, int num_in, void* data) {
    if (vq->packed_ring) {
        virtring_add_packed(vq, iovec, num_out, num_in, data);
    } else {
        virtring_add(vq, iovec, num_out, num_in, data);
    }
}

/*
 * Packed ring specific functions - *_packed().
 */
static bool packed_used_wrap_counter(uint16_t last_used_idx) {
    return !!(last_used_idx & (1 << VRING_PACKED_EVENT_F_WRAP_CTR));
}

static uint16_t packed_last_used(uint16_t last_used_idx) {
    return last_used_idx & ~(-(1 << VRING_PACKED_EVENT_F_WRAP_CTR));
}

static inline bool is_used_desc_packed(const struct libvhost_virt_queue* vq, uint16_t idx, bool used_wrap_counter) {
    bool avail, used;
    uint16_t flags;

    flags = vq->packed.vring.desc[idx].flags;
    avail = !!(flags & (1 << VRING_PACKED_DESC_F_AVAIL));
    used = !!(flags & (1 << VRING_PACKED_DESC_F_USED));

    return avail == used && used == used_wrap_counter;
}

static bool more_used_packed(const struct libvhost_virt_queue* vq) {
    uint16_t last_used;
    uint16_t last_used_idx;
    bool used_wrap_counter;

    last_used_idx = vq->last_used_idx;
    last_used = packed_last_used(last_used_idx);
    used_wrap_counter = packed_used_wrap_counter(last_used_idx);
    return is_used_desc_packed(vq, last_used, used_wrap_counter);
}

static inline bool more_used(const struct libvhost_virt_queue* vq) {
    rmb();
    // NOTICE: the shared used->idx range is [0, 2^16 -1], not [0, ring_num - 1];
    return vq->packed_ring ? more_used_packed(vq) : (vq->last_used_idx != vq->vring.used->idx);
}

static void reset_desc_split(struct libvhost_virt_queue* vq, uint16_t head) {
    uint16_t id = head;
    // reset the desc;
    while (vq->vring.desc[id].flags & VRING_DESC_F_NEXT) {
        id = vq->vring.desc[id].next;
        vq->num_free++;
    }

    // free the indirect vring memory
    if (vq->vring.desc[id].flags & VRING_DESC_F_INDIRECT) {
        struct vring_desc* desc = (struct vring_desc*)vq->vring.desc[id].addr;
        libvhost_free(vq->ctrl, desc);
    }

    vq->vring.desc[id].next = vq->free_head;
    vq->free_head = head;

    /* Plus final descriptor */
    vq->num_free++;
}

static int virtqueue_get_io_status(struct libvhost_io_task* task) {
    if (task->vq->ctrl->type == DEVICE_TYPE_BLK) {
        return ((struct libvhost_virtio_blk_req*)task->priv)->status;
    } else if (task->vq->ctrl->type == DEVICE_TYPE_SCSI) {
        return ((struct libvhost_virtio_scsi_req*)task->priv)->resp.status;
    } else {
        ERROR("UNKNOWN DEVICE TYPE\n");
        return -1;
    }
}

int virtring_get_split(struct libvhost_virt_queue* vq, VhostEvent* event) {
    uint16_t id;
    uint16_t last_used;
    uint32_t len;
    struct libvhost_io_task* task;
    if (!more_used(vq)) {
        return -1;
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
        "%d task: %p\n",
        vq->last_used_idx, last_used, id, len, task);
    task->cb(task);

    reset_desc_split(vq, id);

    vq->last_used_idx++;
    event->data = task->opaque;
    event->res = virtqueue_get_io_status(task);
    virtqueue_free_task(task);
    return 0;
}

int virtring_get_packed(struct libvhost_virt_queue* vq, VhostEvent* event) {
    struct libvhost_io_task* task;
    uint16_t last_used, id, last_used_idx;
    uint32_t len;
    bool used_wrap_counter;
    void* ret;

    if (!more_used(vq)) {
        return -1;
    }

    rmb();
    last_used_idx = vq->last_used_idx;
    used_wrap_counter = packed_used_wrap_counter(last_used_idx);
    last_used = packed_last_used(last_used_idx);
    id = vq->packed.vring.desc[last_used].id;
    len = vq->packed.vring.desc[last_used].len;
    task = vq->desc_state[id];
    if (!task) {
        ERROR("task is null, bug here\n");
        exit(EXIT_FAILURE);
    }
    // clear the desc_state to avoid info leak;
    vq->desc_state[id] = NULL;
    task->cb(task);

    if (vq->indirect && task->indir_desc) {
        libvhost_free(vq->ctrl, task->indir_desc);
        task->indir_desc = NULL;
    }

    vq->free_head = id;
    vq->num_free += task->num_add;

    last_used += task->num_add;
    if (last_used >= vq->size) {
        last_used -= vq->size;
        used_wrap_counter ^= 1;
    }

    DEBUG(
        "[VIRTIO] last_used_idx: %d, used_wrap_counter: %d, free_head: %d"
        ", task: %p\n",
        last_used, used_wrap_counter, vq->free_head, task);

    last_used = (last_used | (used_wrap_counter << VRING_PACKED_EVENT_F_WRAP_CTR));
    vq->last_used_idx = last_used;
    event->data = task->opaque;
    event->res = virtqueue_get_io_status(task);
    virtqueue_free_task(task);
    return 0;
}

int virtqueue_get(struct libvhost_virt_queue* vq, VhostEvent* event) {
    return vq->packed_ring ? virtring_get_packed(vq, event) : virtring_get_split(vq, event);
}

struct libvhost_io_task* virtqueue_get_task(struct libvhost_virt_queue* vq) {
    struct libvhost_io_task* task = vq->free_list.next;
    if (task) {
        vq->free_list.next = task->next;
        memset(task, 0, sizeof(*task));
        task->vq = vq;
        return task;
    }
    return NULL;
}

void virtqueue_free_task(struct libvhost_io_task* task) {
    struct libvhost_virt_queue* vq = task->vq;
    struct libvhost_ctrl* ctrl = vq->ctrl;
    libvhost_free(ctrl, task->priv);
    task->next = vq->free_list.next;
    vq->free_list.next = task;
    // printf("xxx free task: %p\n", task);
}

void virtqueue_kick(struct libvhost_virt_queue* vq) {
    uint64_t kick_value = 1;
    printf("kick vq %d\n", vq->idx);
    write(vq->kickfd, &kick_value, sizeof(kick_value));
}
