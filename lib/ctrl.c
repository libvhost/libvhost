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
#include "vhost_user_spec.h"
#include "libvhost.h"
#include "libvhost_internal.h"
#include "buddy.h"

#include <linux/virtio_blk.h>
#include <linux/virtio_ring.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/unistd.h>
#include <sys/mman.h>

static int vhost_ctrl_get_config(struct libvhost_ctrl* ctrl);

static const char* const vhost_msg_strings[VHOST_USER_MAX] = {
    [VHOST_USER_SET_OWNER] = "VHOST_SET_OWNER",
    [VHOST_USER_RESET_OWNER] = "VHOST_RESET_OWNER",
    [VHOST_USER_SET_FEATURES] = "VHOST_SET_FEATURES",
    [VHOST_USER_GET_FEATURES] = "VHOST_GET_FEATURES",
    [VHOST_USER_SET_VRING_CALL] = "VHOST_SET_VRING_CALL",
    [VHOST_USER_GET_PROTOCOL_FEATURES] = "VHOST_USER_GET_PROTOCOL_FEATURES",
    [VHOST_USER_SET_PROTOCOL_FEATURES] = "VHOST_USER_SET_PROTOCOL_FEATURES",
    [VHOST_USER_SET_VRING_NUM] = "VHOST_SET_VRING_NUM",
    [VHOST_USER_SET_VRING_BASE] = "VHOST_SET_VRING_BASE",
    [VHOST_USER_GET_VRING_BASE] = "VHOST_GET_VRING_BASE",
    [VHOST_USER_SET_VRING_ADDR] = "VHOST_SET_VRING_ADDR",
    [VHOST_USER_SET_VRING_KICK] = "VHOST_SET_VRING_KICK",
    [VHOST_USER_SET_MEM_TABLE] = "VHOST_SET_MEM_TABLE",
    [VHOST_USER_SET_VRING_ENABLE] = "VHOST_SET_VRING_ENABLE",
    [VHOST_USER_GET_QUEUE_NUM] = "VHOST_USER_GET_QUEUE_NUM",
    [VHOST_USER_GET_CONFIG] = "VHOST_USER_GET_CONFIG",
    [VHOST_USER_SET_CONFIG] = "VHOST_USER_SET_CONFIG",
};

/*
If VHOST_USER_F_PROTOCOL_FEATURES has not been negotiated, the ring is
initialized in an enabled state.

If VHOST_USER_F_PROTOCOL_FEATURES has been negotiated, the ring is initialized
in a disabled state. Client must not pass data to/from the backend until ring is
enabled by VHOST_USER_SET_VRING_ENABLE with parameter 1, or after it has been
disabled by VHOST_USER_SET_VRING_ENABLE with parameter 0.

Each ring is initialized in a stopped state, client must not process it until
ring is started, or after it has been stopped.

Client must start ring upon receiving a kick (that is, detecting that file
descriptor is readable) on the descriptor specified by VHOST_USER_SET_VRING_KICK
or receiving the in-band message VHOST_USER_VRING_KICK if negotiated, and stop
ring upon receiving VHOST_USER_GET_VRING_BASE.

*/
#define DEFUALT_VHOST_FEATURES                                                                       \
    ((1ULL << VHOST_F_LOG_ALL) | (1ULL << VIRTIO_F_VERSION_1) | (1ULL << VIRTIO_F_NOTIFY_ON_EMPTY) | \
     (1ULL << VIRTIO_RING_F_EVENT_IDX) | (1ULL << VIRTIO_RING_F_INDIRECT_DESC))
//  (1ULL << VIRTIO_F_RING_PACKED) | (1ULL << VHOST_USER_F_PROTOCOL_FEATURES)

#define LIBVHOST_USER_MAX_QUEUE_PAIRS 8

/* Memory Management */
struct hugepage_info {
    uint64_t addr;
    size_t size;
    char path[256];
    int fd;
};

struct libvhost_mem {
    int nregions;
    struct hugepage_info hugepages[VHOST_MEMORY_MAX_NREGIONS];
    buddy_t* buddy;
};

static int __hugepage_info_alloc(struct hugepage_info* info) {
    snprintf(info->path, sizeof(info->path), "/dev/hugepages/libvhost.%d.XXXXXX", getpid());
    info->fd = mkstemp(info->path);
    if (info->fd < 0) {
        perror("mkstemp");
        return -1;
    }
    unlink(info->path);
    info->addr = (uint64_t)mmap(NULL, info->size, PROT_READ | PROT_WRITE, MAP_SHARED, info->fd, 0);
    if (info->addr == (uint64_t)MAP_FAILED) {
        perror("mmap");
        close(info->fd);
        return -1;
    }
    memset((void*)info->addr, 0, info->size);
    INFO("Add DIMM, addr: 0x%" PRIx64 " size: 0x%" PRIx64 "\n", info->addr, info->size);
    return 0;
}

static int libvhost_mem_add_region(struct libvhost_mem* mem, uint64_t size) {
    struct hugepage_info* info;
    if (mem->nregions >= VHOST_MEMORY_MAX_NREGIONS) {
        fprintf(stderr, "Too many hugepages\n");
        return -1;
    }
    info = &mem->hugepages[mem->nregions];
    mem->nregions++;
    info->size = size;
    return __hugepage_info_alloc(info);
}

static bool libvhost_mem_init(struct libvhost_mem* mem, uint64_t mem_size) {
    if (libvhost_mem_add_region(mem, mem_size) != 0)  {
        return false;
    }
    mem->buddy = buddy_create_with_mem(4096, (void*)(mem->hugepages[0].addr), mem_size);
    if (!mem->buddy) {
        return false;
    }
    return true;
}

static void libvhost_mem_free(struct libvhost_mem* mem) {
    // printf("free_libvhost_mem regions: %d\n", mem->nregions);
    int i;
    for (i = 0; i < mem->nregions; i++) {
        if (mem->hugepages[i].fd >= 0) {
            munmap((void*)mem->hugepages[i].addr, mem->hugepages[i].size);
            close(mem->hugepages[i].fd);
        }
    }
    buddy_destroy_with_mem(mem->buddy);
}

static void libvhost_mem_get_memory_info(struct libvhost_mem* mem, struct libvhost_user_memory* memory) {
    int i;
    memory->nregions = mem->nregions;

    for (i = 0; i < mem->nregions; i++) {
        struct libvhost_user_memory_region* reg = &memory->regions[i];
        /* UNUSED by backend, just fill the va */
        reg->guest_phys_addr = mem->hugepages[i].addr;
        reg->userspace_addr = mem->hugepages[i].addr;
        reg->memory_size = mem->hugepages[i].size;
        reg->mmap_offset = 0;
        INFO("memory region %d \n    size: %" PRIu64 "\n    guest physical addr: 0x%" PRIx64
             "\n    userspace "
             "addr: 0x%" PRIx64 "\n    mmap offset: 0x%" PRIx64 "\n",
             i, reg->memory_size, reg->guest_phys_addr, reg->userspace_addr, reg->mmap_offset);
    }
}

int libvhost_mem_get_memory_fds(struct libvhost_ctrl* ctrl, int* fds, int* size) {
    unsigned int i;
    struct libvhost_mem *mem = ctrl->mem;

    for (i = 0; i < mem->nregions; i++) {
        if (mem->hugepages[i].fd < 0) {
            fprintf(stderr, "Failed to open memory region\n");
            return -1;
        }
        fds[i] = mem->hugepages[i].fd;
    }
    *size = mem->nregions;
    return 0;
}

void* libvhost_malloc(struct libvhost_ctrl* ctrl, uint64_t size) { return buddy_alloc(ctrl->mem->buddy, size); }

void libvhost_free(struct libvhost_ctrl* ctrl, void* ptr) { buddy_free(ctrl->mem->buddy, ptr); }

/* Controller Management */
struct libvhost_ctrl* libvhost_ctrl_create(const char* path) {
    struct libvhost_ctrl* ctrl = calloc(1, sizeof(struct libvhost_ctrl));
    if (!ctrl) {
        ERROR("calloc failed\n");
        return NULL;
    }
    ctrl->sock_path = strdup(path);
    // Set default features.
    ctrl->features = DEFUALT_VHOST_FEATURES;
    ctrl->vqs = calloc(LIBVHOST_USER_MAX_QUEUE_PAIRS, sizeof(struct libvhost_virt_queue));
    ctrl->nr_vqs = 0;
    ctrl->config = (void*)calloc(1, sizeof(struct virtio_blk_config));
    return ctrl;
}

bool libvhost_ctrl_init_memory(struct libvhost_ctrl* ctrl, uint64_t mem_size) {
    ctrl->mem = calloc(1, sizeof(struct libvhost_mem));
    CHECK(ctrl->mem);
    return libvhost_mem_init(ctrl->mem, mem_size);
}

static void __ctrl_free_memory(struct libvhost_ctrl* ctrl) {
    if (ctrl->mem) {
        libvhost_mem_free(ctrl->mem);
        free(ctrl->mem);
    }
}

void libvhost_ctrl_destroy(struct libvhost_ctrl* ctrl) {
    close(ctrl->sock);
    __ctrl_free_memory(ctrl);
    free(ctrl->sock_path);
    free(ctrl->vqs);
    free(ctrl->config);
    free(ctrl);
}

int libvhost_ctrl_connect(struct libvhost_ctrl* ctrl) {
    struct sockaddr_un un;
    size_t len;
    struct libvhost_user_memory memory;

    ctrl->sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctrl->sock == -1) {
        perror("socket");
        return -1;
    }

    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, ctrl->sock_path);
    len = sizeof(un.sun_family) + strlen(ctrl->sock_path);

    if (connect(ctrl->sock, (struct sockaddr*)&un, len) == -1) {
        close(ctrl->sock);
        perror("connect");
        return -1;
    }
    if (vhost_ctrl_get_config(ctrl) != 0) {
        close(ctrl->sock);
        return -1;
    }
    return 0;
}

static char* get_feature_name(int bit) {
    switch (bit) {
        case VIRTIO_F_NOTIFY_ON_EMPTY:
            return "VIRTIO_F_NOTIFY_ON_EMPTY";
        case VHOST_F_LOG_ALL:
            return "VHOST_F_LOG_ALL";
        case VIRTIO_RING_F_INDIRECT_DESC:
            return "VIRTIO_RING_F_INDIRECT_DESC";
        case VIRTIO_RING_F_EVENT_IDX:
            return "VIRTIO_RING_F_EVENT_IDX";
        case VHOST_USER_F_PROTOCOL_FEATURES:
            return "VHOST_USER_F_PROTOCOL_FEATURES";
        case VIRTIO_F_VERSION_1:
            return "VIRTIO_F_VERSION_1";
        case VIRTIO_F_RING_PACKED:
            return "VIRTIO_F_RING_PACKED";
        default:
            return "UNKNOWN";
    }
}

static int negotiate_features(struct libvhost_ctrl* ctrl) {
    uint64_t features;
    int i = 0;
    if (vhost_ioctl(ctrl, VHOST_USER_GET_FEATURES, &features) != 0) {
        ERROR("Unable to get vhost features\n");
        return -1;
    }
    ctrl->features &= features;
    if (vhost_ioctl(ctrl, VHOST_USER_SET_FEATURES, &ctrl->features) != 0) {
        ERROR("Unable to set vhost features\n");
        return -1;
    }
    INFO("Features:\n");
    for (; i < 64; ++i) {
        if (ctrl->features & (1ULL << i)) {
            INFO("    bit: %2d %s\n", i, get_feature_name(i));
        }
    }
    return 0;
}

#define TO_GB(x) ((x) / (1024 * 1024 * 1024))

static int vhost_ctrl_get_config(struct libvhost_ctrl* ctrl) {
    struct libvhost_user_config config = {.size = sizeof(config.region)};
    struct virtio_blk_config* cfg = ctrl->config;

    if (vhost_ioctl(ctrl, VHOST_USER_GET_CONFIG, &config) != 0) {
        ERROR("Unable to get vhost config\n");
        return -1;
    }
    memcpy(cfg, &config.region, sizeof(struct virtio_blk_config));

    /* Capacity unit is sector, not block.*/
    DEBUG("[DEVICE INFO] capacity: %.3f GiB (%" PRIu64 ")\n", TO_GB(1.0 * cfg->capacity * 512), cfg->capacity * 512);
    DEBUG("[DEVICE INFO] size_max: %" PRIu32 "\n", cfg->size_max);
    DEBUG("[DEVICE INFO] seg_max: %" PRIu32 "\n", cfg->seg_max);
    // DEBUG("[DEVICE INFO] cylinders: %" PRIu16 "\n", cfg->cylinders);
    // DEBUG("[DEVICE INFO] heads: %" PRIu8 "\n", cfg->heads);
    // DEBUG("[DEVICE INFO] sectors: %" PRIu8 "\n", cfg->sectors);
    DEBUG("[DEVICE INFO] blk_size: %" PRIu32 "\n", cfg->blk_size);
    DEBUG("[DEVICE INFO] physical_block_exp: %" PRIu8 "\n", cfg->physical_block_exp);
    DEBUG("[DEVICE INFO] alignment_offset: %" PRIu8 "\n", cfg->alignment_offset);
    DEBUG("[DEVICE INFO] min_io_size: %" PRIu16 "\n", cfg->min_io_size);
    DEBUG("[DEVICE INFO] opt_io_size: %" PRIu32 "\n", cfg->opt_io_size);
    DEBUG("[DEVICE INFO] wce: %" PRIu8 "\n", cfg->wce);
    DEBUG("[DEVICE INFO] num_queues: %" PRIu16 "\n", cfg->num_queues);
    DEBUG("[DEVICE INFO] max_discard_sectors: %" PRIu32 "\n", cfg->max_discard_sectors);
    DEBUG("[DEVICE INFO] max_discard_seg: %" PRIu32 "\n", cfg->max_discard_seg);
    DEBUG("[DEVICE INFO] discard_sector_alignment: %" PRIu32 "\n", cfg->discard_sector_alignment);
    DEBUG("[DEVICE INFO] max_write_zeroes_sectors: %" PRIu32 "\n", cfg->max_write_zeroes_sectors);
    DEBUG("[DEVICE INFO] max_write_zeroes_seg: %" PRIu32 "\n", cfg->max_write_zeroes_seg);
    DEBUG("[DEVICE INFO] write_zeroes_may_unmap: %" PRIu8 "\n", cfg->write_zeroes_may_unmap);

    return 0;
}

uint64_t libvhost_ctrl_get_blocksize(struct libvhost_ctrl* ctrl) {
    return ((struct virtio_blk_config*)ctrl->config)->blk_size;
}

int libvhost_ctrl_get_numblocks(struct libvhost_ctrl* ctrl) {
    CHECK(((struct virtio_blk_config*)ctrl->config)->blk_size != 0);
    return ((struct virtio_blk_config*)ctrl->config)->capacity * 512 /
           ((struct virtio_blk_config*)ctrl->config)->blk_size;
}

int libvhost_ctrl_setup(struct libvhost_ctrl* ctrl) {
    struct libvhost_user_memory memory;
    int ret;
    if (vhost_ioctl(ctrl, VHOST_USER_SET_OWNER, 0) != 0) {
        goto fail;
    }
    if (negotiate_features(ctrl) != 0) {
        goto fail;
    }

    /* get mem regions info for passing it to the server */
    libvhost_mem_get_memory_info(ctrl->mem, &memory);
    if (vhost_ioctl(ctrl, VHOST_USER_SET_MEM_TABLE, &memory) != 0) {
        goto fail;
    }
    return 0;
fail:
    close(ctrl->sock);
    return -1;
}

static int vhost_enable_vq(struct libvhost_ctrl* ctrl, struct libvhost_virt_queue* vq) {
    VhostVringState state;
    state.index = vq->idx;
    state.num = vq->size;
    INFO("Setup virtqueue \n");
    // Tell the backend that the virtqueue size.
    if (vhost_ioctl(ctrl, VHOST_USER_SET_VRING_NUM, &state) != 0) {
        ERROR("Unable to set vring num\n");
        return -1;
    }
    INFO("  VHOST_USER_SET_VRING_NUM idx: %d num: %d\n", state.index, state.num);
    state.index = vq->idx;
    state.num = vq->last_used_idx;
    // Tell the backend that the available ring last used index.
    if (vhost_ioctl(ctrl, VHOST_USER_SET_VRING_BASE, &state) != 0) {
        ERROR("Unable to set vring base\n");
        return -1;
    }
    INFO("  VHOST_USER_SET_VRING_BASE idx: %d num: %d\n", state.index, state.num);

    VhostVringAddr addr;
    addr.index = vq->idx;
    addr.desc_user_addr = (uint64_t)vq->vring.desc;
    addr.avail_user_addr = (uint64_t)vq->vring.avail;
    addr.used_user_addr = (uint64_t)vq->vring.used;

    addr.flags = 0;
    if (vhost_ioctl(ctrl, VHOST_USER_SET_VRING_ADDR, &addr) != 0) {
        ERROR("Unable to set vring addr\n");
        return -1;
    }
    INFO(
        "  VHOST_USER_SET_VRING_ADDR idx: %d desc_user_addr: %lx "
        "used_user_addr: %lx avail_user_addr: %lx\n",
        addr.index, addr.desc_user_addr, addr.used_user_addr, addr.avail_user_addr);

    VhostVringFile file;
    file.index = vq->idx;
    file.fd = vq->callfd;

    if (vhost_ioctl(ctrl, VHOST_USER_SET_VRING_CALL, &file) != 0) {
        ERROR("Unable to set vring call\n");
        return -1;
    }
    INFO("  VHOST_USER_SET_VRING_CALL idx: %d fd: %d\n", file.index, file.fd);

    file.index = vq->idx;
    file.fd = vq->kickfd;

    if (vhost_ioctl(ctrl, VHOST_USER_SET_VRING_KICK, &file) != 0) {
        ERROR("Unable to set vring kick\n");
        return -1;
    }
    INFO("  VHOST_USER_SET_VRING_KICK idx: %d fd: %d\n", file.index, file.fd);

    return 0;
}

int libvhost_ctrl_add_virtqueue(struct libvhost_ctrl* ctrl, int size) {
    struct libvhost_virt_queue* vq = &ctrl->vqs[ctrl->nr_vqs++];
    vq->idx = ctrl->nr_vqs - 1;
    vq->size = size;
    vhost_vq_init(vq, ctrl);
    return vhost_enable_vq(ctrl, vq);
}
