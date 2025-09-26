/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "buddy.h"

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>

#include "utils.h"

// --- Constants ---
#define MIN_ALLOC_SHIFT 12 // 2^12 = 4KB

// A node in our free lists
struct block_node {
    LIST_ENTRY(block_node) link;
};

// The main buddy allocator structure
struct vhost_buddy {
    char name[32];
    void *base_addr;
    unsigned int total_size;
    bool is_hugepage;
    bool no_alloc;

    unsigned int min_alloc_shift;
    unsigned int max_alloc_shift;
    unsigned int num_levels;

    // Metadata: positive value is the level of a free block,
    // negative is -(level + 1) for an allocated block.
    int8_t *level_map;
    unsigned int map_entries;

    // One free list per level
    LIST_HEAD(free_list_head, block_node) *free_lists;
};

// --- Helper Functions ---

static inline unsigned int level_to_size(vhost_buddy_t buddy, unsigned int level) {
    return 1U << (level + buddy->min_alloc_shift);
}

static inline unsigned int round_up_pow2(unsigned int v) {
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    v++;
    return v;
}

static inline unsigned int size_to_level(vhost_buddy_t buddy, unsigned int size) {
    if (size == 0) return 0;

    unsigned int block_size = round_up_pow2(size);

    unsigned int shift = __builtin_ctz(block_size);

    if (shift < buddy->min_alloc_shift) shift = buddy->min_alloc_shift;
    if (shift > buddy->max_alloc_shift) return (unsigned int)-1;
    return shift - buddy->min_alloc_shift;
}

// --- API Implementation ---

vhost_buddy_t vhost_buddy_create(const char *name, unsigned int size, bool hugepage) {
    vhost_buddy_t buddy = calloc(1, sizeof(struct vhost_buddy));
    if (!buddy) {
        perror("Failed to allocate buddy handle");
        return NULL;
    }
    strncpy(buddy->name, name, sizeof(buddy->name) - 1);
    buddy->min_alloc_shift = MIN_ALLOC_SHIFT;

    buddy->total_size = round_up_pow2(size);
    if (buddy->total_size < (1U << MIN_ALLOC_SHIFT)) {
        buddy->total_size = (1U << MIN_ALLOC_SHIFT);
    }

    buddy->max_alloc_shift = __builtin_ctz(buddy->total_size);
    buddy->num_levels = buddy->max_alloc_shift - buddy->min_alloc_shift + 1;

    buddy->free_lists = calloc(buddy->num_levels, sizeof(*buddy->free_lists));
    if (!buddy->free_lists) {
        perror("Failed to allocate free lists");
        free(buddy);
        return NULL;
    }

    if (hugepage) {
        buddy->base_addr =
            mmap(NULL, buddy->total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (buddy->base_addr != MAP_FAILED) {
            buddy->is_hugepage = true;
        } else {
            ERROR("Hugepage allocation failed for '%s' (errno: %d %s). Falling back to normal memory.", name, errno,
                  strerror(errno));
            buddy->is_hugepage = false;
        }
    }

    if (!buddy->is_hugepage) {
        buddy->base_addr = mmap(NULL, buddy->total_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (buddy->base_addr == MAP_FAILED) {
            perror("Failed to mmap normal memory");
            free(buddy->free_lists);
            free(buddy);
            return NULL;
        }
    }

    buddy->map_entries = buddy->total_size >> buddy->min_alloc_shift;
    buddy->level_map = calloc(buddy->map_entries, sizeof(int8_t));
    if (!buddy->level_map) {
        perror("Failed to allocate level map");
        munmap(buddy->base_addr, buddy->total_size);
        free(buddy->free_lists);
        free(buddy);
        return NULL;
    }

    for (unsigned int i = 0; i < buddy->num_levels; i++) {
        LIST_INIT(&buddy->free_lists[i]);
    }

    // The entire buffer starts as a single free block on the highest level
    LIST_INSERT_HEAD(&buddy->free_lists[buddy->num_levels - 1], (struct block_node *)buddy->base_addr, link);
    buddy->level_map[0] = buddy->num_levels - 1;

    INFO("Buddy allocator '%s' created. Size: %u KB, Base: %p, Hugepage: %s, MinAllocShift: %u, MaxAllocShift: %u, Levels: %u",
          buddy->name,
          buddy->total_size / 1024, (void *)buddy->base_addr, buddy->is_hugepage ? "Yes" : "No", buddy->min_alloc_shift,
          buddy->max_alloc_shift, buddy->num_levels);

    return buddy;
}


vhost_buddy_t vhost_buddy_create_noalloc(const char* name, void* buf, unsigned int size) {
    vhost_buddy_t buddy = calloc(1, sizeof(struct vhost_buddy));
    if (!buddy) {
        perror("Failed to allocate buddy handle");
        return NULL;
    }
    strncpy(buddy->name, name, sizeof(buddy->name) - 1);
    buddy->min_alloc_shift = MIN_ALLOC_SHIFT;

    buddy->no_alloc = true;
    buddy->base_addr = buf;

    buddy->total_size = round_up_pow2(size);
    if (buddy->total_size != size) {
        ERROR("Size must be a power of two");
        free(buddy);
        return NULL;
    }

    buddy->max_alloc_shift = __builtin_ctz(buddy->total_size);
    buddy->num_levels = buddy->max_alloc_shift - buddy->min_alloc_shift + 1;

    buddy->free_lists = calloc(buddy->num_levels, sizeof(*buddy->free_lists));
    if (!buddy->free_lists) {
        perror("Failed to allocate free lists");
        free(buddy);
        return NULL;
    }

    buddy->map_entries = buddy->total_size >> buddy->min_alloc_shift;
    buddy->level_map = calloc(buddy->map_entries, sizeof(int8_t));
    if (!buddy->level_map) {
        perror("Failed to allocate level map");
        free(buddy->free_lists);
        free(buddy);
        return NULL;
    }

    for (unsigned int i = 0; i < buddy->num_levels; i++) {
        LIST_INIT(&buddy->free_lists[i]);
    }

    // The entire buffer starts as a single free block on the highest level
    LIST_INSERT_HEAD(&buddy->free_lists[buddy->num_levels - 1], (struct block_node *)buddy->base_addr, link);
    buddy->level_map[0] = buddy->num_levels - 1;

    INFO("Buddy allocator '%s' created. Size: %u KB, Base: %p, Hugepage: %s, MinAllocShift: %u, MaxAllocShift: %u, Levels: %u, NoAlloc: true",
          buddy->name,
          buddy->total_size / 1024, (void *)buddy->base_addr, buddy->is_hugepage ? "Yes" : "No", buddy->min_alloc_shift,
          buddy->max_alloc_shift, buddy->num_levels);

    return buddy;
}

void vhost_buddy_destroy(vhost_buddy_t buddy) {
    if (!buddy) return;
    if (!buddy->no_alloc) {
        munmap(buddy->base_addr, buddy->total_size);
    }
    free(buddy->level_map);
    free(buddy->free_lists);
    free(buddy);
}

void *vhost_buddy_alloc(vhost_buddy_t buddy, int size) {
    unsigned int req_level = size_to_level(buddy, size);
    if (req_level == (unsigned int)-1) return NULL;

    unsigned int current_level;
    for (current_level = req_level; current_level < buddy->num_levels; current_level++) {
        if (!LIST_EMPTY(&buddy->free_lists[current_level])) {
            break;
        }
    }

    if (current_level == buddy->num_levels) return NULL;

    struct block_node *block = LIST_FIRST(&buddy->free_lists[current_level]);
    LIST_REMOVE(block, link);

    while (current_level > req_level) {
        current_level--;
        unsigned int block_size = level_to_size(buddy, current_level);
        void *buddy_addr = (char *)block + block_size;

        LIST_INSERT_HEAD(&buddy->free_lists[current_level], (struct block_node *)buddy_addr, link);
        buddy->level_map[((char *)buddy_addr - (char *)buddy->base_addr) >> buddy->min_alloc_shift] = current_level;
    }

    uintptr_t map_idx = ((char *)block - (char *)buddy->base_addr) >> buddy->min_alloc_shift;
    buddy->level_map[map_idx] = -(req_level + 1);

    return block;
}

void vhost_buddy_free(vhost_buddy_t buddy, void *addr) {
    if (!addr) return;

    uintptr_t offset = (char *)addr - (char *)buddy->base_addr;
    uintptr_t map_idx = offset >> buddy->min_alloc_shift;

    int level_signed = buddy->level_map[map_idx];
    if (level_signed >= 0) {
        ERROR("Address %p is not allocated or double freed!", addr);
        return;
    }
    unsigned int current_level = -(level_signed)-1;

    for (; current_level < buddy->num_levels - 1; current_level++) {
        unsigned int block_size = level_to_size(buddy, current_level);
        uintptr_t buddy_offset = offset ^ block_size;
        uintptr_t buddy_map_idx = buddy_offset >> buddy->min_alloc_shift;

        if (buddy_map_idx >= buddy->map_entries || buddy->level_map[buddy_map_idx] != current_level) {
            // Buddy is out of bounds, not free, or not the same size. Stop merging.
            break;
        }

        // Buddy is free, merge them.
        struct block_node *buddy_node = (struct block_node *)((char *)buddy->base_addr + buddy_offset);
        LIST_REMOVE(buddy_node, link);

        offset = (offset < buddy_offset) ? offset : buddy_offset;
        addr = (char *)buddy->base_addr + offset;
    }

    LIST_INSERT_HEAD(&buddy->free_lists[current_level], (struct block_node *)addr, link);
    buddy->level_map[offset >> buddy->min_alloc_shift] = current_level;
}

void *vhost_buddy_base(vhost_buddy_t buddy) { return buddy ? buddy->base_addr : NULL; }

unsigned int vhost_buddy_size(vhost_buddy_t buddy) { return buddy ? buddy->total_size : 0; }
