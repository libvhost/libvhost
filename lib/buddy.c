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
#include "utils.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct buddy {
    unsigned int nmemb;
    unsigned int size;
    char* base;
    unsigned int meta[0];
};

#define L_LEAF(index) ((index)*2 + 1)
#define R_LEAF(index) ((index)*2 + 2)
#define PARENT(index) (((index) + 1) / 2 - 1)

#define IS_POWER_OF_2(x) (!((x) & ((x)-1)))
#define MAX(a, b) ((a) > (b) ? (a) : (b))

static inline unsigned int roundup_power_of_2(unsigned int val) {
    return sizeof(unsigned int) * 8 - __builtin_clz(val);
}

buddy_t buddy_create_with_mem(unsigned int size, void* addr, uint64_t mem_len) {
    struct buddy* buddy;
    unsigned int nodes, i;
    uint64_t offset = 0;
    uint64_t nmemb = (mem_len - sizeof(struct buddy))/ (size + sizeof(unsigned int) * 2);
    CHECK(addr);
    INFO("nmemb: %lu\n", nmemb);
    for (i = 0; i < 64; ++i) {
        if (nmemb < (1 << i)) {
            break;
        }
    }
    nmemb = (1<< (i - 1));
    INFO("change to nmemb: %lu\n", nmemb);

    nodes = nmemb * 2;
    offset = sizeof(struct buddy) + sizeof(unsigned int) * nodes;
    if (offset > mem_len) {
        return NULL;
    }
    buddy = (struct buddy*)addr;
    // offset = AlignUp(offset, 4096);
    if (offset + size * nmemb > mem_len) {
        return NULL;
    }

    buddy->base = (char*)((char*)addr + offset);

    buddy->nmemb = nmemb;
    buddy->size = size;

    for (i = 0; i < buddy->nmemb * 2 - 1; i++) {
        if (IS_POWER_OF_2(i + 1)) {
            nodes /= 2;
        }

        buddy->meta[i] = nodes;
    }

    return buddy;
}

void buddy_destroy_with_mem(buddy_t buddy) {
    (void)buddy;
    // do nothing
}

buddy_t buddy_create(unsigned int nmemb, unsigned int size) {
    struct buddy* buddy;
    unsigned int nodes, i;

    if (!IS_POWER_OF_2(nmemb)) {
        return NULL;
    }

    nodes = nmemb * 2;
    buddy = (struct buddy*)malloc(sizeof(struct buddy) + sizeof(unsigned int) * nodes);
    if (!buddy) {
        return NULL;
    }

    buddy->base = (char*)malloc(size * nmemb);
    if (!buddy->base) {
        goto fail;
    }

    buddy->nmemb = nmemb;
    buddy->size = size;

    for (i = 0; i < buddy->nmemb * 2 - 1; i++) {
        if (IS_POWER_OF_2(i + 1)) {
            nodes /= 2;
        }

        buddy->meta[i] = nodes;
    }

    return buddy;

fail:
    free(buddy);
    return NULL;
}

void buddy_destroy(buddy_t buddy) {
    struct buddy* __buddy = (struct buddy*)buddy;

    free(__buddy->base);
    free(__buddy);
}

void* buddy_base(buddy_t buddy) {
    struct buddy* __buddy = (struct buddy*)buddy;

    return __buddy->base;
}

unsigned int buddy_size(buddy_t buddy) {
    struct buddy* __buddy = (struct buddy*)buddy;

    return __buddy->size;
}

unsigned int buddy_nmemb(buddy_t buddy) {
    struct buddy* __buddy = (struct buddy*)buddy;

    return __buddy->nmemb;
}

void* buddy_alloc(buddy_t buddy, int size) {
    struct buddy* __buddy = (struct buddy*)buddy;
    unsigned int index = 0;
    unsigned int nodes;
    unsigned int offset = 0;
    uint64_t alignup = (size + __buddy->size - 1) / __buddy->size;

    if (!IS_POWER_OF_2(alignup)) {
        alignup = roundup_power_of_2(alignup);
        alignup = (1ULL << alignup);
    }

    if (__buddy->meta[index] < alignup) {
        return NULL;
    }

    for (nodes = __buddy->nmemb; nodes != alignup; nodes /= 2) {
        // INFO("index: %d, L_LEAF(index): %d nodes: %d\n", index, L_LEAF(index), nodes);
        if (__buddy->meta[L_LEAF(index)] >= alignup) {
            index = L_LEAF(index);
        } else {
            index = R_LEAF(index);
        }
    }

    __buddy->meta[index] = 0;
    offset = (index + 1) * nodes - __buddy->nmemb;

    while (index) {
        index = PARENT(index);
        __buddy->meta[index] = MAX(__buddy->meta[L_LEAF(index)], __buddy->meta[R_LEAF(index)]);
    }

    return __buddy->base + offset * __buddy->size;
}

void buddy_free(buddy_t buddy, void* addr) {
    struct buddy* __buddy = (struct buddy*)buddy;
    unsigned int nodes, index = 0;
    unsigned int left_meta, right_meta, offset;

    offset = ((char*)addr - __buddy->base) / __buddy->size;
    if (offset * __buddy->size + __buddy->base != addr) {
        assert(0);
    }

    nodes = 1;
    index = offset + __buddy->nmemb - 1;

    for (; __buddy->meta[index]; index = PARENT(index)) {
        nodes *= 2;
        if (index == 0) {
            return;
        }
    }

    __buddy->meta[index] = nodes;

    while (index) {
        index = PARENT(index);
        nodes *= 2;

        left_meta = __buddy->meta[L_LEAF(index)];
        right_meta = __buddy->meta[R_LEAF(index)];

        if (left_meta + right_meta == nodes) {
            __buddy->meta[index] = nodes;
        } else {
            __buddy->meta[index] = MAX(left_meta, right_meta);
        }
    }
}
