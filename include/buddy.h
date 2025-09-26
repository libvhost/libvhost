/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VHOST_BUDDY_H
#define VHOST_BUDDY_H

#include <stdbool.h>

// Opaque pointer type for the buddy allocator handle
typedef struct vhost_buddy* vhost_buddy_t;

/**
 * @brief Creates a buddy memory allocator instance.
 *
 * @param name The name of the allocator, used for logging.
 * @param size The requested total size of the memory pool (will be rounded up to the next power of two).
 * @param hugepage Whether to attempt using hugepages for the memory pool.
 * @return vhost_buddy_t A handle to the allocator on success, or NULL on failure.
 */
vhost_buddy_t vhost_buddy_create(const char* name, unsigned int size, bool hugepage);

vhost_buddy_t vhost_buddy_create_noalloc(const char* name, void* buf, unsigned int size);

/**
 * @brief Destroys the buddy allocator instance and releases all associated resources.
 *
 * @param buddy The allocator handle to destroy.
 */
void vhost_buddy_destroy(vhost_buddy_t buddy);

/**
 * @brief Allocates a block of memory from the pool.
 *
 * @param buddy The allocator handle.
 * @param size The requested memory size (will be rounded up to the nearest power of two between 4K and 1M).
 * @return void* A pointer to the allocated memory block on success, or NULL if out of memory.
 */
void* vhost_buddy_alloc(vhost_buddy_t buddy, int size);

/**
 * @brief Frees a previously allocated memory block.
 *
 * @param buddy The allocator handle.
 * @param addr A pointer to the memory block to be freed.
 */
void vhost_buddy_free(vhost_buddy_t buddy, void* addr);

/**
 * @brief Gets the base address of the entire memory pool.
 *
 * @param buddy The allocator handle.
 * @return void* The starting address of the entire memory pool.
 */
void* vhost_buddy_base(vhost_buddy_t buddy);

/**
 * @brief Gets the total size of the memory pool.
 *
 * @param buddy The allocator handle.
 * @return unsigned int The total size of the memory pool in bytes.
 */
unsigned int vhost_buddy_size(vhost_buddy_t buddy);

#endif  // VHOST_BUDDY_H