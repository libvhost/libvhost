#ifndef _BUDDY_H_
#define _BUDDY_H_

#include <stdint.h>
typedef void* buddy_t;

buddy_t buddy_create(unsigned int nmemb, unsigned int size);
void buddy_destroy(buddy_t buddy);

buddy_t buddy_create_with_mem(unsigned int size, void* addr, uint64_t mem_len);
void buddy_destroy_with_mem(buddy_t buddy);

void* buddy_alloc(buddy_t buddy, int size);
void buddy_free(buddy_t buddy, void* addr);

#endif
