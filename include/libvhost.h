#ifndef __LIBVHOST_H__
#define __LIBVHOST_H__s

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>
#include <linux/virtio_blk.h>

#ifdef __cplusplus
extern "C" {
#endif

struct libvhost_mem;
struct libvhost_ctrl {
    char* sock_path;
    int status;
    int sock;
    uint64_t features;
    struct libvhost_virt_queue* vqs;
    int nr_vqs;

    struct libvhost_mem* mem;

    /* vritio_blk: struct virtio_blk_config */
    /* virtio_scsi */
    void* config;
};

/* vhost controller */
struct libvhost_ctrl* libvhost_ctrl_create(const char* path);
void libvhost_ctrl_destroy(struct libvhost_ctrl* ctrl);
int libvhost_ctrl_connect(struct libvhost_ctrl* ctrl);
int libvhost_ctrl_setup(struct libvhost_ctrl* ctrl);
bool libvhost_ctrl_init_memory(struct libvhost_ctrl* ctrl, uint64_t mem_size);
int libvhost_ctrl_add_virtqueue(struct libvhost_ctrl* ctrl, int size);
// int vhost_ctrl_del_vq(struct libvhost_ctrl* ctrl);

uint64_t libvhost_ctrl_get_blocksize(struct libvhost_ctrl* ctrl);
int libvhost_ctrl_get_numblocks(struct libvhost_ctrl* ctrl);

/* io */
typedef struct VhostEvent {
    void* data;
    int res;
} VhostEvent;

int libvhost_read(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, char* buf, int len);
int libvhost_write(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, char* buf, int len);
int libvhost_readv(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt);
int libvhost_writev(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt);
int libvhost_submit(struct libvhost_ctrl* ctrl, int q_idx, uint64_t offset, struct iovec* iov, int iovcnt, bool write,
                    void* opaque);

int libvhost_getevents(struct libvhost_ctrl* ctrl, int q_idx, int nr, VhostEvent* events);

void* libvhost_malloc(struct libvhost_ctrl* ctrl, uint64_t size);
void libvhost_free(struct libvhost_ctrl* ctrl, void* ptr);

#ifdef __cplusplus
}
#endif

#endif