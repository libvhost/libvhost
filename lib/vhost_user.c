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
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int vhost_user_write(int fd, void* buf, int len, int* fds, int fd_num) {
    int r;
    struct msghdr msgh;
    struct iovec iov;
    size_t fd_size = fd_num * sizeof(int);
    char control[CMSG_SPACE(fd_size)];
    struct cmsghdr* cmsg;

    memset(&msgh, 0, sizeof(msgh));
    memset(control, 0, sizeof(control));

    iov.iov_base = (uint8_t*)buf;
    iov.iov_len = len;

    msgh.msg_iov = &iov;
    msgh.msg_iovlen = 1;

    if (fds && fd_num > 0) {
        msgh.msg_control = control;
        msgh.msg_controllen = sizeof(control);
        cmsg = CMSG_FIRSTHDR(&msgh);
        cmsg->cmsg_len = CMSG_LEN(fd_size);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsg), fds, fd_size);
    } else {
        msgh.msg_control = NULL;
        msgh.msg_controllen = 0;
    }

    do {
        r = sendmsg(fd, &msgh, 0);
    } while (r < 0 && errno == EINTR);

    if (r == -1) {
        return -errno;
    }

    return 0;
}

static int vhost_user_read(int fd, struct VhostUserMsg* msg) {
    uint32_t valid_flags = VHOST_USER_REPLY_MASK | VHOST_USER_VERSION;
    ssize_t ret;
    size_t sz_hdr = VHOST_USER_HDR_SIZE, sz_payload;

    ret = recv(fd, (void*)msg, sz_hdr, 0);
    if ((size_t)ret != sz_hdr) {
        WARN("Failed to recv msg hdr: %zd instead of %zu.\n", ret, sz_hdr);
        if (ret == -1) {
            return -errno;
        } else {
            return -EBUSY;
        }
    }

    /* validate msg flags */
    if (msg->flags != (valid_flags)) {
        WARN("Failed to recv msg: flags %" PRIx32 " instead of %" PRIx32 ".\n", msg->flags, valid_flags);
        return -EIO;
    }

    sz_payload = msg->size;

    if (sz_payload > VHOST_USER_PAYLOAD_SIZE) {
        WARN("Received oversized msg: payload size %zu > available space %zu\n", sz_payload, VHOST_USER_PAYLOAD_SIZE);
        return -EIO;
    }

    if (sz_payload) {
        ret = recv(fd, (void*)((char*)msg + sz_hdr), sz_payload, 0);
        if ((size_t)ret != sz_payload) {
            WARN("Failed to recv msg payload: %zd instead of %" PRIu32 ".\n", ret, msg->size);
            if (ret == -1) {
                return -errno;
            } else {
                return -EBUSY;
            }
        }
    }

    return 0;
}

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

int vhost_ioctl(struct libvhost_ctrl *ctrl, enum libvhost_user_msg_type req, void* arg) {
    struct VhostUserMsg msg;
    struct VhostVringFile* file = 0;
    int need_reply = 0;
    int fds[VHOST_MEMORY_MAX_NREGIONS];
    int fd_num = 0;
    int i, len, rc;

    DEBUG("Sent message %2d = %s\n", req, vhost_msg_strings[req]);

    msg.request = req;
    msg.flags = VHOST_USER_VERSION;
    msg.size = 0;

    switch (req) {
        case VHOST_USER_GET_FEATURES:
        case VHOST_USER_GET_PROTOCOL_FEATURES:
        case VHOST_USER_GET_QUEUE_NUM:
            need_reply = 1;
            break;

        case VHOST_USER_SET_FEATURES:
        case VHOST_USER_SET_LOG_BASE:
        case VHOST_USER_SET_PROTOCOL_FEATURES:
            msg.payload.u64 = *((uint64_t*)arg);
            msg.size = sizeof(msg.payload.u64);
            break;

        case VHOST_USER_SET_OWNER:
        case VHOST_USER_RESET_OWNER:
            break;

        case VHOST_USER_SET_MEM_TABLE:
            msg.payload.memory = *((struct libvhost_user_memory*)arg);
            msg.size = sizeof(msg.payload.memory.nregions) + sizeof(msg.payload.memory.padding) +
                       (msg.payload.memory.nregions * sizeof(struct libvhost_user_memory_region));
            fd_num = VHOST_MEMORY_MAX_NREGIONS;
            if (libvhost_mem_get_memory_fds(ctrl, fds, &fd_num) != 0) {
                fprintf(stderr, "Failed to open memory region\n");
                return (-1);
            }
            break;

        case VHOST_USER_SET_LOG_FD:
            fds[fd_num++] = *((int*)arg);
            break;

        case VHOST_USER_SET_VRING_NUM:
        case VHOST_USER_SET_VRING_BASE:
        case VHOST_USER_SET_VRING_ENABLE:
            memcpy(&msg.payload.state, arg, sizeof(msg.payload.state));
            msg.size = sizeof(msg.payload.state);
            break;

        case VHOST_USER_GET_VRING_BASE:
            memcpy(&msg.payload.state, arg, sizeof(msg.payload.state));
            msg.size = sizeof(msg.payload.state);
            need_reply = 1;
            break;

        case VHOST_USER_SET_VRING_ADDR:
            memcpy(&msg.payload.addr, arg, sizeof(msg.payload.addr));
            msg.size = sizeof(msg.payload.addr);
            break;

        case VHOST_USER_SET_VRING_KICK:
        case VHOST_USER_SET_VRING_CALL:
        case VHOST_USER_SET_VRING_ERR:
            file = arg;
            msg.payload.u64 = file->index & VHOST_USER_VRING_IDX_MASK;
            msg.size = sizeof(msg.payload.u64);
            if (file->fd > 0) {
                fds[fd_num++] = file->fd;
            } else {
                msg.payload.u64 |= VHOST_USER_VRING_NOFD_MASK;
            }
            break;

        case VHOST_USER_GET_CONFIG:
            memcpy(&msg.payload.cfg, arg, sizeof(msg.payload.cfg));
            msg.size = sizeof(msg.payload.cfg);
            need_reply = 1;
            break;

        case VHOST_USER_SET_CONFIG:
            memcpy(&msg.payload.cfg, arg, sizeof(msg.payload.cfg));
            msg.size = sizeof(msg.payload.cfg);
            break;

        default:
            ERROR("trying to send unknown msg\n");
            return -EINVAL;
    }

    len = VHOST_USER_HDR_SIZE + msg.size;
    rc = vhost_user_write(ctrl->sock, &msg, len, fds, fd_num);
    if (rc < 0) {
        ERROR("%s failed: %d\n", vhost_msg_strings[req], rc);
        return rc;
    }

    if (req == VHOST_USER_SET_MEM_TABLE)
        for (i = 0; i < fd_num; ++i) {
            close(fds[i]);
        }

    if (need_reply) {
        rc = vhost_user_read(ctrl->sock, &msg);
        if (rc < 0) {
            WARN("Received msg failed: %d\n", rc);
            return rc;
        }

        if (req != msg.request) {
            WARN("Received unexpected msg type\n");
            return -EIO;
        }

        switch (req) {
            case VHOST_USER_GET_FEATURES:
            case VHOST_USER_GET_PROTOCOL_FEATURES:
            case VHOST_USER_GET_QUEUE_NUM:
                if (msg.size != sizeof(msg.payload.u64)) {
                    WARN("Received bad msg size\n");
                    return -EIO;
                }
                *((uint64_t*)arg) = msg.payload.u64;
                break;
            case VHOST_USER_GET_VRING_BASE:
                if (msg.size != sizeof(msg.payload.state)) {
                    WARN("Received bad msg size\n");
                    return -EIO;
                }
                memcpy(arg, &msg.payload.state, sizeof(struct VhostVringState));
                break;
            case VHOST_USER_GET_CONFIG:
                if (msg.size != sizeof(msg.payload.cfg)) {
                    WARN("Received bad msg size\n");
                    return -EIO;
                }
                memcpy(arg, &msg.payload.cfg, sizeof(msg.payload.cfg));
                break;
            default:
                WARN("Received unexpected msg type\n");
                return -EBADMSG;
        }
    }
    return 0;
}
