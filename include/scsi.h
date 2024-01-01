/*
 * Copyright 2022 fengli
 *
 * Authors:
 *   fengli@smartx.com
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include <stdint.h>

#define SCSI_DEFAULT_CDB_SIZE                   32
#define SCSI_DEFAULT_SENSE_SIZE                 96

#define CDB_STATUS_GOOD                         0
#define CDB_STATUS_CHECK_CONDITION              0x02U
#define CDB_STATUS_VALID(status)    (((status) & ~0x3eU) == 0)

#define SCSI_SENSE_KEY_MASK                     0x0fU
#define SCSI_SENSE_KEY_NO_SENSE                 0
#define SCSI_SENSE_KEY_UNIT_ATTENTION           6

/* SCSI Inquiry Types */
#define SCSI_INQUIRY_STANDARD                   0x00U
#define SCSI_INQUIRY_EVPD                       0x01U

/* SCSI Inquiry Pages */
#define SCSI_INQUIRY_STANDARD_NONE              0x00U
#define SCSI_INQUIRY_EVPD_SUPPORTED_PAGES       0x00U
#define SCSI_INQUIRY_EVPD_BLOCK_LIMITS          0xb0U

enum scsi_sense_key {
	SCSI_SENSE_NO_SENSE = 0x00,
	SCSI_SENSE_RECOVERED_ERROR = 0x01,
	SCSI_SENSE_NOT_READY = 0x02,
	SCSI_SENSE_MEDIUM_ERROR = 0x03,
	SCSI_SENSE_HARDWARE_ERROR = 0x04,
	SCSI_SENSE_ILLEGAL_REQUEST = 0x05,
	SCSI_SENSE_UNIT_ATTENTION = 0x06,
	SCSI_SENSE_DATA_PROTECT = 0x07,
	SCSI_SENSE_BLANK_CHECK = 0x08,
	SCSI_SENSE_VENDOR_SPECIFIC = 0x09,
	SCSI_SENSE_COPY_ABORTED = 0x0a,
	SCSI_SENSE_ABORTED_COMMAND = 0x0b,
	SCSI_SENSE_VOLUME_OVERFLOW = 0x0d,
	SCSI_SENSE_MISCOMPARE = 0x0e,
};

struct scsi_cdb_read_10 {
    uint8_t command;    /* =0x28 */
    uint8_t b1;
    uint32_t lba;
    uint8_t b6;
    uint16_t xfer_length;
    uint8_t control;
}  __attribute__((packed));
typedef struct scsi_cdb_read_10 scsi_cdb_read_10;

struct scsi_cdb_write_10 {
    uint8_t command;    /* =0x2a */
    uint8_t b1;
    uint32_t lba;
    uint8_t b6;
    uint16_t xfer_length;
    uint8_t control;
}  __attribute__((packed));
typedef struct scsi_cdb_write_10 scsi_cdb_write_10;

struct scsi_cdb_read_capacity_10 {
    uint8_t command;        /* =0x25 */
    uint8_t b1;
    uint32_t lba;
    uint64_t b6_b9;
} __attribute__((packed));
typedef struct scsi_cdb_read_capacity_10 scsi_cdb_read_capacity_10;

static inline void make_lun(uint8_t* lun, uint16_t target, uint32_t lun_id)
{
    /* See QEMU code to choose the way to handle LUNs.
     *
     * So, a valid LUN must have (always channel #0):
     *  lun[0] == 1
     *  lun[1] - target, any value
     *  lun[2] == 0 or (LUN, MSB, 0x40 set, 0x80 clear)
     *  lun[3] - LUN, LSB, any value
     */
    lun[0] = 1;
    lun[1] = target & 0xffU;
    lun[2] = (lun_id >> 8) & 0x3fU;
    if (lun[2]) {
        lun[2] |= 0x40;
    }
    lun[3] = lun_id & 0xffU;
}