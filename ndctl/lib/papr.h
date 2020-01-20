/*
 * Copyright (C) 2020 IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU Lesser General Public License,
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
 * more details.
 */
#ifndef __NDCTL_PAPR_H__
#define __NDCTL_PAPR_H__
#include <stdint.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

/*
 * Sub commands for ND_CMD_CALL. To prevent overlap
 * from ND_CMD_*, values for these enums start at
 * 0x10000
 */
enum {
	DSM_PAPR_MIN =  0x10000,
	DSM_PAPR_SCM_HEALTH = 0x10001,
	DSM_PAPR_SCM_STATS = 0x10002,
	DSM_PAPR_MAX,
};

/* Struct as returned by kernel in response to PAPR_DSM_PAPR_SMART_HEALTH */
struct papr_scm_ndctl_health {
	__be64 health_bitmap;
	__be64 health_bitmap_valid;
} __packed;

/* Buffer layout returned by phyp when reporting drc perf stats */
struct papr_scm_perf_stats {
	uint8_t version; 		/* Should be 0x01 */
	uint8_t reserved1;
	__be16 size;			/* Size of this struct in bytes */
	uint8_t reserved[3];
	uint8_t life_remaining; 	/* Percentage life remaining */
	__be64 host_load_count;	/* Number of mem-reads by host */
	__be64 host_store_count;	/* Number of mem-writes by host */
	__be64 media_read_count;	/* Read counts by the media */
	__be64 media_write_count;	/* Write counts by the media */
	__be64 cache_hit_count;	/* Read/Write serviced by controller */
	__be64 cache_miss_count;	/* Read/Writes requiring media access */
	__be64 media_read_latency;	/* Avg latency(ns) - media read */
	__be64 media_write_latency;	/* Avg latency(ns) - media write */
	__be64 cache_read_latency;	/* Avg latency(ns) - controller read */
	__be64 cache_write_latency;	/* Avg latency(ns) - controller write */
	__be64 poweron_seconds;	/* Seconds controller if powered on */
} __packed;

/* Payload for the ND_CMD_CALL */
struct nd_pkg_papr_scm {
	struct nd_cmd_pkg hdr;
	int32_t cmd_status;
	uint8_t payload[];
} __packed;


/* Bits status indicators for health bitmap */
/* SCM device is encrypted */
#define ND_PAPR_SCM_DIMM_ENCRYPTED		0x1ULL << 15
/* SCM device is unable to persist memory contents */
#define ND_PAPR_SCM_DIMM_UNARMED 		0x1ULL << 7
/* SCM device failed to persist memory contents */
#define ND_PAPR_SCM_DIMM_SHUTDOWN_DIRTY 	0x1ULL << 6
/* SCM device contents are persisted from previous IPL */
#define ND_PAPR_SCM_DIMM_SHUTDOWN_CLEAN 	0x1ULL << 5
/* SCM device contents are not persisted from previous IPL */
#define ND_PAPR_SCM_DIMM_EMPTY	 		0x1ULL << 4
/* SCM device memory life remaining is critically low */
#define ND_PAPR_SCM_DIMM_HEALTH_CRITICAL	0x1ULL << 3
/* SCM device will be garded off next IPL due to failure */
#define ND_PAPR_SCM_DIMM_HEALTH_FATAL		0x1ULL << 2
/* SCM contents cannot persist due to current platform health status */
#define ND_PAPR_SCM_DIMM_HEALTH_UNHEALTHY	0x1ULL << 1
/* SCM device is unable to persist memory contents in certain conditions */
#define ND_PAPR_SCM_DIMM_HEALTH_NON_CRITCAL	0x1ULL << 0

#endif /* __NDCTL_PAPR_H__ */
