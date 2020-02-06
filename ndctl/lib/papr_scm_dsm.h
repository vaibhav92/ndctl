/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 * PAPR SCM Device specific methods for libndctl and ndctl
 *
 * (C) Copyright IBM 2020
 *
 * Author: Vaibhav Jain <vaibhav at linux.ibm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_
#define _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_

#include <linux/types.h>

#ifdef __KERNEL__
#include <linux/ndctl.h>
#else
#include <ndctl.h>
#endif

/*
 * Sub commands for ND_CMD_CALL. To prevent overlap from ND_CMD_*, values for
 * these enums start at 0x10000. These values are then returned from
 * cmd_to_func() making it easy to implement the switch-case block in
 * papr_scm_ndctl()
 */
enum dsm_papr_scm {
	DSM_PAPR_SCM_MIN =  0x10000,
	DSM_PAPR_SCM_HEALTH,
	DSM_PAPR_SCM_STATS,
	DSM_PAPR_SCM_MAX,
};

enum dsm_papr_scm_dimm_health {
	DSM_PAPR_SCM_DIMM_HEALTHY,
	DSM_PAPR_SCM_DIMM_UNHEALTHY,
	DSM_PAPR_SCM_DIMM_CRITICAL,
	DSM_PAPR_SCM_DIMM_FATAL,
};

/* Papr-scm-header + payload expected with ND_CMD_CALL ioctl from libnvdimm */
struct nd_papr_scm_cmd_pkg {
	struct nd_cmd_pkg hdr;		/* Package header containing sub-cmd */
	int32_t cmd_status;		/* Out: Sub-cmd status returned back */
	uint16_t payload_offset;	/* In: offset from start of struct */
	uint16_t payload_version;	/* In/Out: version of the payload */
	uint8_t payload[];		/* In/Out: Sub-cmd data buffer */
};

/* Helpers to evaluate the size of PAPR_SCM envelope */
/* Calculate the papr_scm-header size */
#define ND_PAPR_SCM_ENVELOPE_CONTENT_HDR_SIZE \
	(sizeof(struct nd_papr_scm_cmd_pkg) - sizeof(struct nd_cmd_pkg))
/*
 * Given a type calculate the envelope size
 * (nd-header + papr_scm-header + payload)
 */
#define ND_PAPR_SCM_ENVELOPE_SIZE(_type_)	\
	(sizeof(_type_) + sizeof(struct nd_papr_scm_cmd_pkg))

/* Given a type envelope-content size (papr_scm-header + payload) */
#define ND_PAPR_SCM_ENVELOPE_CONTENT_SIZE(_type_)	\
	(sizeof(_type_) + ND_PAPR_SCM_ENVELOPE_CONTENT_HDR_SIZE)

/*
 * Struct exchanged between kernel & ndctl in for PAPR_DSM_PAPR_SMART_HEALTH
 * Various bitflags indicate the health status of the dimm.
 */
struct nd_papr_scm_dimm_health_stat_v1 {
	/* Dimm not armed. So contents wont persist */
	bool dimm_unarmed;
	/* Previous shutdown did not persist contents */
	bool dimm_bad_shutdown;
	/* Contents from previous shutdown werent restored */
	bool dimm_bad_restore;
	/* Contents of the dimm have been scrubbed */
	bool dimm_scrubbed;
	/* Contents of the dimm cant be modified until CEC reboot */
	bool dimm_locked;
	/* Contents of dimm are encrypted */
	bool dimm_encrypted;

	enum dsm_papr_scm_dimm_health dimm_health;
};

/*
 * Typedef the current struct for dimm_health so that any application
 * or kernel recompiled after introducing a new version autometically
 * supports the new version.
 */
#define nd_papr_scm_dimm_health_stat nd_papr_scm_dimm_health_stat_v1

/* Current version number for the dimm health struct */
#define ND_PAPR_SCM_DIMM_HEALTH_VERSION 1

/* Struct holding a single performance metric */
struct nd_papr_scm_perf_stat {
	u64 statistic_id;
	u64 statistic_value;
};

/* Struct exchanged between kernel and ndctl reporting drc perf stats */
struct nd_papr_scm_perf_stats_v1 {
	/* Number of stats following */
	u32 num_statistics;

	/* zero or more performance matrics */
	struct nd_papr_scm_perf_stat scm_statistics[];
};

/*
 * Typedef the current struct for dimm_stats so that any application
 * or kernel recompiled after introducing a new version autometically
 * supports the new version.
 */
#define nd_papr_scm_perf_stats nd_papr_scm_perf_stats_v1
#define ND_PAPR_SCM_DIMM_PERF_STATS_VERSION 1

/* Convert a libnvdimm nd_cmd_pkg to papr_scm specific pkg */
static struct nd_papr_scm_cmd_pkg *nd_to_papr_cmd_pkg(struct nd_cmd_pkg *cmd)
{
	return (struct nd_papr_scm_cmd_pkg *) cmd;
}

/* Return the payload pointer for a given pcmd */
static void *papr_scm_pcmd_to_payload(struct nd_papr_scm_cmd_pkg *pcmd)
{
	if (pcmd->hdr.nd_size_in == 0 && pcmd->hdr.nd_size_out == 0)
		return NULL;
	else
		return (void *)((u8 *) pcmd + pcmd->payload_offset);
}
#endif /* _UAPI_ASM_POWERPC_PAPR_SCM_DSM_H_ */
