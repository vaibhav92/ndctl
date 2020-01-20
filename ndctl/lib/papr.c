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
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <endian.h>
#include <util/log.h>
#include <ndctl.h>
#include <ndctl/libndctl.h>
#include <lib/private.h>
#include "papr.h"

static bool papr_cmd_is_supported(struct ndctl_dimm * dimm, int cmd)
{
	if (cmd == ND_CMD_SMART)
		return true;

	return !!(dimm->cmd_mask & (1ULL << cmd));
}

static struct nd_pkg_papr_scm * cmd_to_pcmd(struct ndctl_cmd * cmd)
{
	return cmd == NULL ? NULL : &cmd->papr[0];
}

static bool papr_scm_cmd_valid(const struct nd_pkg_papr_scm * pcmd)
{
	if (pcmd == NULL)
		return false;

	if (pcmd->hdr.nd_family != NVDIMM_FAMILY_PAPR)
		return false;

	if (pcmd->hdr.nd_command < DSM_PAPR_MIN ||
	    pcmd->hdr.nd_command >= DSM_PAPR_MAX)
		return false;

	return true;
}

static int pcmd_get_health_bitmap(const struct nd_pkg_papr_scm * pcmd,
				      uint64_t * bitmap)
{
	uint64_t health_bitmap, health_bitmap_valid;
	struct papr_scm_ndctl_health * const health =
		(struct papr_scm_ndctl_health * const) pcmd->payload;

	if (!papr_scm_cmd_valid(pcmd))
		return -EINVAL;

	if (pcmd->cmd_status)
		return -ENXIO;

	if (pcmd->hdr.nd_command != DSM_PAPR_SCM_HEALTH)
		return -EINVAL;


	/* Convert the bitmaps from big endian to cpu endian */
	health_bitmap = be64_to_cpu(health->health_bitmap);
	health_bitmap_valid = be64_to_cpu(health->health_bitmap_valid);

	/* bitwise and the valid_bitmap to health */
	*bitmap = health_bitmap & health_bitmap_valid;

	return 0;
}


static struct ndctl_cmd * papr_new_smart_stats(struct ndctl_dimm * dimm)
{
	struct ndctl_bus *bus = ndctl_dimm_get_bus(dimm);
	struct ndctl_ctx *ctx = ndctl_bus_get_ctx(bus);
	struct ndctl_cmd *cmd;
	struct nd_pkg_papr_scm *pcmd;
	size_t size;

	if (!ndctl_dimm_is_cmd_supported(dimm, ND_CMD_CALL)) {
		dbg(ctx, "unsupported cmd\n");
		return NULL;
	}

	size = sizeof(struct ndctl_cmd) + sizeof(struct nd_pkg_papr_scm) +
		sizeof(struct papr_scm_perf_stats);
	cmd = calloc(1, size);
	if (!cmd)
		return NULL;
	pcmd = cmd_to_pcmd(cmd);

	ndctl_cmd_ref(cmd);
	cmd->dimm = dimm;
	cmd->type = ND_CMD_CALL;
	cmd->size = size;
	cmd->status = 1;
	cmd->firmware_status = (uint32_t *)&pcmd->cmd_status;

	/* Populate the nd_cmd_pkg contained in nd_pkg_papr_scm */
	pcmd->hdr.nd_family = NVDIMM_FAMILY_PAPR;
	pcmd->hdr.nd_command = DSM_PAPR_SCM_STATS;
	pcmd->hdr.nd_fw_size = 0;
	pcmd->hdr.nd_size_in = 0;
	pcmd->hdr.nd_size_out = size - offsetof(struct ndctl_cmd, papr[0].cmd_status);
	pcmd->cmd_status = 0;
	return cmd;
}


static struct ndctl_cmd * papr_new_smart_health(struct ndctl_dimm * dimm)
{
	struct ndctl_bus *bus = ndctl_dimm_get_bus(dimm);
	struct ndctl_ctx *ctx = ndctl_bus_get_ctx(bus);
	struct ndctl_cmd *cmd;
	struct nd_pkg_papr_scm *pcmd;
	size_t size;

	if (!ndctl_dimm_is_cmd_supported(dimm, ND_CMD_CALL)) {
		dbg(ctx, "unsupported cmd\n");
		return NULL;
	}

	size = sizeof(struct ndctl_cmd) + sizeof(struct nd_pkg_papr_scm) +
		sizeof(struct papr_scm_ndctl_health);
	cmd = calloc(1, size);
	if (!cmd)
		return NULL;
	pcmd = cmd_to_pcmd(cmd);

	ndctl_cmd_ref(cmd);
	cmd->dimm = dimm;
	cmd->type = ND_CMD_CALL;
	cmd->size = size;
	cmd->status = 1;
	cmd->firmware_status = &pcmd->cmd_status;

	/* Populate the nd_cmd_pkg contained in nd_pkg_papr_scm */
	pcmd->hdr.nd_family = NVDIMM_FAMILY_PAPR;
	pcmd->hdr.nd_command = DSM_PAPR_SCM_HEALTH;
	pcmd->hdr.nd_fw_size = 0;
	pcmd->hdr.nd_size_in = 0;
	pcmd->hdr.nd_size_out = size - offsetof(struct ndctl_cmd, papr[0].cmd_status);
	pcmd->cmd_status = 0;

	/*
	 * Allocate a smart-stat cmd and assign it as src for the smart-health
	 * command. When the smart-health command completes we fetch stats
	 * and return appropriate flags from papr_smart_get_flags()
	 */
	cmd->source = papr_new_smart_stats(dimm);
	if (!cmd->source)
		info(ctx, "papr: Unable to allocated stats command\n");

	return cmd;
}

static int papr_xlat_firmware_status(struct ndctl_cmd * cmd)
{
	const struct nd_pkg_papr_scm * pcmd = cmd_to_pcmd(cmd);
	switch (pcmd->cmd_status) {
	case 0:
		return FW_SUCCESS;
	default:
		return FW_EUNKNOWN;
	};
}

static unsigned int papr_smart_get_flags(struct ndctl_cmd *cmd)
{
	const struct nd_pkg_papr_scm * pcmd = cmd_to_pcmd(cmd);
	struct ndctl_bus *bus = ndctl_dimm_get_bus(cmd->dimm);
	struct ndctl_ctx *ctx = ndctl_bus_get_ctx(bus);
	unsigned int ret_flags = 0;

	if (!papr_scm_cmd_valid(pcmd) || pcmd->cmd_status)
		return 0;

	if (pcmd->hdr.nd_command == DSM_PAPR_SCM_HEALTH) {

		ret_flags |= (ND_SMART_HEALTH_VALID | ND_SMART_SHUTDOWN_VALID);
		/*
		 * In case the command has an unsubmitted source command then
		 * submit it to the libndctl so that we can get
		 * 'life_used_percentage' from kernel
		 */
		if(cmd->source && ndctl_cmd_get_status(cmd->source) > 0) {

			ndctl_cmd_submit(cmd->source);
			pcmd = cmd_to_pcmd(cmd->source);
			if (ndctl_cmd_get_status(cmd->source) < 0 ||
			    pcmd->cmd_status < 0)
				info(ctx, "papr: Unable to fetch perf stats\n");
			else
				ret_flags |= ND_SMART_USED_VALID;
		}
	}

	return ret_flags;
}

static unsigned int papr_smart_get_health(struct ndctl_cmd *cmd)
{
	int rc;
	uint64_t health_bitmap;
	const struct nd_pkg_papr_scm * pcmd = cmd_to_pcmd(cmd);

	/* Get the health bitmap from the package */
	rc = pcmd_get_health_bitmap(pcmd, &health_bitmap);

	/* Parse the health bitmap and return correct ND_SMART_XX flag */
	if (rc < 0)
		return rc;
	else if (health_bitmap & ND_PAPR_SCM_DIMM_HEALTH_FATAL)
		return ND_SMART_FATAL_HEALTH;
	else if (health_bitmap & ND_PAPR_SCM_DIMM_HEALTH_CRITICAL)
		return ND_SMART_CRITICAL_HEALTH;
	else if ((health_bitmap & ND_PAPR_SCM_DIMM_HEALTH_UNHEALTHY) ||
		 (health_bitmap & ND_PAPR_SCM_DIMM_HEALTH_NON_CRITCAL))
		return ND_SMART_NON_CRITICAL_HEALTH;
	else
		return 0;
}

static unsigned int papr_smart_get_shutdown_state(struct ndctl_cmd *cmd)
{
	uint64_t health_bitmap;
	int rc;
	const struct nd_pkg_papr_scm * pcmd = cmd_to_pcmd(cmd);

	/* Get the health bitmap from the package */
	rc  = pcmd_get_health_bitmap(pcmd, &health_bitmap);

	if (rc < 0)
		return rc;
	else if (health_bitmap & ND_PAPR_SCM_DIMM_SHUTDOWN_DIRTY)
		return 1;
	else
		return 0;
}

static unsigned int papr_smart_get_life_used(struct ndctl_cmd * cmd)
{
	const struct nd_pkg_papr_scm * pcmd;
	const struct papr_scm_perf_stats * stats;

	cmd = cmd->source;
	pcmd = cmd_to_pcmd(cmd);

	/* Sanity checks */
	if (!papr_scm_cmd_valid(pcmd) ||
	    pcmd->cmd_status ||
	    pcmd->hdr.nd_command != DSM_PAPR_SCM_STATS)
		return 0;

	/* Get the stats info from the command payload */
	stats = (const struct papr_scm_perf_stats *) pcmd->payload;
	return 100 - stats->life_remaining;
}

struct ndctl_dimm_ops * const papr_dimm_ops = &(struct ndctl_dimm_ops) {
	.cmd_is_supported = papr_cmd_is_supported,
	.new_smart = papr_new_smart_health,
	.smart_get_flags = papr_smart_get_flags,
	.smart_get_health = papr_smart_get_health,
	.smart_get_shutdown_state = papr_smart_get_shutdown_state,
	.smart_get_life_used = papr_smart_get_life_used,
	.xlat_firmware_status =  papr_xlat_firmware_status,
};
