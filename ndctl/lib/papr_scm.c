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
#include <papr_scm_dsm.h>

/* Utility logging maros for simplify logging */
#define PAPR_DBG(_dimm_, _format_str_, ...) dbg(_dimm_->bus->ctx,	\
					      "papr_scm:"#_format_str_,	\
					      ##__VA_ARGS__)
#define PAPR_INFO(_dimm_, _format_str_, ...) info(_dimm_->bus->ctx,	\
						"papr_scm:"#_format_str_, \
						##__VA_ARGS__)
#define PAPR_ERR(_dimm_, _format_str_, ...) err(_dimm_->bus->ctx,	\
					      "papr_scm:"#_format_str_,	\
					      ##__VA_ARGS__)
#define PAPR_NOTICE(_dimm_, _format_str_, ...) notice(_dimm_->bus->ctx,	\
						    "papr_scm:"#_format_str_, \
						    ##__VA_ARGS__)

/* Command flags to indicate if a given command is parsed of not */
#define CMD_PKG_SUBMITTED 1
#define CMD_PKG_PARSED 2

/* Per dimm data. Holds per-dimm data parsed from the cmd_pkgs */
struct dimm_priv {

	/* Cache the dimm health status */
	struct nd_papr_scm_dimm_health_stat health;
};

static bool papr_cmd_is_supported(struct ndctl_dimm *dimm, int cmd)
{
	/* Handle this separately to support monitor mode */
	if (cmd == ND_CMD_SMART)
		return true;

	return !!(dimm->cmd_mask & (1ULL << cmd));
}

static __u64 pcmd_to_dsm(const struct nd_papr_scm_cmd_pkg *pcmd)
{
	return pcmd->hdr.nd_command;
}

/* Verify if the given command is supported and valid */
static bool cmd_is_valid(struct ndctl_dimm *dimm, struct ndctl_cmd *cmd)
{
	const struct nd_papr_scm_cmd_pkg *pcmd = nd_to_papr_cmd_pkg(cmd->pkg);

	if (dimm == NULL)
		return false;

	if (cmd == NULL) {
		PAPR_ERR(dimm, "Invalid command\n");
		return false;
	}

	/* Verify the command family */
	if (pcmd->hdr.nd_family != NVDIMM_FAMILY_PAPR_SCM) {
		PAPR_ERR(dimm, "Invalid command family:0x%016llx\n",
			 pcmd->hdr.nd_family);
		return false;
	}

	/* Verify the DSM */
	if (pcmd_to_dsm(pcmd) <= DSM_PAPR_SCM_MIN ||
	    pcmd_to_dsm(pcmd) >= DSM_PAPR_SCM_MAX) {
		PAPR_ERR(dimm, "Invalid command :0x%016llx\n",
			 pcmd->hdr.nd_command);
		return false;
	}

	return true;
}

/*
 * Parse the nd_papr_scm_dimm_health_stat_v1 payload embedded in ndctl_cmd and
 * update dimm health/flags
 */
static int update_dimm_health_v1(struct ndctl_dimm *dimm, struct ndctl_cmd *cmd)
{
	struct nd_papr_scm_cmd_pkg *pcmd = nd_to_papr_cmd_pkg(cmd->pkg);
	struct dimm_priv *p = dimm->dimm_user_data;
	const struct nd_papr_scm_dimm_health_stat_v1 *health =
		papr_scm_pcmd_to_payload(pcmd);

	/* Update the dimm flags */
	dimm->flags.f_arm = health->dimm_unarmed;
	dimm->flags.f_flush = health->dimm_bad_shutdown;
	dimm->flags.f_restore = health->dimm_bad_restore;
	dimm->flags.f_smart = (health->dimm_health != 0);

	/* Cache the dimm health information */
	memcpy(&p->health, health, sizeof(*health));
	return 0;
}

/* Check payload version returned and pass the packet to appropriate handler */
static int update_dimm_health(struct ndctl_dimm *dimm, struct ndctl_cmd *cmd)
{
	const struct nd_papr_scm_cmd_pkg *pcmd = nd_to_papr_cmd_pkg(cmd->pkg);

	if (pcmd->payload_version == 1)
		return update_dimm_health_v1(dimm, cmd);

	/* unknown version */
	PAPR_ERR(dimm, "Unknown payload version for dimm_health."
		 "Ver=%d, Supported=%d\n", pcmd->payload_version,
		 ND_PAPR_SCM_DIMM_HEALTH_VERSION);
	return -EINVAL;
}

/* Parse a command payload and update dimm flags/private data */
static int update_dimm_stats(struct ndctl_dimm *dimm, struct ndctl_cmd *cmd)
{
	const struct nd_papr_scm_cmd_pkg *pcmd;

	if (!cmd_is_valid(dimm, cmd))
		return -EINVAL;

	/*
	 * Silently prevent parsing of an already parsed ndctl_cmd else
	 * mark the command as parsed.
	 */
	if (cmd->status >= CMD_PKG_PARSED) {
		return 0;
	} else if (cmd->status < 0) {
		PAPR_ERR(dimm, "Command error %d\n", cmd->status);
		return -ENXIO;
	}

	/* Mark the command as parsed */
	cmd->status = CMD_PKG_PARSED;

	/* Get the command dsm and handle it */
	pcmd = nd_to_papr_cmd_pkg(cmd->pkg);
	switch (pcmd_to_dsm(pcmd)) {
	case DSM_PAPR_SCM_HEALTH:
		return update_dimm_health(dimm, cmd);
	default:
		PAPR_ERR(dimm, "Unhandled dsm-command 0x%016llx\n",
			 pcmd_to_dsm(pcmd));
		return -ENOENT;
	}
}

/* Allocate a struct ndctl_cmd for given dsm command with payload size */
static struct ndctl_cmd *allocate_cmd(struct ndctl_dimm *dimm,
				      __u64 dsm_cmd, size_t payload_size,
				      uint16_t payload_version)
{
	struct ndctl_cmd *cmd;
	struct nd_papr_scm_cmd_pkg *pcmd;
	size_t size;

	size = sizeof(struct ndctl_cmd) +
		sizeof(struct nd_papr_scm_cmd_pkg) + payload_size;
	cmd = calloc(1, size);
	if (!cmd)
		return NULL;
	pcmd = nd_to_papr_cmd_pkg(cmd->pkg);

	ndctl_cmd_ref(cmd);
	cmd->dimm = dimm;
	cmd->type = ND_CMD_CALL;
	cmd->size = size;
	cmd->status = CMD_PKG_SUBMITTED;
	cmd->firmware_status = (u32 *) &pcmd->cmd_status;

	/* Populate the nd_cmd_pkg contained in nd_papr_scm_cmd_pkg */
	pcmd->hdr.nd_family = NVDIMM_FAMILY_PAPR_SCM;
	pcmd->hdr.nd_command = dsm_cmd;

	pcmd->payload_version = payload_version;
	pcmd->payload_offset = sizeof(struct nd_papr_scm_cmd_pkg);

	/* Keep payload size empty. To be populated by called */
	pcmd->hdr.nd_fw_size = 0;
	pcmd->hdr.nd_size_out = 0;
	pcmd->hdr.nd_size_in = 0;

	return cmd;
}

static struct ndctl_cmd *papr_new_smart_health(struct ndctl_dimm *dimm)
{
	struct ndctl_cmd *cmd_ret;

	cmd_ret = allocate_cmd(dimm, DSM_PAPR_SCM_HEALTH,
			       sizeof(struct nd_papr_scm_dimm_health_stat),
			       ND_PAPR_SCM_DIMM_HEALTH_VERSION);
	if (!cmd_ret) {
		PAPR_ERR(dimm, "Unable to allocate smart_health command\n");
		return NULL;
	}

	cmd_ret->pkg[0].nd_size_out = ND_PAPR_SCM_ENVELOPE_CONTENT_SIZE(
		struct nd_papr_scm_dimm_health_stat);

	return cmd_ret;
}

static unsigned int papr_smart_get_health(struct ndctl_cmd *cmd)
{
	struct dimm_priv *p = cmd->dimm->dimm_user_data;

	/*
	 * Update the dimm stats and use some math to return one of
	 * defined ND_SMART_*_HEALTH values
	 */
	if (update_dimm_stats(cmd->dimm, cmd) || !p->health.dimm_health)
		return 0;
	else
		return 1 << (p->health.dimm_health - 1);
}

static unsigned int papr_smart_get_shutdown_state(struct ndctl_cmd *cmd)
{
	struct dimm_priv *p = cmd->dimm->dimm_user_data;

	/* Update dimm state and return f_flush */
	return update_dimm_stats(cmd->dimm, cmd) ?
		0 : p->health.dimm_bad_shutdown;
}

static unsigned int papr_smart_get_flags(struct ndctl_cmd *cmd)
{
	/* In case of error return empty flags * */
	if (update_dimm_stats(cmd->dimm, cmd))
		return 0;

	return ND_SMART_HEALTH_VALID | ND_SMART_SHUTDOWN_VALID;
}

static int papr_dimm_init(struct ndctl_dimm *dimm)
{
	struct dimm_priv *p;

	if (dimm->dimm_user_data) {
		PAPR_DBG(dimm, "Dimm already initialized !!\n");
		return 0;
	}

	p = calloc(1, sizeof(struct dimm_priv));
	if (!p) {
		PAPR_ERR(dimm, "Unable to allocate memory for dimm-private\n");
		return -1;
	}

	dimm->dimm_user_data = p;
	return 0;
}

static void papr_dimm_uninit(struct ndctl_dimm *dimm)
{
	struct dimm_priv *p = dimm->dimm_user_data;

	if (!p) {
		PAPR_DBG(dimm, "Dimm already un-initialized !!\n");
		return;
	}

	dimm->dimm_user_data = NULL;
	free(p);
}

struct ndctl_dimm_ops * const papr_scm_dimm_ops = &(struct ndctl_dimm_ops) {
	.cmd_is_supported = papr_cmd_is_supported,
	.dimm_init = papr_dimm_init,
	.dimm_uninit = papr_dimm_uninit,
	.smart_get_flags = papr_smart_get_flags,
	.new_smart = papr_new_smart_health,
	.smart_get_health = papr_smart_get_health,
	.smart_get_shutdown_state = papr_smart_get_shutdown_state,
};
