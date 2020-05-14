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
#include <util/log.h>
#include <util/util.h>
#include <ndctl.h>
#include <ndctl/libndctl.h>
#include <lib/private.h>
#include <papr_scm_pdsm.h>

/* Utility logging maros for simplify logging */
#define papr_dbg(_dimm_, _format_str_, ...) dbg(_dimm_->bus->ctx,	\
					      "papr_scm:"#_format_str_,	\
					      ##__VA_ARGS__)
#define papr_err(_dimm_, _format_str_, ...) err(_dimm_->bus->ctx,	\
					      "papr_scm:"#_format_str_,	\
					      ##__VA_ARGS__)

/* Helpers to evaluate the size of PDSM envelope */
/* Calculate the papr_scm-header size */
#define ND_PDSM_ENVELOPE_CONTENT_HDR_SIZE \
	(sizeof(struct nd_pdsm_cmd_pkg) - sizeof(struct nd_cmd_pkg))

/* Given a type calculate envelope-content size (papr_scm-header + payload) */
#define ND_PDSM_ENVELOPE_CONTENT_SIZE(_type_)	\
	(sizeof(_type_) + ND_PDSM_ENVELOPE_CONTENT_HDR_SIZE)

/* Command flags to indicate if a given command is parsed of not */
#define CMD_PKG_SUBMITTED 1
#define CMD_PKG_PARSED 2

/* Number of bytes to transffer in each ioctl for pdsm READ_PERF_STATS */
#define GET_PERF_STAT_XFER_SIZE 16

/* Per dimm data. Holds per-dimm data parsed from the cmd_pkgs */
struct dimm_priv {

	/* Cache the dimm health status */
	struct nd_papr_pdsm_health health;

	/* Cache the dimm perf-stats buffer, length in bytes, count */
	ssize_t len_perf_stats;
	ssize_t count_perf_stats;
	struct nd_pdsm_perf_stat *perf_stats;
};

static bool papr_cmd_is_supported(struct ndctl_dimm *dimm, int cmd)
{
	/* Handle this separately to support monitor mode */
	if (cmd == ND_CMD_SMART)
		return true;

	return !!(dimm->cmd_mask & (1ULL << cmd));
}

static __u64 pcmd_to_pdsm(const struct nd_pdsm_cmd_pkg *pcmd)
{
	return pcmd->hdr.nd_command;
}

static u32 papr_get_firmware_status(struct ndctl_cmd *cmd)
{
	const struct nd_pdsm_cmd_pkg *pcmd = nd_to_pdsm_cmd_pkg(cmd->pkg);

	return (u32) pcmd->cmd_status;
}

/* Verify if the given command is supported and valid */
static bool cmd_is_valid(struct ndctl_dimm *dimm, struct ndctl_cmd *cmd)
{
	const struct nd_pdsm_cmd_pkg *pcmd = nd_to_pdsm_cmd_pkg(cmd->pkg);

	if (dimm == NULL)
		return false;

	if (cmd == NULL) {
		papr_err(dimm, "Invalid command\n");
		return false;
	}

	/* Verify the command family */
	if (pcmd->hdr.nd_family != NVDIMM_FAMILY_PAPR_SCM) {
		papr_err(dimm, "Invalid command family:0x%016llx\n",
			 pcmd->hdr.nd_family);
		return false;
	}

	/* Verify the PDSM */
	if (pcmd_to_pdsm(pcmd) <= PAPR_SCM_PDSM_MIN ||
	    pcmd_to_pdsm(pcmd) >= PAPR_SCM_PDSM_MAX) {
		papr_err(dimm, "Invalid command :0x%016llx\n",
			 pcmd->hdr.nd_command);
		return false;
	}

	return true;
}

/*
 * Parse the nd_papr_pdsm_health_v1 payload embedded in ndctl_cmd and
 * update dimm health/flags
 */
static int update_dimm_health_v1(struct ndctl_dimm *dimm, struct ndctl_cmd *cmd)
{
	struct nd_pdsm_cmd_pkg *pcmd = nd_to_pdsm_cmd_pkg(cmd->pkg);
	struct dimm_priv *p = dimm->dimm_user_data;
	const struct nd_papr_pdsm_health_v1 *health =
		pdsm_cmd_to_payload(pcmd);

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
	const struct nd_pdsm_cmd_pkg *pcmd = nd_to_pdsm_cmd_pkg(cmd->pkg);

	if (pcmd->payload_version == 1)
		return update_dimm_health_v1(dimm, cmd);

	/* unknown version */
	papr_err(dimm, "Unknown payload version for dimm_health.\n");
	papr_dbg(dimm, "dimm_health payload Ver=%d, Supported=%d\n",
		 pcmd->payload_version, ND_PAPR_PDSM_HEALTH_VERSION);
	return -EINVAL;
}

/* Parse the PAPR_SCM_PDSM_FETCH_PERF_STATS command package */
static int update_perf_stat_size(struct ndctl_dimm *dimm, struct ndctl_cmd *cmd)
{
	struct nd_pdsm_cmd_pkg *pcmd = nd_to_pdsm_cmd_pkg(cmd->pkg);
	struct dimm_priv *p = dimm->dimm_user_data;
	const struct nd_pdsm_fetch_perf_stats * psize =
		pdsm_cmd_to_payload(pcmd);

	/* is it an unknown version */
	if (pcmd->payload_version != 1) {
		papr_err(dimm, "Unknown payload version for perf stat size\n");
		return -EBADE;
	}

	/* Update the perf_size and reallocate the buffer if needed */
	if (p->len_perf_stats < psize->max_stats_size) {
		struct nd_pdsm_perf_stat *new_stats, *old_stats;
		old_stats = p->perf_stats;

		new_stats = (struct nd_pdsm_perf_stat *)
			calloc(1, psize->max_stats_size);
		if (!new_stats) {
			papr_err(dimm, "Unable to allocate new perf_stats buffer\n");
			return -ENOMEM;
		}
		if (old_stats) {
			/* Copy the old buffer contents to new */
			memcpy(new_stats, old_stats, p->len_perf_stats);
			free(old_stats);
		}
		p->perf_stats = new_stats;
	}

	p->len_perf_stats = psize->max_stats_size;
	papr_dbg(dimm, "dimm perf stats size =%lu\n",
		 p->len_perf_stats);
	return 0;
}

/* Parse a command payload and update dimm flags/private data */
static int update_dimm_stats(struct ndctl_dimm *dimm, struct ndctl_cmd *cmd)
{
	const struct nd_pdsm_cmd_pkg *pcmd;

	if (!cmd_is_valid(dimm, cmd))
		return -EINVAL;

	/*
	 * Silently prevent parsing of an already parsed ndctl_cmd else
	 * mark the command as parsed.
	 */
	if (cmd->status >= CMD_PKG_PARSED) {
		return 0;
	} else if (cmd->status < 0) {
		papr_err(dimm, "Command error %d\n", cmd->status);
		return -ENXIO;
	}

	/* Mark the command as parsed */
	cmd->status = CMD_PKG_PARSED;

	/* Get the pdsm request and handle it */
	pcmd = nd_to_pdsm_cmd_pkg(cmd->pkg);
	switch (pcmd_to_pdsm(pcmd)) {
	case PAPR_SCM_PDSM_HEALTH:
		return update_dimm_health(dimm, cmd);
	case PAPR_SCM_PDSM_FETCH_PERF_STATS:
		return update_perf_stat_size(dimm, cmd);
	default:
		papr_err(dimm, "Unhandled pdsm-request 0x%016llx\n",
			 pcmd_to_pdsm(pcmd));
		return -ENOENT;
	}
}

/* Allocate a struct ndctl_cmd for given pdsm request with payload size */
static struct ndctl_cmd *allocate_cmd(struct ndctl_dimm *dimm,
				      __u64 pdsm_cmd, size_t payload_size,
				      uint16_t payload_version)
{
	struct ndctl_cmd *cmd;
	struct nd_pdsm_cmd_pkg *pcmd;
	size_t size;

	size = sizeof(struct ndctl_cmd) +
		sizeof(struct nd_pdsm_cmd_pkg) + payload_size;
	cmd = calloc(1, size);
	if (!cmd)
		return NULL;
	pcmd = nd_to_pdsm_cmd_pkg(cmd->pkg);

	ndctl_cmd_ref(cmd);
	cmd->dimm = dimm;
	cmd->type = ND_CMD_CALL;
	cmd->size = size;
	cmd->status = CMD_PKG_SUBMITTED;
	cmd->get_firmware_status = &papr_get_firmware_status;

	/* Populate the nd_cmd_pkg contained in nd_pdsm_cmd_pkg */
	pcmd->hdr.nd_family = NVDIMM_FAMILY_PAPR_SCM;
	pcmd->hdr.nd_command = pdsm_cmd;

	pcmd->payload_version = payload_version;
	pcmd->payload_offset = sizeof(struct nd_pdsm_cmd_pkg);

	/* Keep payload size empty. To be populated by called */
	pcmd->hdr.nd_fw_size = 0;
	pcmd->hdr.nd_size_out = 0;
	pcmd->hdr.nd_size_in = 0;

	return cmd;
}

static struct ndctl_cmd *papr_new_smart_health(struct ndctl_dimm *dimm)
{
	struct ndctl_cmd *cmd_ret;

	cmd_ret = allocate_cmd(dimm, PAPR_SCM_PDSM_HEALTH,
			       sizeof(struct nd_papr_pdsm_health),
			       ND_PAPR_PDSM_HEALTH_VERSION);
	if (!cmd_ret) {
		papr_err(dimm, "Unable to allocate smart_health command\n");
		return NULL;
	}

	cmd_ret->pkg[0].nd_size_out = ND_PDSM_ENVELOPE_CONTENT_SIZE(
		struct nd_papr_pdsm_health);

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
		papr_dbg(dimm, "Dimm already initialized !!\n");
		return 0;
	}

	p = calloc(1, sizeof(struct dimm_priv));
	if (!p) {
		papr_err(dimm, "Unable to allocate memory for dimm-private\n");
		return -1;
	}

	dimm->dimm_user_data = p;
	return 0;
}

static void papr_dimm_uninit(struct ndctl_dimm *dimm)
{
	struct dimm_priv *p = dimm->dimm_user_data;

	if (!p) {
		papr_dbg(dimm, "Dimm already un-initialized !!\n");
		return;
	}

	if (p->perf_stats)
		free(p->perf_stats);

	dimm->dimm_user_data = NULL;
	free(p);
}

/*
 * Check if the given command is of type PDSM_READ_PERF_STATS and return
 * 'struct nd_pdsm_read_perf_stats *' otherwise return NULL.
 */
static struct nd_pdsm_read_perf_stats *cmd_to_read_perf(struct ndctl_cmd *cmd)
{
	struct nd_pdsm_cmd_pkg *pcmd = nd_to_pdsm_cmd_pkg(cmd->pkg);

	if (cmd && cmd_is_valid(cmd->dimm, cmd) &&
	    pcmd_to_pdsm(pcmd) == PAPR_SCM_PDSM_READ_PERF_STATS)
		return (struct nd_pdsm_read_perf_stats *)
			(pdsm_cmd_to_payload(pcmd));
	else
		return NULL;
}

/* Callbacks from libndctl core to handle iterable read_perf_stats command */
static u32 papr_get_xfer(struct ndctl_cmd *cmd)
{
	struct nd_pdsm_read_perf_stats *stats = cmd_to_read_perf(cmd);
	if (stats == NULL)
		papr_err(cmd->dimm, "Invalid command\n");
	return stats ? stats->in_length : 0;
}

static u32 papr_get_offset(struct ndctl_cmd *cmd)
{
	struct nd_pdsm_read_perf_stats *stats = cmd_to_read_perf(cmd);
	if (stats == NULL)
		papr_err(cmd->dimm, "Invalid command\n");
	return stats ? stats->in_offset : 0;
}

static void papr_set_xfer(struct ndctl_cmd *cmd, u32 xfer)
{
	struct nd_pdsm_read_perf_stats *stats = cmd_to_read_perf(cmd);
	if (stats == NULL)
		papr_err(cmd->dimm, "Invalid command\n");
	stats->in_length = xfer;
}

static void papr_set_offset(struct ndctl_cmd *cmd, u32 offset)
{
	struct nd_pdsm_read_perf_stats *stats = cmd_to_read_perf(cmd);
	if (stats == NULL)
		papr_err(cmd->dimm, "Invalid command\n");
	stats->in_offset = offset;
}

/* Fetch dimm stats and return a command to read them */
static struct ndctl_cmd * papr_new_stats(struct ndctl_dimm * dimm)
{
	struct dimm_priv * p = dimm->dimm_user_data;
	struct ndctl_cmd * cmd = NULL;
	int rc;

	/*
	 * Submit a pdsm FETCH_PERF_STATS to get the latest stats fetched from
	 * PHYP and have their length returned to libndctl. Next allocate
	 * suitable size buffer in dimm private buffer 'perf_stats' and create
	 * an iterable command for pdsm READ_PERF_STATS to read these stats
	 * from kernel to 'perf_stats'
	 */
	cmd = allocate_cmd(dimm, PAPR_SCM_PDSM_FETCH_PERF_STATS,
			   sizeof (struct nd_pdsm_fetch_perf_stats),
			   ND_PDSM_FETCH_PERF_STATS_VERSION);
	if (!cmd) {
		papr_err(dimm, "Unable to allocate cmd for perf_stats size\n");
		return NULL;
	}

	papr_dbg(dimm, "Fetching dimm stats from papr_scm\n");
	cmd->pkg[0].nd_size_out = ND_PDSM_ENVELOPE_CONTENT_SIZE(
		struct nd_pdsm_fetch_perf_stats);

	/* If successful update the dimm data with length of dimm stats */
	rc = ndctl_cmd_submit_xlat(cmd);
	rc = rc ? rc : update_dimm_stats(dimm, cmd);

	ndctl_cmd_unref(cmd);
	if (rc) {
		papr_err(dimm, "Error fetching perf stats. Err=%d\n", rc);
		return NULL;
	}

	/* allocate pdsm READ_PERF_STATS command having tail xfer buffer */
	cmd = allocate_cmd(dimm, PAPR_SCM_PDSM_READ_PERF_STATS,
			   sizeof(struct nd_pdsm_read_perf_stats) + GET_PERF_STAT_XFER_SIZE,
			   ND_PDSM_READ_PERF_STATS_VERSION);
	if (!cmd) {
		papr_err(dimm, "Unable to allocated read_perf_stats cmd\n");
		return NULL;
	}	/* Update the expected out size from the papr_scm module */

        cmd->pkg[0].nd_size_out =
		ND_PDSM_ENVELOPE_CONTENT_SIZE(struct nd_pdsm_read_perf_stats) +
		GET_PERF_STAT_XFER_SIZE;

        /* Setup the iterators */
	cmd->iter.total_buf = (char *) p->perf_stats;
	cmd->iter.init_offset = 0;
	cmd->iter.max_xfer = GET_PERF_STAT_XFER_SIZE;
	cmd->iter.total_xfer = p->len_perf_stats;
	cmd->iter.dir = READ;
	cmd->iter.data = (u8*)cmd_to_read_perf(cmd)->stats_data;

	/* setup the callbacks */
	cmd->get_xfer = papr_get_xfer;
	cmd->get_offset = papr_get_offset;
	cmd->set_xfer = papr_set_xfer;
	cmd->set_offset = papr_set_offset;

	return cmd;
}

struct ndctl_dimm_ops * const papr_scm_dimm_ops = &(struct ndctl_dimm_ops) {
	.cmd_is_supported = papr_cmd_is_supported,
	.dimm_init = papr_dimm_init,
	.dimm_uninit = papr_dimm_uninit,
	.smart_get_flags = papr_smart_get_flags,
	.get_firmware_status =  papr_get_firmware_status,
	.new_smart = papr_new_smart_health,
	.smart_get_health = papr_smart_get_health,
	.smart_get_shutdown_state = papr_smart_get_shutdown_state,
	.new_stats = papr_new_stats,
};
