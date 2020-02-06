// SPDX-License-Identifier: GPL-2.0

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include <util/log.h>
#include <ndctl.h>
#include <ndctl/libndctl.h>
#include <lib/private.h>

static bool papr_cmd_is_supported(struct ndctl_dimm *dimm, int cmd)
{
	/* Handle this separately to support monitor mode */
	if (cmd == ND_CMD_SMART)
		return true;

	return !!(dimm->cmd_mask & (1ULL << cmd));
}

struct ndctl_dimm_ops * const papr_dimm_ops = &(struct ndctl_dimm_ops) {
	.cmd_is_supported = papr_cmd_is_supported,
};
