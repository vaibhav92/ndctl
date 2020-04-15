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
#include <ndctl.h>
#include <ndctl/libndctl.h>
#include <lib/private.h>
#include <papr_scm_pdsm.h>

static bool papr_cmd_is_supported(struct ndctl_dimm *dimm, int cmd)
{
	/* Handle this separately to support monitor mode */
	if (cmd == ND_CMD_SMART)
		return true;

	return !!(dimm->cmd_mask & (1ULL << cmd));
}

struct ndctl_dimm_ops * const papr_scm_dimm_ops = &(struct ndctl_dimm_ops) {
	.cmd_is_supported = papr_cmd_is_supported,
};
