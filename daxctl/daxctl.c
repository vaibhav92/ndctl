/*
 * Copyright(c) 2015-2017 Intel Corporation. All rights reserved.
 * Copyright(c) 2005 Andreas Ericsson. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

/* originally copied from perf and git */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <daxctl/libdaxctl.h>
#include <util/parse-options.h>
#include <ccan/array_size/array_size.h>

#include <util/strbuf.h>
#include <util/util.h>
#include <util/main.h>
#include <daxctl/builtin.h>

const char daxctl_usage_string[] = "daxctl [--version] [--help] COMMAND [ARGS]";
const char daxctl_more_info_string[] =
	"See 'daxctl help COMMAND' for more information on a specific command.\n"
	" daxctl --list-cmds to see all available commands";

static int cmd_version(int argc, const char **argv, struct daxctl_ctx *ctx)
{
	printf("%s\n", VERSION);
	return 0;
}

static int cmd_help(int argc, const char **argv, struct daxctl_ctx *ctx)
{
	const char * const builtin_help_subcommands[] = {
		"list", NULL,
	};
	struct option builtin_help_options[] = {
		OPT_END(),
	};
	const char *builtin_help_usage[] = {
		"daxctl help [command]",
		NULL
	};

	argc = parse_options_subcommand(argc, argv, builtin_help_options,
			builtin_help_subcommands, builtin_help_usage, 0);

	if (!argv[0]) {
		printf("\n usage: %s\n\n", daxctl_usage_string);
		printf("\n %s\n\n", daxctl_more_info_string);
		return 0;
	}

	return help_show_man_page(argv[0], "daxctl", "DAXCTL_MAN_VIEWER");
}

static struct cmd_struct commands[] = {
	{ "version", .d_fn = cmd_version },
	{ "list", .d_fn = cmd_list },
	{ "help", .d_fn = cmd_help },
	{ "migrate-device-model", .d_fn = cmd_migrate },
	{ "reconfigure-device", .d_fn = cmd_reconfig_device },
	{ "online-memory", .d_fn = cmd_online_memory },
	{ "offline-memory", .d_fn = cmd_offline_memory },
};

int main(int argc, const char **argv)
{
	struct daxctl_ctx *ctx;
	int rc, out;

	/* Look for flags.. */
	argv++;
	argc--;
	main_handle_options(&argv, &argc, daxctl_usage_string, commands,
			ARRAY_SIZE(commands));

	if (argc > 0) {
		if (!prefixcmp(argv[0], "--"))
			argv[0] += 2;
	} else {
		/* The user didn't specify a command; give them help */
		printf("\n usage: %s\n\n", daxctl_usage_string);
		printf("\n %s\n\n", daxctl_more_info_string);
		goto out;
	}

	rc = daxctl_new(&ctx);
	if (rc)
		goto out;
	rc = main_handle_internal_command(argc, argv, ctx, commands,
				     ARRAY_SIZE(commands), PROG_DAXCTL, &out);
	daxctl_unref(ctx);
	if (!rc)
		fprintf(stderr, "Unknown command: '%s'\n", argv[0]);

	return out;
out:
	return 1;
}
