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
#include <ndctl/builtin.h>
#include <ndctl/libndctl.h>
#include <ccan/array_size/array_size.h>

#include <util/parse-options.h>
#include <util/strbuf.h>
#include <util/util.h>
#include <util/main.h>

static const char ndctl_usage_string[] = "ndctl [--version] [--help] COMMAND [ARGS]";
static const char ndctl_more_info_string[] =
	"See 'ndctl help COMMAND' for more information on a specific command.\n"
	" ndctl --list-cmds to see all available commands";

static int cmd_version(int argc, const char **argv, struct ndctl_ctx *ctx)
{
	printf("%s\n", VERSION);
	return 0;
}

static int cmd_help(int argc, const char **argv, struct ndctl_ctx *ctx)
{
	const char * const builtin_help_subcommands[] = {
		"enable-region", "disable-region", "zero-labels",
		"enable-namespace", "disable-namespace", NULL };
	struct option builtin_help_options[] = {
		OPT_END(),
	};
	const char *builtin_help_usage[] = {
		"ndctl help [command]",
		NULL
	};

	argc = parse_options_subcommand(argc, argv, builtin_help_options,
			builtin_help_subcommands, builtin_help_usage, 0);

	if (!argv[0]) {
		printf("\n usage: %s\n\n", ndctl_usage_string);
		printf("\n %s\n\n", ndctl_more_info_string);
		return 0;
	}

	return help_show_man_page(argv[0], "ndctl", "NDCTL_MAN_VIEWER");
}

static struct cmd_struct commands[] = {
	{ "version", { cmd_version } },
	{ "create-nfit", { cmd_create_nfit } },
	{ "enable-namespace", { cmd_enable_namespace } },
	{ "disable-namespace", { cmd_disable_namespace } },
	{ "create-namespace", { cmd_create_namespace } },
	{ "destroy-namespace", { cmd_destroy_namespace } },
	{ "read-infoblock",  { cmd_read_infoblock } },
	{ "write-infoblock",  { cmd_write_infoblock } },
	{ "check-namespace", { cmd_check_namespace } },
	{ "clear-errors", { cmd_clear_errors } },
	{ "enable-region", { cmd_enable_region } },
	{ "disable-region", { cmd_disable_region } },
	{ "enable-dimm", { cmd_enable_dimm } },
	{ "disable-dimm", { cmd_disable_dimm } },
	{ "zero-labels", { cmd_zero_labels } },
	{ "read-labels", { cmd_read_labels } },
	{ "write-labels", { cmd_write_labels } },
	{ "init-labels", { cmd_init_labels } },
	{ "check-labels", { cmd_check_labels } },
	{ "inject-error", { cmd_inject_error } },
	{ "update-firmware", { cmd_update_firmware } },
	{ "inject-smart", { cmd_inject_smart } },
	{ "wait-scrub", { cmd_wait_scrub } },
	{ "start-scrub", { cmd_start_scrub } },
	{ "setup-passphrase", { cmd_setup_passphrase } },
	{ "update-passphrase", { cmd_update_passphrase } },
	{ "remove-passphrase", { cmd_remove_passphrase } },
	{ "freeze-security", { cmd_freeze_security } },
	{ "sanitize-dimm", { cmd_sanitize_dimm } },
#ifdef ENABLE_KEYUTILS
	{ "load-keys", { cmd_load_keys } },
#endif
	{ "wait-overwrite", { cmd_wait_overwrite } },
	{ "list", { cmd_list } },
	{ "monitor", { cmd_monitor } },
	{ "help", { cmd_help } },
	#ifdef ENABLE_TEST
	{ "test", { cmd_test } },
	#endif
	#ifdef ENABLE_DESTRUCTIVE
	{ "bat", { cmd_bat } },
	#endif
};

int main(int argc, const char **argv)
{
	struct ndctl_ctx *ctx;
	int rc, out;

	/* Look for flags.. */
	argv++;
	argc--;
	main_handle_options(&argv, &argc, ndctl_usage_string, commands,
			ARRAY_SIZE(commands));

	if (argc > 0) {
		if (!prefixcmp(argv[0], "--"))
			argv[0] += 2;
	} else {
		/* The user didn't specify a command; give them help */
		printf("\n usage: %s\n\n", ndctl_usage_string);
		printf("\n %s\n\n", ndctl_more_info_string);
		goto out;
	}

	rc = ndctl_new(&ctx);
	if (rc)
		goto out;
	rc = main_handle_internal_command(argc, argv, ctx, commands,
					  ARRAY_SIZE(commands), PROG_NDCTL,
					  &out);
	ndctl_unref(ctx);
	if (!rc)
		fprintf(stderr, "Unknown command: '%s'\n", argv[0]);

	return out;
out:
	return 1;
}
