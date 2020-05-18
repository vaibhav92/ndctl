/*
 * Copyright(c) 2015-2017 Intel Corporation. All rights reserved.
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
#include <limits.h>
#include <util/json.h>
#include <uuid/uuid.h>
#include <json-c/json.h>
#include <ndctl/libndctl.h>
#include <ccan/array_size/array_size.h>
#include <ndctl.h>

static void smart_threshold_to_json(struct ndctl_dimm *dimm,
		struct json_object *jhealth)
{
	unsigned int alarm_control;
	struct json_object *jobj;
	struct ndctl_cmd *cmd;
	int rc;

	cmd = ndctl_dimm_cmd_new_smart_threshold(dimm);
	if (!cmd)
		return;

	rc = ndctl_cmd_submit_xlat(cmd);
	if (rc < 0)
		goto out;

	alarm_control = ndctl_cmd_smart_threshold_get_alarm_control(cmd);
	if (alarm_control & ND_SMART_TEMP_TRIP) {
		unsigned int temp;
		double t;

		jobj = json_object_new_boolean(true);
		if (jobj)
			json_object_object_add(jhealth,
				"alarm_enabled_media_temperature", jobj);
		temp = ndctl_cmd_smart_threshold_get_temperature(cmd);
		t = ndctl_decode_smart_temperature(temp);
		jobj = json_object_new_double(t);
		if (jobj)
			json_object_object_add(jhealth,
				"temperature_threshold", jobj);
	} else {
		jobj = json_object_new_boolean(false);
		if (jobj)
			json_object_object_add(jhealth,
				"alarm_enabled_media_temperature", jobj);
	}

	if (alarm_control & ND_SMART_CTEMP_TRIP) {
		unsigned int temp;
		double t;

		jobj = json_object_new_boolean(true);
		if (jobj)
			json_object_object_add(jhealth,
				"alarm_enabled_ctrl_temperature", jobj);
		temp = ndctl_cmd_smart_threshold_get_ctrl_temperature(cmd);
		t = ndctl_decode_smart_temperature(temp);
		jobj = json_object_new_double(t);
		if (jobj)
			json_object_object_add(jhealth,
				"controller_temperature_threshold", jobj);
	} else {
		jobj = json_object_new_boolean(false);
		if (jobj)
			json_object_object_add(jhealth,
				"alarm_enabled_ctrl_temperature", jobj);
	}

	if (alarm_control & ND_SMART_SPARE_TRIP) {
		unsigned int spares;

		jobj = json_object_new_boolean(true);
		if (jobj)
			json_object_object_add(jhealth,
				"alarm_enabled_spares", jobj);
		spares = ndctl_cmd_smart_threshold_get_spares(cmd);
		jobj = json_object_new_int(spares);
		if (jobj)
			json_object_object_add(jhealth,
				"spares_threshold", jobj);
	} else {
		jobj = json_object_new_boolean(false);
		if (jobj)
			json_object_object_add(jhealth,
				"alarm_enabled_spares", jobj);
	}

 out:
	ndctl_cmd_unref(cmd);
}

struct json_object *util_dimm_health_to_json(struct ndctl_dimm *dimm)
{
	struct json_object *jhealth = json_object_new_object();
	struct json_object *jobj;
	struct ndctl_cmd *cmd;
	unsigned int flags;
	int rc;

	if (!jhealth)
		return NULL;

	cmd = ndctl_dimm_cmd_new_smart(dimm);
	if (!cmd)
		goto err;

	rc = ndctl_cmd_submit_xlat(cmd);
	if (rc < 0) {
		jobj = json_object_new_string("unknown");
		if (jobj)
			json_object_object_add(jhealth, "health_state", jobj);
		goto out;
	}

	flags = ndctl_cmd_smart_get_flags(cmd);
	if (flags & ND_SMART_HEALTH_VALID) {
		unsigned int health = ndctl_cmd_smart_get_health(cmd);

		if (health & ND_SMART_FATAL_HEALTH)
			jobj = json_object_new_string("fatal");
		else if (health & ND_SMART_CRITICAL_HEALTH)
			jobj = json_object_new_string("critical");
		else if (health & ND_SMART_NON_CRITICAL_HEALTH)
			jobj = json_object_new_string("non-critical");
		else
			jobj = json_object_new_string("ok");
		if (jobj)
			json_object_object_add(jhealth, "health_state", jobj);
	}

	if (flags & ND_SMART_TEMP_VALID) {
		unsigned int temp = ndctl_cmd_smart_get_temperature(cmd);
		double t = ndctl_decode_smart_temperature(temp);

		jobj = json_object_new_double(t);
		if (jobj)
			json_object_object_add(jhealth, "temperature_celsius", jobj);
	}

	if (flags & ND_SMART_CTEMP_VALID) {
		unsigned int temp = ndctl_cmd_smart_get_ctrl_temperature(cmd);
		double t = ndctl_decode_smart_temperature(temp);

		jobj = json_object_new_double(t);
		if (jobj)
			json_object_object_add(jhealth,
					"controller_temperature_celsius", jobj);
	}

	if (flags & ND_SMART_SPARES_VALID) {
		unsigned int spares = ndctl_cmd_smart_get_spares(cmd);

		jobj = json_object_new_int(spares);
		if (jobj)
			json_object_object_add(jhealth, "spares_percentage", jobj);
	}

	if (flags & ND_SMART_ALARM_VALID) {
		unsigned int alarm_flags = ndctl_cmd_smart_get_alarm_flags(cmd);
		bool temp_flag = !!(alarm_flags & ND_SMART_TEMP_TRIP);
		bool ctrl_temp_flag = !!(alarm_flags & ND_SMART_CTEMP_TRIP);
		bool spares_flag = !!(alarm_flags & ND_SMART_SPARE_TRIP);

		jobj = json_object_new_boolean(temp_flag);
		if (jobj)
			json_object_object_add(jhealth, "alarm_temperature", jobj);

		jobj = json_object_new_boolean(ctrl_temp_flag);
		if (jobj)
			json_object_object_add(jhealth, "alarm_controller_temperature", jobj);

		jobj = json_object_new_boolean(spares_flag);
		if (jobj)
			json_object_object_add(jhealth, "alarm_spares", jobj);
	}

	smart_threshold_to_json(dimm, jhealth);

	if (flags & ND_SMART_USED_VALID) {
		unsigned int life_used = ndctl_cmd_smart_get_life_used(cmd);

		jobj = json_object_new_int(life_used);
		if (jobj)
			json_object_object_add(jhealth, "life_used_percentage", jobj);
	}

	if (flags & ND_SMART_SHUTDOWN_VALID) {
		unsigned int shutdown = ndctl_cmd_smart_get_shutdown_state(cmd);

		jobj = json_object_new_string(shutdown ? "dirty" : "clean");
		if (jobj)
			json_object_object_add(jhealth, "shutdown_state", jobj);
	}

	if (flags & ND_SMART_SHUTDOWN_COUNT_VALID) {
		unsigned int shutdown = ndctl_cmd_smart_get_shutdown_count(cmd);

		jobj = json_object_new_int(shutdown);
		if (jobj)
			json_object_object_add(jhealth, "shutdown_count", jobj);
	}

	ndctl_cmd_unref(cmd);
	return jhealth;
 err:
	json_object_put(jhealth);
	jhealth = NULL;
 out:
	if (cmd)
		ndctl_cmd_unref(cmd);
	return jhealth;
}

struct json_object *util_dimm_stats_to_json(struct ndctl_dimm *dimm)
{
	struct json_object *jstat = json_object_new_object();
	struct json_object *jobj;
	struct ndctl_cmd *cmd;
	struct ndctl_dimm_stat stat = { 0 };
	char format_buffer[32] = { 0 };
	int rc;
	unsigned int flags;

	if (!jstat)
		return NULL;

	cmd = ndctl_dimm_cmd_new_stats(dimm);
	if (!cmd)
		goto err;

	rc = ndctl_cmd_submit_xlat(cmd);
	if (rc < 0) {
		jobj = json_object_new_string("unknown");
		if (jobj)
			json_object_object_add(jstat, "stats", jobj);
		goto out;
	}

	/* Check if any stats are reported */
	flags = ndctl_cmd_smart_get_flags(cmd);
	if (!(flags & ND_SMART_STATS_VALID))
		goto out;

	/* Iterate through the reported stats list */
	while (ndctl_dimm_get_stat(cmd, &stat) == 0) {
		switch(stat.type) {
		case STAT_TYPE_BOOL:
			jobj = json_object_new_boolean(stat.val.bool_val);
			break;
		case STAT_TYPE_INT:
			jobj = json_object_new_int(stat.val.int_val);
			break;
		case STAT_TYPE_INT64:
			jobj = json_object_new_int64(stat.val.int64_val);
			break;
		case STAT_TYPE_DOUBLE:
			jobj = json_object_new_double(stat.val.double_val);
			break;
		case STAT_TYPE_STR:
			jobj = json_object_new_string(stat.val.str_val);
			break;
		case STAT_TYPE_PERCENT:
			snprintf(format_buffer, sizeof(format_buffer) - 1,
				 "%u%%",stat.val.int_val);
			format_buffer[sizeof(format_buffer) - 1] = '\0';
			jobj = json_object_new_string(format_buffer);
			break;
		default:
			jobj = json_object_new_string("unknown-type");
			break;
		};

		if (jobj)
			json_object_object_add(jstat, stat.name, jobj);
	}
	ndctl_cmd_unref(cmd);
	return jstat;
 err:
	json_object_put(jstat);
	jstat = NULL;
 out:
	if (cmd)
		ndctl_cmd_unref(cmd);
	return jstat;
}
