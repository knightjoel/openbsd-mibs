/*
 * $jwk$
 *
 *
 * Copyright (c) 2006 Joel Knight <enabled@myrealbox.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */


#include <errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/sensors.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "sensorsMIBObjects.h"


oid sensorsMIBObjects_variables_oid[] = { 1,3,6,1,4,1,64512,2 };

struct variable4 sensorsMIBObjects_variables[] = {
/*  magic number        , variable type , ro/rw , callback fn  , L, oidsuffix */
  { SENS_NUMBER		, ASN_INTEGER	, RONLY	, var_sensors      , 2, { 1,1 } },
  { SENS_INDEX		, ASN_INTEGER	, RONLY , var_sensors_table, 4, { 1,2,1,1 } },
  { SENS_DESCR		, ASN_OCTET_STR	, RONLY , var_sensors_table, 4, { 1,2,1,2 } },
  { SENS_TYPE		, ASN_INTEGER	, RONLY , var_sensors_table, 4, { 1,2,1,3 } },
  { SENS_DEVICE		, ASN_OCTET_STR	, RONLY , var_sensors_table, 4, { 1,2,1,4 } },
  { SENS_VALUE		, ASN_OCTET_STR	, RONLY , var_sensors_table, 4, { 1,2,1,5 } },
  { SENS_UNITS		, ASN_OCTET_STR	, RONLY , var_sensors_table, 4, { 1,2,1,6 } },
  { SENS_STATUS		, ASN_INTEGER	, RONLY , var_sensors_table, 4, { 1,2,1,7 } },
};


void init_sensorsMIBObjects(void) {
	REGISTER_MIB("sensorsMIBObjects", sensorsMIBObjects_variables, variable4,
			sensorsMIBObjects_variables_oid);
}

unsigned char *
var_sensors(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	int cnt;
	static u_long ulong_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	if ((cnt = sensor_count()) == -1)
		return (NULL);

	switch(vp->magic) {
		case SENS_NUMBER:
			ulong_ret = cnt;
			break;
		default:
			return (NULL);
	}

	return ((unsigned char *) &ulong_ret);
}


unsigned char *
var_sensors_table(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	int index, cnt, rv;
	struct sensor sensor;
	static u_long ulong_ret;
	static unsigned char str[BUFSIZ];

	if ((cnt = sensor_count()) == -1)
		return (NULL);

	if (header_simple_table(vp, name, length, exact, var_len, write_method, cnt)
			== MATCH_FAILED)
		return (NULL);

	index = name[*length-1]-1;
	while ((rv = sensor_get(index, &sensor)) != 0) {
		if (rv < 0)
			index++;
		else
			return (NULL);
	}

	switch (vp->magic) {
		case SENS_INDEX:
			ulong_ret = name[*length-1];
			return (unsigned char *) &ulong_ret;
		case SENS_DESCR:
			if ((*var_len = strlcpy(str, sensor.desc, BUFSIZ)) !=
					strlen(sensor.desc))
				return (NULL);
			return (unsigned char *) str;
		case SENS_TYPE:
			ulong_ret = sensor.type;
			return (unsigned char *) &ulong_ret;
		case SENS_DEVICE:
			if ((*var_len = strlcpy(str, sensor.device, BUFSIZ)) !=
					strlen(sensor.device))
				return (NULL);
			return (unsigned char *) str;
		case SENS_VALUE:
			sensor_value(&sensor, str);
			*var_len = strlen(str);
			return (unsigned char *) str;
		case SENS_UNITS:
			sensor_units(&sensor, str);
			*var_len = strlen(str);
			return (unsigned char *) str;
		case SENS_STATUS:
			ulong_ret = sensor.status;
			return (unsigned char *) &ulong_ret;
		default:
			return (NULL);
	}
	
	/* NOTREACHED */
}

int
sensor_count(void)
{
	struct sensor sensor;
	int mib[3], i, count;
	size_t len;

	mib[0] = CTL_HW;
	mib[1] = HW_SENSORS;
	len = sizeof(sensor);
	count = 0;

	for (i = 0; i < 256; i++) {
		mib[2] = i;
		if (sysctl(mib, 3, &sensor, &len, NULL, 0) == -1) {
			if (errno != ENOENT)
				return (-1);
			else if (errno == ENOENT)
				continue;
		}
		if (sensor.flags & SENSOR_FINVALID)
			continue;
		count++;
	}

	return (count);
}

int
sensor_get(int index, struct sensor *s)
{
	int mib[3];
	size_t len;

	mib[0] = CTL_HW;
	mib[1] = HW_SENSORS;
	mib[2] = index;
	len = sizeof(struct sensor);

	if (sysctl(mib, 3, s, &len, NULL, 0) == -1) {
		if (errno == ENOENT)
			return (-1);
		else
			return (1);
	}
	if (s->flags & SENSOR_FINVALID)
		return (-1);

	return (0);
}

void
sensor_units(struct sensor *s, char *units)
{
	switch (s->type) {
	case SENSOR_TEMP:
		snprintf(units, BUFSIZ, "degC");
		break;
	case SENSOR_FANRPM:
		snprintf(units, BUFSIZ, "RPM");
		break;
	case SENSOR_VOLTS_DC:
		snprintf(units, BUFSIZ, "V DC");
		break;
	case SENSOR_AMPS:
		snprintf(units, BUFSIZ, "A");
		break;
	case SENSOR_WATTHOUR:
		snprintf(units, BUFSIZ, "Wh");
		break;
	case SENSOR_AMPHOUR:
		snprintf(units, BUFSIZ, "Ah");
		break;
	case SENSOR_INTEGER:
		snprintf(units, BUFSIZ, "raw");
		break;
	case SENSOR_PERCENT:
		snprintf(units, BUFSIZ, "%");
		break;
	case SENSOR_LUX:
		snprintf(units, BUFSIZ, "lx");
		break;
	case SENSOR_DRIVE:
	case SENSOR_INDICATOR:
		snprintf(units, BUFSIZ, "");
		break;
	default:
		snprintf(units, BUFSIZ, "unknown");
		break;
	}
}

void
sensor_value(struct sensor *s, char *v)
{
	switch (s->type) {
	case SENSOR_TEMP:
		snprintf(v, BUFSIZ, "%.2f", (s->value - 273150000) / 1000000.0);
		break;
	case SENSOR_DRIVE:
	case SENSOR_FANRPM:
	case SENSOR_INTEGER:
	case SENSOR_INDICATOR:
		snprintf(v, BUFSIZ, "%.0f", s->value / 1.0);
		break;
	case SENSOR_AMPHOUR:
	case SENSOR_AMPS:
	case SENSOR_LUX:
	case SENSOR_VOLTS_DC:
	case SENSOR_WATTHOUR:
		snprintf(v, BUFSIZ, "%.2f", s->value / 1000000.0);
		break;
	case SENSOR_PERCENT:
		snprintf(v, BUFSIZ, "%.0f", s->value / 1000.0);
		break;
	default:
		snprintf(v, BUFSIZ, "0");
		break;
	}
}

