/*
 * $jwk$
 *
 *
 * Copyright (c) 2006-2011 Joel Knight <knight.joel@gmail.com>
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


#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/sensors.h>
#include <errno.h>
#include <string.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "sensorsMIBObjects.h"

unsigned int num_sensors = 0;
int **sindex;

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
	int i;

	if ((sindex = (int *)malloc(SINDEX_MAX * sizeof(int))) == NULL) {
		snmp_log(LOG_ERR, "init_sensorsMIBObjects: malloc: %s\n", 
				strerror(errno));
		snmp_log(LOG_ERR, "sensorsMIBObjects not loaded\n");
		return;
	}
	for (i = 0; i < SINDEX_MAX; i++) {
		if ((sindex[i] = (int *)malloc(3 * sizeof(int))) == NULL) {
			snmp_log(LOG_ERR, 
					"init_sensorsMIBObjects: malloc: %s\n", 
					strerror(errno));
			snmp_log(LOG_ERR, "sensorsMIBObjects not loaded\n");
			free(sindex);
			return;
		}
	}

	REGISTER_MIB("sensorsMIBObjects", sensorsMIBObjects_variables,
			variable4, sensorsMIBObjects_variables_oid);
}

unsigned char *
var_sensors(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	static u_long ulong_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	sensor_refresh();

	switch(vp->magic) {
		case SENS_NUMBER:
			ulong_ret = num_sensors;
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
	int index;
	struct sensor sensor;
	struct sensordev sdev;
	static u_long ulong_ret;
	static unsigned char str[BUFSIZ];

	sensor_refresh();

	if (num_sensors == 0)
		return (NULL);

	if (header_simple_table(vp, name, length, exact, var_len,
				write_method, num_sensors)
			== MATCH_FAILED)
		return (NULL);

	index = name[*length-1]-1;
	if (sensor_get(index, &sdev, &sensor))
		return (NULL);

	switch (vp->magic) {
		case SENS_INDEX:
			ulong_ret = name[*length-1];
			return (unsigned char *) &ulong_ret;
		case SENS_DESCR:
			sensor_desc(index, &sensor, str, BUFSIZ);
			*var_len = strlen(str);
			return (unsigned char *) str;
		case SENS_TYPE:
			ulong_ret = sensor.type;
			return (unsigned char *) &ulong_ret;
		case SENS_DEVICE:
			if ((*var_len = strlcpy(str, sdev.xname, BUFSIZ)) !=
					strlen(sdev.xname))
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

void
sensor_refresh(void)
{
	struct sensordev sdev;
	int mib[3], i;
	size_t len;

	mib[0] = CTL_HW;
	mib[1] = HW_SENSORS;
	len = sizeof(struct sensordev);

	num_sensors = 0;

	for (i = 0; ; i++) {
		mib[2] = i;
		if (sysctl(mib, 3, &sdev, &len, NULL, 0) == -1) {
			if (errno == ENXIO)
				continue;
			if (errno == ENOENT)
				break;
			if (errno != ENOENT)
				snmp_log(LOG_DEBUG,
					"sensor_refresh: sysctl: %s\n",
					strerror(errno));
			continue;
		}
		sensor_enumerate(&sdev);
	}
}

void
sensor_enumerate(struct sensordev *sdev)
{
	struct sensor s;
	int mib[5], type, idx;
	size_t len;

	mib[0] = CTL_HW;
	mib[1] = HW_SENSORS;
	mib[2] = sdev->num;

	/* iterate sensor types */
	for (type = 0; type < SENSOR_MAX_TYPES; type++) {
		mib[3] = type;
		/* iterate each sensor of type 'type' */
		for (idx = 0; idx < sdev->maxnumt[type]; idx++) {
			mib[4] = idx;
			len = sizeof(struct sensor);
			if (sysctl(mib, 5, &s, &len, NULL, 0) == -1) {
				snmp_log(LOG_DEBUG,
					"sensor_enumerate: sysctl: %s\n",
					strerror(errno));
				continue;
			}
			if (len && (s.flags & SENSOR_FINVALID) == 0
				&& num_sensors < SINDEX_MAX) {
				sindex[num_sensors][0] = mib[2];
				sindex[num_sensors][1] = mib[3];
				sindex[num_sensors][2] = mib[4];
				num_sensors++;
			}
		}
	}
}

int
sensor_get(u_int index, struct sensordev *sdev, struct sensor *s)
{
	int mib[5];
	size_t len;

	mib[0] = CTL_HW;
	mib[1] = HW_SENSORS;
	mib[2] = sindex[index][0];
	mib[3] = sindex[index][1];
	mib[4] = sindex[index][2];

	len = sizeof(struct sensordev);
	if (sysctl(mib, 3, sdev, &len, NULL, 0) == -1) {
		if (errno == ENOENT)
			return (-1);
		else
			return (1);
	}

	len = sizeof(struct sensor);
	if (sysctl(mib, 5, s, &len, NULL, 0) == -1) {
		if (errno == ENOENT)
			return (-1);
		else
			return (1);
	}

	return (0);
}

void
sensor_desc(u_int index, struct sensor *s, char *desc, size_t len)
{
	if (strlen(s->desc) == 0) {
		snprintf(desc, len, "%s%d", 
			sensor_type_s[s->type], sindex[index][2]);
	} else {
		snprintf(desc, len, "%s", s->desc);
	}
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

