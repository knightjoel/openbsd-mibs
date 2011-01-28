/*
 * $jwk$
 *
 *
 * Copyright (c) 2006-2007 Joel Knight <knight.joel@gmail.com>
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


#ifndef _MIBGROUP_SENSORSMIBOBJECTS_H
#define _MIBGROUP_SENSORSMIBOBJECTS_H

#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/sensors.h>

#define SENS_NUMBER		1
#define SENS_INDEX		2
#define SENS_DESCR		3
#define SENS_TYPE		4
#define SENS_DEVICE		5
#define SENS_VALUE		6
#define SENS_UNITS		7
#define SENS_STATUS		8

/* index an arbitrary number of sensors (not devices) */
#define SINDEX_MAX 100

config_require(util_funcs)

FindVarMethod var_sensors;
FindVarMethod var_sensors_table;


void		 init_sensorsMIBObjects(void);
void		 sensor_enumerate(struct sensordev *);
void		 sensor_desc(u_int, struct sensor *, char *, size_t);
int		 sensor_get(u_int, struct sensordev *, struct sensor *);
void		 sensor_units(struct sensor *, char *);
void		 sensor_value(struct sensor *, char *);
void		 sensor_refresh(void);
unsigned char	*var_sensors(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_sensors_table(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);

#endif /* _MIBGROUP_SENSORSMIBOBJECTS_H */

