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


#ifndef _MIBGROUP_CARPMIBOBJECTS_H
#define _MIBGROUP_CARPMIBOBJECTS_H

#include <netinet/ip_carp.h>
#include <ifaddrs.h>


#define CARPIF_NUMBER		1
#define CARPIF_INDEX		2
#define CARPIF_DESCR		3
#define CARPIF_VHID		4
#define CARPIF_DEV		5
#define CARPIF_ADVBASE		6
#define CARPIF_ADVSKEW		7
#define CARPIF_STATE		8

config_require(util_funcs)

FindVarMethod var_carpif;
FindVarMethod var_carpif_table;

struct carpif {
	struct ifaddrs ifa;
	struct carpreq carpr;
};

void		 init_carpMIBObjects(void);
int		 carpif_count(void);
int		 carpif_get(int, struct carpif *);
unsigned char	*var_carpif(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_carpif_table(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);

#endif /* _MIBGROUP_CARPMIBOBJECTS_H */

