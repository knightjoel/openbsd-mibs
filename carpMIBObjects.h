/*
 * $jwk$
 *
 *
 * Copyright (c) 2006-2007 Joel Knight <enabled@myrealbox.com>
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


#define CARP_SYSCTL1		100
#define CARP_SYSCTL2		101
#define CARP_SYSCTL3		102
#define CARP_SYSCTL4		103
#define CARPIF_NUMBER		200
#define CARPIF_INDEX		201
#define CARPIF_DESCR		202
#define CARPIF_VHID		203
#define CARPIF_DEV		204
#define CARPIF_ADVBASE		205
#define CARPIF_ADVSKEW		206
#define CARPIF_STATE		207
#define CARP_IPRECV		220
#define CARP_IP6RECV		221
#define CARP_BADIF		222
#define CARP_BADTTL		223
#define CARP_HDROPS		224
#define CARP_BADCHKSUM		225
#define CARP_BADVER		226
#define CARP_TOOSHORT		227
#define CARP_BADAUTH		228
#define CARP_BADVHID		229
#define CARP_BADADDRS		230
#define CARP_IPSENT		231
#define CARP_IP6SENT		232
#define CARP_NOMEM		233

config_require(util_funcs)

FindVarMethod var_carpif;
FindVarMethod var_carpif_table;
FindVarMethod var_carp_stats;
FindVarMethod var_carp_sysctl;

struct carpif {
	struct ifaddrs ifa;
	struct carpreq carpr;
};


void		 init_carpMIBObjects(void);
int		 carpif_count(void);
int		 carpif_get(int, struct carpif *);
int		 carp_sysctl_get(int);
unsigned char	*var_carpif(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_carp_stats(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_carpif_table(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);

#endif /* _MIBGROUP_CARPMIBOBJECTS_H */

