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


#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/ip_carp.h>

#include <kvm.h>
#include <errno.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "carpMIBObjects.h"


oid carpMIBObjects_variables_oid[] = { 1,3,6,1,4,1,64512,3 };

struct variable4 carpMIBObjects_variables[] = {
/*  magic number        , variable type , ro/rw , callback fn  , L, oidsuffix */
  { CARP_SYSCTL1	, ASN_INTEGER	, RONLY	, var_carp_sysctl , 2, { 1,1 } },
  { CARP_SYSCTL2	, ASN_INTEGER	, RONLY	, var_carp_sysctl , 2, { 1,2 } },
  { CARP_SYSCTL3	, ASN_INTEGER	, RONLY	, var_carp_sysctl , 2, { 1,3 } },
  { CARP_SYSCTL4	, ASN_INTEGER	, RONLY	, var_carp_sysctl , 2, { 1,4 } },
  { CARPIF_NUMBER	, ASN_INTEGER	, RONLY	, var_carpif      , 2, { 2,1 } },
  { CARPIF_INDEX	, ASN_INTEGER	, RONLY , var_carpif_table, 4, { 2,2,1,1 } },
  { CARPIF_DESCR	, ASN_OCTET_STR	, RONLY , var_carpif_table, 4, { 2,2,1,2 } },
  { CARPIF_VHID		, ASN_INTEGER	, RONLY , var_carpif_table, 4, { 2,2,1,3 } },
  { CARPIF_DEV		, ASN_OCTET_STR	, RONLY , var_carpif_table, 4, { 2,2,1,4 } },
  { CARPIF_ADVBASE	, ASN_INTEGER	, RONLY , var_carpif_table, 4, { 2,2,1,5 } },
  { CARPIF_ADVSKEW	, ASN_INTEGER	, RONLY , var_carpif_table, 4, { 2,2,1,6 } },
  { CARPIF_STATE	, ASN_INTEGER	, RONLY , var_carpif_table, 4, { 2,2,1,7 } },
  { CARP_IPRECV		, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,1 } },
  { CARP_IP6RECV	, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,2 } },
  { CARP_BADIF		, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,3 } },
  { CARP_BADTTL		, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,4 } },
  { CARP_HDROPS		, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,5 } },
  { CARP_BADCHKSUM	, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,6 } },
  { CARP_BADVER		, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,7 } },
  { CARP_TOOSHORT	, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,8 } },
  { CARP_BADAUTH	, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,9 } },
  { CARP_BADVHID	, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,10 } },
  { CARP_BADADDRS	, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,11 } },
  { CARP_IPSENT		, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,12 } },
  { CARP_IP6SENT	, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,13 } },
  { CARP_NOMEM		, ASN_COUNTER64	, RONLY , var_carp_stats,   2, { 3,14 } },
};


void init_carpMIBObjects(void) {
	extern kvm_t *kd;

	if (kvm_nlist(kd, nl)) {
		snmp_log(LOG_ERR, "init_carpMIBObjects: no namelist\n");
		return;
	}

	REGISTER_MIB("carpMIBObjects", carpMIBObjects_variables, variable4,
			carpMIBObjects_variables_oid);
}

unsigned char *
var_carpif(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	int cnt;
	static u_long ulong_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	switch(vp->magic) {
		case CARPIF_NUMBER:
			if ((cnt = carpif_count()) == -1)
				return (NULL);
			ulong_ret = cnt;
			break;
		default:
			return (NULL);
	}

	return ((unsigned char *) &ulong_ret);
}


unsigned char *
var_carpif_table(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	int index, cnt;
	struct carpif carp;
	static u_long ulong_ret;
	static char ifname[IFNAMSIZ];

	if ((cnt = carpif_count()) == -1)
		return (NULL);

	if (header_simple_table(vp, name, length, exact, var_len, write_method, cnt)
			== MATCH_FAILED)
		return (NULL);

	index = name[*length-1]-1;
	if (carpif_get(index, &carp))
		return (NULL);

	switch (vp->magic) {
		case CARPIF_INDEX:
			ulong_ret = name[*length-1];
			return (unsigned char *) &ulong_ret;
		case CARPIF_DESCR:
			*var_len = strlcpy(ifname, carp.ifa.ifa_name, 
						sizeof(ifname));
			return (unsigned char *) ifname;
		case CARPIF_VHID:
			ulong_ret = carp.carpr.carpr_vhid;
			return (unsigned char *) &ulong_ret;
		case CARPIF_DEV:
			*var_len = strlcpy(ifname, carp.carpr.carpr_carpdev,
					sizeof(ifname));
			return (unsigned char *) ifname;
		case CARPIF_ADVBASE:
			ulong_ret = carp.carpr.carpr_advbase;
			return (unsigned char *) &ulong_ret;
		case CARPIF_ADVSKEW:
			ulong_ret = carp.carpr.carpr_advskew;
			return (unsigned char *) &ulong_ret;
		case CARPIF_STATE:
			ulong_ret = carp.carpr.carpr_state;
			return (unsigned char *) &ulong_ret;
		default:
			return (NULL);
	}
	
	/* NOTREACHED */
}

unsigned char *
var_carp_stats(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct carpstats carpstat;
	static struct counter64 c64;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	/* XXX should use a #define */
	if (nl[0].n_value == 0)
		return (NULL);
	if (klookup(nl[0].n_value, &carpstat, sizeof(carpstat)) == 0)
		return (NULL);

	switch(vp->magic) {
		case CARP_IPRECV:
			c64.high = carpstat.carps_ipackets >> 32;
			c64.low = carpstat.carps_ipackets & 0xffffffff;
			break;
		case CARP_IP6RECV:
			c64.high = carpstat.carps_ipackets6 >> 32;
			c64.low = carpstat.carps_ipackets6 & 0xffffffff;
			break;
		case CARP_BADIF:
			c64.high = carpstat.carps_badif >> 32;
			c64.low = carpstat.carps_badif & 0xffffffff;
			break;
		case CARP_BADTTL:
			c64.high = carpstat.carps_badttl >> 32;
			c64.low = carpstat.carps_badttl & 0xffffffff;
			break;
		case CARP_HDROPS:
			c64.high = carpstat.carps_hdrops >> 32;
			c64.low = carpstat.carps_hdrops & 0xffffffff;
			break;
		case CARP_BADCHKSUM:
			c64.high = carpstat.carps_badsum >> 32;
			c64.low = carpstat.carps_badsum & 0xffffffff;
			break;
		case CARP_BADVER:
			c64.high = carpstat.carps_badver >> 32;
			c64.low = carpstat.carps_badver & 0xffffffff;
			break;
		case CARP_TOOSHORT:
			c64.high = carpstat.carps_badlen >> 32;
			c64.low = carpstat.carps_badlen & 0xffffffff;
			break;
		case CARP_BADAUTH:
			c64.high = carpstat.carps_badauth >> 32;
			c64.low = carpstat.carps_badauth & 0xffffffff;
			break;
		case CARP_BADVHID:
			c64.high = carpstat.carps_badvhid >> 32;
			c64.low = carpstat.carps_badvhid & 0xffffffff;
			break;
		case CARP_BADADDRS:
			c64.high = carpstat.carps_badaddrs >> 32;
			c64.low = carpstat.carps_badaddrs & 0xffffffff;
			break;
		case CARP_IPSENT:
			c64.high = carpstat.carps_opackets >> 32;
			c64.low = carpstat.carps_opackets & 0xffffffff;
			break;
		case CARP_IP6SENT:
			c64.high = carpstat.carps_opackets6 >> 32;
			c64.low = carpstat.carps_opackets6 & 0xffffffff;
			break;
		case CARP_NOMEM:
			c64.high = carpstat.carps_onomem >> 32;
			c64.low = carpstat.carps_onomem & 0xffffffff;
			break;
		default:
			snmp_log(LOG_ERR,
				"var_carp_stats: can't find magic %u\n",
				vp->magic);
			return (NULL);
	}

	*var_len = sizeof(c64);
	return ((unsigned char *) &c64);
}

unsigned char *
var_carp_sysctl(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	int index, v;
	static u_long ulong_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	index = name[*length-2];

	switch(vp->magic) {
		case CARP_SYSCTL1:
		case CARP_SYSCTL2:
		case CARP_SYSCTL3:
		case CARP_SYSCTL4:
			if ((v = carp_sysctl_get(index)) == -1)
				return (NULL);
			ulong_ret = v ? 1 : 2;   /* truthvalue */
			break;
		default:
			return (NULL);
	}

	return ((unsigned char *) &ulong_ret);
}

int
carpif_count(void)
{
	struct ifaddrs *ifap, *ifa;
	int cnt = 0;

	if (getifaddrs(&ifap) != 0)
		return (-1);

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_LINK &&
			!strncmp(ifa->ifa_name, "carp", 4))
			cnt++;
	}

	freeifaddrs(ifap);
	return (cnt);
}

int
carpif_get(int index, struct carpif *carp)
{
	struct ifaddrs *ifap, *ifa;
	struct ifreq ifr;
	struct carpreq carpr;
	int i = 0, s;

	if (getifaddrs(&ifap) != 0)
		return (-1);

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr->sa_family == AF_LINK &&
			!strncmp(ifa->ifa_name, "carp", 4) &&
			i++ == index)
			break;
	}

	if (ifa == NULL)
		return (-1);

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		snmp_log(LOG_ERR, "carpif_get: socket: %s\n",
			strerror(errno));
		freeifaddrs(ifap);
		return (-1);
	}

	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_addr, ifa->ifa_addr,
		MIN(sizeof(ifr.ifr_addr), ifa->ifa_addr->sa_len));
	strlcpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name));
	memset((char *)&carpr, 0, sizeof(carpr));
	ifr.ifr_data = (caddr_t)&carpr;

	if (ioctl(s, SIOCGVH, (caddr_t)&ifr) == -1) {
		snmp_log(LOG_ERR, "carpif_get: ioctl: %s\n",
			strerror(errno));
		freeifaddrs(ifap);
		return (-1);
	}

	memcpy(&carp->ifa, ifa, sizeof(struct ifaddrs));
	carp->ifa.ifa_next = NULL;
	memcpy(&carp->carpr, &carpr, sizeof(struct carpreq));

	close(s);
	freeifaddrs(ifap);
	return (0);
}

int
carp_sysctl_get(int index)
{
	int mib[4], v;
	size_t len;

	mib[0] = CTL_NET;
	mib[1] = PF_INET;
	mib[2] = IPPROTO_CARP;
	mib[3] = index;
	len = sizeof(v);

	if (sysctl(mib, 4, &v, &len, NULL, 0) == -1) {
		snmp_log(LOG_ERR, "carp_sysctl_get: sysctl: %s\n",
			strerror(errno));
		return (-1);
	}

	return (v);
}

