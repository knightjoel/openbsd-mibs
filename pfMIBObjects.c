/*
 * $jwk$
 *
 *
 * Copyright (c) 2004-2008 Joel Knight <knight.joel@gmail.com>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <net/if_pfsync.h>

#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "pfMIBObjects.h"


#define PFRB_FOREACH(var, buf)				\
	for ((var) = pfr_buf_next((buf), NULL);		\
	    (var) != NULL;				\
	    (var) = pfr_buf_next((buf), (var)))

int		dev = -1;
char 		*pfi_table[255][IFNAMSIZ];
unsigned int	pfi_count;
unsigned int	pft_count;
unsigned int	pfl_count;
time_t		pfi_table_age;

size_t buf_esize[PFRB_MAX] = { 0,
	sizeof(struct pfr_tstats), 
	sizeof(struct pfr_astats),
	sizeof(struct pfi_kif)
};

oid pfMIBObjects_variables_oid[] = { 1,3,6,1,4,1,64512,1 };

struct variable4 pfMIBObjects_variables[] = {
/*  magic number        , variable type , ro/rw , callback fn  , L, oidsuffix */
  { RUNNING		, ASN_INTEGER   , RONLY , var_pfMIBObjects, 2, { 1,1 } },
  { RUNTIME		, ASN_TIMETICKS , RONLY , var_pfMIBObjects, 2, { 1,2 } },
  { DEBUG		, ASN_INTEGER   , RONLY , var_pfMIBObjects, 2, { 1,3 } },
  { HOSTID		, ASN_OCTET_STR , RONLY , var_pfMIBObjects, 2, { 1,4 } },
  { MATCH		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,1 } },
  { BADOFFSET		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,2 } },
  { FRAGMENT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,3 } },
  { SHORT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,4 } },
  { NORMALIZE		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,5 } },
  { MEMORY		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,6 } },
  { TIMESTAMP		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,7 } },
  { CONGEST		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,8 } },
  { IPOPTIONS		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,9 } },
  { PROTCKSUM		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,10 } },
  { BADSTATE		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,11 } },
  { STATEINS		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,12 } },
  { MAXSTATES		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,13 } },
  { SRCLIMIT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,14 } },
  { SYNPROXY		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,15 } },
  { STATES_COUNT	, ASN_UNSIGNED  , RONLY , var_pfMIBObjects, 2, { 3,1 } },
  { STATES_SEARCHES	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,2 } },
  { STATES_INSERTS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,3 } },
  { STATES_REMOVALS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,4 } },
  { PF_LOGIF_NAME	, ASN_OCTET_STR , RONLY , var_pfMIBObjects, 2, { 4,1 } },
  { IPBYTESIN		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,2 } },
  { IPBYTESOUT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,3 } },
  { IPPKTSINPASS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,4 } },
  { IPPKTSINDROP	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,5 } },
  { IPPKTSOUTPASS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,6 } },
  { IPPKTSOUTDROP	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,7 } },
  { IP6BYTESIN		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,8 } },
  { IP6BYTESOUT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,9 } },
  { IP6PKTSINPASS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,10 } },
  { IP6PKTSINDROP	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,11 } },
  { IP6PKTSOUTPASS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,12 } },
  { IP6PKTSOUTDROP	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,13 } },
  { SRCTRACK_COUNT	, ASN_UNSIGNED  , RONLY , var_pfMIBObjects, 2, { 5,1 } },
  { SRCTRACK_SEARCHES	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 5,2 } },
  { SRCTRACK_INSERTS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 5,3 } },
  { SRCTRACK_REMOVALS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 5,4 } },
  { LIMIT_STATES	, ASN_UNSIGNED  , RONLY , var_limits, 2, { 6,1 } },
  { LIMIT_SRC_NODES	, ASN_UNSIGNED  , RONLY , var_limits, 2, { 6,2 } },
  { LIMIT_FRAGS		, ASN_UNSIGNED  , RONLY , var_limits, 2, { 6,3 } },
  { TM_TCP_FIRST	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,1 } },
  { TM_TCP_OPENING	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,2 } },
  { TM_TCP_ESTAB	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,3 } },
  { TM_TCP_CLOSING	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,4 } },
  { TM_TCP_FINWAIT	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,5 } },
  { TM_TCP_CLOSED	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,6 } },
  { TM_UDP_FIRST	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,7 } },
  { TM_UDP_SINGLE	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,8 } },
  { TM_UDP_MULTIPLE	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,9 } },
  { TM_ICMP_FIRST	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,10 } },
  { TM_ICMP_ERROR	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,11 } },
  { TM_OTHER_FIRST	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,12 } },
  { TM_OTHER_SINGLE	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,13 } },
  { TM_OTHER_MULTIPLE	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,14 } },
  { TM_FRAGMENT		, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,15 } },
  { TM_INTERVAL		, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,16 } },
  { TM_ADAPT_START	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,17 } },
  { TM_ADAPT_END	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,18 } },
  { TM_SRC_TRACK	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,19 } },
  { PF_IFNUMBER		, ASN_INTEGER   , RONLY , var_table_number, 2, { 8,1 } },
  { PF_IFINDEX		, ASN_INTEGER   , RONLY , var_if_table, 4, { 8,128,1,1 } },
  { PF_IFNAME		, ASN_OCTET_STR , RONLY , var_if_table, 4, { 8,128,1,2 } },
  { PF_IFTYPE		, ASN_INTEGER   , RONLY , var_if_table, 4, { 8,128,1,3 } },
  { PF_IFREF		, ASN_UNSIGNED	, RONLY	, var_if_table, 4, { 8,128,1,4 } },
  { PF_IFRULES		, ASN_UNSIGNED	, RONLY	, var_if_table, 4, { 8,128,1,5 } },
  { PF_IFIN4PASSPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,6 } },
  { PF_IFIN4PASSBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,7 } },
  { PF_IFIN4BLOCKPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,8 } },
  { PF_IFIN4BLOCKBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,9 } },
  { PF_IFOUT4PASSPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,10 } },
  { PF_IFOUT4PASSBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,11 } },
  { PF_IFOUT4BLOCKPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,12 } },
  { PF_IFOUT4BLOCKBYTES , ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,13 } },
  { PF_IFIN6PASSPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,14 } },
  { PF_IFIN6PASSBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,15 } },
  { PF_IFIN6BLOCKPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,16 } },
  { PF_IFIN6BLOCKBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,17 } },
  { PF_IFOUT6PASSPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,18 } },
  { PF_IFOUT6PASSBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,19 } },
  { PF_IFOUT6BLOCKPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,20 } },
  { PF_IFOUT6BLOCKBYTES , ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,21 } },
  { PF_TANUMBER		, ASN_INTEGER	, RONLY	, var_table_number, 2, { 9,1 } },
  { PF_TAINDEX		, ASN_INTEGER	, RONLY	, var_tables_table, 4, { 9,128,1,1 } },
  { PF_TANAME		, ASN_OCTET_STR	, RONLY	, var_tables_table, 4, { 9,128,1,2 } },
  { PF_TAADDRESSES	, ASN_INTEGER	, RONLY	, var_tables_table, 4, { 9,128,1,3 } },
  { PF_TAANCHORREFS	, ASN_INTEGER	, RONLY	, var_tables_table, 4, { 9,128,1,4 } },
  { PF_TARULEREFS	, ASN_INTEGER	, RONLY	, var_tables_table, 4, { 9,128,1,5 } },
  { PF_TAEVALSMATCH	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,6 } },
  { PF_TAEVALSNOMATCH	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,7 } },
  { PF_TAINPASSPKTS	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,8 } },
  { PF_TAINPASSBYTES	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,9 } },
  { PF_TAINBLOCKPKTS	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,10 } },
  { PF_TAINBLOCKBYTES	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,11 } },
  { PF_TAINXPASSPKTS	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,12 } },
  { PF_TAINXPASSBYTES	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,13 } },
  { PF_TAOUTPASSPKTS	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,14 } },
  { PF_TAOUTPASSBYTES	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,15 } },
  { PF_TAOUTBLOCKPKTS	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,16 } },
  { PF_TAOUTBLOCKBYTES	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,17 } },
  { PF_TAOUTXPASSPKTS	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,18 } },
  { PF_TAOUTXPASSBYTES	, ASN_COUNTER64	, RONLY	, var_tables_table, 4, { 9,128,1,19 } },
  { PF_TASTATSCLEARED	, ASN_TIMETICKS	, RONLY , var_tables_table, 4, { 9,128,1,20 } },
  { PF_TADDRTABLEINDEX	, ASN_INTEGER	, RONLY , var_tbl_addr_table, 4, { 9,129,1,1 } },
  { PF_TADDRNET		, ASN_IPADDRESS	, RONLY , var_tbl_addr_table, 4, { 9,129,1,2 } },
  { PF_TADDRMASK	, ASN_INTEGER	, RONLY , var_tbl_addr_table, 4, { 9,129,1,3 } },
  { PF_TADDRCLEARED	, ASN_TIMETICKS	, RONLY , var_tbl_addr_table, 4, { 9,129,1,4 } },
  { PF_TADDRINBLOCKPKTS	, ASN_COUNTER64	, RONLY , var_tbl_addr_table, 4, { 9,129,1,5 } },
  { PF_TADDRINBLOCKBYTES, ASN_COUNTER64	, RONLY , var_tbl_addr_table, 4, { 9,129,1,6 } },
  { PF_TADDRINPASSPKTS	, ASN_COUNTER64	, RONLY , var_tbl_addr_table, 4, { 9,129,1,7 } },
  { PF_TADDRINPASSBYTES	, ASN_COUNTER64	, RONLY , var_tbl_addr_table, 4, { 9,129,1,8 } },
  { PF_TADDROUTBLOCKPKTS, ASN_COUNTER64	, RONLY , var_tbl_addr_table, 4, { 9,129,1,9 } },
  { PF_TADDROUTBLOCKBYTES,ASN_COUNTER64	, RONLY , var_tbl_addr_table, 4, { 9,129,1,10 } },
  { PF_TADDROUTPASSPKTS , ASN_COUNTER64	, RONLY , var_tbl_addr_table, 4, { 9,129,1,11 } },
  { PF_TADDROUTPASSBYTES, ASN_COUNTER64	, RONLY , var_tbl_addr_table, 4, { 9,129,1,12 } },
  { PF_LANUMBER		, ASN_INTEGER	, RONLY	, var_table_number, 2, { 10,1 } },
  { PF_LAINDEX		, ASN_INTEGER	, RONLY	, var_labels_table, 4, { 10,128,1,1 } },
  { PF_LANAME		, ASN_OCTET_STR	, RONLY	, var_labels_table, 4, { 10,128,1,2 } },
  { PF_LAEVALS		, ASN_COUNTER64	, RONLY	, var_labels_table, 4, { 10,128,1,3 } },
  { PF_LAPKTS		, ASN_COUNTER64	, RONLY	, var_labels_table, 4, { 10,128,1,4 } },
  { PF_LABYTES		, ASN_COUNTER64	, RONLY	, var_labels_table, 4, { 10,128,1,5 } },
  { PF_LAINPKTS		, ASN_COUNTER64	, RONLY	, var_labels_table, 4, { 10,128,1,6 } },
  { PF_LAINBYTES	, ASN_COUNTER64	, RONLY	, var_labels_table, 4, { 10,128,1,7 } },
  { PF_LAOUTPKTS	, ASN_COUNTER64	, RONLY	, var_labels_table, 4, { 10,128,1,8 } },
  { PF_LAOUTBYTES	, ASN_COUNTER64	, RONLY	, var_labels_table, 4, { 10,128,1,9 } },
  { PFSYNC_IPRECV	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,1 } },
  { PFSYNC_IP6RECV	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,2 } },
  { PFSYNC_BADIF	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,3 } },
  { PFSYNC_BADTTL	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,4 } },
  { PFSYNC_HDROPS	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,5 } },
  { PFSYNC_BADVER	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,6 } },
  { PFSYNC_BADACT	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,7 } },
  { PFSYNC_BADLEN	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,8 } },
  { PFSYNC_BADAUTH	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,9 } },
  { PFSYNC_STALE	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,10 } },
  { PFSYNC_BADVAL	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,11 } },
  { PFSYNC_BADSTATE	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,12 } },
  { PFSYNC_IPSENT	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,13 } },
  { PFSYNC_IP6SENT	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,14 } },
  { PFSYNC_NOMEM	, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,15 } },
  { PFSYNC_OERR		, ASN_COUNTER64	, RONLY	, var_pfsync_stats, 2, { 11,16 } }
};


void init_pfMIBObjects(void) {
	REGISTER_MIB("pfMIBObjects", pfMIBObjects_variables, variable4,
			pfMIBObjects_variables_oid);

	if ((dev = open("/dev/pf", O_RDONLY)) == -1) {
		snmp_log(LOG_CRIT, "unable to open /dev/pf: %s\n", strerror(errno));
		return;
	}

	bzero(&pfi_table, sizeof(pfi_table));
	pfi_count = 0;
	pfi_refresh();
	pft_refresh();
}

unsigned char *
var_limits(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pfioc_limit pl;
	
	static u_long ulong_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	if (dev == -1)
		return (NULL);

	memset(&pl, 0, sizeof(pl));

	switch(vp->magic) {

		case LIMIT_STATES:
			pl.index = PF_LIMIT_STATES;
			break;

		case LIMIT_SRC_NODES:
			pl.index = PF_LIMIT_SRC_NODES;
			break;
			
		case LIMIT_FRAGS:
			pl.index = PF_LIMIT_FRAGS;
			break;
						
		default:
			return (NULL);
	}

	if (ioctl(dev, DIOCGETLIMIT, &pl)) {
		snmp_log(LOG_ERR, "var_limits: ioctl: %s\n", strerror(errno));
		return (NULL);
	}
	ulong_ret = pl.limit;
	return ((unsigned char *) &ulong_ret);
}

unsigned char *
var_pfMIBObjects(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pf_status s;
	time_t runtime;
	
	static long long_ret;
	static u_long ulong_ret;
	static unsigned char string[SPRINT_MAX_LEN];
	static struct counter64 c64;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED )
		return (NULL);

	if (dev == -1)
		return (NULL);

	memset(&s, 0, sizeof(s));
	if (ioctl(dev, DIOCGETSTATUS, &s)) {
		snmp_log(LOG_ERR, "var_pfMIBObjects: ioctl: %s\n",
				strerror(errno));
		return (NULL);
	}

	switch(vp->magic) {

		case RUNNING:
			long_ret = (long) s.running;
			return ((unsigned char *) &long_ret);

		case RUNTIME:
			if (s.since > 0)
				runtime = time(NULL) - s.since;
			else
				runtime = 0;
			long_ret = (long) runtime * 100;
			return ((unsigned char *) &long_ret);

		case DEBUG:
			long_ret = (long) s.debug;
			return ((unsigned char *) &long_ret);

		case HOSTID:
			sprintf(string, "0x%08x", ntohl(s.hostid));
			*var_len = strlen(string);
			return ((unsigned char *) string);

		case MATCH:
			c64.high = s.counters[PFRES_MATCH] >> 32;
			c64.low = s.counters[PFRES_MATCH] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case BADOFFSET:
			c64.high = s.counters[PFRES_BADOFF] >> 32;
			c64.low = s.counters[PFRES_BADOFF] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case FRAGMENT:
			c64.high = s.counters[PFRES_FRAG] >> 32;
			c64.low = s.counters[PFRES_FRAG] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case SHORT:
			c64.high = s.counters[PFRES_SHORT] >> 32;
			c64.low = s.counters[PFRES_SHORT] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case NORMALIZE:
			c64.high = s.counters[PFRES_NORM] >> 32;
			c64.low = s.counters[PFRES_NORM] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case MEMORY:
			c64.high = s.counters[PFRES_MEMORY] >> 32;
			c64.low = s.counters[PFRES_MEMORY] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case TIMESTAMP:
			c64.high = s.counters[PFRES_TS] >> 32;
			c64.low = s.counters[PFRES_TS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case CONGEST:
			c64.high = s.counters[PFRES_CONGEST] >> 32;
			c64.low = s.counters[PFRES_CONGEST] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IPOPTIONS:
			c64.high = s.counters[PFRES_IPOPTIONS] >> 32;
			c64.low = s.counters[PFRES_IPOPTIONS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case PROTCKSUM:
			c64.high = s.counters[PFRES_PROTCKSUM] >> 32;
			c64.low = s.counters[PFRES_PROTCKSUM] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case BADSTATE:
			c64.high = s.counters[PFRES_BADSTATE] >> 32;
			c64.low = s.counters[PFRES_BADSTATE] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case STATEINS:
			c64.high = s.counters[PFRES_STATEINS] >> 32;
			c64.low = s.counters[PFRES_STATEINS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case MAXSTATES:
			c64.high = s.counters[PFRES_MAXSTATES] >> 32;
			c64.low = s.counters[PFRES_MAXSTATES] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case SRCLIMIT:
			c64.high = s.counters[PFRES_SRCLIMIT] >> 32;
			c64.low = s.counters[PFRES_SRCLIMIT] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case SYNPROXY:
			c64.high = s.counters[PFRES_SYNPROXY] >> 32;
			c64.low = s.counters[PFRES_SYNPROXY] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case STATES_COUNT:
			ulong_ret = (long) s.states;
			return ((unsigned char *) &ulong_ret);

		case STATES_SEARCHES:
			c64.high = s.fcounters[FCNT_STATE_SEARCH] >> 32;
			c64.low = s.fcounters[FCNT_STATE_SEARCH] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case STATES_INSERTS:
			c64.high = s.fcounters[FCNT_STATE_INSERT] >> 32;
			c64.low = s.fcounters[FCNT_STATE_INSERT] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case STATES_REMOVALS:
			c64.high = s.fcounters[FCNT_STATE_REMOVALS] >> 32;
			c64.low = s.fcounters[FCNT_STATE_REMOVALS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case PF_LOGIF_NAME:
			strlcpy(string, s.ifname, sizeof(string));
			*var_len = strlen(string);
			return ((unsigned char *) string);

		case IPBYTESIN:
			c64.high = s.bcounters[IPV4][IN] >> 32;
			c64.low = s.bcounters[IPV4][IN] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IPBYTESOUT:
			c64.high = s.bcounters[IPV4][OUT] >> 32;
			c64.low = s.bcounters[IPV4][OUT] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IPPKTSINPASS:
			c64.high = s.pcounters[IPV4][IN][PF_PASS] >> 32;
			c64.low = s.pcounters[IPV4][IN][PF_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IPPKTSINDROP:
			c64.high = s.pcounters[IPV4][IN][PF_DROP] >> 32;
			c64.low = s.pcounters[IPV4][IN][PF_DROP] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IPPKTSOUTPASS:
			c64.high = s.pcounters[IPV4][OUT][PF_PASS] >> 32;
			c64.low = s.pcounters[IPV4][OUT][PF_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IPPKTSOUTDROP:
			c64.high = s.pcounters[IPV4][OUT][PF_DROP] >> 32;
			c64.low = s.pcounters[IPV4][OUT][PF_DROP] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IP6BYTESIN:
			c64.high = s.bcounters[IPV6][IN] >> 32;
			c64.low = s.bcounters[IPV6][IN] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IP6BYTESOUT:
			c64.high = s.bcounters[IPV6][OUT] >> 32;
			c64.low = s.bcounters[IPV6][OUT] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IP6PKTSINPASS:
			c64.high = s.pcounters[IPV6][IN][PF_PASS] >> 32;
			c64.low = s.pcounters[IPV6][IN][PF_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IP6PKTSINDROP:
			c64.high = s.pcounters[IPV6][IN][PF_DROP] >> 32;
			c64.low = s.pcounters[IPV6][IN][PF_DROP] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IP6PKTSOUTPASS:
			c64.high = s.pcounters[IPV6][OUT][PF_PASS] >> 32;
			c64.low = s.pcounters[IPV6][OUT][PF_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case IP6PKTSOUTDROP:
			c64.high = s.pcounters[IPV6][OUT][PF_DROP] >> 32;
			c64.low = s.pcounters[IPV6][OUT][PF_DROP] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case SRCTRACK_COUNT:
			ulong_ret = (long) s.src_nodes;
			return ((unsigned char *) &ulong_ret);

		case SRCTRACK_SEARCHES:
			c64.high = s.scounters[SCNT_SRC_NODE_SEARCH] >> 32;
			c64.low = s.scounters[SCNT_SRC_NODE_SEARCH] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case SRCTRACK_INSERTS:
			c64.high = s.scounters[SCNT_SRC_NODE_INSERT] >> 32;
			c64.low = s.scounters[SCNT_SRC_NODE_INSERT] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case SRCTRACK_REMOVALS:
			c64.high = s.scounters[SCNT_SRC_NODE_REMOVALS] >> 32;
			c64.low = s.scounters[SCNT_SRC_NODE_REMOVALS] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);
						
		default:
			return (NULL);
	}

	/* NOTREACHED */
}

unsigned char *
var_pfsync_stats(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	int mib[4] = { CTL_NET, AF_INET, IPPROTO_PFSYNC, PFSYNCCTL_STATS };
	size_t len;
	struct pfsyncstats pfsyncstat;
	static struct counter64 c64;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	len = sizeof(pfsyncstat);
	if (sysctl(mib, 4, &pfsyncstat, &len, NULL, 0) == -1) {
		snmp_log(LOG_ERR, "var_pfsync_stats: sysctl: %s\n",
			strerror(errno));
		return (NULL);
	}

	switch(vp->magic) {
		case PFSYNC_IPRECV:
			c64.high = pfsyncstat.pfsyncs_ipackets >> 32;
			c64.low = pfsyncstat.pfsyncs_ipackets & 0xffffffff;
			break;
		case PFSYNC_IP6RECV:
			c64.high = pfsyncstat.pfsyncs_ipackets6 >> 32;
			c64.low = pfsyncstat.pfsyncs_ipackets6 & 0xffffffff;
			break;
		case PFSYNC_BADIF:
			c64.high = pfsyncstat.pfsyncs_badif >> 32;
			c64.low = pfsyncstat.pfsyncs_badif & 0xffffffff;
			break;
		case PFSYNC_BADTTL:
			c64.high = pfsyncstat.pfsyncs_badttl >> 32;
			c64.low = pfsyncstat.pfsyncs_badttl & 0xffffffff;
			break;
		case PFSYNC_HDROPS:
			c64.high = pfsyncstat.pfsyncs_hdrops >> 32;
			c64.low = pfsyncstat.pfsyncs_hdrops & 0xffffffff;
			break;
		case PFSYNC_BADVER:
			c64.high = pfsyncstat.pfsyncs_badver >> 32;
			c64.low = pfsyncstat.pfsyncs_badver & 0xffffffff;
			break;
		case PFSYNC_BADACT:
			c64.high = pfsyncstat.pfsyncs_badact >> 32;
			c64.low = pfsyncstat.pfsyncs_badact & 0xffffffff;
			break;
		case PFSYNC_BADLEN:
			c64.high = pfsyncstat.pfsyncs_badlen >> 32;
			c64.low = pfsyncstat.pfsyncs_badlen & 0xffffffff;
			break;
		case PFSYNC_BADAUTH:
			c64.high = pfsyncstat.pfsyncs_badauth >> 32;
			c64.low = pfsyncstat.pfsyncs_badauth & 0xffffffff;
			break;
		case PFSYNC_STALE:
			c64.high = pfsyncstat.pfsyncs_stale >> 32;
			c64.low = pfsyncstat.pfsyncs_stale & 0xffffffff;
			break;
		case PFSYNC_BADVAL:
			c64.high = pfsyncstat.pfsyncs_badval >> 32;
			c64.low = pfsyncstat.pfsyncs_badval & 0xffffffff;
			break;
		case PFSYNC_BADSTATE:
			c64.high = pfsyncstat.pfsyncs_badstate >> 32;
			c64.low = pfsyncstat.pfsyncs_badstate & 0xffffffff;
			break;
		case PFSYNC_IPSENT:
			c64.high = pfsyncstat.pfsyncs_opackets >> 32;
			c64.low = pfsyncstat.pfsyncs_opackets & 0xffffffff;
			break;
		case PFSYNC_IP6SENT:
			c64.high = pfsyncstat.pfsyncs_opackets6 >> 32;
			c64.low = pfsyncstat.pfsyncs_opackets6 & 0xffffffff;
			break;
		case PFSYNC_NOMEM:
			c64.high = pfsyncstat.pfsyncs_onomem >> 32;
			c64.low = pfsyncstat.pfsyncs_onomem & 0xffffffff;
			break;
		case PFSYNC_OERR:
			c64.high = pfsyncstat.pfsyncs_oerrors >> 32;
			c64.low = pfsyncstat.pfsyncs_oerrors & 0xffffffff;
			break;
		default:
			snmp_log(LOG_ERR,
				"var_pfsync_stats: can't find magic %u\n",
				vp->magic);
			return (NULL);
	}

	*var_len = sizeof(c64);
	return ((unsigned char *) &c64);
}

unsigned char *
var_timeouts(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pfioc_tm pt;

	static long long_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	if (dev == -1)
		return (NULL);

	memset(&pt, 0, sizeof(pt));
	switch(vp->magic) {

		case TM_TCP_FIRST:
			pt.timeout = PFTM_TCP_FIRST_PACKET;
			break;

		case TM_TCP_OPENING:
			pt.timeout = PFTM_TCP_OPENING;
			break;

		case TM_TCP_ESTAB:
			pt.timeout = PFTM_TCP_ESTABLISHED;
			break;

		case TM_TCP_CLOSING:
			pt.timeout = PFTM_TCP_CLOSING;
			break;

		case TM_TCP_FINWAIT:
			pt.timeout = PFTM_TCP_FIN_WAIT;
			break;

		case TM_TCP_CLOSED:
			pt.timeout = PFTM_TCP_CLOSED;
			break;

		case TM_UDP_FIRST:
			pt.timeout = PFTM_UDP_FIRST_PACKET;
			break;

		case TM_UDP_SINGLE:
			pt.timeout = PFTM_UDP_SINGLE;
			break;

		case TM_UDP_MULTIPLE:
			pt.timeout = PFTM_UDP_MULTIPLE;
			break;

		case TM_ICMP_FIRST:
			pt.timeout = PFTM_ICMP_FIRST_PACKET;
			break;

		case TM_ICMP_ERROR:
			pt.timeout = PFTM_ICMP_ERROR_REPLY;
			break;

		case TM_OTHER_FIRST:
			pt.timeout = PFTM_OTHER_FIRST_PACKET;
			break;

		case TM_OTHER_SINGLE:
			pt.timeout = PFTM_OTHER_SINGLE;
			break;

		case TM_OTHER_MULTIPLE:
			pt.timeout = PFTM_OTHER_MULTIPLE;
			break;

		case TM_FRAGMENT:
			pt.timeout = PFTM_FRAG;
			break;

		case TM_INTERVAL:
			pt.timeout = PFTM_INTERVAL;
			break;

		case TM_ADAPT_START:
			pt.timeout = PFTM_ADAPTIVE_START;
			break;

		case TM_ADAPT_END:
			pt.timeout = PFTM_ADAPTIVE_END;
			break;

		case TM_SRC_TRACK:
			pt.timeout = PFTM_SRC_NODE;
			break;

		default:
			return (NULL);
	}

	if (ioctl(dev, DIOCGETTIMEOUT, &pt)) {
		snmp_log(LOG_ERR, "var_timeouts: ioctl: %s\n", strerror(errno));
		return (NULL);
	}
	long_ret = pt.seconds;
	return ((unsigned char *) &long_ret);
}

unsigned char *
var_table_number(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	static u_long ulong_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	if (dev == -1)
		return (NULL);

	if ((time(NULL) - pfi_table_age) > PFI_TABLE_MAXAGE)
		pfi_refresh();

	switch (vp->magic) {
		case PF_IFNUMBER:
			ulong_ret = pfi_count;
			return ((unsigned char *) &ulong_ret);

		case PF_TANUMBER:
			pft_refresh();
			ulong_ret = pft_count;
			return ((unsigned char *) &ulong_ret);
		
		case PF_LANUMBER:
			pfl_refresh();
			ulong_ret = pfl_count;
			return ((unsigned char *) &ulong_ret);

		default:
			return (NULL);
	}
}


unsigned char *
var_if_table(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pfr_buffer b;
	struct pfi_kif *p;
	int index;
	static struct counter64 c64;
	static u_long ulong_ret;

	if (header_simple_table(vp, name, length, exact, var_len, write_method, pfi_count)
			== MATCH_FAILED)
		return (NULL);

	if (dev == -1)
		return (NULL);

	if ((time(NULL) - pfi_table_age) > PFI_TABLE_MAXAGE)
		pfi_refresh();

	index = name[*length-1]-1;
	if (!pfi_table[index])
		return (NULL);

	if (pfi_get(&b, (const char *)&pfi_table[index]) 
			|| b.pfrb_size == 0) {
		free(b.pfrb_caddr);
		return (NULL);
	} 
	/* we only ask for 1 interface from pfi_get() */
	p = b.pfrb_caddr;

	switch (vp->magic) {
		case PF_IFINDEX:
			ulong_ret = index + 1;
			free(b.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_IFNAME:
			*var_len = strlen(&pfi_table[index]);
			free(b.pfrb_caddr);
			return ((unsigned char *) pfi_table[index]);

		case PF_IFTYPE:
			/* XXX weak test; group names can end in digits */
			ulong_ret = isdigit(p->pfik_name[strlen(p->pfik_name)-1]) ? 
				PFI_IFTYPE_INSTANCE : PFI_IFTYPE_GROUP;
			free(b.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_IFREF:
			ulong_ret = p->pfik_states;
			free(b.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_IFRULES:
			ulong_ret = p->pfik_rules;
			free(b.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_IFIN4PASSPKTS:
			c64.high = p->pfik_packets[IPV4][IN][PASS] >> 32;
			c64.low = p->pfik_packets[IPV4][IN][PASS] & 0xffffffff;
			break;

		case PF_IFIN4PASSBYTES:
			c64.high = p->pfik_bytes[IPV4][IN][PASS] >> 32;
			c64.low = p->pfik_bytes[IPV4][IN][PASS] & 0xffffffff;
			break;

		case PF_IFIN4BLOCKPKTS:
			c64.high = p->pfik_packets[IPV4][IN][BLOCK] >> 32;
			c64.low = p->pfik_packets[IPV4][IN][BLOCK] & 0xffffffff;
			break;

		case PF_IFIN4BLOCKBYTES:
			c64.high = p->pfik_bytes[IPV4][IN][BLOCK] >> 32;
			c64.low = p->pfik_bytes[IPV4][IN][BLOCK] & 0xffffffff;
			break;

		case PF_IFOUT4PASSPKTS:
			c64.high = p->pfik_packets[IPV4][OUT][PASS] >> 32;
			c64.low = p->pfik_packets[IPV4][OUT][PASS] & 0xffffffff;
			break;

		case PF_IFOUT4PASSBYTES:
			c64.high = p->pfik_bytes[IPV4][OUT][PASS] >> 32;
			c64.low = p->pfik_bytes[IPV4][OUT][PASS] & 0xffffffff;
			break;

		case PF_IFOUT4BLOCKPKTS:
			c64.high = p->pfik_packets[IPV4][OUT][BLOCK] >> 32;
			c64.low = p->pfik_packets[IPV4][OUT][BLOCK] & 0xffffffff;
			break;

		case PF_IFOUT4BLOCKBYTES:
			c64.high = p->pfik_bytes[IPV4][OUT][BLOCK] >> 32;
			c64.low = p->pfik_bytes[IPV4][OUT][BLOCK] & 0xffffffff;
			break;

		case PF_IFIN6PASSPKTS:
			c64.high = p->pfik_packets[IPV6][IN][PASS] >> 32;
			c64.low = p->pfik_packets[IPV6][IN][PASS] & 0xffffffff;
			break;

		case PF_IFIN6PASSBYTES:
			c64.high = p->pfik_bytes[IPV6][IN][PASS] >> 32;
			c64.low = p->pfik_bytes[IPV6][IN][PASS] & 0xffffffff;
			break;

		case PF_IFIN6BLOCKPKTS:
			c64.high = p->pfik_packets[IPV6][IN][BLOCK] >> 32;
			c64.low = p->pfik_packets[IPV6][IN][BLOCK] & 0xffffffff;
			break;

		case PF_IFIN6BLOCKBYTES:
			c64.high = p->pfik_bytes[IPV6][IN][BLOCK] >> 32;
			c64.low = p->pfik_bytes[IPV6][IN][BLOCK] & 0xffffffff;
			break;

		case PF_IFOUT6PASSPKTS:
			c64.high = p->pfik_packets[IPV6][OUT][PASS] >> 32;
			c64.low = p->pfik_packets[IPV6][OUT][PASS] & 0xffffffff;
			break;

		case PF_IFOUT6PASSBYTES:
			c64.high = p->pfik_bytes[IPV6][OUT][PASS] >> 32;
			c64.low = p->pfik_bytes[IPV6][OUT][PASS] & 0xffffffff;
			break;

		case PF_IFOUT6BLOCKPKTS:
			c64.high = p->pfik_packets[IPV6][OUT][BLOCK] >> 32;
			c64.low = p->pfik_packets[IPV6][OUT][BLOCK] & 0xffffffff;
			break;

		case PF_IFOUT6BLOCKBYTES:
			c64.high = p->pfik_bytes[IPV6][OUT][BLOCK] >> 32;
			c64.low = p->pfik_bytes[IPV6][OUT][BLOCK] & 0xffffffff;
			break;
			
		default:
			free(b.pfrb_caddr);
			return (NULL);
	}
	
	free(b.pfrb_caddr);
	*var_len = sizeof(c64);
	return ((unsigned char *) &c64);
}

unsigned char * 
var_labels_table(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	u_long nr, mnr, lnr;
	struct pfioc_rule pr;
	static struct counter64 c64;
	static u_long ulong_ret;
	static char lname[PF_RULE_LABEL_SIZE];
	int index;
	int got_match = 0;

	if (dev == -1)
		return (NULL);
	

	pfl_refresh();
	if (header_simple_table(vp, name, length, exact, var_len, write_method, pfl_count)
			== MATCH_FAILED) {
		return (NULL);
	}

	index = name[*length-1];

	memset(&pr, 0, sizeof(pr));
	if (ioctl(dev, DIOCGETRULES, &pr)) {
		snmp_log(LOG_ERR, "var_labels_table: ioctl: %s\n",
			strerror(errno));
		return (NULL);
	}

	mnr = pr.nr;
	lnr = 0;
	for (nr = 0; nr < mnr; ++nr) {
		pr.nr = nr;
		if (ioctl(dev, DIOCGETRULE, &pr)) {
			snmp_log(LOG_ERR, "var_labels_table: ioctl: %s\n",
				strerror(errno));
			return (NULL);
		}

		if (pr.rule.label[0]) {
			lnr++;
			if (lnr == index) {
				got_match++;
				break;
			}
		}
	}

	if (!got_match)
		return (NULL);
	
	switch (vp->magic) {
		case PF_LAINDEX:
			ulong_ret = index;
			return ((unsigned char *) &ulong_ret);

		case PF_LANAME:
			*var_len = strlen(pr.rule.label);
			strlcpy(lname, pr.rule.label, sizeof(lname));
			return ((unsigned char *) lname);

		case PF_LAEVALS:
			c64.high = pr.rule.evaluations >> 32;
			c64.low = pr.rule.evaluations & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case PF_LAPKTS:
			c64.high = (pr.rule.packets[IN] >> 32) 
				+ (pr.rule.packets[OUT] >> 32);
			c64.low = (pr.rule.packets[IN] & 0xffffffff) 
				+ (pr.rule.packets[OUT] & 0xffffffff);
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case PF_LABYTES:
			c64.high = (pr.rule.bytes[IN] >> 32)
				+ (pr.rule.bytes[OUT] >> 32);
			c64.low = (pr.rule.bytes[IN] & 0xffffffff)
				+ (pr.rule.bytes[OUT] & 0xffffffff);
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case PF_LAINPKTS:
			c64.high = pr.rule.packets[IN] >> 32;
			c64.low = pr.rule.packets[IN] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case PF_LAINBYTES:
			c64.high = pr.rule.bytes[IN] >> 32;
			c64.low = pr.rule.bytes[IN] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case PF_LAOUTPKTS:
			c64.high = pr.rule.packets[OUT] >> 32;
			c64.low = pr.rule.packets[OUT] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		case PF_LAOUTBYTES:
			c64.high = pr.rule.bytes[OUT] >> 32;
			c64.low = pr.rule.bytes[OUT] & 0xffffffff;
			*var_len = sizeof(c64);
			return ((unsigned char *) &c64);

		default:
			return (NULL);
	}

	/* NOTREACHED */
}

unsigned char *
var_tables_table(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pfr_buffer b;
	struct pfr_tstats *ts = NULL;
	static struct counter64 c64;
	static u_long ulong_ret;
	static char tname[PF_TABLE_NAME_SIZE];
	int index, i = 0;

	if (dev == -1)
		return (NULL);
	
	if (pft_get(&b)) {
		snmp_log(LOG_ERR,
			"var_tables_table: can't get list of pf tables\n");
		return (NULL);
	}

	pft_refresh(); 
	if (header_simple_table(vp, name, length, exact, var_len, write_method, pft_count)
			== MATCH_FAILED) {
		free(b.pfrb_caddr);
		return (NULL);
	}

	index = name[*length-1];

	PFRB_FOREACH(ts, &b) {
		if (!(ts->pfrts_flags & PFR_TFLAG_ACTIVE))
			continue;
		if (++i == index)
			break;
	}

	if (ts == NULL) {
		free(b.pfrb_caddr);
		return (NULL);
	}

	switch (vp->magic) {
		case PF_TAINDEX:
			ulong_ret = index;
			free(b.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_TANAME:
			*var_len = strlen(ts->pfrts_name);
			strlcpy(tname, ts->pfrts_name, sizeof(tname));
			free(b.pfrb_caddr);
			return ((unsigned char *) tname);

		case PF_TAADDRESSES:
			ulong_ret = ts->pfrts_cnt;
			free(b.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_TAANCHORREFS:
			ulong_ret = ts->pfrts_refcnt[PFR_REFCNT_ANCHOR];
			free(b.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_TARULEREFS:
			ulong_ret = ts->pfrts_refcnt[PFR_REFCNT_RULE];
			free(b.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_TAEVALSMATCH:
			c64.high = ts->pfrts_match >> 32;
			c64.low = ts->pfrts_match & 0xffffffff;
			break;

		case PF_TAEVALSNOMATCH:
			c64.high = ts->pfrts_nomatch >> 32;
			c64.low = ts->pfrts_nomatch & 0xffffffff;
			break;

		case PF_TAINPASSPKTS:
			c64.high = ts->pfrts_packets[IN][PFR_OP_PASS] >> 32;
			c64.low = ts->pfrts_packets[IN][PFR_OP_PASS] & 0xffffffff;
			break;

		case PF_TAINPASSBYTES:
			c64.high = ts->pfrts_bytes[IN][PFR_OP_PASS] >> 32;
			c64.low = ts->pfrts_bytes[IN][PFR_OP_PASS] & 0xffffffff;
			break;

		case PF_TAINBLOCKPKTS:
			c64.high = ts->pfrts_packets[IN][PFR_OP_BLOCK] >> 32;
			c64.low = ts->pfrts_packets[IN][PFR_OP_BLOCK] & 0xffffffff;
			break;

		case PF_TAINBLOCKBYTES:
			c64.high = ts->pfrts_bytes[IN][PFR_OP_BLOCK] >> 32;
			c64.low = ts->pfrts_bytes[IN][PFR_OP_BLOCK] & 0xffffffff;
			break;

		case PF_TAINXPASSPKTS:
			c64.high = ts->pfrts_packets[IN][PFR_OP_XPASS] >> 32;
			c64.low = ts->pfrts_packets[IN][PFR_OP_XPASS] & 0xffffffff;
			break;

		case PF_TAINXPASSBYTES:
			c64.high = ts->pfrts_bytes[IN][PFR_OP_XPASS] >> 32;
			c64.low = ts->pfrts_bytes[IN][PFR_OP_XPASS] & 0xffffffff;
			break;

		case PF_TAOUTPASSPKTS:
			c64.high = ts->pfrts_packets[OUT][PFR_OP_PASS] >> 32;
			c64.low = ts->pfrts_packets[OUT][PFR_OP_PASS] & 0xffffffff;
			break;

		case PF_TAOUTPASSBYTES:
			c64.high = ts->pfrts_bytes[OUT][PFR_OP_PASS] >> 32;
			c64.low = ts->pfrts_bytes[OUT][PFR_OP_PASS] & 0xffffffff;
			break;

		case PF_TAOUTBLOCKPKTS:
			c64.high = ts->pfrts_packets[OUT][PFR_OP_BLOCK] >> 32;
			c64.low = ts->pfrts_packets[OUT][PFR_OP_BLOCK] & 0xffffffff;
			break;

		case PF_TAOUTBLOCKBYTES:
			c64.high = ts->pfrts_bytes[OUT][PFR_OP_BLOCK] >> 32;
			c64.low = ts->pfrts_bytes[OUT][PFR_OP_BLOCK] & 0xffffffff;
			break;

		case PF_TAOUTXPASSPKTS:
			c64.high = ts->pfrts_packets[OUT][PFR_OP_XPASS] >> 32;
			c64.low = ts->pfrts_packets[OUT][PFR_OP_XPASS] & 0xffffffff;
			break;

		case PF_TAOUTXPASSBYTES:
			c64.high = ts->pfrts_bytes[OUT][PFR_OP_XPASS] >> 32;
			c64.low = ts->pfrts_bytes[OUT][PFR_OP_XPASS] & 0xffffffff;
			break;

		case PF_TASTATSCLEARED:
			ulong_ret = (long) (time(NULL) - ts->pfrts_tzero) * 100;
			free(b.pfrb_caddr);
			return (unsigned char *) &ulong_ret;

		default:
			free(b.pfrb_caddr);
			return (NULL);
	}

	free(b.pfrb_caddr);
	*var_len = sizeof(c64);
	return ((unsigned char *) &c64);
}

/* this function returns OIDs of the form
 * 1.3.6.1.4.1.64512.1.9.129.1.X.A.B.B.B.B.C
 * where
 * X = oid from the request
 * A = tableIndex
 * B.B.B.B. = the network/host IP address
 * C = the bitmask
 * The tableIndex starts at offset 12 in the OID array
 */
unsigned char *
var_tbl_addr_table(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pfr_buffer bt, ba;
	struct pfr_tstats *ts;
	struct pfr_table filter;
	struct pfr_astats *as;
	int table_index = 1, result, break_flag = 0;
	static oid cur_oid[MAX_OID_LEN]; 
	oid *op;
	u_char *cp;
	static struct counter64 c64;
	static u_long ulong_ret;

	if (dev == -1)
		return (NULL);

	if (pft_get(&bt)) {
		snmp_log(LOG_ERR,
			"var_tbl_addr_table: can't get list of pf tables\n");
		return (NULL);
	}
	/* no tables exist */
	if (bt.pfrb_size == 0)
		return (NULL);

	memcpy((char *)cur_oid, (char *)vp->name, (int)(vp->namelen) * sizeof(oid));

	PFRB_FOREACH(ts, &bt) {
		if (!(ts->pfrts_flags & PFR_TFLAG_ACTIVE))
			continue;
		if (ts->pfrts_cnt == 0) {
			op = cur_oid + 12;
			*op++ = table_index;
			result = snmp_oid_compare(name, *length, cur_oid, 12);
			if (exact) {	/* GET */
			       if (result == 0) {
				       	/* this is the table that was requested but
					 * it's empty */
					free(bt.pfrb_caddr);
					free(ba.pfrb_caddr);
					return (NULL);
				} else {
					table_index++;
					continue;
				}
			} else if (!exact) { /* GET-NEXT */
				table_index++;
				continue;
			}
		}

		bzero(&filter, sizeof(struct pfr_table));
		if (strlcpy(filter.pfrt_name, ts->pfrts_t.pfrt_name, 
				sizeof(filter.pfrt_name)) 
				>= sizeof(filter.pfrt_name)) {
			free(bt.pfrb_caddr);
			free(ba.pfrb_caddr);
			return (NULL);
		}
		if (pftable_addr_get(&ba, &filter) || ba.pfrb_size == 0) {
			snmp_log(LOG_ERR,
				"var_tbl_addr_table: "
				"can't get list of addrs for pf table %s\n",
				filter.pfrt_name);
			continue;
		}
		PFRB_FOREACH(as, &ba) {
			if (as->pfras_a.pfra_af != AF_INET)
				continue;
			/* construct new oid */
			op = cur_oid + 12;
			*op++ = table_index;
			cp = (u_char *)&(as->pfras_a.pfra_u);
			*op++ = *cp++;
			*op++ = *cp++;
			*op++ = *cp++;
			*op++ = *cp++;
			*op++ = (u_char *)as->pfras_a.pfra_net;
			result = snmp_oid_compare(name, *length, cur_oid, 18);
			if ((exact && (result == 0)) || (!exact && (result < 0))) {
				*length = 18;
				for (result = 0; result < *length; result++)
					name[result] = cur_oid[result];
				break_flag++;
				break;
			}
		}
		if (break_flag)
			break;
		free(ba.pfrb_caddr);
		table_index++;
	}
	free(bt.pfrb_caddr);

	/* no match found */
	if (break_flag == 0) 
		return (NULL);

	*var_len = sizeof(ulong_ret);

	switch (vp->magic) {
		case PF_TADDRTABLEINDEX:
			ulong_ret = table_index;
			free(ba.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);
			
		case PF_TADDRNET:
			cp = (u_char *)&as->pfras_a.pfra_u;
			memcpy((char *)&ulong_ret, cp, 4);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);
			
		case PF_TADDRMASK:
			ulong_ret = as->pfras_a.pfra_net;
			free(ba.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);
			
		case PF_TADDRCLEARED:
			ulong_ret = (long) (time(NULL) - as->pfras_tzero) * 100;
			free(ba.pfrb_caddr);
			return ((unsigned char *) &ulong_ret);

		case PF_TADDRINBLOCKPKTS:
			c64.high = as->pfras_packets[IN][PFR_OP_BLOCK] >> 32;
			c64.low = as->pfras_packets[IN][PFR_OP_BLOCK] & 0xffffffff;
			*var_len = sizeof(c64);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &c64);
			
		case PF_TADDRINBLOCKBYTES:
			c64.high = as->pfras_bytes[IN][PFR_OP_BLOCK] >> 32;
			c64.low = as->pfras_bytes[IN][PFR_OP_BLOCK] & 0xffffffff;
			*var_len = sizeof(c64);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &c64);
			
		case PF_TADDRINPASSPKTS:
			c64.high = as->pfras_packets[IN][PFR_OP_PASS] >> 32;
			c64.low = as->pfras_packets[IN][PFR_OP_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &c64);
			
		case PF_TADDRINPASSBYTES:
			c64.high = as->pfras_bytes[IN][PFR_OP_PASS] >> 32;
			c64.low = as->pfras_bytes[IN][PFR_OP_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &c64);
			
		case PF_TADDROUTBLOCKPKTS:
			c64.high = as->pfras_packets[OUT][PFR_OP_BLOCK] >> 32;
			c64.low = as->pfras_packets[OUT][PFR_OP_BLOCK] & 0xffffffff;
			*var_len = sizeof(c64);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &c64);
			
		case PF_TADDROUTBLOCKBYTES:
			c64.high = as->pfras_bytes[OUT][PFR_OP_BLOCK] >> 32;
			c64.low = as->pfras_bytes[OUT][PFR_OP_BLOCK] & 0xffffffff;
			*var_len = sizeof(c64);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &c64);
			
		case PF_TADDROUTPASSPKTS:
			c64.high = as->pfras_packets[OUT][PFR_OP_PASS] >> 32;
			c64.low = as->pfras_packets[OUT][PFR_OP_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &c64);
			
		case PF_TADDROUTPASSBYTES:
			c64.high = as->pfras_bytes[OUT][PFR_OP_PASS] >> 32;
			c64.low = as->pfras_bytes[OUT][PFR_OP_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			free(ba.pfrb_caddr);
			return ((unsigned char *) &c64);

		default:
			free(ba.pfrb_caddr);
			return (NULL);
	}
}

int
pfi_get(struct pfr_buffer *b, const char *filter)
{
	bzero(b, sizeof(struct pfr_buffer));
	b->pfrb_type = PFRB_IFACES;
	for (;;) {
		pfr_buf_grow(b, b->pfrb_size);
		b->pfrb_size = b->pfrb_msize;
		if (pfi_get_ifaces(filter, b->pfrb_caddr, &(b->pfrb_size))) {
			snmp_log(LOG_ERR,
				"pfi_get: can't get pf interface %s\n",
				filter);
			return (1);
		}
		if (b->pfrb_size <= b->pfrb_msize)
			break;
	}

	return (0);
}

int
pft_get(struct pfr_buffer *b)
{
	struct pfr_table filter;
    
	bzero(b, sizeof(struct pfr_buffer));
	bzero(&filter, sizeof(filter));
	b->pfrb_type = PFRB_TSTATS;
	
	for (;;) {
		pfr_buf_grow(b, b->pfrb_size);
		b->pfrb_size = b->pfrb_msize;
		if (pfr_get_tstats(&filter, b->pfrb_caddr, &(b->pfrb_size), 0)) {
			snmp_log(LOG_ERR,
				"pft_get: can't get pf table stats\n");
			return (1);
		}
		if (b->pfrb_size <= b->pfrb_msize)
			break;
	}

	return (0);
}


int
pftable_addr_get(struct pfr_buffer *b, struct pfr_table *filter)
{
	bzero(b, sizeof(struct pfr_buffer));
	b->pfrb_type = PFRB_ASTATS;

	for (;;) {
		pfr_buf_grow(b, b->pfrb_size);
		b->pfrb_size = b->pfrb_msize;
		if (pfr_get_astats(filter, b->pfrb_caddr, &(b->pfrb_size), 0)) {
			return (1);
		}
		if (b->pfrb_size <= b->pfrb_msize)
			break;
	}
	
	return (0);
}

int
pfi_refresh(void)
{
	struct pfr_buffer b;
	struct pfi_kif *p;
	int i, match=0;

	if (pfi_get(&b, NULL)) {
		snmp_log(LOG_ERR, "pfi_refresh: can't get list of interfaces\n");
		return (1);
	}

	for (p = pfr_buf_next(&b, NULL); p != NULL; 
			p = pfr_buf_next(&b, p), match = 0) {
		for (i = 0; i < pfi_count && !match; i++) {
			if (strncmp(p->pfik_name, &pfi_table[i], IFNAMSIZ) == 0)
				match = 1;
		}
		if (!match) {
			snprintf(pfi_table[pfi_count], IFNAMSIZ, p->pfik_name);
			pfi_count++;
		}
	}

	pfi_table_age = time(NULL);
	free(b.pfrb_caddr);

	return (0);
}

int
pfl_refresh(void)
{
	u_long nr, mnr;
	struct pfioc_rule pr;

	pfl_count = 0;
	memset(&pr, 0, sizeof(pr));
	if (ioctl(dev, DIOCGETRULES, &pr)) {
		snmp_log(LOG_ERR, "pfl_refresh: ioctl: %s\n", strerror(errno));
		return (NULL);
	}

	mnr = pr.nr;
	for (nr = 0; nr < mnr; ++nr) {
		pr.nr = nr;
		if (ioctl(dev, DIOCGETRULE, &pr)) {
			snmp_log(LOG_ERR, "pfl_refresh: ioctl: %s\n",
				strerror(errno));
			return (NULL);
		}

		if (pr.rule.label[0])
			pfl_count++;
	}

	return (0);
}


int
pft_refresh(void)
{
	struct pfr_buffer b;
	struct pfr_tstats *ts = NULL;

	if (pft_get(&b)) {
		snmp_log(LOG_ERR, "pft_refresh: can't get list of pf tables\n");
		return (1);
	}

	pft_count = 0;
	PFRB_FOREACH(ts, &b) {
		if (!(ts->pfrts_flags & PFR_TFLAG_ACTIVE))
			continue;
		pft_count++;
	}

	free(b.pfrb_caddr);

	return (0);
}

/* the following code taken from pfctl(8) in OpenBSD 3.5-release */

int
pfi_get_ifaces(const char *filter, struct pfi_kif *buf, int *size)
{
	struct pfioc_iface io;

	if (size == NULL || *size < 0 || (*size && buf == NULL)) {
		snmp_log(LOG_DEBUG, "pfi_get_ifaces: failed\n");
		return (-1);
	}

	bzero(&io, sizeof(io));
	if (filter != NULL) {
		if (strlcpy(io.pfiio_name, filter, sizeof(io.pfiio_name)) >=
			sizeof(io.pfiio_name)) {
			snmp_log(LOG_ERR, "pfi_get_ifaces: strlcpy failed\n");
			return (-1);
		}
	}
	io.pfiio_buffer = buf;
	io.pfiio_esize = sizeof(*buf);
	io.pfiio_size = *size;
	if (ioctl(dev, DIOCIGETIFACES, &io)) {
		snmp_log(LOG_ERR, "pfi_get_ifaces: ioctl: %s\n",
			strerror(errno));
		return (-1);
	}
	*size = io.pfiio_size;

	return (0);
}

int
pfr_get_astats(struct pfr_table *tbl, struct pfr_astats *addr, int *size,
		int flags)
{
	struct pfioc_table io;

	if (tbl == NULL || size == NULL || *size < 0 ||
	    (*size && addr == NULL)) 
		return (-1);

	bzero(&io, sizeof io);
	io.pfrio_flags = flags;
	io.pfrio_table = *tbl;
	io.pfrio_buffer = addr;
	io.pfrio_esize = sizeof(*addr);
	io.pfrio_size = *size;
	if (ioctl(dev, DIOCRGETASTATS, &io)) 
		return (-1);
	*size = io.pfrio_size;
	return (0);
}

int
pfr_get_tstats(struct pfr_table *filter, struct pfr_tstats *tbl, int *size,
	int flags)
{
	struct pfioc_table io;

	if (size == NULL || *size < 0 || (*size && tbl == NULL))
		return (-1);
	bzero(&io, sizeof io);
	io.pfrio_flags = flags;
	if (filter != NULL)
		io.pfrio_table = *filter;
	io.pfrio_buffer = tbl;
	io.pfrio_esize = sizeof(*tbl);
	io.pfrio_size = *size;
	if (ioctl(dev, DIOCRGETTSTATS, &io))
		return (-1);
	*size = io.pfrio_size;
	return (0);
}

int
pfr_buf_grow(struct pfr_buffer *b, int minsize)
{
	caddr_t p;
	size_t bs;

	if (minsize != 0 && minsize <= b->pfrb_msize)
		return (0);
	bs = buf_esize[b->pfrb_type];
	if (!b->pfrb_msize) {
		if (minsize < 64)
			minsize = 64;
		b->pfrb_caddr = calloc(bs, minsize);
		if (b->pfrb_caddr == NULL)
			return (-1);
		b->pfrb_msize = minsize;
	} else {
		if (minsize == 0)
			minsize = b->pfrb_msize * 2;
		if (minsize < 0 || minsize >= SIZE_T_MAX / bs) {
			/* msize overflow */
			return (-1);
		}
		p = realloc(b->pfrb_caddr, minsize * bs);
		if (p == NULL)
			return (-1);
		bzero(p + b->pfrb_msize * bs, (minsize - b->pfrb_msize) * bs);
		b->pfrb_caddr = p;
		b->pfrb_msize = minsize;
	}
	return (0);
}

void *
pfr_buf_next(struct pfr_buffer *b, const void *prev)
{
	size_t bs;

	if (b == NULL)
		return (NULL);
	if (b->pfrb_size == 0)
		return (NULL);
	if (prev == NULL) 
		return (b->pfrb_caddr);
	bs = buf_esize[b->pfrb_type];
	if ((((caddr_t)prev)-((caddr_t)b->pfrb_caddr)) / bs >= b->pfrb_size-1)
		return (NULL);

	return (((caddr_t)prev) + bs);
}

