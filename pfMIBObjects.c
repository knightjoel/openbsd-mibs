/*
 * $Id$
 *
 * jwk
 */


#include <config.h>

#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>

#include "mibincl.h"
#include "util_funcs.h"
#include "pfMIBObjects.h"

int	dev = -1;
char *pfi_table[255][255];
unsigned int pfi_count;
time_t pfi_table_age;

oid pfMIBObjects_variables_oid[] = { 1,3,6,1,4,1,64512,1 };

struct variable4 pfMIBObjects_variables[] = {
/*  magic number        , variable type , ro/rw , callback fn  , L, oidsuffix */
  { RUNNING		, ASN_INTEGER   , RONLY , var_pfMIBObjects, 2, { 1,1 } },
  { RUNTIME		, ASN_TIMETICKS , RONLY , var_pfMIBObjects, 2, { 1,2 } },
  { DEBUG		, ASN_INTEGER   , RONLY , var_pfMIBObjects, 2, { 1,2 } },
  { HOSTID		, ASN_OCTET_STR , RONLY , var_pfMIBObjects, 2, { 1,4 } },
  { MATCH		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,1 } },
  { BADOFFSET		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,2 } },
  { FRAGMENT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,2 } },
  { SHORT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,4 } },
  { NORMALIZE		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,5 } },
  { MEMORY		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,6 } },
  { STATES_COUNT	, ASN_UNSIGNED  , RONLY , var_pfMIBObjects, 2, { 3,1 } },
  { STATES_SEARCHES	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,2 } },
  { STATES_INSERTS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,2 } },
  { STATES_REMOVALS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,4 } },
  { PF_LOGIF_NAME	, ASN_OCTET_STR , RONLY , var_pfMIBObjects, 2, { 4,1 } },
  { IPBYTESIN		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,2 } },
  { IPBYTESOUT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,2 } },
  { IPPKTSINPASS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,4 } },
  { IPPKTSINDROP	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,5 } },
  { IPPKTSOUTPASS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,6 } },
  { IPPKTSOUTDROP	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,7 } },
  { IP6BYTESIN		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,8 } },
  { IP6BYTESOUT		, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,9 } },
  { IP6PKTSINPASS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,10 } },
  { IP6PKTSINDROP	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,11 } },
  { IP6PKTSOUTPASS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,12 } },
  { IP6PKTSOUTDROP	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,12 } },
  { SRCTRACK_COUNT	, ASN_UNSIGNED  , RONLY , var_pfMIBObjects, 2, { 5,1 } },
  { SRCTRACK_SEARCHES	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 5,2 } },
  { SRCTRACK_INSERTS	, ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 5,2 } },
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
  { TM_ADAPT_STAR	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,17 } },
  { TM_ADAPT_END	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,18 } },
  { TM_SRC_TRACK	, ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,19 } },
  { PF_IFNUMBER		, ASN_INTEGER   , RONLY , var_if_number, 2, { 8,1 } },
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
  { PF_IFOUT4BLOCKBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,13 } },
  { PF_IFIN6PASSPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,14 } },
  { PF_IFIN6PASSBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,15 } },
  { PF_IFIN6BLOCKPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,16 } },
  { PF_IFIN6BLOCKBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,17 } },
  { PF_IFOUT6PASSPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,18 } },
  { PF_IFOUT6PASSBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,19 } },
  { PF_IFOUT6BLOCKPKTS	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,20 } },
  { PF_IFOUT6BLOCKBYTES	, ASN_COUNTER64	, RONLY	, var_if_table, 4, { 8,128,1,21 } },
};


void init_pfMIBObjects(void) {
	REGISTER_MIB("pfMIBObjects", pfMIBObjects_variables, variable4,
			pfMIBObjects_variables_oid);

	if ((dev = open("/dev/pf", O_RDONLY)) == -1) 
		ERROR_MSG("Could not open /dev/pf");

	bzero(&pfi_table, sizeof(pfi_table));
	pfi_count = 0;
	pfi_refresh();
}

unsigned char *
var_limits(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pfioc_limit pl;
	
	static u_long ulong_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return NULL;

	if (dev == -1)
		return NULL;

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
			ERROR_MSG("");
			return NULL;
	}

	if (ioctl(dev, DIOCGETLIMIT, &pl)) {
		ERROR_MSG("ioctl error doing DIOCGETLIMIT");
		return NULL;
	}
	ulong_ret = pl.limit;
	return (unsigned char *) &ulong_ret;
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
		return NULL;

	if (dev == -1)
		return NULL;

	memset(&s, 0, sizeof(s));
	if (ioctl(dev, DIOCGETSTATUS, &s)) {
		ERROR_MSG("ioctl error doing DIOCGETSTATUS");
		return NULL;
	}

	switch(vp->magic) {

		case RUNNING:
			long_ret = (long) s.running;
			return (unsigned char *) &long_ret;

		case RUNTIME:
			if (s.since > 0)
				runtime = time(NULL) - s.since;
			else
				runtime = 0;
			long_ret = (long) runtime * 100;
			return (unsigned char *) &long_ret;

		case DEBUG:
			long_ret = (long) s.debug;
			return (unsigned char *) &long_ret;

		case HOSTID:
			sprintf(string, "0x%08x", ntohl(s.hostid));
			*var_len = strlen(string);
			return (unsigned char *) string;

		case MATCH:
			c64.high = s.counters[PFRES_MATCH] >> 32;
			c64.low = s.counters[PFRES_MATCH] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case BADOFFSET:
			c64.high = s.counters[PFRES_BADOFF] >> 32;
			c64.low = s.counters[PFRES_BADOFF] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case FRAGMENT:
			c64.high = s.counters[PFRES_FRAG] >> 32;
			c64.low = s.counters[PFRES_FRAG] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case SHORT:
			c64.high = s.counters[PFRES_SHORT] >> 32;
			c64.low = s.counters[PFRES_SHORT] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case NORMALIZE:
			c64.high = s.counters[PFRES_NORM] >> 32;
			c64.low = s.counters[PFRES_NORM] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case MEMORY:
			c64.high = s.counters[PFRES_MEMORY] >> 32;
			c64.low = s.counters[PFRES_MEMORY] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case STATES_COUNT:
			ulong_ret = (long) s.states;
			return (unsigned char *) &ulong_ret;

		case STATES_SEARCHES:
			c64.high = s.fcounters[FCNT_STATE_SEARCH] >> 32;
			c64.low = s.fcounters[FCNT_STATE_SEARCH] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case STATES_INSERTS:
			c64.high = s.fcounters[FCNT_STATE_INSERT] >> 32;
			c64.low = s.fcounters[FCNT_STATE_INSERT] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case STATES_REMOVALS:
			c64.high = s.fcounters[FCNT_STATE_REMOVALS] >> 32;
			c64.low = s.fcounters[FCNT_STATE_REMOVALS] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case PF_LOGIF_NAME:
			strlcpy(string, s.ifname, sizeof(string));
			*var_len = strlen(string);
			return (unsigned char *) string;

		case IPBYTESIN:
			c64.high = s.bcounters[IPV4][IN] >> 32;
			c64.low = s.bcounters[IPV4][IN] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPBYTESOUT:
			c64.high = s.bcounters[IPV4][OUT] >> 32;
			c64.low = s.bcounters[IPV4][OUT] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPPKTSINPASS:
			c64.high = s.pcounters[IPV4][IN][PF_PASS] >> 32;
			c64.low = s.pcounters[IPV4][IN][PF_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPPKTSINDROP:
			c64.high = s.pcounters[IPV4][IN][PF_DROP] >> 32;
			c64.low = s.pcounters[IPV4][IN][PF_DROP] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPPKTSOUTPASS:
			c64.high = s.pcounters[IPV4][OUT][PF_PASS] >> 32;
			c64.low = s.pcounters[IPV4][OUT][PF_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPPKTSOUTDROP:
			c64.high = s.pcounters[IPV4][OUT][PF_DROP] >> 32;
			c64.low = s.pcounters[IPV4][OUT][PF_DROP] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6BYTESIN:
			c64.high = s.bcounters[IPV6][IN] >> 32;
			c64.low = s.bcounters[IPV6][IN] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6BYTESOUT:
			c64.high = s.bcounters[IPV6][OUT] >> 32;
			c64.low = s.bcounters[IPV6][OUT] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6PKTSINPASS:
			c64.high = s.pcounters[IPV6][IN][PF_PASS] >> 32;
			c64.low = s.pcounters[IPV6][IN][PF_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6PKTSINDROP:
			c64.high = s.pcounters[IPV6][IN][PF_DROP] >> 32;
			c64.low = s.pcounters[IPV6][IN][PF_DROP] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6PKTSOUTPASS:
			c64.high = s.pcounters[IPV6][OUT][PF_PASS] >> 32;
			c64.low = s.pcounters[IPV6][OUT][PF_PASS] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6PKTSOUTDROP:
			c64.high = s.pcounters[IPV6][OUT][PF_DROP] >> 32;
			c64.low = s.pcounters[IPV6][OUT][PF_DROP] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case SRCTRACK_COUNT:
			ulong_ret = (long) s.src_nodes;
			return (unsigned char *) &ulong_ret;

		case SRCTRACK_SEARCHES:
			c64.high = s.scounters[SCNT_SRC_NODE_SEARCH] >> 32;
			c64.low = s.scounters[SCNT_SRC_NODE_SEARCH] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case SRCTRACK_INSERTS:
			c64.high = s.scounters[SCNT_SRC_NODE_INSERT] >> 32;
			c64.low = s.scounters[SCNT_SRC_NODE_INSERT] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case SRCTRACK_REMOVALS:
			c64.high = s.scounters[SCNT_SRC_NODE_REMOVALS] >> 32;
			c64.low = s.scounters[SCNT_SRC_NODE_REMOVALS] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;
						
		default:
			ERROR_MSG("");
	}

	return NULL;
}

unsigned char *
var_timeouts(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pfioc_tm pt;

	static long long_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return NULL;

	if (dev == -1)
		return NULL;

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
			ERROR_MSG("");
			return NULL;
	}

	if (ioctl(dev, DIOCGETTIMEOUT, &pt)) {
		ERROR_MSG("ioctl error doing DIOCGETTIMEOUT");
		return NULL;
	}
	long_ret = pt.seconds;
	return (unsigned char *) &long_ret;
}

unsigned char *
var_if_number(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	static u_long ulong_ret;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED)
		return (NULL);

	if ((time(NULL) - pfi_table_age) > PFI_TABLE_MAXAGE)
		pfi_refresh();

	switch (vp->magic) {
		case PF_IFNUMBER:
			ulong_ret = pfi_count;
			return (unsigned char *) &ulong_ret;
		
		default:
			ERROR_MSG("");
			return (NULL);
	}
}


unsigned char *
var_if_table(struct variable *vp, oid *name, size_t *length, int exact,
		size_t *var_len, WriteMethod **write_method)
{
	struct pfr_buffer b;
	struct pfi_if *p;
	int index;
	static struct counter64 c64;
	static u_long ulong_ret;

	if (header_simple_table(vp, name, length, exact, var_len, write_method, pfi_count)
			== MATCH_FAILED)
		return (NULL);

	if (dev == -1)
		return (NULL);

	index = name[*length-1]-1;
	if (!pfi_table[index])
		return (NULL);

	if ((time(NULL) - pfi_table_age) > PFI_TABLE_MAXAGE)
		pfi_refresh();

	if (pfi_get(&b, (const char *)&pfi_table[index], PFI_FLAG_INSTANCE) 
			|| b.pfrb_size == 0) {
		free(b.pfrb_caddr);
		switch (vp->magic) {
			case PF_IFINDEX:
				ulong_ret = index + 1;
				return (unsigned char *) &ulong_ret;

			case PF_IFNAME:
				*var_len = strlen(&pfi_table[index]);
				return (unsigned char *) pfi_table[index];

			case PF_IFTYPE:
				ulong_ret = PFI_IFTYPE_DETACH;
				return (unsigned char *) &ulong_ret;

			case PF_IFREF:
			case PF_IFRULES:
				ulong_ret = 0;
				return (unsigned char *) &ulong_ret;

			default:
				c64.high = 0;
				c64.low = 0;
				*var_len = sizeof(c64);
				return (unsigned char *) &c64;
		}
	} 
	/* we only ask for 1 interface from pfi_get() */
	p = b.pfrb_caddr;

	switch (vp->magic) {
		case PF_IFINDEX:
			ulong_ret = index + 1;
			free(b.pfrb_caddr);
			return (unsigned char *) &ulong_ret;

		case PF_IFNAME:
			*var_len = strlen(p->pfif_name);
			free(b.pfrb_caddr);
			return (unsigned char *) p->pfif_name;

		case PF_IFTYPE:
			ulong_ret = PFI_IFTYPE_INSTANCE;
			free(b.pfrb_caddr);
			return (unsigned char *) &ulong_ret;

		case PF_IFREF:
			ulong_ret = p->pfif_states;
			free(b.pfrb_caddr);
			return (unsigned char *) &ulong_ret;

		case PF_IFRULES:
			ulong_ret = p->pfif_rules;
			free(b.pfrb_caddr);
			return (unsigned char *) &ulong_ret;

		case PF_IFIN4PASSPKTS:
			c64.high = p->pfif_packets[IPV4][IN][PASS] >> 32;
			c64.low = p->pfif_packets[IPV4][IN][PASS] & 0xffffffff;
			break;

		case PF_IFIN4PASSBYTES:
			c64.high = p->pfif_bytes[IPV4][IN][PASS] >> 32;
			c64.low = p->pfif_bytes[IPV4][IN][PASS] & 0xffffffff;
			break;

		case PF_IFIN4BLOCKPKTS:
			c64.high = p->pfif_packets[IPV4][IN][BLOCK] >> 32;
			c64.low = p->pfif_packets[IPV4][IN][BLOCK] & 0xffffffff;
			break;

		case PF_IFIN4BLOCKBYTES:
			c64.high = p->pfif_bytes[IPV4][IN][BLOCK] >> 32;
			c64.low = p->pfif_bytes[IPV4][IN][BLOCK] & 0xffffffff;
			break;

		case PF_IFOUT4PASSPKTS:
			c64.high = p->pfif_packets[IPV4][OUT][PASS] >> 32;
			c64.low = p->pfif_packets[IPV4][OUT][PASS] & 0xffffffff;
			break;

		case PF_IFOUT4PASSBYTES:
			c64.high = p->pfif_bytes[IPV4][OUT][PASS] >> 32;
			c64.low = p->pfif_bytes[IPV4][OUT][PASS] & 0xffffffff;
			break;

		case PF_IFOUT4BLOCKPKTS:
			c64.high = p->pfif_packets[IPV4][OUT][BLOCK] >> 32;
			c64.low = p->pfif_packets[IPV4][OUT][BLOCK] & 0xffffffff;
			break;

		case PF_IFOUT4BLOCKBYTES:
			c64.high = p->pfif_bytes[IPV4][OUT][BLOCK] >> 32;
			c64.low = p->pfif_bytes[IPV4][OUT][BLOCK] & 0xffffffff;
			break;

		case PF_IFIN6PASSPKTS:
			c64.high = p->pfif_packets[IPV6][IN][PASS] >> 32;
			c64.low = p->pfif_packets[IPV6][IN][PASS] & 0xffffffff;
			break;

		case PF_IFIN6PASSBYTES:
			c64.high = p->pfif_bytes[IPV6][IN][PASS] >> 32;
			c64.low = p->pfif_bytes[IPV6][IN][PASS] & 0xffffffff;
			break;

		case PF_IFIN6BLOCKPKTS:
			c64.high = p->pfif_packets[IPV6][IN][BLOCK] >> 32;
			c64.low = p->pfif_packets[IPV6][IN][BLOCK] & 0xffffffff;
			break;

		case PF_IFIN6BLOCKBYTES:
			c64.high = p->pfif_bytes[IPV6][IN][BLOCK] >> 32;
			c64.low = p->pfif_bytes[IPV6][IN][BLOCK] & 0xffffffff;
			break;

		case PF_IFOUT6PASSPKTS:
			c64.high = p->pfif_packets[IPV6][OUT][PASS] >> 32;
			c64.low = p->pfif_packets[IPV6][OUT][PASS] & 0xffffffff;
			break;

		case PF_IFOUT6PASSBYTES:
			c64.high = p->pfif_bytes[IPV6][OUT][PASS] >> 32;
			c64.low = p->pfif_bytes[IPV6][OUT][PASS] & 0xffffffff;
			break;

		case PF_IFOUT6BLOCKPKTS:
			c64.high = p->pfif_packets[IPV6][OUT][BLOCK] >> 32;
			c64.low = p->pfif_packets[IPV6][OUT][BLOCK] & 0xffffffff;
			break;

		case PF_IFOUT6BLOCKBYTES:
			c64.high = p->pfif_bytes[IPV6][OUT][BLOCK] >> 32;
			c64.low = p->pfif_bytes[IPV6][OUT][BLOCK] & 0xffffffff;
			break;
			
		default:
			ERROR_MSG("");
			return (NULL);
	}
	
	free(b.pfrb_caddr);
	*var_len = sizeof(c64);
	return (unsigned char *) &c64;
}

int
pfi_get(struct pfr_buffer *b, const char *filter, int flags)
{
	bzero(b, sizeof(struct pfr_buffer));
	for (;;) {
		pfr_buf_grow(b, b->pfrb_size);
		b->pfrb_size = b->pfrb_msize;
		if (pfi_get_ifaces(filter, b->pfrb_caddr, &(b->pfrb_size), flags)) {
			ERROR_MSG("pfi_get_ifaces() failed");
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
	struct pfi_if *p;
	int i, match=0;

	if (pfi_get(&b, NULL, PFI_FLAG_INSTANCE)) {
		ERROR_MSG("Could not get list of interfaces");
		return (1);
	}

	for (p = pfr_buf_next(&b, NULL); p != NULL; 
			p = pfr_buf_next(&b, p), match = 0) {
		for (i = 0; i < pfi_count && !match; i++) {
			if (strncmp(p->pfif_name, &pfi_table[i], IFNAMSIZ) == 0)
				match = 1;
		}
		if (!match) {
			snprintf(pfi_table[pfi_count], IFNAMSIZ, p->pfif_name);
			pfi_count++;
		}
	}

	pfi_table_age = time(NULL);
	free(b.pfrb_caddr);

	return (0);
}

/* the following code taken from pfctl(8) in OpenBSD 3.5-release */

int
pfi_get_ifaces(const char *filter, struct pfi_if *buf, int *size, int flags)
{
	struct pfioc_iface io;

	bzero(&io, sizeof(io));
	io.pfiio_flags = flags;
	if (filter != NULL) {
		if (strlcpy(io.pfiio_name, filter, sizeof(io.pfiio_name)) >=
			sizeof(io.pfiio_name)) {
			ERROR_MSG("strlcpy(): source buffer too large");
			return (-1);
		}
	}
	io.pfiio_buffer = buf;
	io.pfiio_esize = sizeof(*buf);
	io.pfiio_size = *size;
	if (ioctl(dev, DIOCIGETIFACES, &io)) {
		ERROR_MSG("ioct failed");
		return (-1);
	}
	*size = io.pfiio_size;

	return (0);
}

int
pfr_buf_grow(struct pfr_buffer *b, int minsize)
{
	caddr_t p;
	size_t bs;

	if (minsize != 0 && minsize <= b->pfrb_msize)
		return (0);
	bs = sizeof(struct pfi_if);
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
	bs = sizeof(struct pfi_if);
	if ((((caddr_t)prev)-((caddr_t)b->pfrb_caddr)) / bs >= b->pfrb_size-1)
		return (NULL);

	return (((caddr_t)prev) + bs);
}

