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

enum { IN, OUT };
enum { IPV4, IPV6 };

int dev = -1;
oid pfMIBObjects_variables_oid[] = { 1,3,6,1,4,1,64512,1 };


struct variable2 pfMIBObjects_variables[] = {
/*  magic number        , variable type , ro/rw , callback fn  , L, oidsuffix */
  { RUNNING             , ASN_INTEGER   , RONLY , var_pfMIBObjects, 2, { 1,1 } },
  { RUNTIME             , ASN_TIMETICKS , RONLY , var_pfMIBObjects, 2, { 1,2 } },
  { DEBUG               , ASN_INTEGER   , RONLY , var_pfMIBObjects, 2, { 1,2 } },
  { HOSTID              , ASN_OCTET_STR , RONLY , var_pfMIBObjects, 2, { 1,4 } },
  { MATCH               , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,1 } },
  { BADOFFSET           , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,2 } },
  { FRAGMENT            , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,2 } },
  { SHORT               , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,4 } },
  { NORMALIZE           , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,5 } },
  { MEMORY              , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 2,6 } },
  { STATES_COUNT        , ASN_UNSIGNED  , RONLY , var_pfMIBObjects, 2, { 3,1 } },
  { STATES_SEARCHES     , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,2 } },
  { STATES_INSERTS      , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,2 } },
  { STATES_REMOVALS     , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 3,4 } },
  { NAME                , ASN_OCTET_STR , RONLY , var_pfMIBObjects, 2, { 4,1 } },
  { IPBYTESIN           , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,2 } },
  { IPBYTESOUT          , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,2 } },
  { IPPKTSINPASS        , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,4 } },
  { IPPKTSINDROP        , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,5 } },
  { IPPKTSOUTPASS       , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,6 } },
  { IPPKTSOUTDROP       , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,7 } },
  { IP6BYTESIN          , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,8 } },
  { IP6BYTESOUT         , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,9 } },
  { IP6PKTSINPASS       , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,10 } },
  { IP6PKTSINDROP       , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,11 } },
  { IP6PKTSOUTPASS      , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,12 } },
  { IP6PKTSOUTDROP      , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 4,12 } },
  { SRCTRACK_COUNT      , ASN_UNSIGNED  , RONLY , var_pfMIBObjects, 2, { 5,1 } },
  { SRCTRACK_SEARCHES   , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 5,2 } },
  { SRCTRACK_INSERTS    , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 5,2 } },
  { SRCTRACK_REMOVALS   , ASN_COUNTER64 , RONLY , var_pfMIBObjects, 2, { 5,4 } },
  { LIMIT_STATES        , ASN_UNSIGNED  , RONLY , var_limits, 2, { 6,1 } },
  { LIMIT_SRC_NODES     , ASN_UNSIGNED  , RONLY , var_limits, 2, { 6,2 } },
  { LIMIT_FRAGS         , ASN_UNSIGNED  , RONLY , var_limits, 2, { 6,3 } },
  { TM_TCP_FIRST        , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,1 } },
  { TM_TCP_OPENING      , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,2 } },
  { TM_TCP_ESTAB        , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,3 } },
  { TM_TCP_CLOSING      , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,4 } },
  { TM_TCP_FINWAIT      , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,5 } },
  { TM_TCP_CLOSED       , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,6 } },
  { TM_UDP_FIRST        , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,7 } },
  { TM_UDP_SINGLE       , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,8 } },
  { TM_UDP_MULTIPLE     , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,9 } },
  { TM_ICMP_FIRST       , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,10 } },
  { TM_ICMP_ERROR       , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,11 } },
  { TM_OTHER_FIRST      , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,12 } },
  { TM_OTHER_SINGLE     , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,13 } },
  { TM_OTHER_MULTIPLE   , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,14 } },
  { TM_FRAGMENT         , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,15 } },
  { TM_INTERVAL         , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,16 } },
  { TM_ADAPT_START      , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,17 } },
  { TM_ADAPT_END        , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,18 } },
  { TM_SRC_TRACK        , ASN_INTEGER   , RONLY , var_timeouts, 2, { 7,19 } },
};
/*    (L = length of the oidsuffix) */


void init_pfMIBObjects(void) {
	REGISTER_MIB("pfMIBObjects", pfMIBObjects_variables, variable2,
			pfMIBObjects_variables_oid);

	if ((dev = open("/dev/pf", O_RDONLY)) == -1) 
		ERROR_MSG("Could not open /dev/pf");
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
		size_t  *var_len, WriteMethod **write_method)
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
			runtime = time(NULL) - s.since;
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

		case NAME:
			sprintf(string, "%s", s.ifname);
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

