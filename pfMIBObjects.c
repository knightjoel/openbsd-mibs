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
#include "OpenBSD.h"

enum { IN, OUT };
enum { IPV4, IPV6 };

int dev = -1;
oid OpenBSD_variables_oid[] = { 1,3,6,1,4,1,64512 };


struct variable4 OpenBSD_variables[] = {
/*  magic number        , variable type , ro/rw , callback fn  , L, oidsuffix */
  { RUNNING             , ASN_INTEGER   , RONLY , var_OpenBSD, 3, { 1,1,1 } },
  { RUNTIME             , ASN_TIMETICKS , RONLY , var_OpenBSD, 3, { 1,1,2 } },
  { DEBUG               , ASN_INTEGER   , RONLY , var_OpenBSD, 3, { 1,1,3 } },
  { HOSTID              , ASN_OCTET_STR , RONLY , var_OpenBSD, 3, { 1,1,4 } },
  { MATCH               , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,1 } },
  { BADOFFSET           , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,2 } },
  { FRAGMENT            , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,3 } },
  { SHORT               , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,4 } },
  { NORMALIZE           , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,5 } },
  { MEMORY              , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,6 } },
  { COUNT               , ASN_UNSIGNED  , RONLY , var_OpenBSD, 3, { 1,3,1 } },
  { SEARCHES            , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,3,2 } },
  { INSERTS             , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,3,3 } },
  { REMOVALS            , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,3,4 } },
  { NAME                , ASN_OCTET_STR , RONLY , var_OpenBSD, 3, { 1,4,1 } },
  { IPBYTESIN           , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,2 } },
  { IPBYTESOUT          , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,3 } },
  { IPPKTSINPASS        , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,4 } },
  { IPPKTSINDROP        , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,5 } },
  { IPPKTSOUTPASS       , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,6 } },
  { IPPKTSOUTDROP       , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,7 } },
  { IP6BYTESIN          , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,8 } },
  { IP6BYTESOUT         , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,9 } },
  { IP6PKTSINPASS       , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,10 } },
  { IP6PKTSINDROP       , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,11 } },
  { IP6PKTSOUTPASS      , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,12 } },
  { IP6PKTSOUTDROP      , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,4,13 } },
};
/*    (L = length of the oidsuffix) */


void init_OpenBSD(void) {
	REGISTER_MIB("OpenBSD", OpenBSD_variables, variable4,
			OpenBSD_variables_oid);

	if ((dev = open("/dev/pf", O_RDONLY)) == -1) 
		ERROR_MSG("Could not open /dev/pf");
}

unsigned char *
var_OpenBSD(struct variable *vp, oid *name, size_t *length, int exact,
		size_t  *var_len, WriteMethod **write_method)
{
	struct pf_status s;
	time_t runtime;
	
	static long long_ret;
	static u_long ulong_ret;
	static unsigned char string[SPRINT_MAX_LEN];
	static oid objid[MAX_OID_LEN];
	static struct counter64 c64;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED )
		return NULL;

	if (dev == -1)
		return NULL;

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

		case COUNT:
			ulong_ret = (long) s.states;
			return (unsigned char *) &ulong_ret;

		case SEARCHES:
			c64.high = s.fcounters[FCNT_STATE_SEARCH] >> 32;
			c64.low = s.fcounters[FCNT_STATE_SEARCH] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case INSERTS:
			c64.high = s.fcounters[FCNT_STATE_INSERT] >> 32;
			c64.low = s.fcounters[FCNT_STATE_INSERT] & 0xffffffff;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case REMOVALS:
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

		default:
			ERROR_MSG("");

	}

	return NULL;
}


