/*
 * $Id$
 *
 * jwk
 */


#ifdef IN_UCD_SNMP_SOURCE
#include <config.h>
#include "mibincl.h"
#include "util_funcs.h"
#else /* !IN_UCD_SNMP_SOURCE */
#include <ucd-snmp/ucd-snmp-config.h>
#include <ucd-snmp/ucd-snmp-includes.h>
#include <ucd-snmp/ucd-snmp-agent-includes.h>
#endif /* !IN_UCD_SNMP_SOURCE */

#include "OpenBSD.h"


oid OpenBSD_variables_oid[] = { 1,3,6,1,4,1,64512 };


struct variable4 OpenBSD_variables[] = {
/*  magic number        , variable type , ro/rw , callback fn  , L, oidsuffix */
  { RUNNING             , ASN_INTEGER   , RONLY , var_OpenBSD, 3, { 1,1,1 } },
  { UPTIME              , ASN_TIMETICKS , RONLY , var_OpenBSD, 3, { 1,1,2 } },
  { DEBUG               , ASN_INTEGER   , RONLY , var_OpenBSD, 3, { 1,1,3 } },
  { HOSTID              , ASN_OCTET_STR , RONLY , var_OpenBSD, 3, { 1,1,4 } },
  { MATCH               , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,1 } },
  { BAD-OFFSET          , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,2 } },
  { FRAGMENT            , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,3 } },
  { SHORT               , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,4 } },
  { NORMALIZE           , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,5 } },
  { MEMORY              , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,2,6 } },
  { COUNT               , ASN_UNSIGNED  , RONLY , var_OpenBSD, 3, { 1,3,1 } },
  { SEARCHES            , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,3,2 } },
  { INSERTS             , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,3,3 } },
  { REMOVALS            , ASN_COUNTER64 , RONLY , var_OpenBSD, 3, { 1,3,4 } },
  { NAME                , ASN_OCTET_STR , RONLY , var_OpenBSD, 3, { 1,4,1 } },
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
}

unsigned char *
var_OpenBSD(struct variable *vp, oid *name, size_t *length, int exact,
		size_t  *var_len, WriteMethod **write_method)
{
	static long long_ret;
	static u_long ulong_ret;
	static unsigned char string[SPRINT_MAX_LEN];
	static oid objid[MAX_OID_LEN];
	static struct counter64 c64;

	if (header_generic(vp, name, length, exact, var_len, write_method)
			== MATCH_FAILED )
		return NULL;


	switch(vp->magic) {

		case RUNNING:
			long_ret = 0;
			return (unsigned char *) &long_ret;

		case UPTIME:
			long_ret = 0;
			return (unsigned char *) &long_ret;

		case DEBUG:
			long_ret = 0;
			return (unsigned char *) &long_ret;

		case HOSTID:
			*string = 0;
			*var_len = strlen(string);
			return (unsigned char *) string;

		case MATCH:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case BAD-OFFSET:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case FRAGMENT:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case SHORT:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case NORMALIZE:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case MEMORY:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case COUNT:
			ulong_ret = 0;
			return (unsigned char *) &ulong_ret;

		case SEARCHES:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case INSERTS:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case REMOVALS:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case NAME:
			*string = 0;
			*var_len = strlen(string);
			return (unsigned char *) string;

		case IPBYTESIN:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPBYTESOUT:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPPKTSINPASS:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPPKTSINDROP:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPPKTSOUTPASS:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IPPKTSOUTDROP:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6BYTESIN:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6BYTESOUT:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6PKTSINPASS:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6PKTSINDROP:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6PKTSOUTPASS:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		case IP6PKTSOUTDROP:
			c64.high = 0;
			c64.low = 0;
			*var_len = sizeof(c64);
			return (unsigned char *) &c64;

		default:
			ERROR_MSG("");

	}

	return NULL;
}


