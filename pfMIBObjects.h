/*
 * $Id$
 *
 * jwk
 */


#ifndef _MIBGROUP_PFMIBOBJECTS_H
#define _MIBGROUP_PFMIBOBJECTS_H

#define RUNNING               1
#define RUNTIME               2
#define DEBUG                 3
#define HOSTID                4
#define MATCH                 5
#define BADOFFSET             6
#define FRAGMENT              7
#define SHORT                 8
#define NORMALIZE             9
#define MEMORY                10
#define STATES_COUNT          11
#define STATES_SEARCHES       12
#define STATES_INSERTS        13
#define STATES_REMOVALS       14
#define NAME                  15
#define IPBYTESIN             16
#define IPBYTESOUT            17
#define IPPKTSINPASS          18
#define IPPKTSINDROP          19
#define IPPKTSOUTPASS         20
#define IPPKTSOUTDROP         21
#define IP6BYTESIN            22
#define IP6BYTESOUT           23
#define IP6PKTSINPASS         24
#define IP6PKTSINDROP         25
#define IP6PKTSOUTPASS        26
#define IP6PKTSOUTDROP        27
#define SRCTRACK_COUNT        28
#define SRCTRACK_SEARCHES     29
#define SRCTRACK_INSERTS      30
#define SRCTRACK_REMOVALS     31
#define LIMIT_STATES          32
#define LIMIT_SRC_NODES       33
#define LIMIT_FRAGS           34
#define TM_TCP_FIRST          35
#define TM_TCP_OPENING        36
#define TM_TCP_ESTAB          37
#define TM_TCP_CLOSING        38
#define TM_TCP_FINWAIT        39
#define TM_TCP_CLOSED         40
#define TM_UDP_FIRST          41
#define TM_UDP_SINGLE         42
#define TM_UDP_MULTIPLE       43
#define TM_ICMP_FIRST         44
#define TM_ICMP_ERROR         45
#define TM_OTHER_FIRST        46
#define TM_OTHER_SINGLE       47
#define TM_OTHER_MULTIPLE     48
#define TM_FRAGMENT           49
#define TM_INTERVAL           50
#define TM_ADAPT_START        51
#define TM_ADAPT_END          52
#define TM_SRC_TRACK          53


config_require(util_funcs)


/* function prototypes */
void   init_pfMIBObjects(void);

FindVarMethod var_limits;
FindVarMethod var_pfMIBObjects;
FindVarMethod var_timeouts;


#endif /* _MIBGROUP_PFMIBOBJECTS_H */
