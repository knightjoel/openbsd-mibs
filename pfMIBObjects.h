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


config_require(util_funcs)


/* function prototypes */
void   init_pfMIBObjects(void);

FindVarMethod var_limits;
FindVarMethod var_pfMIBObjects;


#endif /* _MIBGROUP_PFMIBOBJECTS_H */
