/*
 * $id$
 *
 * jwk
 */


#ifndef _MIBGROUP_OPENBSD_H
#define _MIBGROUP_OPENBSD_H

#define RUNNING               1
#define UPTIME                2
#define DEBUG                 3
#define HOSTID                4
#define MATCH                 5
#define BAD-OFFSET            6
#define FRAGMENT              7
#define SHORT                 8
#define NORMALIZE             9
#define MEMORY                10
#define COUNT                 11
#define SEARCHES              12
#define INSERTS               13
#define REMOVALS              14
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


config_require(util_funcs)


/* function prototypes */
void   init_OpenBSD(void);
FindVarMethod var_OpenBSD;



#endif /* _MIBGROUP_OPENBSD_H */
