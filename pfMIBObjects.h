/*
 * $jwk$
 *
 *
 * Copyright (c) 2004-2007 Joel Knight <knight.joel@gmail.com>
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


#ifndef _MIBGROUP_PFMIBOBJECTS_H
#define _MIBGROUP_PFMIBOBJECTS_H

#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <kvm.h>

#define RUNNING			1
#define RUNTIME			2
#define DEBUG			3
#define HOSTID			4
#define MATCH			5
#define BADOFFSET		6
#define FRAGMENT		7
#define SHORT			8
#define NORMALIZE		9
#define MEMORY			10
#define TIMESTAMP		11
#define CONGEST			12
#define IPOPTIONS		13
#define PROTCKSUM		14
#define BADSTATE		15
#define STATEINS		16
#define MAXSTATES		17
#define SRCLIMIT		18
#define SYNPROXY		19
#define STATES_COUNT		20
#define STATES_SEARCHES		21
#define STATES_INSERTS		22
#define STATES_REMOVALS		23
#define PF_LOGIF_NAME		24
#define IPBYTESIN		25
#define IPBYTESOUT		26
#define IPPKTSINPASS		27
#define IPPKTSINDROP		28
#define IPPKTSOUTPASS		29
#define IPPKTSOUTDROP		30
#define IP6BYTESIN		31
#define IP6BYTESOUT		32
#define IP6PKTSINPASS		33
#define IP6PKTSINDROP		34
#define IP6PKTSOUTPASS		35
#define IP6PKTSOUTDROP		36
#define SRCTRACK_COUNT		37
#define SRCTRACK_SEARCHES	38
#define SRCTRACK_INSERTS	39
#define SRCTRACK_REMOVALS	40
#define LIMIT_STATES		41
#define LIMIT_SRC_NODES		42
#define LIMIT_FRAGS		43
#define TM_TCP_FIRST		44
#define TM_TCP_OPENING		45
#define TM_TCP_ESTAB		46
#define TM_TCP_CLOSING		47
#define TM_TCP_FINWAIT		48
#define TM_TCP_CLOSED		49
#define TM_UDP_FIRST		50
#define TM_UDP_SINGLE		51
#define TM_UDP_MULTIPLE		52
#define TM_ICMP_FIRST		53
#define TM_ICMP_ERROR		54
#define TM_OTHER_FIRST		55
#define TM_OTHER_SINGLE		56
#define TM_OTHER_MULTIPLE	57
#define TM_FRAGMENT		58
#define TM_INTERVAL		59
#define TM_ADAPT_START		60
#define TM_ADAPT_END		61
#define TM_SRC_TRACK		62
#define PF_IFNUMBER		128
#define PF_IFINDEX		129
#define PF_IFNAME		130
#define PF_IFTYPE		131
#define PF_IFREF		132
#define PF_IFRULES		133
#define PF_IFIN4PASSPKTS	134
#define PF_IFIN4PASSBYTES	135
#define PF_IFIN4BLOCKPKTS	136
#define PF_IFIN4BLOCKBYTES	137
#define PF_IFOUT4PASSPKTS	138
#define PF_IFOUT4PASSBYTES	139
#define PF_IFOUT4BLOCKPKTS	140
#define PF_IFOUT4BLOCKBYTES	141
#define PF_IFIN6PASSPKTS	142
#define PF_IFIN6PASSBYTES	143
#define PF_IFIN6BLOCKPKTS	144
#define PF_IFIN6BLOCKBYTES	145
#define PF_IFOUT6PASSPKTS	146
#define PF_IFOUT6PASSBYTES	147
#define PF_IFOUT6BLOCKPKTS	148
#define PF_IFOUT6BLOCKBYTES	149
#define PF_TANUMBER		150
#define PF_TAINDEX		151
#define PF_TANAME		152
#define PF_TAADDRESSES		153
#define PF_TAANCHORREFS		154
#define PF_TARULEREFS		155
#define PF_TAEVALSMATCH		156
#define PF_TAEVALSNOMATCH	157
#define PF_TAINPASSPKTS		158
#define PF_TAINPASSBYTES	159
#define PF_TAINBLOCKPKTS	160
#define PF_TAINBLOCKBYTES	161
#define PF_TAINXPASSPKTS	162
#define PF_TAINXPASSBYTES	163
#define PF_TAOUTPASSPKTS	164
#define PF_TAOUTPASSBYTES	165
#define PF_TAOUTBLOCKPKTS	166
#define PF_TAOUTBLOCKBYTES	167
#define PF_TAOUTXPASSPKTS	168
#define PF_TAOUTXPASSBYTES	169
#define PF_TASTATSCLEARED	170
#define PF_TADDRTABLEINDEX	171
#define PF_TADDRNET		172
#define PF_TADDRMASK		173
#define PF_TADDRCLEARED		174
#define PF_TADDRINBLOCKPKTS	175
#define PF_TADDRINBLOCKBYTES	176
#define PF_TADDRINPASSPKTS	177
#define PF_TADDRINPASSBYTES	178
#define PF_TADDROUTBLOCKPKTS	179
#define PF_TADDROUTBLOCKBYTES	180
#define PF_TADDROUTPASSPKTS	181
#define PF_TADDROUTPASSBYTES	182
#define PF_LANUMBER		183
#define PF_LAINDEX		184
#define PF_LANAME		185
#define PF_LAEVALS		186
#define PF_LAPKTS		187
#define PF_LABYTES		188
#define PF_LAINPKTS		189
#define PF_LAINBYTES		190
#define PF_LAOUTPKTS		191
#define PF_LAOUTBYTES		192
#define PFSYNC_IPRECV		193
#define PFSYNC_IP6RECV		194
#define PFSYNC_BADIF		195
#define PFSYNC_BADTTL		196
#define PFSYNC_HDROPS		197
#define PFSYNC_BADVER		198
#define PFSYNC_BADACT		199
#define PFSYNC_BADLEN		200
#define PFSYNC_BADAUTH		201
#define PFSYNC_STALE		202
#define PFSYNC_BADVAL		203
#define PFSYNC_BADSTATE		204
#define PFSYNC_IPSENT		205
#define PFSYNC_IP6SENT		206
#define PFSYNC_NOMEM		207
#define PFSYNC_OERR		208


#define PFI_IFTYPE_GROUP	0
#define PFI_IFTYPE_INSTANCE	1
#define PFI_TABLE_MAXAGE	5

enum { IN, OUT };
enum { IPV4, IPV6 };
enum { PASS, BLOCK };

enum { PFRB_TSTATS = 1, PFRB_ASTATS, PFRB_IFACES, PFRB_MAX };


config_require(util_funcs)

FindVarMethod var_if_number;
FindVarMethod var_if_table;
FindVarMethod var_limits;
FindVarMethod var_pfMIBObjects;
FindVarMethod var_tables_table;
FindVarMethod var_tbl_addr_table;
FindVarMethod var_timeouts;
FindVarMethod var_labels_table;

/* from pfctl */
struct pfr_buffer {
	int	 pfrb_type;	/* type of content, see enum above */
	int	 pfrb_size;	/* number of objects in buffer */
	int	 pfrb_msize;	/* maximum number of objects in buffer */
	void    *pfrb_caddr;	/* malloc'ated memory area */
};


void		 init_pfMIBObjects(void);
void 		*pfr_buf_next(struct pfr_buffer *, const void *);
int		 pfi_get(struct pfr_buffer *, const char *);
int		 pfi_get_ifaces(const char *, struct pfi_kif *, int *);
int		 pfi_refresh(void);
int		 pfr_buf_grow(struct pfr_buffer *, int);
void		*pfr_buf_next(struct pfr_buffer *, const void *);
unsigned char	*var_if_table(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_pfMIBObjects(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_pfsync_stats(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_limits(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_table_number(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_tables_table(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_tbl_addr_table(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_timeouts(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_labels_table(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);


#endif /* _MIBGROUP_PFMIBOBJECTS_H */
