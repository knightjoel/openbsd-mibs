/*
 * $jwk$
 *
 *
 * Copyright (c) 2004,2005 Joel Knight <enabled@myrealbox.com>
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
#define STATES_COUNT		11
#define STATES_SEARCHES		12
#define STATES_INSERTS		13
#define STATES_REMOVALS		14
#define PF_LOGIF_NAME		15
#define IPBYTESIN		16
#define IPBYTESOUT		17
#define IPPKTSINPASS		18
#define IPPKTSINDROP		19
#define IPPKTSOUTPASS		20
#define IPPKTSOUTDROP		21
#define IP6BYTESIN		22
#define IP6BYTESOUT		23
#define IP6PKTSINPASS		24
#define IP6PKTSINDROP		25
#define IP6PKTSOUTPASS		26
#define IP6PKTSOUTDROP		27
#define SRCTRACK_COUNT		28
#define SRCTRACK_SEARCHES	29
#define SRCTRACK_INSERTS	30
#define SRCTRACK_REMOVALS	31
#define LIMIT_STATES		32
#define LIMIT_SRC_NODES		33
#define LIMIT_FRAGS		34
#define TM_TCP_FIRST		35
#define TM_TCP_OPENING		36
#define TM_TCP_ESTAB		37
#define TM_TCP_CLOSING		38
#define TM_TCP_FINWAIT		39
#define TM_TCP_CLOSED		40
#define TM_UDP_FIRST		41
#define TM_UDP_SINGLE		42
#define TM_UDP_MULTIPLE		43
#define TM_ICMP_FIRST		44
#define TM_ICMP_ERROR		45
#define TM_OTHER_FIRST		46
#define TM_OTHER_SINGLE		47
#define TM_OTHER_MULTIPLE	48
#define TM_FRAGMENT		49
#define TM_INTERVAL		50
#define TM_ADAPT_START		51
#define TM_ADAPT_END		52
#define TM_SRC_TRACK		53
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


#define PFI_IFTYPE_GROUP	0
#define PFI_IFTYPE_INSTANCE	1
#define PFI_IFTYPE_DETACH	2
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

/* from pfctl */
struct pfr_buffer {
	int	 pfrb_type;	/* type of content, see enum above */
	int	 pfrb_size;	/* number of objects in buffer */
	int	 pfrb_msize;	/* maximum number of objects in buffer */
	void    *pfrb_caddr;	/* malloc'ated memory area */
};


void		 init_pfMIBObjects(void);
void 		*pfr_buf_next(struct pfr_buffer *, const void *);
int		 pfi_get(struct pfr_buffer *, const char *, int);
int		 pfi_get_ifaces(const char *, struct pfi_if *, int *, int);
int		 pfi_refresh(void);
int		 pfr_buf_grow(struct pfr_buffer *, int);
void		*pfr_buf_next(struct pfr_buffer *, const void *);
unsigned char	*var_if_table(struct variable *, oid *, size_t *, int,
	size_t *, WriteMethod **);
unsigned char	*var_pfMIBObjects(struct variable *, oid *, size_t *, int,
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


#endif /* _MIBGROUP_PFMIBOBJECTS_H */
