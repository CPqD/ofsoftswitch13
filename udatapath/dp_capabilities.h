/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#ifndef DP_CAPABILITIES_H
#define DP_CAPABILITIES_H 1


#include "openflow/openflow.h"


/****************************************************************************
 * Datapath capabilities.
 ****************************************************************************/

#define DP_SUPPORTED_CAPABILITIES ( OFPC_FLOW_STATS        \
                               | OFPC_TABLE_STATS          \
                               | OFPC_PORT_STATS           \
                               | OFPC_GROUP_STATS          \
                            /* | OFPC_IP_REASM       */    \
                               | OFPC_QUEUE_STATS)
                               /*| OFPC_PORT_BLOCKED */    
    
#define DP_SUPPORTED_ACTIONS ( (1 << OFPAT_OUTPUT)          \
                             | (2 << OFPAT_COPY_TTL_OUT)    \
                             | (3 << OFPAT_COPY_TTL_IN)     \
                             | (4 << OFPAT_SET_MPLS_TTL)    \
                             | (5 << OFPAT_DEC_MPLS_TTL)    \
                             | (6 << OFPAT_PUSH_VLAN)       \
                             | (7 << OFPAT_POP_VLAN)        \
                             | (8 << OFPAT_PUSH_MPLS)       \
                             | (9 << OFPAT_POP_MPLS)        \
                             | (10 << OFPAT_SET_QUEUE)      \
                             | (11 << OFPAT_GROUP)          \
                             | (12 << OFPAT_SET_NW_TTL)     \
                             | (13 << OFPAT_DEC_NW_TTL)      )    
                           
#define DP_SUPPORTED_MATCH_FIELDS ( OFPXMT_OFB_IN_PORT        \
                                  | OFPXMT_OFB_IN_PHY_PORT    \
                                  | OFPXMT_OFB_METADATA       \
                                  | OFPXMT_OFB_ETH_DST        \
                                  | OFPXMT_OFB_ETH_SRC        \
                                  | OFPXMT_OFB_ETH_TYPE       \
                                  | OFPXMT_OFB_VLAN_VID       \
                                  | OFPXMT_OFB_VLAN_PCP       \
                                  | OFPXMT_OFB_IP_DSCP        \
                                  | OFPXMT_OFB_IP_ECN         \
                                  | OFPXMT_OFB_IP_PROTO       \
                                  | OFPXMT_OFB_IPV4_SRC       \
                                  | OFPXMT_OFB_IPV4_DST       \
                                  | OFPXMT_OFB_TCP_SRC        \
                                  | OFPXMT_OFB_TCP_DST        \
                                  | OFPXMT_OFB_TCP_FLAGS      \
                                  | OFPXMT_OFB_UDP_SRC        \
                                  | OFPXMT_OFB_UDP_DST        \
                                  | OFPXMT_OFB_SCTP_SRC       \
                                  | OFPXMT_OFB_SCTP_DST       \
                                  | OFPXMT_OFB_ICMPV4_CODE    \
                                  | OFPXMT_OFB_ICMPV4_TYPE    \
                                  | OFPXMT_OFB_ARP_OP         \
                                  | OFPXMT_OFB_ARP_SHA        \
                                  | OFPXMT_OFB_ARP_SPA        \
                                  | OFPXMT_OFB_ARP_THA        \
                                  | OFPXMT_OFB_ARP_TPA        \
                                  | OFPXMT_OFB_IPV6_SRC       \
                                  | OFPXMT_OFB_IPV6_DST       \
                                  | OFPXMT_OFB_IPV6_FLABEL    \
                                  | OFPXMT_OFB_ICMPV6_CODE    \
                                  | OFPXMT_OFB_ICMPV6_TYPE    \
                                  | OFPXMT_OFB_IPV6_ND_SLL    \
                                  | OFPXMT_OFB_IPV6_ND_TARGET \
                                  | OFPXMT_OFB_IPV6_ND_TLL    \
                                  | OFPXMT_OFB_MPLS_LABEL     \
                                  | OFPXMT_OFB_MPLS_TC         )
                                
#define DP_SUPPORTED_GROUPS ( OFPGT_ALL      \
							| OFPGT_SELECT   \
							| OFPGT_INDIRECT \
							| OFPGT_FF       )

#define DP_SUPPORTED_GROUP_CAPABILITIES ( OFPGFC_SELECT_WEIGHT      \
							            /*| OFPGFC_SELECT_LIVENESS    \
							            | OFPGFC_CHAINING           \
							            | OFPGFC_CHAINING_CHECKS*/)
#endif /* DP_CAPABILITIES_H */
