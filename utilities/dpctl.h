/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#ifndef DPCTL_H
#define DPCTL_H 1

#include "openflow/openflow.h"

struct names8 {
    uint8_t   code;
    char     *name;
};

struct names16 {
    uint16_t   code;
    char      *name;
};

struct names32 {
    uint32_t   code;
    char      *name;
};



static struct names32 port_names[] = {
        {OFPP_IN_PORT,    "in_port"},
        {OFPP_TABLE,      "table"},
        {OFPP_NORMAL,     "normal"},
        {OFPP_FLOOD,      "flood"},
        {OFPP_ALL,        "all"},
        {OFPP_CONTROLLER, "ctrl"},
        {OFPP_LOCAL,      "local"},
        {OFPP_ANY,        "any"}
};

static struct names32 queue_names[] = {
        {OFPQ_ALL, "all"}
};

static struct names32 group_names[] = {
        {OFPG_ALL, "all"},
        {OFPG_ANY, "any"}
};

static struct names16 ext_header_names[] = {
        {OFPIEH_NONEXT, "no_next"},
        {OFPIEH_ESP,    "esp"},
        {OFPIEH_AUTH,   "auth"},
        {OFPIEH_DEST,   "dest"},
        {OFPIEH_FRAG,   "frag"},
        {OFPIEH_ROUTER, "router"},
        {OFPIEH_HOP,    "hop"},
        {OFPIEH_UNREP,  "unrep"},
        {OFPIEH_UNSEQ,  "unseq"}
};

static struct names8 group_type_names[] = {
        {OFPGT_ALL,      "all"},
        {OFPGT_SELECT,   "sel"},
        {OFPGT_INDIRECT, "ind"},
        {OFPGT_FF,       "ff"}
};

static struct names16 group_mod_cmd_names[] = {
        {OFPGC_ADD,    "add"},
        {OFPGC_MODIFY, "mod"},
        {OFPGC_DELETE, "del"}
};

static struct names16 meter_mod_cmd_names[] = {
        {OFPMC_ADD,    "add"},
        {OFPMC_MODIFY, "mod"},
        {OFPMC_DELETE, "del"}
};

static struct names8 table_names[] = {
        {0xff, "all"}
};

static struct names16 inst_names[] = {
        {OFPIT_GOTO_TABLE,     "goto"},
        {OFPIT_WRITE_METADATA, "meta"},
        {OFPIT_WRITE_ACTIONS,  "write"},
        {OFPIT_APPLY_ACTIONS,  "apply"},
        {OFPIT_CLEAR_ACTIONS,  "clear"},
        {OFPIT_METER,  "meter"}
};

static struct names8 flow_mod_cmd_names[] = {
        {OFPFC_ADD,           "add"},
        {OFPFC_MODIFY,        "mod"},
        {OFPFC_MODIFY_STRICT, "mods"},
        {OFPFC_DELETE,        "del"},
        {OFPFC_DELETE_STRICT, "dels"}
};

static struct names32 buffer_names[] = {
        {0xffffffff, "none"}
};

static struct names16 vlan_vid_names[] = {
        {OFPVID_PRESENT,  "any"},
        {OFPVID_NONE, "none"}
};


static struct names16 action_names[] = {
        {OFPAT_OUTPUT,         "output"},
        {OFPAT_COPY_TTL_OUT,   "ttl_out"},
        {OFPAT_COPY_TTL_IN,    "ttl_in"},
        {OFPAT_SET_MPLS_TTL,   "mpls_ttl"},
        {OFPAT_DEC_MPLS_TTL,   "mpls_dec"},
        {OFPAT_PUSH_VLAN,      "push_vlan"},
        {OFPAT_POP_VLAN,       "pop_vlan"},
        {OFPAT_PUSH_PBB,       "push_pbb"},
        {OFPAT_POP_PBB,        "pop_pbb"},
        {OFPAT_PUSH_MPLS,      "push_mpls"},
        {OFPAT_POP_MPLS,       "pop_mpls"},
        {OFPAT_SET_QUEUE,      "queue"},
        {OFPAT_GROUP,          "group"},
        {OFPAT_SET_NW_TTL,     "nw_ttl"},
        {OFPAT_DEC_NW_TTL,     "nw_dec"},
        {OFPAT_SET_FIELD,      "set_field"}
};

static struct names16 band_names[] = {
    {OFPMBT_DROP, "drop"},
    {OFPMBT_DSCP_REMARK, "dscp_remark"}
}; 

#define FLOW_MOD_COMMAND       "cmd"
#define FLOW_MOD_COOKIE        "cookie"
#define FLOW_MOD_COOKIE_MASK   "cookie_mask"
#define FLOW_MOD_TABLE_ID      "table"
#define FLOW_MOD_IDLE          "idle"
#define FLOW_MOD_HARD          "hard"
#define FLOW_MOD_PRIO          "prio"
#define FLOW_MOD_BUFFER        "buffer"
#define FLOW_MOD_OUT_PORT      "out_port"
#define FLOW_MOD_OUT_GROUP     "out_group"
#define FLOW_MOD_FLAGS         "flags"
#define FLOW_MOD_MATCH         "match"


#define MATCH_IN_PORT        "in_port"
#define MATCH_DL_SRC         "eth_src"
#define MATCH_DL_SRC_MASK    "eth_src_mask"
#define MATCH_DL_DST         "eth_dst"
#define MATCH_DL_DST_MASK    "eth_dst_mask"
#define MATCH_DL_VLAN        "vlan_vid"
#define MATCH_IP_DSCP        "ip_dscp"
#define MATCH_IP_ECN         "ip_ecn"
#define MATCH_DL_VLAN_PCP    "vlan_pcp"
#define MATCH_DL_TYPE        "eth_type"
#define MATCH_NW_PROTO       "ip_proto"
#define MATCH_NW_SRC         "ip_src"
#define MATCH_NW_SRC_MASK    "nw_src_mask"
#define MATCH_NW_DST         "ip_dst"
#define MATCH_NW_DST_MASK    "ipv4_dst_mask"
#define MATCH_TP_SRC         "tcp_src"
#define MATCH_TP_DST         "tcp_dst"
#define MATCH_TP_FLAG        "tcp_flags"
#define MATCH_TP_FLAG_MASK   "tcp_flags_mask"
#define MATCH_UDP_SRC        "udp_src"
#define MATCH_UDP_DST        "udp_dst"
#define MATCH_SCTP_SRC       "sctp_src"
#define MATCH_SCTP_DST       "sctp_dst"
#define MATCH_ICMPV4_CODE    "icmp_code"
#define MATCH_ICMPV4_TYPE    "icmp_type"
#define MATCH_ARP_OP         "arp_op"
#define MATCH_ARP_SHA        "arp_sha"
#define MATCH_ARP_THA        "arp_tha"
#define MATCH_ARP_SPA        "arp_spa"
#define MATCH_ARP_TPA        "arp_tpa"
#define MATCH_NW_SRC_IPV6    "ipv6_src"
#define MATCH_NW_DST_IPV6    "ipv6_dst"
#define MATCH_ICMPV6_CODE    "icmpv6_code"
#define MATCH_ICMPV6_TYPE    "icmpv6_type"
#define MATCH_IPV6_FLABEL    "ipv6_flabel"
#define MATCH_IPV6_ND_TARGET "ipv6_nd_target"
#define MATCH_IPV6_ND_SLL    "ipv6_nd_sll"
#define MATCH_IPV6_ND_TLL    "ipv6_nd_tll"
#define MATCH_MPLS_LABEL     "mpls_label"
#define MATCH_MPLS_TC        "mpls_tc"
#define MATCH_MPLS_BOS       "mpls_bos"
#define MATCH_METADATA       "meta"
#define MATCH_METADATA_MASK  "meta_mask"
#define MATCH_STATE          "state"
#define MATCH_STATE_MASK     "state_mask"
#define MATCH_FLAGS          "flags"
#define MATCH_FLAGS_MASK     "flags_mask"
#define MATCH_PBB_ISID       "pbb_isid"
#define MATCH_TUNNEL_ID      "tunn_id"    
#define MATCH_EXT_HDR        "ext_hdr"

#define GROUP_MOD_COMMAND "cmd"
#define GROUP_MOD_TYPE    "type"
#define GROUP_MOD_GROUP   "group"

#define BUCKET_WEIGHT       "weight"
#define BUCKET_WATCH_PORT   "port"
#define BUCKET_WATCH_GROUP  "group"

#define METER_MOD_COMMAND "cmd"
#define METER_MOD_FLAGS   "flags"
#define METER_MOD_METER   "meter"

#define BAND_RATE "rate"
#define BAND_BURST_SIZE "burst"
#define BAND_PREC_LEVEL "prec_level"

#define CONFIG_FLAGS "flags"
#define CONFIG_MISS  "miss"


#define PORT_MOD_PORT      "port"
#define PORT_MOD_HW_ADDR   "addr"
#define PORT_MOD_HW_CONFIG "conf"
#define PORT_MOD_MASK      "mask"
#define PORT_MOD_ADVERTISE "adv"


#define TABLE_MOD_TABLE  "table"
#define TABLE_MOD_CONFIG "conf"

#define KEY_VAL    "="
#define KEY_VAL2   ":"
#define KEY_SEP    ","
#define MASK_SEP   "/"

#define ADD   "+"
#define WILDCARD_SUB   '-'



#define NUM_ELEMS( x )   (sizeof(x) / sizeof(x[0]))


#endif /* DPCTL_H */
