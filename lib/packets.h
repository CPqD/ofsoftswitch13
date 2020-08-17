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
#ifndef PACKETS_H
#define PACKETS_H 1

#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>
#include "compiler.h"
#include "random.h"
#include "util.h"

#define ETH_ADDR_LEN           6

static const uint8_t eth_addr_broadcast[ETH_ADDR_LEN] UNUSED
    = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static inline bool eth_addr_is_broadcast(const uint8_t ea[6])
{
    return (ea[0] & ea[1] & ea[2] & ea[3] & ea[4] & ea[5]) == 0xff;
}
static inline bool eth_addr_is_multicast(const uint8_t ea[6])
{
    return ea[0] & 1;
}
static inline bool eth_addr_is_local(const uint8_t ea[6])
{
    return ea[0] & 2;
}
static inline bool eth_addr_is_zero(const uint8_t ea[6])
{
    return !(ea[0] | ea[1] | ea[2] | ea[3] | ea[4] | ea[5]);
}
static inline bool eth_addr_equals(const uint8_t a[ETH_ADDR_LEN],
                                   const uint8_t b[ETH_ADDR_LEN])
{
    return !memcmp(a, b, ETH_ADDR_LEN);
}
static inline uint64_t eth_addr_to_uint64(const uint8_t ea[ETH_ADDR_LEN])
{
    return (((uint64_t) ea[0] << 40)
            | ((uint64_t) ea[1] << 32)
            | ((uint64_t) ea[2] << 24)
            | ((uint64_t) ea[3] << 16)
            | ((uint64_t) ea[4] << 8)
            | ea[5]);
}
static inline void eth_addr_from_uint64(uint64_t x, uint8_t ea[ETH_ADDR_LEN])
{
    ea[0] = x >> 40;
    ea[1] = x >> 32;
    ea[2] = x >> 24;
    ea[3] = x >> 16;
    ea[4] = x >> 8;
    ea[5] = x;
}
static inline void eth_addr_random(uint8_t ea[ETH_ADDR_LEN])
{
    random_bytes(ea, ETH_ADDR_LEN);
    ea[0] &= ~1;                /* Unicast. */
    ea[0] |= 2;                 /* Private. */
}
/* Returns true if 'ea' is a reserved multicast address, that a bridge must
 * never forward, false otherwise. */
static inline bool eth_addr_is_reserved(const uint8_t ea[ETH_ADDR_LEN])
{
    return (ea[0] == 0x01
            && ea[1] == 0x80
            && ea[2] == 0xc2
            && ea[3] == 0x00
            && ea[4] == 0x00
            && (ea[5] & 0xf0) == 0x00);
}

#define ETH_ADDR_FMT                                                    \
    "%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8 ":%02" PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]


#define ETH_TYPE_II_START      0x0600
#define ETH_TYPE_IP            0x0800
#define ETH_TYPE_IPV6          0x86dd
#define ETH_TYPE_ARP           0x0806
#define ETH_TYPE_TRILL         0x22f3
#define ETH_TYPE_VLAN          0x8100
#define ETH_TYPE_SVLAN         0x9200
#define ETH_TYPE_VLAN_QinQ     0x9100
#define ETH_TYPE_VLAN_PBB_B    0x88a8
#define ETH_TYPE_VLAN_PBB_S    0x88e7
#define ETH_TYPE_MPLS          0x8847
#define ETH_TYPE_MPLS_MCAST    0x8848

#define ETH_HEADER_LEN 14
#define ETH_PAYLOAD_MIN 46
#define ETH_PAYLOAD_MAX 1500
#define ETH_TOTAL_MIN (ETH_HEADER_LEN + ETH_PAYLOAD_MIN)
#define ETH_TOTAL_MAX (ETH_HEADER_LEN + ETH_PAYLOAD_MAX)
#define ETH_VLAN_TOTAL_MAX (ETH_HEADER_LEN + VLAN_HEADER_LEN + ETH_PAYLOAD_MAX)
struct eth_header {
    uint8_t eth_dst[ETH_ADDR_LEN];
    uint8_t eth_src[ETH_ADDR_LEN];
    uint16_t eth_type;
} __attribute__((packed));
BUILD_ASSERT_DECL(ETH_HEADER_LEN == sizeof(struct eth_header));

#define LLC_DSAP_SNAP 0xaa
#define LLC_SSAP_SNAP 0xaa
#define LLC_CNTL_SNAP 3

#define LLC_HEADER_LEN 3
struct llc_header {
    uint8_t llc_dsap;
    uint8_t llc_ssap;
    uint8_t llc_cntl;
} __attribute__((packed));
BUILD_ASSERT_DECL(LLC_HEADER_LEN == sizeof(struct llc_header));

#define SNAP_ORG_ETHERNET "\0\0" /* The compiler adds a null byte, so
                                    sizeof(SNAP_ORG_ETHERNET) == 3. */
#define SNAP_HEADER_LEN 5
struct snap_header {
    uint8_t snap_org[3];
    uint16_t snap_type;
} __attribute__((packed));
BUILD_ASSERT_DECL(SNAP_HEADER_LEN == sizeof(struct snap_header));

#define LLC_SNAP_HEADER_LEN (LLC_HEADER_LEN + SNAP_HEADER_LEN)
struct llc_snap_header {
    struct llc_header llc;
    struct snap_header snap;
} __attribute__((packed));
BUILD_ASSERT_DECL(LLC_SNAP_HEADER_LEN == sizeof(struct llc_snap_header));

#define VLAN_VID_MASK 0x0fff
#define VLAN_VID_SHIFT 0
#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13
#define VLAN_PCP_BITMASK 0x0007 /* the least 3-bit is valid */

#define VLAN_VID_MAX 4095
#define VLAN_PCP_MAX 7

#define VLAN_HEADER_LEN 4
struct vlan_header {
    uint16_t vlan_tci;          /* Lowest 12 bits are VLAN ID. */
    uint16_t vlan_next_type;
};
BUILD_ASSERT_DECL(VLAN_HEADER_LEN == sizeof(struct vlan_header));

/*This structure is used to reconstruct the vlan tag on netdev*/
struct vlan_tag {
    uint16_t vlan_tp_id;          /* Lowest 12 bits are VLAN ID. */
    uint16_t vlan_tci;
};

#define VLAN_ETH_HEADER_LEN (ETH_HEADER_LEN + VLAN_HEADER_LEN)
struct vlan_eth_header {
    uint8_t veth_dst[ETH_ADDR_LEN];
    uint8_t veth_src[ETH_ADDR_LEN];
    uint16_t veth_type;         /* Always htons(ETH_TYPE_VLAN). */
    uint16_t veth_tci;          /* Lowest 12 bits are VLAN ID. */
    uint16_t veth_next_type;
} __attribute__((packed));
BUILD_ASSERT_DECL(VLAN_ETH_HEADER_LEN == sizeof(struct vlan_eth_header));

/* The "(void) (ip)[0]" below has no effect on the value, since it's the first
 * argument of a comma expression, but it makes sure that 'ip' is a pointer.
 * This is useful since a common mistake is to pass an integer instead of a
 * pointer to IP_ARGS. */
#define IP_FMT "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8
#define IP_ARGS(ip)                             \
        ((void) (ip)[0],			\
        ((uint8_t const *) ip)[0]),		\
        ((uint8_t const *) ip)[1],              \
        ((uint8_t const *) ip)[2],              \
        ((uint8_t const *) ip)[3]

#define IP_VER(ip_ihl_ver) ((ip_ihl_ver) >> 4)
#define IP_IHL(ip_ihl_ver) ((ip_ihl_ver) & 15)
#define IP_IHL_VER(ihl, ver) (((ver) << 4) | (ihl))

/* TOS fields. */
#define IP_ECN_MASK 0x03
#define IP_DSCP_MASK 0xfc


#define IP_TYPE_ICMP   1
#define IP_TYPE_TCP    6
#define IP_TYPE_UDP   17
#define IP_TYPE_SCTP 132



#define IPV4_VERSION 4
#define IP_DONT_FRAGMENT  0x4000 /* Don't fragment. */
#define IP_MORE_FRAGMENTS 0x2000 /* More fragments. */
#define IP_FRAG_OFF_MASK  0x1fff /* Fragment offset. */
#define IP_IS_FRAGMENT(ip_frag_off) \
        ((ip_frag_off) & htons(IP_MORE_FRAGMENTS | IP_FRAG_OFF_MASK))

#define IP_ADDR_LEN 4

#define IP_HEADER_LEN 20
struct ip_header {
    uint8_t ip_ihl_ver;
    uint8_t ip_tos;
    uint16_t ip_tot_len;
    uint16_t ip_id;
    uint16_t ip_frag_off;
    uint8_t ip_ttl;
    uint8_t ip_proto;
    uint16_t ip_csum;
    uint32_t ip_src;
    uint32_t ip_dst;
};
BUILD_ASSERT_DECL(IP_HEADER_LEN == sizeof(struct ip_header));

#define IPV6_TYPE_HBH 0
#define IPV6_TYPE_DOH 60
#define IPV6_TYPE_RH  43
#define IPV6_TYPE_FH  44
#define IPV6_TYPE_AH  51
#define IPV6_TYPE_ESP 50
#define IPV6_TYPE_ICMPV6   58
#define IPV6_NO_NEXT_HEADER 59

#define IPV6_VER(ipv6_ver_tc_fl) ((ipv6_ver_tc_fl) >> 28)
#define IPV6_TC(ipv6_ver_tc_fl) ((ipv6_ver_tc_fl) & 0xff00000)
#define IPV6_FLABEL(ipv6_ver_tc_fl) ((ipv6_ver_tc_fl) & 0xffff)

#define IPV6_VERSION 6
#define IPV6_DSCP_MASK 0x0fc00000
#define IPV6_DSCP_SHIFT 22
#define IPV6_ECN_MASK 0x0003
#define IPV6_ECN_SHIFT 20
#define IPV6_FLABEL_MASK 0x000fffff
#define IPV6_HEADER_LEN 40
struct ipv6_header {
    uint32_t ipv6_ver_tc_fl;
    uint16_t ipv6_pay_len;
    uint8_t  ipv6_next_hd;
    uint8_t ipv6_hop_limit;
    struct in6_addr ipv6_src;
    struct in6_addr ipv6_dst;
};
BUILD_ASSERT_DECL(IPV6_HEADER_LEN == sizeof(struct ipv6_header));

enum ipv6_ext_hdr_order_T1 {
    HBH = 1 << 0,
    DESTINATION = 1 << 1,
    ROUTING = 1 << 2,
    FRAGMENT = 1 << 3,
    AUTHENTICATION = 1 << 4,
    ESP = 1 << 5,
};

#define ICMPV6_NEIGHSOL 135
#define ICMPV6_NEIGHADV 136

#define ICMP_HEADER_LEN 4
struct icmp_header {
    uint8_t icmp_type;
    uint8_t icmp_code;
    uint16_t icmp_csum;
};
BUILD_ASSERT_DECL(ICMP_HEADER_LEN == sizeof(struct icmp_header));


#define ND_OPT_SLL 1
#define ND_OPT_TLL 2

#define IPV6_ND_HEADER_LEN 20
struct ipv6_nd_header{
    uint32_t reserved;
    struct in6_addr target_addr;
};
BUILD_ASSERT_DECL(IPV6_ND_HEADER_LEN == sizeof(struct ipv6_nd_header));

#define IPV6_ND_OPT_HD_LEN 2
struct ipv6_nd_options_hd{
    uint8_t type;
    uint8_t length;
};
BUILD_ASSERT_DECL(IPV6_ND_OPT_HD_LEN == sizeof(struct ipv6_nd_options_hd));

#define UDP_HEADER_LEN 8
struct udp_header {
    uint16_t udp_src;
    uint16_t udp_dst;
    uint16_t udp_len;
    uint16_t udp_csum;
};
BUILD_ASSERT_DECL(UDP_HEADER_LEN == sizeof(struct udp_header));

#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

#define TCP_FLAGS(tcp_ctl) (htons(tcp_ctl) & 0x003f)
#define TCP_OFFSET(tcp_ctl) (htons(tcp_ctl) >> 12)

#define TCP_HEADER_LEN 20
struct tcp_header {
    uint16_t tcp_src;
    uint16_t tcp_dst;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_ctl;
    uint16_t tcp_winsz;
    uint16_t tcp_csum;
    uint16_t tcp_urg;
};
BUILD_ASSERT_DECL(TCP_HEADER_LEN == sizeof(struct tcp_header));

#define SCTP_HEADER_LEN 12
struct sctp_header {
    uint16_t sctp_src;
    uint16_t sctp_dst;
    uint32_t sctp_ver_tag;
    uint32_t sctp_csum;
};
BUILD_ASSERT_DECL(SCTP_HEADER_LEN == sizeof(struct sctp_header));

#define ARP_HRD_ETHERNET 1
#define ARP_PRO_IP 0x0800
#define ARP_OP_REQUEST 1
#define ARP_OP_REPLY 2

#define ARP_ETH_HEADER_LEN 28
struct arp_eth_header {
    /* Generic members. */
    uint16_t ar_hrd;           /* Hardware type. */
    uint16_t ar_pro;           /* Protocol type. */
    uint8_t ar_hln;            /* Hardware address length. */
    uint8_t ar_pln;            /* Protocol address length. */
    uint16_t ar_op;            /* Opcode. */

    /* Ethernet+IPv4 specific members. */
    uint8_t ar_sha[ETH_ADDR_LEN]; /* Sender hardware address. */
    uint32_t ar_spa;           /* Sender protocol address. */
    uint8_t ar_tha[ETH_ADDR_LEN]; /* Target hardware address. */
    uint32_t ar_tpa;           /* Target protocol address. */
} __attribute__((packed));
BUILD_ASSERT_DECL(ARP_ETH_HEADER_LEN == sizeof(struct arp_eth_header));

struct qtag_prefix {
    uint16_t eth_type;      /* ETH_TYPE_VLAN */
    uint16_t tci;
};


#define PBB_ISID_LEN 3
#define PBB_HEADER_LEN 18
#define PBB_ISID_MASK 0xffffff

struct pbb_header {
    uint32_t id; /* Service Instance Identifier */
    uint8_t c_eth_dst[ETH_ADDR_LEN]; /* Customer Destination Address */
    uint8_t c_eth_src[ETH_ADDR_LEN]; /* Customer Source Address */
    uint16_t pbb_next_type;
};

#define MPLS_LABEL_MAX   1048575
#define MPLS_TC_MAX            7

#define MPLS_HEADER_LEN 4
struct mpls_header {
    uint32_t fields;
};

#define MPLS_TTL_MASK 0x000000ff
#define MPLS_TTL_SHIFT 0
#define MPLS_S_MASK 0x00000100
#define MPLS_S_SHIFT 8
#define MPLS_TC_MASK 0x00000e00
#define MPLS_TC_SHIFT 9
#define MPLS_LABEL_MASK 0xfffff000
#define MPLS_LABEL_SHIFT 12

BUILD_ASSERT_DECL(MPLS_HEADER_LEN == sizeof(struct mpls_header));

struct protocols_std {
   struct eth_header      * eth;
   struct snap_header     * eth_snap; /* points to SNAP header if eth is 802.3 */
   struct vlan_header     * vlan;
   struct vlan_header     * vlan_last; /* points to the last VLAN header */
   struct mpls_header     * mpls;
   struct pbb_header      * pbb;
   struct ip_header       * ipv4;
   struct ipv6_header     * ipv6;
   struct arp_eth_header  * arp;
   struct tcp_header      * tcp;
   struct udp_header      * udp;
   struct sctp_header     * sctp;
   struct icmp_header     * icmp;
};

static inline void
protocol_reset(struct protocols_std *proto) {
    proto->eth       = NULL;
    proto->eth_snap  = NULL;
    proto->vlan      = NULL;
    proto->vlan_last = NULL;
    proto->mpls      = NULL;
    proto->ipv4      = NULL;
    proto->ipv6      = NULL;
    proto->arp       = NULL;
    proto->tcp       = NULL;
    proto->udp       = NULL;
    proto->sctp      = NULL;
    proto->icmp      = NULL;
    proto->pbb       = NULL;
}


#endif /* packets.h */
