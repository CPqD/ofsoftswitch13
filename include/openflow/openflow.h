/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
 * Junior University
 * Copyright (c) 2011, 2012 Open Networking Foundation
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

/* OpenFlow: protocol between controller and datapath. */

#ifndef OPENFLOW_OPENFLOW_H
#define OPENFLOW_OPENFLOW_H 1

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

#ifdef SWIG
#define OFP_ASSERT(EXPR)        /* SWIG can't handle OFP_ASSERT. */
#elif !defined(__cplusplus)
/* Build-time assertion for use in a declaration context. */
#define OFP_ASSERT(EXPR)                                                \
        extern int (*build_assert(void))[ sizeof(struct {               \
                    unsigned int build_assert_failed : (EXPR) ? 1 : -1; })]
#else /* __cplusplus */
#define OFP_ASSERT(_EXPR) typedef int build_assert_failed[(_EXPR) ? 1 : -1]
#endif /* __cplusplus */

#ifndef SWIG
#define OFP_PACKED __attribute__((packed))
#else
#define OFP_PACKED              /* SWIG doesn't understand __attribute. */
#endif

/* Version number:
 * OpenFlow versions released: 0x01 = 1.0 ; 0x02 = 1.1 ; 0x03 = 1.2
 *     0x04 = 1.3
 */
/* The most significant bit in the version field is reserved and must
 * be set to zero.
 */
#define OFP_VERSION   0x04
#define PIPELINE_TABLES 64
#define OFP_MAX_TABLE_NAME_LEN 32
#define OFP_MAX_PORT_NAME_LEN  16
/* Official IANA registered port for OpenFlow. */
#define OFP_TCP_PORT  6653
#define OFP_SSL_PORT  6653

#define OFP_ETH_ALEN 6          /* Bytes in an Ethernet address. */

/* Port numbering. Ports are numbered starting from 1. */
enum ofp_port_no {
    /* Maximum number of physical and logical switch ports. */
    OFPP_MAX        = 0xffffff00,

    /* Reserved OpenFlow Port (fake output "ports"). */
    OFPP_IN_PORT    = 0xfffffff8,  /* Send the packet out the input port.  This
                                      reserved port must be explicitly used
                                      in order to send back out of the input
                                      port. */
    OFPP_TABLE      = 0xfffffff9,  /* Submit the packet to the first flow table
                                      NB: This destination port can only be
                                      used in packet-out messages. */
    OFPP_NORMAL     = 0xfffffffa,  /* Forward using non-OpenFlow pipeline. */
    OFPP_FLOOD      = 0xfffffffb,  /* Flood using non-OpenFlow pipeline. */
    OFPP_ALL        = 0xfffffffc,  /* All standard ports except input port. */
    OFPP_CONTROLLER = 0xfffffffd,  /* Send to controller. */
    OFPP_LOCAL      = 0xfffffffe,  /* Local openflow "port". */
    OFPP_ANY        = 0xffffffff   /* Special value used in some requests when
                                      no port is specified (i.e. wildcarded). */
};

enum ofp_type {
    /* Immutable messages. */
    OFPT_HELLO              = 0,  /* Symmetric message */
    OFPT_ERROR              = 1,  /* Symmetric message */
    OFPT_ECHO_REQUEST       = 2,  /* Symmetric message */
    OFPT_ECHO_REPLY         = 3,  /* Symmetric message */
    OFPT_EXPERIMENTER       = 4,  /* Symmetric message */

    /* Switch configuration messages. */
    OFPT_FEATURES_REQUEST   = 5,  /* Controller/switch message */
    OFPT_FEATURES_REPLY     = 6,  /* Controller/switch message */
    OFPT_GET_CONFIG_REQUEST = 7,  /* Controller/switch message */
    OFPT_GET_CONFIG_REPLY   = 8,  /* Controller/switch message */
    OFPT_SET_CONFIG         = 9,  /* Controller/switch message */

    /* Asynchronous messages. */
    OFPT_PACKET_IN          = 10, /* Async message */
    OFPT_FLOW_REMOVED       = 11, /* Async message */
    OFPT_PORT_STATUS        = 12, /* Async message */

    /* Controller command messages. */
    OFPT_PACKET_OUT         = 13, /* Controller/switch message */
    OFPT_FLOW_MOD           = 14, /* Controller/switch message */
    OFPT_GROUP_MOD          = 15, /* Controller/switch message */
    OFPT_PORT_MOD           = 16, /* Controller/switch message */
    OFPT_TABLE_MOD          = 17, /* Controller/switch message */

    /* Multipart messages. */
    OFPT_MULTIPART_REQUEST      = 18, /* Controller/switch message */
    OFPT_MULTIPART_REPLY        = 19, /* Controller/switch message */

    /* Barrier messages. */
    OFPT_BARRIER_REQUEST    = 20, /* Controller/switch message */
    OFPT_BARRIER_REPLY      = 21, /* Controller/switch message */

    /* Queue Configuration messages. */
    OFPT_QUEUE_GET_CONFIG_REQUEST = 22,  /* Controller/switch message */
    OFPT_QUEUE_GET_CONFIG_REPLY   = 23,  /* Controller/switch message */

    /* Controller role change request messages. */
    OFPT_ROLE_REQUEST       = 24, /* Controller/switch message */
    OFPT_ROLE_REPLY         = 25, /* Controller/switch message */

    /* Asynchronous message configuration. */
    OFPT_GET_ASYNC_REQUEST  = 26, /* Controller/switch message */
    OFPT_GET_ASYNC_REPLY    = 27, /* Controller/switch message */
    OFPT_SET_ASYNC          = 28, /* Controller/switch message */

    /* Meters and rate limiters configuration messages. */
    OFPT_METER_MOD          = 29, /* Controller/switch message */
};

/* Header on all OpenFlow packets. */
struct ofp_header {
    uint8_t version;    /* OFP_VERSION. */
    uint8_t type;       /* One of the OFPT_ constants. */
    uint16_t length;    /* Length including this ofp_header. */
    uint32_t xid;       /* Transaction id associated with this packet.
                           Replies use the same id as was in the request
                           to facilitate pairing. */
};
OFP_ASSERT(sizeof(struct ofp_header) == 8);

/* Hello elements types.
 */
enum ofp_hello_elem_type {
    OFPHET_VERSIONBITMAP          = 1,  /* Bitmap of version supported. */
};

/* Common header for all Hello Elements */
struct ofp_hello_elem_header {
    uint16_t         type;    /* One of OFPHET_*. */
    uint16_t         length;  /* Length in bytes of the element,
                                 including this header, excluding padding. */
};
OFP_ASSERT(sizeof(struct ofp_hello_elem_header) == 4);

/* Version bitmap Hello Element */
struct ofp_hello_elem_versionbitmap {
    uint16_t         type;    /* OFPHET_VERSIONBITMAP. */
    uint16_t         length;  /* Length in bytes of this element,
                                 including this header, excluding padding. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the bitmaps, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    uint32_t         bitmaps[0];   /* List of bitmaps - supported versions */
};
OFP_ASSERT(sizeof(struct ofp_hello_elem_versionbitmap) == 4);

/* OFPT_HELLO.  This message includes zero or more hello elements having
 * variable size. Unknown elements types must be ignored/skipped, to allow
 * for future extensions. */
struct ofp_hello {
    struct ofp_header header;

    /* Hello element list */
    struct ofp_hello_elem_header elements[0]; /* List of elements - 0 or more */
};
OFP_ASSERT(sizeof(struct ofp_hello) == 8);

#define OFP_DEFAULT_MISS_SEND_LEN   128

enum ofp_config_flags {
    /* Handling of IP fragments. */
    OFPC_FRAG_NORMAL   = 0,       /* No special handling for fragments. */
    OFPC_FRAG_DROP     = 1 << 0,  /* Drop fragments. */
    OFPC_FRAG_REASM    = 1 << 1,  /* Reassemble (only if OFPC_IP_REASM set). */
    OFPC_FRAG_MASK     = 3,       /* Bitmask of flags dealing with frag. */
};

/* Switch configuration. */
struct ofp_switch_config {
    struct ofp_header header;
    uint16_t flags;             /* Bitmap of OFPC_* flags. */
    uint16_t miss_send_len;     /* Max bytes of packet that datapath
                                   should send to the controller. See
                                   ofp_controller_max_len for valid values.
                                   */
};
OFP_ASSERT(sizeof(struct ofp_switch_config) == 12);

/* Flags to configure the table. Reserved for future use. */
enum ofp_table_config {
    OFPTC_DEPRECATED_MASK       = 3,  /* Deprecated bits */
};

/* Table numbering. Tables can use any number up to OFPT_MAX. */
enum ofp_table {
    /* Last usable table number. */
    OFPTT_MAX        = 0xfe,

    /* Fake tables. */
    OFPTT_ALL        = 0xff   /* Wildcard table used for table config,
                                 flow stats and flow deletes. */
};


/* Configure/Modify behavior of a flow table */
struct ofp_table_mod {
    struct ofp_header header;
    uint8_t table_id;       /* ID of the table, OFPTT_ALL indicates all tables */
    uint8_t pad[3];         /* Pad to 32 bits */
    uint32_t config;        /* Bitmap of OFPTC_* flags */
};
OFP_ASSERT(sizeof(struct ofp_table_mod) == 16);

/* Capabilities supported by the datapath. */
enum ofp_capabilities {
    OFPC_FLOW_STATS     = 1 << 0,  /* Flow statistics. */
    OFPC_TABLE_STATS    = 1 << 1,  /* Table statistics. */
    OFPC_PORT_STATS     = 1 << 2,  /* Port statistics. */
    OFPC_GROUP_STATS    = 1 << 3,  /* Group statistics. */
    OFPC_IP_REASM       = 1 << 5,  /* Can reassemble IP fragments. */
    OFPC_QUEUE_STATS    = 1 << 6,  /* Queue statistics. */
    OFPC_PORT_BLOCKED   = 1 << 8   /* Switch will block looping ports. */
};

/* Flags to indicate behavior of the physical port.  These flags are
 * used in ofp_port to describe the current configuration.  They are
 * used in the ofp_port_mod message to configure the port's behavior.
 */
enum ofp_port_config {
    OFPPC_PORT_DOWN    = 1 << 0,  /* Port is administratively down. */

    OFPPC_NO_RECV      = 1 << 2,  /* Drop all packets received by port. */
    OFPPC_NO_FWD       = 1 << 5,  /* Drop packets forwarded to port. */
    OFPPC_NO_PACKET_IN = 1 << 6   /* Do not send packet-in msgs for port. */
};

/* Current state of the physical port.  These are not configurable from
 * the controller.
 */
enum ofp_port_state {
    OFPPS_LINK_DOWN    = 1 << 0,  /* No physical link present. */
    OFPPS_BLOCKED      = 1 << 1,  /* Port is blocked */
    OFPPS_LIVE         = 1 << 2,  /* Live for Fast Failover Group. */
};

/* Features of ports available in a datapath. */
enum ofp_port_features {
    OFPPF_10MB_HD    = 1 << 0,  /* 10 Mb half-duplex rate support. */
    OFPPF_10MB_FD    = 1 << 1,  /* 10 Mb full-duplex rate support. */
    OFPPF_100MB_HD   = 1 << 2,  /* 100 Mb half-duplex rate support. */
    OFPPF_100MB_FD   = 1 << 3,  /* 100 Mb full-duplex rate support. */
    OFPPF_1GB_HD     = 1 << 4,  /* 1 Gb half-duplex rate support. */
    OFPPF_1GB_FD     = 1 << 5,  /* 1 Gb full-duplex rate support. */
    OFPPF_10GB_FD    = 1 << 6,  /* 10 Gb full-duplex rate support. */
    OFPPF_40GB_FD    = 1 << 7,  /* 40 Gb full-duplex rate support. */
    OFPPF_100GB_FD   = 1 << 8,  /* 100 Gb full-duplex rate support. */
    OFPPF_1TB_FD     = 1 << 9,  /* 1 Tb full-duplex rate support. */
    OFPPF_OTHER      = 1 << 10, /* Other rate, not in the list. */

    OFPPF_COPPER     = 1 << 11, /* Copper medium. */
    OFPPF_FIBER      = 1 << 12, /* Fiber medium. */
    OFPPF_AUTONEG    = 1 << 13, /* Auto-negotiation. */
    OFPPF_PAUSE      = 1 << 14, /* Pause. */
    OFPPF_PAUSE_ASYM = 1 << 15  /* Asymmetric pause. */
};

/* Description of a port */
struct ofp_port {
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN];
    uint8_t pad2[2];                  /* Align to 64 bits. */
    char name[OFP_MAX_PORT_NAME_LEN]; /* Null-terminated */

    uint32_t config;        /* Bitmap of OFPPC_* flags. */
    uint32_t state;         /* Bitmap of OFPPS_* flags. */

    /* Bitmaps of OFPPF_* that describe features.  All bits zeroed if
     * unsupported or unavailable. */
    uint32_t curr;          /* Current features. */
    uint32_t advertised;    /* Features being advertised by the port. */
    uint32_t supported;     /* Features supported by the port. */
    uint32_t peer;          /* Features advertised by peer. */

    uint32_t curr_speed;    /* Current port bitrate in kbps. */
    uint32_t max_speed;     /* Max port bitrate in kbps */
};
OFP_ASSERT(sizeof(struct ofp_port) == 64);

/* Switch features. */
struct ofp_switch_features {
    struct ofp_header header;
    uint64_t datapath_id;   /* Datapath unique ID.  The lower 48-bits are for
                               a MAC address, while the upper 16-bits are
                               implementer-defined. */

    uint32_t n_buffers;     /* Max packets buffered at once. */

    uint8_t n_tables;       /* Number of tables supported by datapath. */
    uint8_t auxiliary_id;   /* Identify auxiliary connections */
    uint8_t pad[2];         /* Align to 64-bits. */

    /* Features. */
    uint32_t capabilities;  /* Bitmap of support "ofp_capabilities". */
    uint32_t reserved;
};
OFP_ASSERT(sizeof(struct ofp_switch_features) == 32);

/* What changed about the physical port */
enum ofp_port_reason {
    OFPPR_ADD     = 0,         /* The port was added. */
    OFPPR_DELETE  = 1,         /* The port was removed. */
    OFPPR_MODIFY  = 2,         /* Some attribute of the port has changed. */
};

/* A physical port has changed in the datapath */
struct ofp_port_status {
    struct ofp_header header;
    uint8_t reason;          /* One of OFPPR_*. */
    uint8_t pad[7];          /* Align to 64-bits. */
    struct ofp_port desc;
};
OFP_ASSERT(sizeof(struct ofp_port_status) == 80);

/* Modify behavior of the physical port */
struct ofp_port_mod {
    struct ofp_header header;
    uint32_t port_no;
    uint8_t pad[4];
    uint8_t hw_addr[OFP_ETH_ALEN]; /* The hardware address is not
                                      configurable.  This is used to
                                      sanity-check the request, so it must
                                      be the same as returned in an
                                      ofp_port struct. */
    uint8_t pad2[2];        /* Pad to 64 bits. */
    uint32_t config;        /* Bitmap of OFPPC_* flags. */
    uint32_t mask;          /* Bitmap of OFPPC_* flags to be changed. */

    uint32_t advertise;     /* Bitmap of OFPPF_*.  Zero all bits to prevent
                               any action taking place. */
    uint8_t pad3[4];        /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_port_mod) == 40);

/* ## -------------------------- ## */
/* ## OpenFlow Extensible Match. ## */
/* ## -------------------------- ## */

/* The match type indicates the match structure (set of fields that compose the
 * match) in use. The match type is placed in the type field at the beginning
 * of all match structures. The "OpenFlow Extensible Match" type corresponds
 * to OXM TLV format described below and must be supported by all OpenFlow
 * switches. Extensions that define other match types may be published on the
 * ONF wiki. Support for extensions is optional.
 */
enum ofp_match_type {
    OFPMT_STANDARD = 0,       /* Deprecated. */
    OFPMT_OXM      = 1,       /* OpenFlow Extensible Match */
};

/* Fields to match against flows */
struct ofp_match {
    uint16_t type;             /* One of OFPMT_* */
    uint16_t length;           /* Length of ofp_match (excluding padding) */
    /* Followed by:
     *   - Exactly (length - 4) (possibly 0) bytes containing OXM TLVs, then
     *   - Exactly ((length + 7)/8*8 - length) (between 0 and 7) bytes of
     *     all-zero bytes
     * In summary, ofp_match is padded as needed, to make its overall size
     * a multiple of 8, to preserve alignment in structures using it.
     */
    uint8_t oxm_fields[0];     /* 0 or more OXM match fields */
    uint8_t pad[4];            /* Zero bytes - see above for sizing */
};
OFP_ASSERT(sizeof(struct ofp_match) == 8);

/* Components of a OXM TLV header.
 * Those macros are not valid for the experimenter class, macros for the
 * experimenter class will depend on the experimenter header used. */
#define OXM_HEADER__(CLASS, FIELD, HASMASK, LENGTH) \
    (((CLASS) << 16) | ((FIELD) << 9) | ((HASMASK) << 8) | (LENGTH))
#define OXM_HEADER(CLASS, FIELD, LENGTH) \
    OXM_HEADER__(CLASS, FIELD, 0, LENGTH)
#define OXM_HEADER_W(CLASS, FIELD, LENGTH) \
    OXM_HEADER__(CLASS, FIELD, 1, (LENGTH) * 2)
#define OXM_CLASS(HEADER) ((HEADER) >> 16)
#define OXM_FIELD(HEADER) (((HEADER) >> 9) & 0x7f)
#define OXM_TYPE(HEADER) (((HEADER) >> 9) & 0x7fffff)
#define OXM_HASMASK(HEADER) (((HEADER) >> 8) & 1)
#define OXM_LENGTH(HEADER) ((HEADER) & 0xff)

#define OXM_MAKE_WILD_HEADER(HEADER) \
        OXM_HEADER_W(OXM_CLASS(HEADER), OXM_FIELD(HEADER), OXM_LENGTH(HEADER))

/* OXM Class IDs.
 * The high order bit differentiate reserved classes from member classes.
 * Classes 0x0000 to 0x7FFF are member classes, allocated by ONF.
 * Classes 0x8000 to 0xFFFE are reserved classes, reserved for standardisation.
 */
enum ofp_oxm_class {
    OFPXMC_NXM_0          = 0x0000,    /* Backward compatibility with NXM */
    OFPXMC_NXM_1          = 0x0001,    /* Backward compatibility with NXM */
    OFPXMC_OPENFLOW_BASIC = 0x8000,    /* Basic class for OpenFlow */
    OFPXMC_EXPERIMENTER   = 0xFFFF,    /* Experimenter class */
};

/* OXM Flow match field types for OpenFlow basic class. */
enum oxm_ofb_match_fields {
    OFPXMT_OFB_IN_PORT        = 0,  /* Switch input port. */
    OFPXMT_OFB_IN_PHY_PORT    = 1,  /* Switch physical input port. */
    OFPXMT_OFB_METADATA       = 2,  /* Metadata passed between tables. */
    OFPXMT_OFB_ETH_DST        = 3,  /* Ethernet destination address. */
    OFPXMT_OFB_ETH_SRC        = 4,  /* Ethernet source address. */
    OFPXMT_OFB_ETH_TYPE       = 5,  /* Ethernet frame type. */
    OFPXMT_OFB_VLAN_VID       = 6,  /* VLAN id. */
    OFPXMT_OFB_VLAN_PCP       = 7,  /* VLAN priority. */
    OFPXMT_OFB_IP_DSCP        = 8,  /* IP DSCP (6 bits in ToS field). */
    OFPXMT_OFB_IP_ECN         = 9,  /* IP ECN (2 bits in ToS field). */
    OFPXMT_OFB_IP_PROTO       = 10, /* IP protocol. */
    OFPXMT_OFB_IPV4_SRC       = 11, /* IPv4 source address. */
    OFPXMT_OFB_IPV4_DST       = 12, /* IPv4 destination address. */
    OFPXMT_OFB_TCP_SRC        = 13, /* TCP source port. */
    OFPXMT_OFB_TCP_DST        = 14, /* TCP destination port. */
    OFPXMT_OFB_UDP_SRC        = 15, /* UDP source port. */
    OFPXMT_OFB_UDP_DST        = 16, /* UDP destination port. */
    OFPXMT_OFB_SCTP_SRC       = 17, /* SCTP source port. */
    OFPXMT_OFB_SCTP_DST       = 18, /* SCTP destination port. */
    OFPXMT_OFB_ICMPV4_TYPE    = 19, /* ICMP type. */
    OFPXMT_OFB_ICMPV4_CODE    = 20, /* ICMP code. */
    OFPXMT_OFB_ARP_OP         = 21, /* ARP opcode. */
    OFPXMT_OFB_ARP_SPA        = 22, /* ARP source IPv4 address. */
    OFPXMT_OFB_ARP_TPA        = 23, /* ARP target IPv4 address. */
    OFPXMT_OFB_ARP_SHA        = 24, /* ARP source hardware address. */
    OFPXMT_OFB_ARP_THA        = 25, /* ARP target hardware address. */
    OFPXMT_OFB_IPV6_SRC       = 26, /* IPv6 source address. */
    OFPXMT_OFB_IPV6_DST       = 27, /* IPv6 destination address. */
    OFPXMT_OFB_IPV6_FLABEL    = 28, /* IPv6 Flow Label */
    OFPXMT_OFB_ICMPV6_TYPE    = 29, /* ICMPv6 type. */
    OFPXMT_OFB_ICMPV6_CODE    = 30, /* ICMPv6 code. */
    OFPXMT_OFB_IPV6_ND_TARGET = 31, /* Target address for ND. */
    OFPXMT_OFB_IPV6_ND_SLL    = 32, /* Source link-layer for ND. */
    OFPXMT_OFB_IPV6_ND_TLL    = 33, /* Target link-layer for ND. */
    OFPXMT_OFB_MPLS_LABEL     = 34, /* MPLS label. */
    OFPXMT_OFB_MPLS_TC        = 35, /* MPLS TC. */
    OFPXMT_OFB_MPLS_BOS       = 36, /* MPLS BoS bit. */
    OFPXMT_OFB_PBB_ISID       = 37, /* PBB I-SID. */
    OFPXMT_OFB_TUNNEL_ID      = 38, /* Logical Port Metadata. */
    OFPXMT_OFB_IPV6_EXTHDR    = 39, /* IPv6 Extension Header pseudo-field */
};

#define OFPXMT_OFB_ALL    ((UINT64_C(1) << 40) - 1)

/* OpenFlow port on which the packet was received.
 * May be a physical port, a logical port, or the reserved port OFPP_LOCAL
 *
 * Prereqs: None.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_IN_PORT    OXM_HEADER  (0x8000, OFPXMT_OFB_IN_PORT, 4)

/* Physical port on which the packet was received.
 *
 * Consider a packet received on a tunnel interface defined over a link
 * aggregation group (LAG) with two physical port members.  If the tunnel
 * interface is the logical port bound to OpenFlow.  In this case,
 * OFPXMT_OF_IN_PORT is the tunnel's port number and OFPXMT_OF_IN_PHY_PORT is
 * the physical port number of the LAG on which the tunnel is configured.
 *
 * When a packet is received directly on a physical port and not processed by a
 * logical port, OFPXMT_OF_IN_PORT and OFPXMT_OF_IN_PHY_PORT have the same
 * value.
 *
 * This field is usually not available in a regular match and only available
 * in ofp_packet_in messages when it's different from OXM_OF_IN_PORT.
 *
 * Prereqs: OXM_OF_IN_PORT must be present.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_IN_PHY_PORT OXM_HEADER  (0x8000, OFPXMT_OFB_IN_PHY_PORT, 4)

/* Table metadata.
 *
 * Prereqs: None.
 *
 * Format: 64-bit integer in network byte order.
 *
 * Masking: Arbitrary masks.
 */
#define OXM_OF_METADATA   OXM_HEADER  (0x8000, OFPXMT_OFB_METADATA, 8)
#define OXM_OF_METADATA_W OXM_HEADER_W(0x8000, OFPXMT_OFB_METADATA, 8)

/* Source or destination address in Ethernet header.
 *
 * Prereqs: None.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_ETH_DST    OXM_HEADER  (0x8000, OFPXMT_OFB_ETH_DST, 6)
#define OXM_OF_ETH_DST_W  OXM_HEADER_W(0x8000, OFPXMT_OFB_ETH_DST, 6)
#define OXM_OF_ETH_SRC    OXM_HEADER  (0x8000, OFPXMT_OFB_ETH_SRC, 6)
#define OXM_OF_ETH_SRC_W  OXM_HEADER_W(0x8000, OFPXMT_OFB_ETH_SRC, 6)

/* Packet's Ethernet type.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_ETH_TYPE   OXM_HEADER  (0x8000, OFPXMT_OFB_ETH_TYPE, 2)

/* The VLAN id is 12-bits, so we can use the entire 16 bits to indicate
 * special conditions.
 */
enum ofp_vlan_id {
    OFPVID_PRESENT = 0x1000, /* Bit that indicate that a VLAN id is set */
    OFPVID_NONE    = 0x0000, /* No VLAN id was set. */
};
/* Define for compatibility */
#define OFP_VLAN_NONE      OFPVID_NONE

/* 802.1Q VID.
 *
 * For a packet with an 802.1Q header, this is the VLAN-ID (VID) from the
 * outermost tag, with the CFI bit forced to 1. For a packet with no 802.1Q
 * header, this has value OFPVID_NONE.
 *
 * Prereqs: None.
 *
 * Format: 16-bit integer in network byte order with bit 13 indicating
 * presence of VLAN header and 3 most-significant bits forced to 0.
 * Only the lower 13 bits have meaning.
 *
 * Masking: Arbitrary masks.
 *
 * This field can be used in various ways:
 *
 *   - If it is not constrained at all, the nx_match matches packets without
 *     an 802.1Q header or with an 802.1Q header that has any VID value.
 *
 *   - Testing for an exact match with 0x0 matches only packets without
 *     an 802.1Q header.
 *
 *   - Testing for an exact match with a VID value with CFI=1 matches packets
 *     that have an 802.1Q header with a specified VID.
 *
 *   - Testing for an exact match with a nonzero VID value with CFI=0 does
 *     not make sense.  The switch may reject this combination.
 *
 *   - Testing with nxm_value=0, nxm_mask=0x0fff matches packets with no 802.1Q
 *     header or with an 802.1Q header with a VID of 0.
 *
 *   - Testing with nxm_value=0x1000, nxm_mask=0x1000 matches packets with
 *     an 802.1Q header that has any VID value.
 */
#define OXM_OF_VLAN_VID   OXM_HEADER  (0x8000, OFPXMT_OFB_VLAN_VID, 2)
#define OXM_OF_VLAN_VID_W OXM_HEADER_W(0x8000, OFPXMT_OFB_VLAN_VID, 2)

/* 802.1Q PCP.
 *
 * For a packet with an 802.1Q header, this is the VLAN-PCP from the
 * outermost tag.  For a packet with no 802.1Q header, this has value
 * 0.
 *
 * Prereqs: OXM_OF_VLAN_VID must be different from OFPVID_NONE.
 *
 * Format: 8-bit integer with 5 most-significant bits forced to 0.
 * Only the lower 3 bits have meaning.
 *
 * Masking: Not maskable.
 */
#define OXM_OF_VLAN_PCP   OXM_HEADER  (0x8000, OFPXMT_OFB_VLAN_PCP, 1)

/* The Diff Serv Code Point (DSCP) bits of the IP header.
 * Part of the IPv4 ToS field or the IPv6 Traffic Class field.
 *
 * Prereqs: OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer with 2 most-significant bits forced to 0.
 * Only the lower 6 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_IP_DSCP     OXM_HEADER  (0x8000, OFPXMT_OFB_IP_DSCP, 1)

/* The ECN bits of the IP header.
 * Part of the IPv4 ToS field or the IPv6 Traffic Class field.
 *
 * Prereqs: OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer with 6 most-significant bits forced to 0.
 * Only the lower 2 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_IP_ECN     OXM_HEADER  (0x8000, OFPXMT_OFB_IP_ECN, 1)

/* The "protocol" byte in the IP header.
 *
 * Prereqs: OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define OXM_OF_IP_PROTO   OXM_HEADER  (0x8000, OFPXMT_OFB_IP_PROTO, 1)

/* The source or destination address in the IP header.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x0800 exactly.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Arbitrary masks.
 */
#define OXM_OF_IPV4_SRC     OXM_HEADER  (0x8000, OFPXMT_OFB_IPV4_SRC, 4)
#define OXM_OF_IPV4_SRC_W   OXM_HEADER_W(0x8000, OFPXMT_OFB_IPV4_SRC, 4)
#define OXM_OF_IPV4_DST     OXM_HEADER  (0x8000, OFPXMT_OFB_IPV4_DST, 4)
#define OXM_OF_IPV4_DST_W   OXM_HEADER_W(0x8000, OFPXMT_OFB_IPV4_DST, 4)

/* The source or destination port in the TCP header.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must be either 0x0800 or 0x86dd.
 *   OXM_OF_IP_PROTO must match 6 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_TCP_SRC    OXM_HEADER  (0x8000, OFPXMT_OFB_TCP_SRC, 2)
#define OXM_OF_TCP_DST    OXM_HEADER  (0x8000, OFPXMT_OFB_TCP_DST, 2)

/* The source or destination port in the UDP header.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd.
 *   OXM_OF_IP_PROTO must match 17 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_UDP_SRC    OXM_HEADER  (0x8000, OFPXMT_OFB_UDP_SRC, 2)
#define OXM_OF_UDP_DST    OXM_HEADER  (0x8000, OFPXMT_OFB_UDP_DST, 2)

/* The source or destination port in the SCTP header.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match either 0x0800 or 0x86dd.
 *   OXM_OF_IP_PROTO must match 132 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_SCTP_SRC   OXM_HEADER  (0x8000, OFPXMT_OFB_SCTP_SRC, 2)
#define OXM_OF_SCTP_DST   OXM_HEADER  (0x8000, OFPXMT_OFB_SCTP_DST, 2)

/* The type or code in the ICMP header.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x0800 exactly.
 *   OXM_OF_IP_PROTO must match 1 exactly.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define OXM_OF_ICMPV4_TYPE  OXM_HEADER  (0x8000, OFPXMT_OFB_ICMPV4_TYPE, 1)
#define OXM_OF_ICMPV4_CODE  OXM_HEADER  (0x8000, OFPXMT_OFB_ICMPV4_CODE, 1)

/* ARP opcode.
 *
 * For an Ethernet+IP ARP packet, the opcode in the ARP header.  Always 0
 * otherwise.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 16-bit integer in network byte order.
 *
 * Masking: Not maskable. */
#define OXM_OF_ARP_OP     OXM_HEADER  (0x8000, OFPXMT_OFB_ARP_OP, 2)

/* For an Ethernet+IP ARP packet, the source or target protocol address
 * in the ARP header.  Always 0 otherwise.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 32-bit integer in network byte order.
 *
 * Masking: Arbitrary masks.
 */
#define OXM_OF_ARP_SPA    OXM_HEADER  (0x8000, OFPXMT_OFB_ARP_SPA, 4)
#define OXM_OF_ARP_SPA_W  OXM_HEADER_W(0x8000, OFPXMT_OFB_ARP_SPA, 4)
#define OXM_OF_ARP_TPA    OXM_HEADER  (0x8000, OFPXMT_OFB_ARP_TPA, 4)
#define OXM_OF_ARP_TPA_W  OXM_HEADER_W(0x8000, OFPXMT_OFB_ARP_TPA, 4)

/* For an Ethernet+IP ARP packet, the source or target hardware address
 * in the ARP header.  Always 0 otherwise.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x0806 exactly.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
#define OXM_OF_ARP_SHA    OXM_HEADER   (0x8000, OFPXMT_OFB_ARP_SHA, 6)
#define OXM_OF_ARP_SHA_W  OXM_HEADER_W (0x8000, OFPXMT_OFB_ARP_SHA, 6)
#define OXM_OF_ARP_THA    OXM_HEADER   (0x8000, OFPXMT_OFB_ARP_THA, 6)
#define OXM_OF_ARP_THA_W  OXM_HEADER_W (0x8000, OFPXMT_OFB_ARP_THA, 6)


/* The source or destination address in the IPv6 header.
 *
 * Prereqs: OXM_OF_ETH_TYPE must match 0x86dd exactly.
 *
 * Format: 128-bit IPv6 address.
 *
 * Masking: Arbitrary masks.
 */
#define OXM_OF_IPV6_SRC    OXM_HEADER  (0x8000, OFPXMT_OFB_IPV6_SRC, 16)
#define OXM_OF_IPV6_SRC_W  OXM_HEADER_W(0x8000, OFPXMT_OFB_IPV6_SRC, 16)
#define OXM_OF_IPV6_DST    OXM_HEADER  (0x8000, OFPXMT_OFB_IPV6_DST, 16)
#define OXM_OF_IPV6_DST_W  OXM_HEADER_W(0x8000, OFPXMT_OFB_IPV6_DST, 16)

/* The IPv6 Flow Label
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x86dd exactly
 *
 * Format: 32-bit integer with 12 most-significant bits forced to 0.
 * Only the lower 20 bits have meaning.
 *
 * Masking: Arbitrary masks.
 */
#define OXM_OF_IPV6_FLABEL   OXM_HEADER  (0x8000, OFPXMT_OFB_IPV6_FLABEL, 4)
#define OXM_OF_IPV6_FLABEL_W OXM_HEADER_W(0x8000, OFPXMT_OFB_IPV6_FLABEL, 4)

/* The type or code in the ICMPv6 header.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x86dd exactly.
 *   OXM_OF_IP_PROTO must match 58 exactly.
 *
 * Format: 8-bit integer.
 *
 * Masking: Not maskable. */
#define OXM_OF_ICMPV6_TYPE OXM_HEADER  (0x8000, OFPXMT_OFB_ICMPV6_TYPE, 1)
#define OXM_OF_ICMPV6_CODE OXM_HEADER  (0x8000, OFPXMT_OFB_ICMPV6_CODE, 1)

/* The target address in an IPv6 Neighbor Discovery message.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x86dd exactly.
 *   OXM_OF_IP_PROTO must match 58 exactly.
 *   OXM_OF_ICMPV6_TYPE must be either 135 or 136.
 *
 * Format: 128-bit IPv6 address.
 *
 * Masking: Not maskable. */
#define OXM_OF_IPV6_ND_TARGET OXM_HEADER (0x8000, OFPXMT_OFB_IPV6_ND_TARGET, 16)

/* The source link-layer address option in an IPv6 Neighbor Discovery
 * message.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x86dd exactly.
 *   OXM_OF_IP_PROTO must match 58 exactly.
 *   OXM_OF_ICMPV6_TYPE must be exactly 135.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
#define OXM_OF_IPV6_ND_SLL  OXM_HEADER  (0x8000, OFPXMT_OFB_IPV6_ND_SLL, 6)

/* The target link-layer address option in an IPv6 Neighbor Discovery
 * message.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x86dd exactly.
 *   OXM_OF_IP_PROTO must match 58 exactly.
 *   OXM_OF_ICMPV6_TYPE must be exactly 136.
 *
 * Format: 48-bit Ethernet MAC address.
 *
 * Masking: Not maskable. */
#define OXM_OF_IPV6_ND_TLL  OXM_HEADER  (0x8000, OFPXMT_OFB_IPV6_ND_TLL, 6)

/* The LABEL in the first MPLS shim header.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
 *
 * Format: 32-bit integer in network byte order with 12 most-significant
 * bits forced to 0. Only the lower 20 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_MPLS_LABEL  OXM_HEADER  (0x8000, OFPXMT_OFB_MPLS_LABEL, 4)

/* The TC in the first MPLS shim header.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
 *
 * Format: 8-bit integer with 5 most-significant bits forced to 0.
 * Only the lower 3 bits have meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_MPLS_TC     OXM_HEADER  (0x8000, OFPXMT_OFB_MPLS_TC, 1)

/* The BoS bit in the first MPLS shim header.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x8847 or 0x8848 exactly.
 *
 * Format: 8-bit integer with 7 most-significant bits forced to 0.
 * Only the lowest bit have a meaning.
 *
 * Masking: Not maskable. */
#define OXM_OF_MPLS_BOS     OXM_HEADER  (0x8000, OFPXMT_OFB_MPLS_BOS, 1)

/* IEEE 802.1ah I-SID.
 *
 * For a packet with a PBB header, this is the I-SID from the
 * outermost service tag.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x88E7 exactly.
 *
 * Format: 24-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_PBB_ISID   OXM_HEADER  (0x8000, OFPXMT_OFB_PBB_ISID, 3)
#define OXM_OF_PBB_ISID_W OXM_HEADER_W(0x8000, OFPXMT_OFB_PBB_ISID, 3)

/* Logical Port Metadata.
 *
 * Metadata associated with a logical port.
 * If the logical port performs encapsulation and decapsulation, this
 * is the demultiplexing field from the encapsulation header.
 * For example, for a packet received via GRE tunnel including a (32-bit) key,
 * the key is stored in the low 32-bits and the high bits are zeroed.
 * For a MPLS logical port, the low 20 bits represent the MPLS Label.
 * For a VxLAN logical port, the low 24 bits represent the VNI.
 * If the packet is not received through a logical port, the value is 0.
 *
 * Prereqs: None.
 *
 * Format: 64-bit integer in network byte order.
 *
 * Masking: Arbitrary masks. */
#define OXM_OF_TUNNEL_ID    OXM_HEADER  (0x8000, OFPXMT_OFB_TUNNEL_ID, 8)
#define OXM_OF_TUNNEL_ID_W  OXM_HEADER_W(0x8000, OFPXMT_OFB_TUNNEL_ID, 8)

/* The IPv6 Extension Header pseudo-field.
 *
 * Prereqs:
 *   OXM_OF_ETH_TYPE must match 0x86dd exactly
 *
 * Format: 16-bit integer with 7 most-significant bits forced to 0.
 * Only the lower 9 bits have meaning.
 *
 * Masking: Maskable. */
#define OXM_OF_IPV6_EXTHDR   OXM_HEADER  (0x8000, OFPXMT_OFB_IPV6_EXTHDR, 2)
#define OXM_OF_IPV6_EXTHDR_W OXM_HEADER_W(0x8000, OFPXMT_OFB_IPV6_EXTHDR, 2)

/* Bit definitions for IPv6 Extension Header pseudo-field. */
enum ofp_ipv6exthdr_flags {      
    OFPIEH_NONEXT = 1 << 0,     /* "No next header" encountered. */
    OFPIEH_ESP    = 1 << 1,     /* Encrypted Sec Payload header present. */
    OFPIEH_AUTH   = 1 << 2,     /* Authentication header present. */
    OFPIEH_DEST   = 1 << 3,     /* 1 or 2 dest headers present. */
    OFPIEH_FRAG   = 1 << 4,     /* Fragment header present. */
    OFPIEH_ROUTER = 1 << 5,     /* Router header present. */
    OFPIEH_HOP    = 1 << 6,     /* Hop-by-hop header present. */
    OFPIEH_UNREP  = 1 << 7,     /* Unexpected repeats encountered. */
    OFPIEH_UNSEQ  = 1 << 8,     /* Unexpected sequencing encountered. */
};

/* Header for OXM experimenter match fields.
 * The experimenter class should not use OXM_HEADER() macros for defining
 * fields due to this extra header. */
struct ofp_oxm_experimenter_header {
    uint32_t oxm_header;        /* oxm_class = OFPXMC_EXPERIMENTER */
    uint32_t experimenter;      /* Experimenter ID which takes the same
                                   form as in struct ofp_experimenter_header. */
};
OFP_ASSERT(sizeof(struct ofp_oxm_experimenter_header) == 8);

/* ## ----------------- ## */
/* ## OpenFlow Actions. ## */
/* ## ----------------- ## */

enum ofp_action_type {
    OFPAT_OUTPUT       = 0,  /* Output to switch port. */
    OFPAT_COPY_TTL_OUT = 11, /* Copy TTL "outwards" -- from next-to-outermost
                                to outermost */
    OFPAT_COPY_TTL_IN  = 12, /* Copy TTL "inwards" -- from outermost to
                               next-to-outermost */
    OFPAT_SET_MPLS_TTL = 15, /* MPLS TTL */
    OFPAT_DEC_MPLS_TTL = 16, /* Decrement MPLS TTL */

    OFPAT_PUSH_VLAN    = 17, /* Push a new VLAN tag */
    OFPAT_POP_VLAN     = 18, /* Pop the outer VLAN tag */
    OFPAT_PUSH_MPLS    = 19, /* Push a new MPLS tag */
    OFPAT_POP_MPLS     = 20, /* Pop the outer MPLS tag */
    OFPAT_SET_QUEUE    = 21, /* Set queue id when outputting to a port */
    OFPAT_GROUP        = 22, /* Apply group. */
    OFPAT_SET_NW_TTL   = 23, /* IP TTL. */
    OFPAT_DEC_NW_TTL   = 24, /* Decrement IP TTL. */
    OFPAT_SET_FIELD    = 25, /* Set a header field using OXM TLV format. */
    OFPAT_PUSH_PBB     = 26, /* Push a new PBB service tag (I-TAG) */
    OFPAT_POP_PBB      = 27, /* Pop the outer PBB service tag (I-TAG) */
    OFPAT_EXPERIMENTER = 0xffff
};

/* Action header that is common to all actions.  The length includes the
 * header and any padding used to make the action 64-bit aligned.
 * NB: The length of an action *must* always be a multiple of eight. */
struct ofp_action_header {
    uint16_t type;                  /* One of OFPAT_*. */
    uint16_t len;                   /* Length of action, including this
                                       header.  This is the length of action,
                                       including any padding to make it
                                       64-bit aligned. */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_action_header) == 8);

enum ofp_controller_max_len {
    OFPCML_MAX       = 0xffe5, /* maximum max_len value which can be used
                                  to request a specific byte length. */
    OFPCML_NO_BUFFER = 0xffff  /* indicates that no buffering should be
                                  applied and the whole packet is to be
                                  sent to the controller. */
};

/* Action structure for OFPAT_OUTPUT, which sends packets out 'port'.
 * When the 'port' is the OFPP_CONTROLLER, 'max_len' indicates the max
 * number of bytes to send.  A 'max_len' of zero means no bytes of the
 * packet should be sent. A 'max_len' of OFPCML_NO_BUFFER means that
 * the packet is not buffered and the complete packet is to be sent to
 * the controller. */
struct ofp_action_output {
    uint16_t type;                  /* OFPAT_OUTPUT. */
    uint16_t len;                   /* Length is 16. */
    uint32_t port;                  /* Output port. */
    uint16_t max_len;               /* Max length to send to controller. */
    uint8_t pad[6];                 /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_action_output) == 16);

/* Action structure for OFPAT_SET_MPLS_TTL. */
struct ofp_action_mpls_ttl {
    uint16_t type;                  /* OFPAT_SET_MPLS_TTL. */
    uint16_t len;                   /* Length is 8. */
    uint8_t mpls_ttl;               /* MPLS TTL */
    uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct ofp_action_mpls_ttl) == 8);

/* Action structure for OFPAT_PUSH_VLAN/MPLS/PBB. */
struct ofp_action_push {
    uint16_t type;                  /* OFPAT_PUSH_VLAN/MPLS/PBB. */
    uint16_t len;                   /* Length is 8. */
    uint16_t ethertype;             /* Ethertype */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp_action_push) == 8);

/* Action structure for OFPAT_POP_MPLS. */
struct ofp_action_pop_mpls {
    uint16_t type;                  /* OFPAT_POP_MPLS. */
    uint16_t len;                   /* Length is 8. */
    uint16_t ethertype;             /* Ethertype */
    uint8_t pad[2];
};
OFP_ASSERT(sizeof(struct ofp_action_pop_mpls) == 8);

/* Action structure for OFPAT_GROUP. */
struct ofp_action_group {
    uint16_t type;                  /* OFPAT_GROUP. */
    uint16_t len;                   /* Length is 8. */
    uint32_t group_id;              /* Group identifier. */
};
OFP_ASSERT(sizeof(struct ofp_action_group) == 8);

/* Action structure for OFPAT_SET_NW_TTL. */
struct ofp_action_nw_ttl {
    uint16_t type;                  /* OFPAT_SET_NW_TTL. */
    uint16_t len;                   /* Length is 8. */
    uint8_t nw_ttl;                 /* IP TTL */
    uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct ofp_action_nw_ttl) == 8);

/* Action structure for OFPAT_SET_FIELD. */
struct ofp_action_set_field {
    uint16_t type;                  /* OFPAT_SET_FIELD. */
    uint16_t len;                   /* Length is padded to 64 bits. */
    /* Followed by:
     *   - Exactly (4 + oxm_length) bytes containing a single OXM TLV, then
     *   - Exactly ((8 + oxm_length) + 7)/8*8 - (8 + oxm_length)
     *     (between 0 and 7) bytes of all-zero bytes
     */
    uint8_t field[4];               /* OXM TLV - Make compiler happy */
};
OFP_ASSERT(sizeof(struct ofp_action_set_field) == 8);

/* Action header for OFPAT_EXPERIMENTER.
 * The rest of the body is experimenter-defined. */
struct ofp_action_experimenter_header {
    uint16_t type;                  /* OFPAT_EXPERIMENTER. */
    uint16_t len;                   /* Length is a multiple of 8. */
    uint32_t experimenter;          /* Experimenter ID which takes the same
                                       form as in struct
                                       ofp_experimenter_header. */
};
OFP_ASSERT(sizeof(struct ofp_action_experimenter_header) == 8);

/* ## ---------------------- ## */
/* ## OpenFlow Instructions. ## */
/* ## ---------------------- ## */

enum ofp_instruction_type {
    OFPIT_GOTO_TABLE = 1,       /* Setup the next table in the lookup
                                   pipeline */
    OFPIT_WRITE_METADATA = 2,   /* Setup the metadata field for use later in
                                   pipeline */
    OFPIT_WRITE_ACTIONS = 3,    /* Write the action(s) onto the datapath action
                                   set */
    OFPIT_APPLY_ACTIONS = 4,    /* Applies the action(s) immediately */
    OFPIT_CLEAR_ACTIONS = 5,    /* Clears all actions from the datapath
                                   action set */
    OFPIT_METER = 6,            /* Apply meter (rate limiter) */

    OFPIT_EXPERIMENTER = 0xFFFF  /* Experimenter instruction */
};

/* Instruction header that is common to all instructions.  The length includes
 * the header and any padding used to make the instruction 64-bit aligned.
 * NB: The length of an instruction *must* always be a multiple of eight. */
struct ofp_instruction {
    uint16_t type;                /* Instruction type */
    uint16_t len;                 /* Length of this struct in bytes. */
};
OFP_ASSERT(sizeof(struct ofp_instruction) == 4);

/* Instruction structure for OFPIT_GOTO_TABLE */
struct ofp_instruction_goto_table {
    uint16_t type;                /* OFPIT_GOTO_TABLE */
    uint16_t len;                 /* Length of this struct in bytes. */
    uint8_t table_id;             /* Set next table in the lookup pipeline */
    uint8_t pad[3];               /* Pad to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_instruction_goto_table) == 8);

/* Instruction structure for OFPIT_WRITE_METADATA */
struct ofp_instruction_write_metadata {
    uint16_t type;                /* OFPIT_WRITE_METADATA */
    uint16_t len;                 /* Length of this struct in bytes. */
    uint8_t pad[4];               /* Align to 64-bits */
    uint64_t metadata;            /* Metadata value to write */
    uint64_t metadata_mask;       /* Metadata write bitmask */
};
OFP_ASSERT(sizeof(struct ofp_instruction_write_metadata) == 24);

/* Instruction structure for OFPIT_WRITE/APPLY/CLEAR_ACTIONS */
struct ofp_instruction_actions {
    uint16_t type;              /* One of OFPIT_*_ACTIONS */
    uint16_t len;               /* Length of this struct in bytes. */
    uint8_t pad[4];             /* Align to 64-bits */
    struct ofp_action_header actions[0];  /* 0 or more actions associated with
                                             OFPIT_WRITE_ACTIONS and
                                             OFPIT_APPLY_ACTIONS */
};
OFP_ASSERT(sizeof(struct ofp_instruction_actions) == 8);

/* Instruction structure for OFPIT_METER */
struct ofp_instruction_meter {
    uint16_t type;                /* OFPIT_METER */
    uint16_t len;                 /* Length is 8. */
    uint32_t meter_id;            /* Meter instance. */
};
OFP_ASSERT(sizeof(struct ofp_instruction_meter) == 8);

/* Instruction structure for experimental instructions */
struct ofp_instruction_experimenter {
    uint16_t type;      /* OFPIT_EXPERIMENTER */
    uint16_t len;               /* Length of this struct in bytes */
    uint32_t experimenter;      /* Experimenter ID which takes the same form
                                   as in struct ofp_experimenter_header. */
    /* Experimenter-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp_instruction_experimenter) == 8);

/* ## --------------------------- ## */
/* ## OpenFlow Flow Modification. ## */
/* ## --------------------------- ## */

enum ofp_flow_mod_command {
    OFPFC_ADD           = 0, /* New flow. */
    OFPFC_MODIFY        = 1, /* Modify all matching flows. */
    OFPFC_MODIFY_STRICT = 2, /* Modify entry strictly matching wildcards and
                                priority. */
    OFPFC_DELETE        = 3, /* Delete all matching flows. */
    OFPFC_DELETE_STRICT = 4, /* Delete entry strictly matching wildcards and
                                priority. */
};

/* Value used in "idle_timeout" and "hard_timeout" to indicate that the entry
 * is permanent. */
#define OFP_FLOW_PERMANENT 0

/* By default, choose a priority in the middle. */
#define OFP_DEFAULT_PRIORITY 0x8000

enum ofp_flow_mod_flags {
    OFPFF_SEND_FLOW_REM = 1 << 0,  /* Send flow removed message when flow
                                    * expires or is deleted. */
    OFPFF_CHECK_OVERLAP = 1 << 1,  /* Check for overlapping entries first. */
    OFPFF_RESET_COUNTS  = 1 << 2,  /* Reset flow packet and byte counts. */
    OFPFF_NO_PKT_COUNTS = 1 << 3,  /* Don't keep track of packet count. */
    OFPFF_NO_BYT_COUNTS = 1 << 4,  /* Don't keep track of byte count. */
};

/* Flow setup and teardown (controller -> datapath). */
struct ofp_flow_mod {
    struct ofp_header header;
    uint64_t cookie;              /* Opaque controller-issued identifier. */
    uint64_t cookie_mask;         /* Mask used to restrict the cookie bits
                                     that must match when the command is
                                     OFPFC_MODIFY* or OFPFC_DELETE*. A value
                                     of 0 indicates no restriction. */
    uint8_t table_id;             /* ID of the table to put the flow in.
                                     For OFPFC_DELETE_* commands, OFPTT_ALL
                                     can also be used to delete matching
                                     flows from all tables. */
    uint8_t command;              /* One of OFPFC_*. */
    uint16_t idle_timeout;        /* Idle time before discarding (seconds). */
    uint16_t hard_timeout;        /* Max time before discarding (seconds). */
    uint16_t priority;            /* Priority level of flow entry. */
    uint32_t buffer_id;           /* Buffered packet to apply to, or
                                     OFP_NO_BUFFER.
                                     Not meaningful for OFPFC_DELETE*. */
    uint32_t out_port;            /* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output port.  A value of OFPP_ANY
                                     indicates no restriction. */
    uint32_t out_group;           /* For OFPFC_DELETE* commands, require
                                     matching entries to include this as an
                                     output group.  A value of OFPG_ANY
                                     indicates no restriction. */
    uint16_t flags;               /* Bitmap of OFPFF_* flags. */
    uint8_t pad[2];
    struct ofp_match match;       /* Fields to match. Variable size. */
    /* The variable size and padded match is always followed by instructions. */
    /*struct ofp_instruction instructions[0];*/ /* Instruction set - 0 or more.
                                                 The length of the instruction
                                                 set is inferred from the
                                                 length field in the header. */
};
OFP_ASSERT(sizeof(struct ofp_flow_mod) == 56);

/* Group numbering. Groups can use any number up to OFPG_MAX. */
enum ofp_group {
    /* Last usable group number. */
    OFPG_MAX        = 0xffffff00,

    /* Fake groups. */
    OFPG_ALL        = 0xfffffffc,  /* Represents all groups for group delete
                                      commands. */
    OFPG_ANY        = 0xffffffff   /* Special wildcard: no group specified. */
};

/* Group commands */
enum ofp_group_mod_command {
    OFPGC_ADD    = 0,       /* New group. */
    OFPGC_MODIFY = 1,       /* Modify all matching groups. */
    OFPGC_DELETE = 2,       /* Delete all matching groups. */
};

/* Bucket for use in groups. */
struct ofp_bucket {
    uint16_t len;                   /* Length of the bucket in bytes, including
                                       this header and any padding to make it
                                       64-bit aligned. */
    uint16_t weight;                /* Relative weight of bucket.  Only
                                       defined for select groups. */
    uint32_t watch_port;            /* Port whose state affects whether this
                                       bucket is live.  Only required for fast
                                       failover groups. */
    uint32_t watch_group;           /* Group whose state affects whether this
                                       bucket is live.  Only required for fast
                                       failover groups. */
    uint8_t pad[4];
    struct ofp_action_header actions[0]; /* 0 or more actions associated with
                                            the bucket - The action list length
                                            is inferred from the length
                                            of the bucket. */
};
OFP_ASSERT(sizeof(struct ofp_bucket) == 16);

/* Group setup and teardown (controller -> datapath). */
struct ofp_group_mod {
    struct ofp_header header;
    uint16_t command;             /* One of OFPGC_*. */
    uint8_t type;                 /* One of OFPGT_*. */
    uint8_t pad;                  /* Pad to 64 bits. */
    uint32_t group_id;            /* Group identifier. */
    struct ofp_bucket buckets[0]; /* The length of the bucket array is inferred
                                     from the length field in the header. */
};
OFP_ASSERT(sizeof(struct ofp_group_mod) == 16);

/* Group types.  Values in the range [128, 255] are reserved for experimental
 * use. */
enum ofp_group_type {
    OFPGT_ALL      = 0, /* All (multicast/broadcast) group.  */
    OFPGT_SELECT   = 1, /* Select group. */
    OFPGT_INDIRECT = 2, /* Indirect group. */
    OFPGT_FF       = 3, /* Fast failover group. */
};

/* Special buffer-id to indicate 'no buffer' */
#define OFP_NO_BUFFER 0xffffffff

/* Send packet (controller -> datapath). */
struct ofp_packet_out {
    struct ofp_header header;
    uint32_t buffer_id;           /* ID assigned by datapath (OFP_NO_BUFFER
                                     if none). */
    uint32_t in_port;             /* Packet's input port or OFPP_CONTROLLER. */
    uint16_t actions_len;         /* Size of action array in bytes. */
    uint8_t pad[6];
    struct ofp_action_header actions[0]; /* Action list - 0 or more. */
    /* The variable size action list is optionally followed by packet data.
     * This data is only present and meaningful if buffer_id == -1.
     * uint8_t data[0];              Packet data.  The length is inferred
                                     from the length field in the header. */
};
OFP_ASSERT(sizeof(struct ofp_packet_out) == 24);

/* Why is this packet being sent to the controller? */
enum ofp_packet_in_reason {
    OFPR_NO_MATCH    = 0,   /* No matching flow (table-miss flow entry). */
    OFPR_ACTION      = 1,   /* Action explicitly output to controller. */
    OFPR_INVALID_TTL = 2,   /* Packet has invalid TTL */
};

/* Packet received on port (datapath -> controller). */
struct ofp_packet_in {
    struct ofp_header header;
    uint32_t buffer_id;     /* ID assigned by datapath. */
    uint16_t total_len;     /* Full length of frame. */
    uint8_t reason;         /* Reason packet is being sent (one of OFPR_*) */
    uint8_t table_id;       /* ID of the table that was looked up */
    uint64_t cookie;        /* Cookie of the flow entry that was looked up. */
    struct ofp_match match; /* Packet metadata. Variable size. */
    /* The variable size and padded match is always followed by:
     *   - Exactly 2 all-zero padding bytes, then
     *   - An Ethernet frame whose length is inferred from header.length.
     * The padding bytes preceding the Ethernet frame ensure that the IP
     * header (if any) following the Ethernet header is 32-bit aligned.
     */
    //uint8_t pad[2];       /* Align to 64 bit + 16 bit */
    //uint8_t data[0];      /* Ethernet frame */
};
OFP_ASSERT(sizeof(struct ofp_packet_in) == 32);

/* Why was this flow removed? */
enum ofp_flow_removed_reason {
    OFPRR_IDLE_TIMEOUT = 0,     /* Flow idle time exceeded idle_timeout. */
    OFPRR_HARD_TIMEOUT = 1,     /* Time exceeded hard_timeout. */
    OFPRR_DELETE       = 2,     /* Evicted by a DELETE flow mod. */
    OFPRR_GROUP_DELETE = 3,     /* Group was removed. */
    OFPRR_METER_DELETE = 4,     /* Meter was removed */
};

/* Flow removed (datapath -> controller). */
struct ofp_flow_removed {
    struct ofp_header header;
    uint64_t cookie;          /* Opaque controller-issued identifier. */

    uint16_t priority;        /* Priority level of flow entry. */
    uint8_t reason;           /* One of OFPRR_*. */
    uint8_t table_id;         /* ID of the table */

    uint32_t duration_sec;    /* Time flow was alive in seconds. */
    uint32_t duration_nsec;   /* Time flow was alive in nanoseconds beyond
                                 duration_sec. */
    uint16_t idle_timeout;    /* Idle timeout from original flow mod. */
    uint16_t hard_timeout;    /* Hard timeout from original flow mod. */
    uint64_t packet_count;
    uint64_t byte_count;
    struct ofp_match match;   /* Description of fields. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp_flow_removed) == 56);

/* Meter numbering. Flow meters can use any number up to OFPM_MAX. */
enum ofp_meter {
    /* Last usable meter. */
    OFPM_MAX        = 0xffff0000,

    /* Virtual meters. */
    OFPM_SLOWPATH   = 0xfffffffd,  /* Meter for slow datapath. */
    OFPM_CONTROLLER = 0xfffffffe,  /* Meter for controller connection. */
    OFPM_ALL        = 0xffffffff,  /* Represents all meters for stat requests
                                      commands. */
};

/* Meter band types */
enum ofp_meter_band_type {
    OFPMBT_DROP            = 1,      /* Drop packet. */
    OFPMBT_DSCP_REMARK     = 2,      /* Remark DSCP in the IP header. */
    OFPMBT_EXPERIMENTER    = 0xFFFF  /* Experimenter meter band. */
};

/* Common header for all meter bands */
struct ofp_meter_band_header {
    uint16_t        type;    /* One of OFPMBT_*. */
    uint16_t        len;     /* Length in bytes of this band. */
    uint32_t        rate;    /* Rate for this band. */
    uint32_t        burst_size; /* Size of bursts. */
};
OFP_ASSERT(sizeof(struct ofp_meter_band_header) == 12);

/* OFPMBT_DROP band - drop packets */
struct ofp_meter_band_drop {
    uint16_t        type;    /* OFPMBT_DROP. */
    uint16_t        len;     /* Length in bytes of this band. */
    uint32_t        rate;    /* Rate for dropping packets. */
    uint32_t        burst_size; /* Size of bursts. */
    uint8_t         pad[4];
};
OFP_ASSERT(sizeof(struct ofp_meter_band_drop) == 16);

/* OFPMBT_DSCP_REMARK band - Remark DSCP in the IP header */
struct ofp_meter_band_dscp_remark {
    uint16_t        type;    /* OFPMBT_DSCP_REMARK. */
    uint16_t        len;     /* Length in bytes of this band. */
    uint32_t        rate;    /* Rate for remarking packets. */
    uint32_t        burst_size; /* Size of bursts. */
    uint8_t         prec_level; /* Number of drop precedence level to add. */
    uint8_t         pad[3];
};
OFP_ASSERT(sizeof(struct ofp_meter_band_dscp_remark) == 16);

/* OFPMBT_EXPERIMENTER band - Experimenter type.
 * The rest of the band is experimenter-defined. */
struct ofp_meter_band_experimenter {
    uint16_t        type;    /* One of OFPMBT_*. */
    uint16_t        len;     /* Length in bytes of this band. */
    uint32_t        rate;    /* Rate for this band. */
    uint32_t        burst_size;   /* Size of bursts. */
    uint32_t        experimenter; /* Experimenter ID which takes the same
                                     form as in struct
                                     ofp_experimenter_header. */
};
OFP_ASSERT(sizeof(struct ofp_meter_band_experimenter) == 16);

/* Meter commands */
enum ofp_meter_mod_command {
    OFPMC_ADD,              /* New meter. */
    OFPMC_MODIFY,           /* Modify specified meter. */
    OFPMC_DELETE,           /* Delete specified meter. */
};

/* Meter configuration flags */
enum ofp_meter_flags {
    OFPMF_KBPS    = 1 << 0,     /* Rate value in kb/s (kilo-bit per second). */
    OFPMF_PKTPS   = 1 << 1,     /* Rate value in packet/sec. */
    OFPMF_BURST   = 1 << 2,     /* Do burst size. */
    OFPMF_STATS   = 1 << 3,     /* Collect statistics. */
};

/* Meter configuration. OFPT_METER_MOD. */
struct ofp_meter_mod {
    struct ofp_header   header;
    uint16_t            command;        /* One of OFPMC_*. */
    uint16_t            flags;          /* Bitmap of OFPMF_* flags. */
    uint32_t            meter_id;       /* Meter instance. */
    struct ofp_meter_band_header bands[0]; /* The band list length is
                                           inferred from the length field
                                           in the header. */
};
OFP_ASSERT(sizeof(struct ofp_meter_mod) == 16);

/* Values for 'type' in ofp_error_message.  These values are immutable: they
 * will not change in future versions of the protocol (although new values may
 * be added). */
enum ofp_error_type {
    OFPET_HELLO_FAILED         = 0,  /* Hello protocol failed. */
    OFPET_BAD_REQUEST          = 1,  /* Request was not understood. */
    OFPET_BAD_ACTION           = 2,  /* Error in action description. */
    OFPET_BAD_INSTRUCTION      = 3,  /* Error in instruction list. */
    OFPET_BAD_MATCH            = 4,  /* Error in match. */
    OFPET_FLOW_MOD_FAILED      = 5,  /* Problem modifying flow entry. */
    OFPET_GROUP_MOD_FAILED     = 6,  /* Problem modifying group entry. */
    OFPET_PORT_MOD_FAILED      = 7,  /* Port mod request failed. */
    OFPET_TABLE_MOD_FAILED     = 8,  /* Table mod request failed. */
    OFPET_QUEUE_OP_FAILED      = 9,  /* Queue operation failed. */
    OFPET_SWITCH_CONFIG_FAILED = 10, /* Switch config request failed. */
    OFPET_ROLE_REQUEST_FAILED  = 11, /* Controller Role request failed. */
    OFPET_METER_MOD_FAILED     = 12, /* Error in meter. */
    OFPET_TABLE_FEATURES_FAILED = 13, /* Setting table features failed. */
    OFPET_EXPERIMENTER = 0xffff      /* Experimenter error messages. */
};

/* ofp_error_msg 'code' values for OFPET_HELLO_FAILED.  'data' contains an
 * ASCII text string that may give failure details. */
enum ofp_hello_failed_code {
    OFPHFC_INCOMPATIBLE = 0,    /* No compatible version. */
    OFPHFC_EPERM        = 1,    /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_REQUEST.  'data' contains at least
 * the first 64 bytes of the failed request. */
enum ofp_bad_request_code {
    OFPBRC_BAD_VERSION      = 0,  /* ofp_header.version not supported. */
    OFPBRC_BAD_TYPE         = 1,  /* ofp_header.type not supported. */
    OFPBRC_BAD_MULTIPART    = 2,  /* ofp_multipart_request.type not supported. */
    OFPBRC_BAD_EXPERIMENTER = 3,  /* Experimenter id not supported
                                   * (in ofp_experimenter_header or
                                   * ofp_multipart_request or
                                   * ofp_multipart_reply). */
    OFPBRC_BAD_EXP_TYPE     = 4,  /* Experimenter type not supported. */
    OFPBRC_EPERM            = 5,  /* Permissions error. */
    OFPBRC_BAD_LEN          = 6,  /* Wrong request length for type. */
    OFPBRC_BUFFER_EMPTY     = 7,  /* Specified buffer has already been used. */
    OFPBRC_BUFFER_UNKNOWN   = 8,  /* Specified buffer does not exist. */
    OFPBRC_BAD_TABLE_ID     = 9,  /* Specified table-id invalid or does not
                                   * exist. */
    OFPBRC_IS_SLAVE         = 10, /* Denied because controller is slave. */
    OFPBRC_BAD_PORT         = 11, /* Invalid port. */
    OFPBRC_BAD_PACKET       = 12, /* Invalid packet in packet-out. */
    OFPBRC_MULTIPART_BUFFER_OVERFLOW    = 13, /* ofp_multipart_request
                                     overflowed the assigned buffer. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_ACTION.  'data' contains at least
 * the first 64 bytes of the failed request. */
enum ofp_bad_action_code {
    OFPBAC_BAD_TYPE           = 0,  /* Unknown or unsupported action type. */
    OFPBAC_BAD_LEN            = 1,  /* Length problem in actions. */
    OFPBAC_BAD_EXPERIMENTER   = 2,  /* Unknown experimenter id specified. */
    OFPBAC_BAD_EXP_TYPE       = 3,  /* Unknown action for experimenter id. */
    OFPBAC_BAD_OUT_PORT       = 4,  /* Problem validating output port. */
    OFPBAC_BAD_ARGUMENT       = 5,  /* Bad action argument. */
    OFPBAC_EPERM              = 6,  /* Permissions error. */
    OFPBAC_TOO_MANY           = 7,  /* Can't handle this many actions. */
    OFPBAC_BAD_QUEUE          = 8,  /* Problem validating output queue. */
    OFPBAC_BAD_OUT_GROUP      = 9,  /* Invalid group id in forward action. */
    OFPBAC_MATCH_INCONSISTENT = 10, /* Action can't apply for this match,
                                       or Set-Field missing prerequisite. */
    OFPBAC_UNSUPPORTED_ORDER  = 11, /* Action order is unsupported for the
                                 action list in an Apply-Actions instruction */
    OFPBAC_BAD_TAG            = 12, /* Actions uses an unsupported
                                       tag/encap. */
    OFPBAC_BAD_SET_TYPE       = 13, /* Unsupported type in SET_FIELD action. */
    OFPBAC_BAD_SET_LEN        = 14, /* Length problem in SET_FIELD action. */
    OFPBAC_BAD_SET_ARGUMENT   = 15, /* Bad argument in SET_FIELD action. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_INSTRUCTION.  'data' contains at least
 * the first 64 bytes of the failed request. */
enum ofp_bad_instruction_code {
    OFPBIC_UNKNOWN_INST     = 0, /* Unknown instruction. */
    OFPBIC_UNSUP_INST       = 1, /* Switch or table does not support the
                                    instruction. */
    OFPBIC_BAD_TABLE_ID     = 2, /* Invalid Table-ID specified. */
    OFPBIC_UNSUP_METADATA   = 3, /* Metadata value unsupported by datapath. */
    OFPBIC_UNSUP_METADATA_MASK = 4, /* Metadata mask value unsupported by
                                       datapath. */
    OFPBIC_BAD_EXPERIMENTER = 5, /* Unknown experimenter id specified. */
    OFPBIC_BAD_EXP_TYPE     = 6, /* Unknown instruction for experimenter id. */
    OFPBIC_BAD_LEN          = 7, /* Length problem in instructions. */
    OFPBIC_EPERM            = 8, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_BAD_MATCH.  'data' contains at least
 * the first 64 bytes of the failed request. */
enum ofp_bad_match_code {
    OFPBMC_BAD_TYPE         = 0,  /* Unsupported match type specified by the
                                     match */
    OFPBMC_BAD_LEN          = 1,  /* Length problem in match. */
    OFPBMC_BAD_TAG          = 2,  /* Match uses an unsupported tag/encap. */
    OFPBMC_BAD_DL_ADDR_MASK = 3,  /* Unsupported datalink addr mask - switch
                                     does not support arbitrary datalink
                                     address mask. */
    OFPBMC_BAD_NW_ADDR_MASK = 4,  /* Unsupported network addr mask - switch
                                     does not support arbitrary network
                                     address mask. */
    OFPBMC_BAD_WILDCARDS    = 5,  /* Unsupported combination of fields masked
                                     or omitted in the match. */
    OFPBMC_BAD_FIELD        = 6,  /* Unsupported field type in the match. */
    OFPBMC_BAD_VALUE        = 7,  /* Unsupported value in a match field. */
    OFPBMC_BAD_MASK         = 8,  /* Unsupported mask specified in the match,
                                     field is not dl-address or nw-address. */
    OFPBMC_BAD_PREREQ       = 9,  /* A prerequisite was not met. */
    OFPBMC_DUP_FIELD        = 10, /* A field type was duplicated. */
    OFPBMC_EPERM            = 11, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_FLOW_MOD_FAILED.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_flow_mod_failed_code {
    OFPFMFC_UNKNOWN      = 0,   /* Unspecified error. */
    OFPFMFC_TABLE_FULL   = 1,   /* Flow not added because table was full. */
    OFPFMFC_BAD_TABLE_ID = 2,   /* Table does not exist */
    OFPFMFC_OVERLAP      = 3,   /* Attempted to add overlapping flow with
                                   CHECK_OVERLAP flag set. */
    OFPFMFC_EPERM        = 4,   /* Permissions error. */
    OFPFMFC_BAD_TIMEOUT  = 5,   /* Flow not added because of unsupported
                                   idle/hard timeout. */
    OFPFMFC_BAD_COMMAND  = 6,   /* Unsupported or unknown command. */
    OFPFMFC_BAD_FLAGS    = 7,   /* Unsupported or unknown flags. */
};

/* ofp_error_msg 'code' values for OFPET_GROUP_MOD_FAILED.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_group_mod_failed_code {
    OFPGMFC_GROUP_EXISTS         = 0,  /* Group not added because a group ADD
                                          attempted to replace an
                                          already-present group. */
    OFPGMFC_INVALID_GROUP        = 1,  /* Group not added because Group
                                          specified is invalid. */
    OFPGMFC_WEIGHT_UNSUPPORTED   = 2,  /* Switch does not support unequal load
                                          sharing with select groups. */
    OFPGMFC_OUT_OF_GROUPS        = 3,  /* The group table is full. */
    OFPGMFC_OUT_OF_BUCKETS       = 4,  /* The maximum number of action buckets
                                          for a group has been exceeded. */
    OFPGMFC_CHAINING_UNSUPPORTED = 5,  /* Switch does not support groups that
                                          forward to groups. */
    OFPGMFC_WATCH_UNSUPPORTED    = 6,  /* This group cannot watch the watch_port
                                          or watch_group specified. */
    OFPGMFC_LOOP                 = 7,  /* Group entry would cause a loop. */
    OFPGMFC_UNKNOWN_GROUP        = 8,  /* Group not modified because a group
                                          MODIFY attempted to modify a
                                          non-existent group. */
    OFPGMFC_CHAINED_GROUP        = 9,  /* Group not deleted because another
                                          group is forwarding to it. */
    OFPGMFC_BAD_TYPE             = 10, /* Unsupported or unknown group type. */
    OFPGMFC_BAD_COMMAND          = 11, /* Unsupported or unknown command. */
    OFPGMFC_BAD_BUCKET           = 12, /* Error in bucket. */
    OFPGMFC_BAD_WATCH            = 13, /* Error in watch port/group. */
    OFPGMFC_EPERM                = 14, /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_PORT_MOD_FAILED.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_port_mod_failed_code {
    OFPPMFC_BAD_PORT      = 0,   /* Specified port number does not exist. */
    OFPPMFC_BAD_HW_ADDR   = 1,   /* Specified hardware address does not
                                  * match the port number. */
    OFPPMFC_BAD_CONFIG    = 2,   /* Specified config is invalid. */
    OFPPMFC_BAD_ADVERTISE = 3,   /* Specified advertise is invalid. */
    OFPPMFC_EPERM         = 4,   /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_TABLE_MOD_FAILED.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_table_mod_failed_code {
    OFPTMFC_BAD_TABLE  = 0,      /* Specified table does not exist. */
    OFPTMFC_BAD_CONFIG = 1,      /* Specified config is invalid. */
    OFPTMFC_EPERM      = 2,      /* Permissions error. */
};

/* ofp_error msg 'code' values for OFPET_QUEUE_OP_FAILED. 'data' contains
 * at least the first 64 bytes of the failed request */
enum ofp_queue_op_failed_code {
    OFPQOFC_BAD_PORT   = 0,     /* Invalid port (or port does not exist). */
    OFPQOFC_BAD_QUEUE  = 1,     /* Queue does not exist. */
    OFPQOFC_EPERM      = 2,     /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_SWITCH_CONFIG_FAILED. 'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_switch_config_failed_code {
    OFPSCFC_BAD_FLAGS  = 0,      /* Specified flags is invalid. */
    OFPSCFC_BAD_LEN    = 1,      /* Specified len is invalid. */
    OFPSCFC_EPERM      = 2,      /* Permissions error. */
};

/* ofp_error_msg 'code' values for OFPET_ROLE_REQUEST_FAILED. 'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_role_request_failed_code {
    OFPRRFC_STALE      = 0,      /* Stale Message: old generation_id. */
    OFPRRFC_UNSUP      = 1,      /* Controller role change unsupported. */
    OFPRRFC_BAD_ROLE   = 2,      /* Invalid role. */
};

/* ofp_error_msg 'code' values for OFPET_METER_MOD_FAILED.  'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_meter_mod_failed_code {
    OFPMMFC_UNKNOWN       = 0,  /* Unspecified error. */
    OFPMMFC_METER_EXISTS  = 1,  /* Meter not added because a Meter ADD
                                 * attempted to replace an existing Meter. */
    OFPMMFC_INVALID_METER = 2,  /* Meter not added because Meter specified
                                 * is invalid,
                                 * or invalid meter in meter action. */
    OFPMMFC_UNKNOWN_METER = 3,  /* Meter not modified because a Meter MODIFY
                                 * attempted to modify a non-existent Meter,
                                 * or bad meter in meter action. */
    OFPMMFC_BAD_COMMAND   = 4,  /* Unsupported or unknown command. */
    OFPMMFC_BAD_FLAGS     = 5,  /* Flag configuration unsupported. */
    OFPMMFC_BAD_RATE      = 6,  /* Rate unsupported. */
    OFPMMFC_BAD_BURST     = 7,  /* Burst size unsupported. */
    OFPMMFC_BAD_BAND      = 8,  /* Band unsupported. */
    OFPMMFC_BAD_BAND_VALUE = 9, /* Band value unsupported. */
    OFPMMFC_OUT_OF_METERS = 10, /* No more meters available. */
    OFPMMFC_OUT_OF_BANDS  = 11, /* The maximum number of properties
                                 * for a meter has been exceeded. */
};

/* ofp_error_msg 'code' values for OFPET_TABLE_FEATURES_FAILED. 'data' contains
 * at least the first 64 bytes of the failed request. */
enum ofp_table_features_failed_code {
    OFPTFFC_BAD_TABLE    = 0,      /* Specified table does not exist. */
    OFPTFFC_BAD_METADATA = 1,      /* Invalid metadata mask. */
    OFPTFFC_BAD_TYPE     = 2,      /* Unknown property type. */
    OFPTFFC_BAD_LEN      = 3,      /* Length problem in properties. */
    OFPTFFC_BAD_ARGUMENT = 4,      /* Unsupported property value. */
    OFPTFFC_EPERM        = 5,      /* Permissions error. */
};

/* OFPT_ERROR: Error message (datapath -> controller). */
struct ofp_error_msg {
    struct ofp_header header;

    uint16_t type;
    uint16_t code;
    uint8_t data[0];          /* Variable-length data.  Interpreted based
                                 on the type and code.  No padding. */
};
OFP_ASSERT(sizeof(struct ofp_error_msg) == 12);

/* OFPET_EXPERIMENTER: Error message (datapath -> controller). */
struct ofp_error_experimenter_msg {
    struct ofp_header header;

    uint16_t type;            /* OFPET_EXPERIMENTER. */
    uint16_t exp_type;        /* Experimenter defined. */
    uint32_t experimenter;    /* Experimenter ID which takes the same form
                                 as in struct ofp_experimenter_header. */
    uint8_t data[0];          /* Variable-length data.  Interpreted based
                                 on the type and code.  No padding. */
};
OFP_ASSERT(sizeof(struct ofp_error_experimenter_msg) == 16);

enum ofp_multipart_type {
    /* Description of this OpenFlow switch.
     * The request body is empty.
     * The reply body is struct ofp_desc. */
    OFPMP_DESC = 0,

    /* Individual flow statistics.
     * The request body is struct ofp_flow_stats_request.
     * The reply body is an array of struct ofp_flow_stats. */
    OFPMP_FLOW = 1,

    /* Aggregate flow statistics.
     * The request body is struct ofp_aggregate_stats_request.
     * The reply body is struct ofp_aggregate_stats_reply. */
    OFPMP_AGGREGATE = 2,

    /* Flow table statistics.
     * The request body is empty.
     * The reply body is an array of struct ofp_table_stats. */
    OFPMP_TABLE = 3,

    /* Port statistics.
     * The request body is struct ofp_port_stats_request.
     * The reply body is an array of struct ofp_port_stats. */
    OFPMP_PORT_STATS = 4,

    /* Queue statistics for a port
     * The request body is struct ofp_queue_stats_request.
     * The reply body is an array of struct ofp_queue_stats */
    OFPMP_QUEUE = 5,

    /* Group counter statistics.
     * The request body is struct ofp_group_stats_request.
     * The reply is an array of struct ofp_group_stats. */
    OFPMP_GROUP = 6,

    /* Group description.
     * The request body is empty.
     * The reply body is an array of struct ofp_group_desc. */
    OFPMP_GROUP_DESC = 7,

    /* Group features.
     * The request body is empty.
     * The reply body is struct ofp_group_features. */
    OFPMP_GROUP_FEATURES = 8,

    /* Meter statistics.
     * The request body is struct ofp_meter_multipart_requests.
     * The reply body is an array of struct ofp_meter_stats. */
    OFPMP_METER = 9,

    /* Meter configuration.
     * The request body is struct ofp_meter_multipart_requests.
     * The reply body is an array of struct ofp_meter_config. */
    OFPMP_METER_CONFIG = 10,

    /* Meter features.
     * The request body is empty.
     * The reply body is struct ofp_meter_features. */
    OFPMP_METER_FEATURES = 11,

    /* Table features.
     * The request body is either empty or contains an array of
     * struct ofp_table_features containing the controller's
     * desired view of the switch. If the switch is unable to
     * set the specified view an error is returned.
     * The reply body is an array of struct ofp_table_features. */
    OFPMP_TABLE_FEATURES = 12,

    /* Port description.
     * The request body is empty.
     * The reply body is an array of struct ofp_port. */
    OFPMP_PORT_DESC = 13,

    /* Experimenter extension.
     * The request and reply bodies begin with
     * struct ofp_experimenter_multipart_header.
     * The request and reply bodies are otherwise experimenter-defined. */
    OFPMP_EXPERIMENTER = 0xffff
};

/* Backward compatibility with 1.3.1 - avoid breaking the API. */
#define ofp_multipart_types ofp_multipart_type

enum ofp_multipart_request_flags {
    OFPMPF_REQ_MORE  = 1 << 0  /* More requests to follow. */
};

struct ofp_multipart_request {
    struct ofp_header header;
    uint16_t type;              /* One of the OFPMP_* constants. */
    uint16_t flags;             /* OFPMPF_REQ_* flags. */
    uint8_t pad[4];
    uint8_t body[0];            /* Body of the request. 0 or more bytes. */
};
OFP_ASSERT(sizeof(struct ofp_multipart_request) == 16);

enum ofp_multipart_reply_flags {
    OFPMPF_REPLY_MORE  = 1 << 0  /* More replies to follow. */
};

struct ofp_multipart_reply {
    struct ofp_header header;
    uint16_t type;              /* One of the OFPMP_* constants. */
    uint16_t flags;             /* OFPMPF_REPLY_* flags. */
    uint8_t pad[4];
    uint8_t body[0];            /* Body of the reply. 0 or more bytes. */
};
OFP_ASSERT(sizeof(struct ofp_multipart_reply) == 16);

#define DESC_STR_LEN   256
#define SERIAL_NUM_LEN 32
/* Body of reply to OFPMP_DESC request.  Each entry is a NULL-terminated
 * ASCII string. */
struct ofp_desc {
    char mfr_desc[DESC_STR_LEN];       /* Manufacturer description. */
    char hw_desc[DESC_STR_LEN];        /* Hardware description. */
    char sw_desc[DESC_STR_LEN];        /* Software description. */
    char serial_num[SERIAL_NUM_LEN];   /* Serial number. */
    char dp_desc[DESC_STR_LEN];        /* Human readable description of datapath. */
};
OFP_ASSERT(sizeof(struct ofp_desc) == 1056);

/* Body for ofp_multipart_request of type OFPMP_FLOW. */
struct ofp_flow_stats_request {
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats),
                                 OFPTT_ALL for all tables. */
    uint8_t pad[3];           /* Align to 32 bits. */
    uint32_t out_port;        /* Require matching entries to include this
                                 as an output port.  A value of OFPP_ANY
                                 indicates no restriction. */
    uint32_t out_group;       /* Require matching entries to include this
                                 as an output group.  A value of OFPG_ANY
                                 indicates no restriction. */
    uint8_t pad2[4];          /* Align to 64 bits. */
    uint64_t cookie;          /* Require matching entries to contain this
                                 cookie value */
    uint64_t cookie_mask;     /* Mask used to restrict the cookie bits that
                                 must match. A value of 0 indicates
                                 no restriction. */
    struct ofp_match match;   /* Fields to match. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp_flow_stats_request) == 40);

/* Body of reply to OFPMP_FLOW request. */
struct ofp_flow_stats {
    uint16_t length;          /* Length of this entry. */
    uint8_t table_id;         /* ID of table flow came from. */
    uint8_t pad;
    uint32_t duration_sec;    /* Time flow has been alive in seconds. */
    uint32_t duration_nsec;   /* Time flow has been alive in nanoseconds beyond
                                 duration_sec. */
    uint16_t priority;        /* Priority of the entry. */
    uint16_t idle_timeout;    /* Number of seconds idle before expiration. */
    uint16_t hard_timeout;    /* Number of seconds before expiration. */
    uint16_t flags;           /* Bitmap of OFPFF_* flags. */
    uint8_t pad2[4];          /* Align to 64-bits. */
    uint64_t cookie;          /* Opaque controller-issued identifier. */
    uint64_t packet_count;    /* Number of packets in flow. */
    uint64_t byte_count;      /* Number of bytes in flow. */
    struct ofp_match match;   /* Description of fields. Variable size. */
    /* The variable size and padded match is always followed by instructions. */
    //struct ofp_instruction instructions[0]; /* Instruction set - 0 or more. */
};
OFP_ASSERT(sizeof(struct ofp_flow_stats) == 56);

/* Body for ofp_multipart_request of type OFPMP_AGGREGATE. */
struct ofp_aggregate_stats_request {
    uint8_t table_id;         /* ID of table to read (from ofp_table_stats)
                                 OFPTT_ALL for all tables. */
    uint8_t pad[3];           /* Align to 32 bits. */
    uint32_t out_port;        /* Require matching entries to include this
                                 as an output port.  A value of OFPP_ANY
                                 indicates no restriction. */
    uint32_t out_group;       /* Require matching entries to include this
                                 as an output group.  A value of OFPG_ANY
                                 indicates no restriction. */
    uint8_t pad2[4];          /* Align to 64 bits. */
    uint64_t cookie;          /* Require matching entries to contain this
                                 cookie value */
    uint64_t cookie_mask;     /* Mask used to restrict the cookie bits that
                                 must match. A value of 0 indicates
                                 no restriction. */
    struct ofp_match match;   /* Fields to match. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp_aggregate_stats_request) == 40);

/* Body of reply to OFPMP_AGGREGATE request. */
struct ofp_aggregate_stats_reply {
    uint64_t packet_count;    /* Number of packets in flows. */
    uint64_t byte_count;      /* Number of bytes in flows. */
    uint32_t flow_count;      /* Number of flows. */
    uint8_t pad[4];           /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_aggregate_stats_reply) == 24);

/* Table Feature property types.
 * Low order bit cleared indicates a property for a regular Flow Entry.
 * Low order bit set indicates a property for the Table-Miss Flow Entry.
 */
enum ofp_table_feature_prop_type {
    OFPTFPT_INSTRUCTIONS           = 0,  /* Instructions property. */
    OFPTFPT_INSTRUCTIONS_MISS      = 1,  /* Instructions for table-miss. */
    OFPTFPT_NEXT_TABLES            = 2,  /* Next Table property. */
    OFPTFPT_NEXT_TABLES_MISS       = 3,  /* Next Table for table-miss. */
    OFPTFPT_WRITE_ACTIONS          = 4,  /* Write Actions property. */
    OFPTFPT_WRITE_ACTIONS_MISS     = 5,  /* Write Actions for table-miss. */
    OFPTFPT_APPLY_ACTIONS          = 6,  /* Apply Actions property. */
    OFPTFPT_APPLY_ACTIONS_MISS     = 7,  /* Apply Actions for table-miss. */
    OFPTFPT_MATCH                  = 8,  /* Match property. */
    OFPTFPT_WILDCARDS              = 10, /* Wildcards property. */
    OFPTFPT_WRITE_SETFIELD         = 12, /* Write Set-Field property. */
    OFPTFPT_WRITE_SETFIELD_MISS    = 13, /* Write Set-Field for table-miss. */
    OFPTFPT_APPLY_SETFIELD         = 14, /* Apply Set-Field property. */
    OFPTFPT_APPLY_SETFIELD_MISS    = 15, /* Apply Set-Field for table-miss. */
    OFPTFPT_EXPERIMENTER           = 0xFFFE, /* Experimenter property. */
    OFPTFPT_EXPERIMENTER_MISS      = 0xFFFF, /* Experimenter for table-miss. */
};

/* Common header for all Table Feature Properties */
struct ofp_table_feature_prop_header {
    uint16_t         type;    /* One of OFPTFPT_*. */
    uint16_t         length;  /* Length in bytes of this property. */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_header) == 4);

/* Instructions property */
struct ofp_table_feature_prop_instructions {
    uint16_t         type;    /* One of OFPTFPT_INSTRUCTIONS,
                                 OFPTFPT_INSTRUCTIONS_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the instruction ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    struct ofp_instruction   instruction_ids[0];   /* List of instructions */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_instructions) == 4);

/* Next Tables property */
struct ofp_table_feature_prop_next_tables {
    uint16_t         type;    /* One of OFPTFPT_NEXT_TABLES,
                                 OFPTFPT_NEXT_TABLES_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the table_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    uint8_t          next_table_ids[0];        /* List of table ids. */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_next_tables) == 4);

/* Actions property */
struct ofp_table_feature_prop_actions {
    uint16_t         type;    /* One of OFPTFPT_WRITE_ACTIONS,
                                 OFPTFPT_WRITE_ACTIONS_MISS,
                                 OFPTFPT_APPLY_ACTIONS,
                                 OFPTFPT_APPLY_ACTIONS_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the action_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    struct ofp_action_header  action_ids[0];      /* List of actions */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_actions) == 4);

/* Match, Wildcard or Set-Field property */
struct ofp_table_feature_prop_oxm {
    uint16_t         type;    /* One of OFPTFPT_MATCH,
                                 OFPTFPT_WILDCARDS,
                                 OFPTFPT_WRITE_SETFIELD,
                                 OFPTFPT_WRITE_SETFIELD_MISS,
                                 OFPTFPT_APPLY_SETFIELD,
                                 OFPTFPT_APPLY_SETFIELD_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    /* Followed by:
     *   - Exactly (length - 4) bytes containing the oxm_ids, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    uint32_t         oxm_ids[0];   /* Array of OXM headers */
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_oxm) == 4);

/* Experimenter table feature property */
struct ofp_table_feature_prop_experimenter {
    uint16_t         type;    /* One of OFPTFPT_EXPERIMENTER,
                                 OFPTFPT_EXPERIMENTER_MISS. */
    uint16_t         length;  /* Length in bytes of this property. */
    uint32_t         experimenter;  /* Experimenter ID which takes the same
                                       form as in struct
                                       ofp_experimenter_header. */
    uint32_t         exp_type;      /* Experimenter defined. */
    /* Followed by:
     *   - Exactly (length - 12) bytes containing the experimenter data, then
     *   - Exactly (length + 7)/8*8 - (length) (between 0 and 7)
     *     bytes of all-zero bytes */
    uint32_t         experimenter_data[0];
};
OFP_ASSERT(sizeof(struct ofp_table_feature_prop_experimenter) == 12);

/* Body for ofp_multipart_request of type OFPMP_TABLE_FEATURES./
 * Body of reply to OFPMP_TABLE_FEATURES request. */
struct ofp_table_features {
    uint16_t length;         /* Length is padded to 64 bits. */
    uint8_t table_id;        /* Identifier of table.  Lower numbered tables
                                are consulted first. */
    uint8_t pad[5];          /* Align to 64-bits. */
    char name[OFP_MAX_TABLE_NAME_LEN];
    uint64_t metadata_match; /* Bits of metadata table can match. */
    uint64_t metadata_write; /* Bits of metadata table can write. */
    uint32_t config;         /* Bitmap of OFPTC_* values */
    uint32_t max_entries;    /* Max number of entries supported. */

    /* Table Feature Property list */
    struct ofp_table_feature_prop_header properties[0]; /* List of properties */
};
OFP_ASSERT(sizeof(struct ofp_table_features) == 64);

/* Body of reply to OFPMP_TABLE request. */
struct ofp_table_stats {
    uint8_t table_id;        /* Identifier of table.  Lower numbered tables
                                are consulted first. */
    uint8_t pad[3];          /* Align to 32-bits. */
    uint32_t active_count;   /* Number of active entries. */
    uint64_t lookup_count;   /* Number of packets looked up in table. */
    uint64_t matched_count;  /* Number of packets that hit table. */
};
OFP_ASSERT(sizeof(struct ofp_table_stats) == 24);

/* Body for ofp_multipart_request of type OFPMP_PORT. */
struct ofp_port_stats_request {
    uint32_t port_no;        /* OFPMP_PORT message must request statistics
                              * either for a single port (specified in
                              * port_no) or for all ports (if port_no ==
                              * OFPP_ANY). */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_port_stats_request) == 8);

/* Body of reply to OFPMP_PORT request. If a counter is unsupported, set
 * the field to all ones. */
struct ofp_port_stats {
    uint32_t port_no;
    uint8_t pad[4];          /* Align to 64-bits. */
    uint64_t rx_packets;     /* Number of received packets. */
    uint64_t tx_packets;     /* Number of transmitted packets. */
    uint64_t rx_bytes;       /* Number of received bytes. */
    uint64_t tx_bytes;       /* Number of transmitted bytes. */
    uint64_t rx_dropped;     /* Number of packets dropped by RX. */
    uint64_t tx_dropped;     /* Number of packets dropped by TX. */
    uint64_t rx_errors;      /* Number of receive errors.  This is a super-set
                                of more specific receive errors and should be
                                greater than or equal to the sum of all
                                rx_*_err values. */
    uint64_t tx_errors;      /* Number of transmit errors.  This is a super-set
                                of more specific transmit errors and should be
                                greater than or equal to the sum of all
                                tx_*_err values (none currently defined.) */
    uint64_t rx_frame_err;   /* Number of frame alignment errors. */
    uint64_t rx_over_err;    /* Number of packets with RX overrun. */
    uint64_t rx_crc_err;     /* Number of CRC errors. */
    uint64_t collisions;     /* Number of collisions. */
    uint32_t duration_sec;   /* Time port has been alive in seconds. */
    uint32_t duration_nsec;  /* Time port has been alive in nanoseconds beyond
                                duration_sec. */
};
OFP_ASSERT(sizeof(struct ofp_port_stats) == 112);

/* Body of OFPMP_GROUP request. */
struct ofp_group_stats_request {
    uint32_t group_id;       /* All groups if OFPG_ALL. */
    uint8_t pad[4];          /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_group_stats_request) == 8);

/* Used in group stats replies. */
struct ofp_bucket_counter {
    uint64_t packet_count;   /* Number of packets processed by bucket. */
    uint64_t byte_count;     /* Number of bytes processed by bucket. */
};
OFP_ASSERT(sizeof(struct ofp_bucket_counter) == 16);

/* Body of reply to OFPMP_GROUP request. */
struct ofp_group_stats {
    uint16_t length;         /* Length of this entry. */
    uint8_t pad[2];          /* Align to 64 bits. */
    uint32_t group_id;       /* Group identifier. */
    uint32_t ref_count;      /* Number of flows or groups that directly forward
                                to this group. */
    uint8_t pad2[4];         /* Align to 64 bits. */
    uint64_t packet_count;   /* Number of packets processed by group. */
    uint64_t byte_count;     /* Number of bytes processed by group. */
    uint32_t duration_sec;   /* Time group has been alive in seconds. */
    uint32_t duration_nsec;  /* Time group has been alive in nanoseconds beyond
                                duration_sec. */
    struct ofp_bucket_counter bucket_stats[0]; /* One counter set per bucket. */
};
OFP_ASSERT(sizeof(struct ofp_group_stats) == 40);

/* Body of reply to OFPMP_GROUP_DESC request. */
struct ofp_group_desc {
    uint16_t length;              /* Length of this entry. */
    uint8_t type;                 /* One of OFPGT_*. */
    uint8_t pad;                  /* Pad to 64 bits. */
    uint32_t group_id;            /* Group identifier. */
    struct ofp_bucket buckets[0];   /* List of buckets - 0 or more. */
};
OFP_ASSERT(sizeof(struct ofp_group_desc) == 8);

/* Backward compatibility with 1.3.1 - avoid breaking the API. */
#define ofp_group_desc_stats ofp_group_desc

/* Group configuration flags */
enum ofp_group_capabilities {
    OFPGFC_SELECT_WEIGHT   = 1 << 0,  /* Support weight for select groups */
    OFPGFC_SELECT_LIVENESS = 1 << 1,  /* Support liveness for select groups */
    OFPGFC_CHAINING        = 1 << 2,  /* Support chaining groups */
    OFPGFC_CHAINING_CHECKS = 1 << 3,  /* Check chaining for loops and delete */
};

/* Body of reply to OFPMP_GROUP_FEATURES request. Group features. */
struct ofp_group_features {
    uint32_t  types;           /* Bitmap of (1 << OFPGT_*) values supported. */
    uint32_t  capabilities;    /* Bitmap of OFPGFC_* capability supported. */
    uint32_t  max_groups[4];   /* Maximum number of groups for each type. */
    uint32_t  actions[4];      /* Bitmaps of (1 << OFPAT_*) values supported. */
};
OFP_ASSERT(sizeof(struct ofp_group_features) == 40);

/* Body of OFPMP_METER and OFPMP_METER_CONFIG requests. */
struct ofp_meter_multipart_request {
    uint32_t meter_id;       /* Meter instance, or OFPM_ALL. */
    uint8_t pad[4];          /* Align to 64 bits. */
};
OFP_ASSERT(sizeof(struct ofp_meter_multipart_request) == 8);

/* Statistics for each meter band */
struct ofp_meter_band_stats {
    uint64_t        packet_band_count;   /* Number of packets in band. */
    uint64_t        byte_band_count;     /* Number of bytes in band. */
};
OFP_ASSERT(sizeof(struct ofp_meter_band_stats) == 16);

/* Body of reply to OFPMP_METER request. Meter statistics. */
struct ofp_meter_stats {
    uint32_t        meter_id;         /* Meter instance. */
    uint16_t        len;              /* Length in bytes of this stats. */
    uint8_t         pad[6];
    uint32_t        flow_count;       /* Number of flows bound to meter. */
    uint64_t        packet_in_count;  /* Number of packets in input. */
    uint64_t        byte_in_count;    /* Number of bytes in input. */
    uint32_t   duration_sec;  /* Time meter has been alive in seconds. */
    uint32_t   duration_nsec; /* Time meter has been alive in nanoseconds beyond
                                 duration_sec. */
    struct ofp_meter_band_stats band_stats[0]; /* The band_stats length is
                                         inferred from the length field. */
};
OFP_ASSERT(sizeof(struct ofp_meter_stats) == 40);

/* Body of reply to OFPMP_METER_CONFIG request. Meter configuration. */
struct ofp_meter_config {
    uint16_t        length;           /* Length of this entry. */
    uint16_t        flags;            /* All OFPMF_* that apply. */
    uint32_t        meter_id;         /* Meter instance. */
    struct ofp_meter_band_header bands[0]; /* The bands length is
                                         inferred from the length field. */
};
OFP_ASSERT(sizeof(struct ofp_meter_config) == 8);

/* Body of reply to OFPMP_METER_FEATURES request. Meter features. */
struct ofp_meter_features {
    uint32_t    max_meter;    /* Maximum number of meters. */
    uint32_t    band_types;   /* Bitmaps of (1 << OFPMBT_*) values supported. */
    uint32_t    capabilities; /* Bitmaps of "ofp_meter_flags". */
    uint8_t     max_bands;    /* Maximum bands per meters */
    uint8_t     max_color;    /* Maximum color value */
    uint8_t     pad[2];
};
OFP_ASSERT(sizeof(struct ofp_meter_features) == 16);

/* Body for ofp_multipart_request/reply of type OFPMP_EXPERIMENTER. */
struct ofp_experimenter_multipart_header {
    uint32_t experimenter;    /* Experimenter ID which takes the same form
                                 as in struct ofp_experimenter_header. */
    uint32_t exp_type;        /* Experimenter defined. */
    /* Experimenter-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp_experimenter_multipart_header) == 8);

/* Experimenter extension. */
struct ofp_experimenter_header {
    struct ofp_header header;   /* Type OFPT_EXPERIMENTER. */
    uint32_t experimenter;      /* Experimenter ID:
                                 * - MSB 0: low-order bytes are IEEE OUI.
                                 * - MSB != 0: defined by ONF. */
    uint32_t exp_type;          /* Experimenter defined. */
    /* Experimenter-defined arbitrary additional data. */
};
OFP_ASSERT(sizeof(struct ofp_experimenter_header) == 16);

/* All ones is used to indicate all queues in a port (for stats retrieval). */
#define OFPQ_ALL      0xffffffff

/* Min rate > 1000 means not configured. */
#define OFPQ_MIN_RATE_UNCFG      0xffff

/* Max rate > 1000 means not configured. */
#define OFPQ_MAX_RATE_UNCFG      0xffff

enum ofp_queue_properties {
    OFPQT_MIN_RATE      = 1,      /* Minimum datarate guaranteed. */
    OFPQT_MAX_RATE      = 2,      /* Maximum datarate. */
    OFPQT_EXPERIMENTER  = 0xffff  /* Experimenter defined property. */
};

/* Common description for a queue. */
struct ofp_queue_prop_header {
    uint16_t property;    /* One of OFPQT_. */
    uint16_t len;         /* Length of property, including this header. */
    uint8_t pad[4];       /* 64-bit alignment. */
};
OFP_ASSERT(sizeof(struct ofp_queue_prop_header) == 8);

/* Min-Rate queue property description. */
struct ofp_queue_prop_min_rate {
    struct ofp_queue_prop_header prop_header; /* prop: OFPQT_MIN, len: 16. */
    uint16_t rate;        /* In 1/10 of a percent; >1000 -> disabled. */
    uint8_t pad[6];       /* 64-bit alignment */
};
OFP_ASSERT(sizeof(struct ofp_queue_prop_min_rate) == 16);

/* Max-Rate queue property description. */
struct ofp_queue_prop_max_rate {
    struct ofp_queue_prop_header prop_header; /* prop: OFPQT_MAX, len: 16. */
    uint16_t rate;        /* In 1/10 of a percent; >1000 -> disabled. */
    uint8_t pad[6];       /* 64-bit alignment */
};
OFP_ASSERT(sizeof(struct ofp_queue_prop_max_rate) == 16);

/* Experimenter queue property description. */
struct ofp_queue_prop_experimenter {
    struct ofp_queue_prop_header prop_header; /* prop: OFPQT_EXPERIMENTER, len: 16. */
    uint32_t experimenter;          /* Experimenter ID which takes the same
                                       form as in struct
                                       ofp_experimenter_header. */
    uint8_t pad[4];       /* 64-bit alignment */
    uint8_t data[0];      /* Experimenter defined data. */
};
OFP_ASSERT(sizeof(struct ofp_queue_prop_experimenter) == 16);

/* Full description for a queue. */
struct ofp_packet_queue {
    uint32_t queue_id;     /* id for the specific queue. */
    uint32_t port;         /* Port this queue is attached to. */
    uint16_t len;          /* Length in bytes of this queue desc. */
    uint8_t pad[6];        /* 64-bit alignment. */
    struct ofp_queue_prop_header properties[0]; /* List of properties. */
};
OFP_ASSERT(sizeof(struct ofp_packet_queue) == 16);

/* Query for port queue configuration. */
struct ofp_queue_get_config_request {
    struct ofp_header header;
    uint32_t port;         /* Port to be queried. Should refer
                              to a valid physical port (i.e. <= OFPP_MAX),
                              or OFPP_ANY to request all configured
                              queues.*/
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_queue_get_config_request) == 16);

/* Queue configuration for a given port. */
struct ofp_queue_get_config_reply {
    struct ofp_header header;
    uint32_t port;
    uint8_t pad[4];
    struct ofp_packet_queue queues[0]; /* List of configured queues. */
};
OFP_ASSERT(sizeof(struct ofp_queue_get_config_reply) == 16);

/* OFPAT_SET_QUEUE action struct: send packets to given queue on port. */
struct ofp_action_set_queue {
    uint16_t type;            /* OFPAT_SET_QUEUE. */
    uint16_t len;             /* Len is 8. */
    uint32_t queue_id;        /* Queue id for the packets. */
};
OFP_ASSERT(sizeof(struct ofp_action_set_queue) == 8);

struct ofp_queue_stats_request {
    uint32_t port_no;        /* All ports if OFPP_ANY. */
    uint32_t queue_id;       /* All queues if OFPQ_ALL. */
};
OFP_ASSERT(sizeof(struct ofp_queue_stats_request) == 8);

struct ofp_queue_stats {
    uint32_t port_no;
    uint32_t queue_id;       /* Queue i.d */
    uint64_t tx_bytes;       /* Number of transmitted bytes. */
    uint64_t tx_packets;     /* Number of transmitted packets. */
    uint64_t tx_errors;      /* Number of packets dropped due to overrun. */
    uint32_t duration_sec;   /* Time queue has been alive in seconds. */
    uint32_t duration_nsec;  /* Time queue has been alive in nanoseconds beyond
                                duration_sec. */
};
OFP_ASSERT(sizeof(struct ofp_queue_stats) == 40);

/* Configures the "role" of the sending controller.  The default role is:
 *
 *    - Equal (OFPCR_ROLE_EQUAL), which allows the controller access to all
 *      OpenFlow features. All controllers have equal responsibility.
 *
 * The other possible roles are a related pair:
 *
 *    - Master (OFPCR_ROLE_MASTER) is equivalent to Equal, except that there
 *      may be at most one Master controller at a time: when a controller
 *      configures itself as Master, any existing Master is demoted to the
 *      Slave role.
 *
 *    - Slave (OFPCR_ROLE_SLAVE) allows the controller read-only access to
 *      OpenFlow features.  In particular attempts to modify the flow table
 *      will be rejected with an OFPBRC_EPERM error.
 *
 *      Slave controllers do not receive OFPT_PACKET_IN or OFPT_FLOW_REMOVED
 *      messages, but they do receive OFPT_PORT_STATUS messages.
 */

/* Controller roles. */
enum ofp_controller_role {
    OFPCR_ROLE_NOCHANGE = 0,    /* Don't change current role. */
    OFPCR_ROLE_EQUAL    = 1,    /* Default role, full access. */
    OFPCR_ROLE_MASTER   = 2,    /* Full access, at most one master. */
    OFPCR_ROLE_SLAVE    = 3,    /* Read-only access. */
};

/* Role request and reply message. */
struct ofp_role_request {
    struct ofp_header header;   /* Type OFPT_ROLE_REQUEST/OFPT_ROLE_REPLY. */
    uint32_t role;              /* One of OFPCR_ROLE_*. */
    uint8_t pad[4];             /* Align to 64 bits. */
    uint64_t generation_id;     /* Master Election Generation Id */
};
OFP_ASSERT(sizeof(struct ofp_role_request) == 24);

/* Asynchronous message configuration. */
struct ofp_async_config {
    struct ofp_header header;     /* OFPT_GET_ASYNC_REPLY or OFPT_SET_ASYNC. */
    uint32_t packet_in_mask[2];   /* Bitmasks of OFPR_* values. */
    uint32_t port_status_mask[2]; /* Bitmasks of OFPPR_* values. */
    uint32_t flow_removed_mask[2];/* Bitmasks of OFPRR_* values. */
};
OFP_ASSERT(sizeof(struct ofp_async_config) == 32);

#endif /* openflow/openflow.h */
