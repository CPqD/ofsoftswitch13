/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil
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
 */

#ifndef OFL_STRUCTS_H
#define OFL_STRUCTS_H 1

#include <sys/types.h>
#include <stdio.h>

#include <netinet/icmp6.h>
#include "../include/openflow/openflow.h"
#include "ofl.h"
#include "ofl-actions.h"
#include "ofl-packets.h"
#include "../lib/hmap.h"


struct ofl_exp;

/****************************************************************************
 * Supplementary structure definitions.
 ****************************************************************************/

struct ofl_packet_queue {
    uint32_t   queue_id; /* id for the specific queue. */
    size_t                         properties_num;
    struct ofl_queue_prop_header **properties;
};


struct ofl_queue_prop_header {
    enum ofp_queue_properties   type; /* One of OFPQT_. */
};

struct ofl_queue_prop_min_rate {
    struct ofl_queue_prop_header   header; /* OFPQT_MIN_RATE */

    uint16_t   rate; /* In 1/10 of a percent; >1000 -> disabled. */
};

struct ofl_queue_prop_max_rate {
    struct ofl_queue_prop_header   header; /* OFPQT_MAX_RATE */

    uint16_t   rate; /* In 1/10 of a percent; >1000 -> disabled. */
};

struct ofl_queue_prop_experimenter {
    struct ofl_queue_prop_header prop_header; /* prop: OFPQT_EXPERIMENTER, len: 16. */
    uint32_t experimenter;
    uint8_t *data; /* Experimenter defined data. */
};


struct ofl_instruction_header {
    enum ofp_instruction_type   type; /* Instruction type */
};

struct ofl_instruction_goto_table {
    struct ofl_instruction_header   header; /* OFPIT_GOTO_TABLE */

    uint8_t   table_id; /* Set next table in the lookup pipeline */
};



struct ofl_instruction_write_metadata {
    struct ofl_instruction_header   header; /* OFPIT_WRITE_METADATA */

    uint64_t   metadata;      /* Metadata value to write */
    uint64_t   metadata_mask; /* Metadata write bitmask */
};


struct ofl_instruction_actions {
    struct ofl_instruction_header   header; /* OFPIT_WRITE|APPLY_ACTIONS */

    size_t                     actions_num;
    struct ofl_action_header **actions;
};

struct ofl_instruction_meter {
    struct ofl_instruction_header   header; /* OFPIT_METER */
    uint32_t meter_id;

};

/* Instruction structure for experimental instructions */
struct ofl_instruction_experimenter {
    struct ofl_instruction_header   header; /* OFPIT_EXPERIMENTER */

    uint32_t   experimenter_id; /* Experimenter ID */
};

struct ofl_config {
    uint16_t   flags;         /* OFPC_* flags. */
    uint16_t   miss_send_len; /* Max bytes of new flow that datapath should
                                send to the controller. */
};

struct ofl_async_config {
    uint32_t packet_in_mask[2]; /* Bitmasks of OFPR_* values. */
    uint32_t port_status_mask[2]; /* Bitmasks of OFPPR_* values. */
    uint32_t flow_removed_mask[2];/* Bitmasks of OFPRR_* values. */
};

struct ofl_bucket {
    uint16_t   weight;      /* Relative weight of bucket. Only
                              defined for select groups. */
    uint32_t   watch_port;  /* Port whose state affects whether this
                              bucket is live. Only required for fast
                              failover groups. */
    uint32_t   watch_group; /* Group whose state affects whether this
                              bucket is live. Only required for fast
                              failover groups. */
    size_t                     actions_num;
    struct ofl_action_header **actions;
};

struct ofl_flow_stats {
    uint8_t                         table_id;      /* ID of table flow came from. */
    uint32_t                        duration_sec;  /* Time flow has been alive in secs. */
    uint32_t                        duration_nsec; /* Time flow has been alive in nsecs
                                                     beyond duration_sec. */
    uint16_t                        priority;      /* Priority of the entry. Only meaningful
                                                     when this is not an exact-match entry. */
    uint16_t                        idle_timeout;  /* Number of seconds idle before
                                                     expiration. */
    uint16_t                        hard_timeout;  /* Number of seconds before expiration. */
    uint16_t                        flags;         /* One of OFPFF_*/ 
    uint64_t                        cookie;        /* Opaque controller-issued identifier. */
    uint64_t                        packet_count;  /* Number of packets in flow. */
    uint64_t                        byte_count;    /* Number of bytes in flow. */
    struct ofl_match_header        *match;         /* Description of fields. */
    size_t                          instructions_num;
    struct ofl_instruction_header **instructions; /* Instruction set. */
};



struct ofl_table_stats {
    uint8_t    table_id;      /* Identifier of table. Lower numbered tables
                                are consulted first. */
    uint32_t   active_count;  /* Number of active entries. */
    uint64_t   lookup_count;  /* Number of packets looked up in table. */
    uint64_t   matched_count; /* Number of packets that hit table. */
};

struct ofl_table_feature_prop_header {
    uint16_t type;                /* Table feature type */
    uint16_t length;              /* Property length */
};
// Is this needed ? Jean II
OFP_ASSERT(sizeof(struct ofl_table_feature_prop_header) == 4);

/* Instructions property */
struct ofl_table_feature_prop_instructions {
    struct ofl_table_feature_prop_header header;
    size_t ids_num;
    struct ofl_instruction_header *instruction_ids; /* List of instructions */
};

struct ofl_table_feature_prop_next_tables {
    struct ofl_table_feature_prop_header header;
    size_t table_num;
    uint8_t *next_table_ids;
};

/* Actions property */
struct ofl_table_feature_prop_actions {
    struct ofl_table_feature_prop_header header;
    size_t actions_num;
    struct ofl_action_header *action_ids; /*Actions list*/
};

struct ofl_table_feature_prop_oxm {
    struct ofl_table_feature_prop_header header;
    size_t oxm_num;
    uint32_t *oxm_ids; /* Array of OXM headers */
};


/* Body for ofp_multipart_request of type OFPMP_TABLE_FEATURES./
* Body of reply to OFPMP_TABLE_FEATURES request. */
struct ofl_table_features {
    uint16_t length;  /* Length is padded to 64 bits. */
    uint8_t table_id; /* Identifier of table. Lower numbered tables
                         are consulted first. */
    uint8_t pad[5];   /* Align to 64-bits. */
    char *name;
    uint64_t metadata_match; /* Bits of metadata table can match. */
    uint64_t metadata_write; /* Bits of metadata table can write. */
    uint32_t config;         /* Bitmap of OFPTC_* values */
    uint32_t max_entries;    /* Max number of entries supported. */
    size_t properties_num;  /* Number of properties*/
    /* Table Feature Property list */
    struct ofl_table_feature_prop_header **properties;
};

struct ofl_match_header {
    uint16_t   type;             /* One of OFPMT_* */
    uint16_t   length;           /* Match length */
};

struct ofl_match {
    struct ofl_match_header   header; /* Match header */
    struct hmap match_fields;         /* Match fields. Contain OXM TLV's  */
};

struct ofl_match_tlv{

    struct hmap_node hmap_node;
    uint32_t header;    /* TLV header */
    uint8_t *value;     /* TLV value */
};


/* Common header for all meter bands */
struct ofl_meter_band_header {
    uint16_t type; /* One of OFPMBT_*. */
    uint32_t rate; /* Rate for this band. */
    uint32_t burst_size; /* Size of bursts. */
};


/* OFPMBT_DROP band - drop packets */
struct ofl_meter_band_drop {
    uint16_t type; /* OFPMBT_DROP. */
    uint32_t rate; /* Rate for dropping packets. */
    uint32_t burst_size; /* Size of bursts. */
};

/* OFPMBT_DSCP_REMARK band - Remark DSCP in the IP header */
struct ofl_meter_band_dscp_remark {
    uint16_t type; /* OFPMBT_DSCP_REMARK. */
    uint32_t rate; /* Rate for remarking packets. */
    uint32_t burst_size; /* Size of bursts. */
    uint8_t prec_level; /* Number of precendence level to substract. */
};

/* OFPMBT_EXPERIMENTER band - Write actions in action set */
struct ofl_meter_band_experimenter {
    uint16_t type; /* One of OFPMBT_*. */
    uint32_t rate; /* Rate for this band. */
    uint32_t burst_size; /* Size of bursts. */
    uint32_t experimenter; /* Experimenter ID which takes the same
                            form as in struct
                            ofp_experimenter_header. */
};

struct ofl_port_stats {
    uint32_t   port_no;
    uint64_t   rx_packets;   /* Number of received packets. */
    uint64_t   tx_packets;   /* Number of transmitted packets. */
    uint64_t   rx_bytes;     /* Number of received bytes. */
    uint64_t   tx_bytes;     /* Number of transmitted bytes. */
    uint64_t   rx_dropped;   /* Number of packets dropped by RX. */
    uint64_t   tx_dropped;   /* Number of packets dropped by TX. */
    uint64_t   rx_errors;    /* Number of receive errors. This is a super-set
                               of more specific receive errors and should be
                               greater than or equal to the sum of all
                               rx_*_err values. */
    uint64_t   tx_errors;    /* Number of transmit errors. This is a super-set
                               of more specific transmit errors and should be
                               greater than or equal to the sum of all
                               tx_*_err values (none currently defined.) */
    uint64_t   rx_frame_err; /* Number of frame alignment errors. */
    uint64_t   rx_over_err;  /* Number of packets with RX overrun. */
    uint64_t   rx_crc_err;   /* Number of CRC errors. */
    uint64_t   collisions;   /* Number of collisions. */
    uint32_t   duration_sec; /* Time port has been alive in seconds */
    uint32_t   duration_nsec; /* Time port has been alive in nanoseconds
                                 beyond duration_sec */
};

struct ofl_bucket_counter {
    uint64_t   packet_count; /* Number of packets processed by bucket. */
    uint64_t   byte_count;   /* Number of bytes processed by bucket. */
};

struct ofl_group_stats {
    uint32_t   group_id;
    uint32_t   ref_count;
    uint64_t   packet_count;
    uint64_t   byte_count;
    size_t                      counters_num;
    uint32_t   duration_sec; /* Time group has been alive in seconds */
    uint32_t   duration_nsec; /* Time group has been alive in nanoseconds
                                 beyond duration_sec */
    struct ofl_bucket_counter **counters;
};


struct ofl_port {
    uint32_t   port_no;
    uint8_t    hw_addr[OFP_ETH_ALEN];
    char      *name;

    uint32_t   config;        /* Bitmap of OFPPC_* flags. */
    uint32_t   state;         /* Bitmap of OFPPS_* flags. */

    uint32_t   curr;          /* Current features. */
    uint32_t   advertised;    /* Features being advertised by the port. */
    uint32_t   supported;     /* Features supported by the port. */
    uint32_t   peer;          /* Features advertised by peer. */

    uint32_t   curr_speed;    /* Current port bitrate in kbps. */
    uint32_t   max_speed;     /* Max port bitrate in kbps */
};



struct ofl_queue_stats {
    uint32_t   port_no;
    uint32_t   queue_id;   /* Queue i.d */
    uint64_t   tx_bytes;   /* Number of transmitted bytes. */
    uint64_t   tx_packets; /* Number of transmitted packets. */
    uint64_t   tx_errors;  /* Number of packets dropped due to overrun. */
    uint32_t   duration_sec; /* Time queue has been alive in seconds */
    uint32_t   duration_nsec; /* Time queue has been alive in nanoseconds
                                 beyond duration_sec */
};

struct ofl_group_desc_stats {
    uint8_t             type;        /* One of OFPGT_*. */
    uint32_t            group_id;    /* Group identifier. */

    size_t              buckets_num;
    struct ofl_bucket **buckets;
};


/* Statistics for each meter band */
struct ofl_meter_band_stats {
    uint64_t packet_band_count; /* Number of packets in band. */
    uint64_t byte_band_count;  /* Number of bytes in band. */

    /* Token bucket */
    uint64_t last_fill;
    uint64_t tokens;
};

/* Body of reply to OFPMP_METER request. Meter statistics. */
struct ofl_meter_stats {
    uint32_t meter_id; /* Meter instance. */
    uint16_t len;             /* Length in bytes of this stats. */
    uint32_t flow_count;      /* Number of flows bound to meter. */
    uint64_t packet_in_count; /* Number of packets in input. */
    uint64_t byte_in_count;   /* Number of bytes in input. */
    uint32_t duration_sec;    /* Time meter has been alive in seconds. */
    uint32_t duration_nsec;   /* Time meter has been alive in nanoseconds beyond
                               duration_sec. */
    size_t meter_bands_num;
    struct ofl_meter_band_stats **band_stats; /* The band_stats length is
                                                  inferred from the length field. */
};

/* Body of reply to OFPMP_METER_CONFIG request. Meter configuration. */
struct ofl_meter_config {
    uint16_t length; /* Length of this entry. */
    uint16_t flags; /* All OFPMC_* that apply. */
    uint32_t meter_id; /* Meter instance. */
    size_t meter_bands_num;
    struct ofl_meter_band_header **bands; /* The bands length is
                                              inferred from the length field. */
};

struct ofl_meter_features {
    uint32_t max_meter; /* Maximum number of meters. */
    uint32_t band_types; /* Bitmaps of OFPMBT_* values supported. */
    uint32_t capabilities; /* Bitmaps of "ofp_meter_flags". */
    uint8_t max_bands; /* Maximum bands per meters */
    uint8_t max_color; /* Maximum color value */
};

/****************************************************************************
 * Utility functions to match structure
 ****************************************************************************/
void
ofl_structs_match_init(struct ofl_match *match);

#ifdef __cplusplus
extern "C" {
#endif
void
ofl_structs_match_put8(struct ofl_match *match, uint32_t header, uint8_t value);

void
ofl_structs_match_put8m(struct ofl_match *match, uint32_t header, uint8_t value, uint8_t mask);

void
ofl_structs_match_put16(struct ofl_match *match, uint32_t header, uint16_t value);

void
ofl_structs_match_put16m(struct ofl_match *match, uint32_t header, uint16_t value, uint16_t mask);

void
ofl_structs_match_put32(struct ofl_match *match, uint32_t header, uint32_t value);

void
ofl_structs_match_put32m(struct ofl_match *match, uint32_t header, uint32_t value, uint32_t mask);

void
ofl_structs_match_put64(struct ofl_match *match, uint32_t header, uint64_t value);

void
ofl_structs_match_put64m(struct ofl_match *match, uint32_t header, uint64_t value, uint64_t mask);

void
ofl_structs_match_put_pbb_isid(struct ofl_match *match, uint32_t header, uint8_t value[PBB_ISID_LEN]);

void
ofl_structs_match_put_pbb_isidm(struct ofl_match *match, uint32_t header, uint8_t value[PBB_ISID_LEN], uint8_t mask[PBB_ISID_LEN]);

void
ofl_structs_match_put_eth(struct ofl_match *match, uint32_t header, uint8_t value[ETH_ADDR_LEN]);

void
ofl_structs_match_put_eth_m(struct ofl_match *match, uint32_t header, uint8_t value[ETH_ADDR_LEN], uint8_t mask[ETH_ADDR_LEN]);

void
ofl_structs_match_put_ipv6(struct ofl_match *match, uint32_t header, uint8_t value[IPv6_ADDR_LEN] );

void
ofl_structs_match_put_ipv6m(struct ofl_match *match, uint32_t header, uint8_t value[IPv6_ADDR_LEN], uint8_t mask[IPv6_ADDR_LEN]);

#ifdef __cplusplus
}
#endif

int
ofl_structs_match_ofp_total_len(struct ofl_match *match);


/****************************************************************************
 * Functions for (un)packing structures
 ****************************************************************************/

size_t
ofl_structs_instructions_pack(struct ofl_instruction_header *src, struct ofp_instruction *dst, struct ofl_exp *exp);

size_t
ofl_structs_meter_band_pack(struct ofl_meter_band_header *src, struct ofp_meter_band_header *dst);

size_t
ofl_structs_meter_conf_pack(struct ofl_meter_config *src, struct ofp_meter_config *dst, uint8_t* data);

size_t
ofl_structs_meter_stats_pack(struct ofl_meter_stats *src, struct ofp_meter_stats *dst);

size_t
ofl_structs_table_properties_pack(struct ofl_table_feature_prop_header * src, struct ofp_table_feature_prop_header *dst, uint8_t *data, struct ofl_exp *exp);

size_t
ofl_structs_table_features_pack(struct ofl_table_features *src, struct ofp_table_features *dst, uint8_t* data, struct ofl_exp *exp);

size_t
ofl_structs_bucket_pack(struct ofl_bucket *src, struct ofp_bucket *dst, struct ofl_exp *exp);

size_t
ofl_structs_flow_stats_pack(struct ofl_flow_stats *src, uint8_t *dst, struct ofl_exp *exp);

size_t
ofl_structs_group_stats_pack(struct ofl_group_stats *src, struct ofp_group_stats *dst);

size_t
ofl_structs_queue_prop_pack(struct ofl_queue_prop_header *src, struct ofp_queue_prop_header *dst);

size_t
ofl_structs_packet_queue_pack(struct ofl_packet_queue *src, struct ofp_packet_queue *dst);

size_t
ofl_structs_port_stats_pack(struct ofl_port_stats *src, struct ofp_port_stats *dst);


size_t
ofl_structs_port_pack(struct ofl_port *src, struct ofp_port *dst);

size_t
ofl_structs_table_stats_pack(struct ofl_table_stats *src, struct ofp_table_stats *dst);


size_t
ofl_structs_queue_stats_pack(struct ofl_queue_stats *src, struct ofp_queue_stats *dst);

size_t
ofl_structs_group_desc_stats_pack(struct ofl_group_desc_stats *src, struct ofp_group_desc_stats *dst, struct ofl_exp *exp);

size_t
ofl_structs_bucket_counter_pack(struct ofl_bucket_counter *src, struct ofp_bucket_counter *dst);

size_t
ofl_structs_match_pack(struct ofl_match_header *src, struct ofp_match *dst, uint8_t* oxm_fields, struct ofl_exp *exp);

ofl_err
ofl_structs_instructions_unpack(struct ofp_instruction *src, size_t *len, struct ofl_instruction_header **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_table_features_unpack(struct ofp_table_features *src, size_t *len, struct ofl_table_features **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_bucket_unpack(struct ofp_bucket *src, size_t *len, uint8_t gtype, struct ofl_bucket **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_flow_stats_unpack(struct ofp_flow_stats *src,uint8_t *buf, size_t *len, struct ofl_flow_stats **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_queue_prop_unpack(struct ofp_queue_prop_header *src, size_t *len, struct ofl_queue_prop_header **dst);

ofl_err
ofl_structs_packet_queue_unpack(struct ofp_packet_queue *src, size_t *len, struct ofl_packet_queue **dst);

ofl_err
ofl_structs_port_unpack(struct ofp_port *src, size_t *len, struct ofl_port **dst);

ofl_err
ofl_structs_table_stats_unpack(struct ofp_table_stats *src, size_t *len, struct ofl_table_stats **dst);

ofl_err
ofl_structs_port_stats_unpack(struct ofp_port_stats *src, size_t *len, struct ofl_port_stats **dst);

ofl_err
ofl_structs_group_stats_unpack(struct ofp_group_stats *src, size_t *len, struct ofl_group_stats **dst);

ofl_err
ofl_structs_queue_stats_unpack(struct ofp_queue_stats *src, size_t *len, struct ofl_queue_stats **dst);

ofl_err
ofl_structs_meter_band_unpack(struct ofp_meter_band_header *src, size_t *len, struct ofl_meter_band_header **dst);

ofl_err
ofl_structs_group_desc_stats_unpack(struct ofp_group_desc_stats *src, size_t *len, struct ofl_group_desc_stats **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_bucket_counter_unpack(struct ofp_bucket_counter *src, size_t *len, struct ofl_bucket_counter **dst);

ofl_err
ofl_structs_match_unpack(struct ofp_match *src,uint8_t *buf, size_t *len, struct ofl_match_header **dst, struct ofl_exp *exp);

ofl_err
ofl_structs_meter_band_stats_unpack(struct ofp_meter_band_stats *src, size_t *len, struct ofl_meter_band_stats **dst);

ofl_err
ofl_structs_meter_stats_unpack(struct ofp_meter_stats *src, size_t *len, struct ofl_meter_stats **dst);

ofl_err
ofl_structs_meter_config_unpack(struct ofp_meter_config *src, size_t *len, struct ofl_meter_config **dst);

/****************************************************************************
 * Functions for freeing action structures
 ****************************************************************************/

void
ofl_structs_free_meter_bands(struct ofl_meter_band_header *meter_band);

void
ofl_structs_free_packet_queue(struct ofl_packet_queue *queue);

void
ofl_structs_free_instruction(struct ofl_instruction_header *inst, struct ofl_exp *exp);

void
ofl_structs_free_table_stats(struct ofl_table_stats *stats);

void
ofl_structs_free_bucket(struct ofl_bucket *bucket, struct ofl_exp *exp);

void
ofl_structs_free_flow_stats(struct ofl_flow_stats *stats, struct ofl_exp *exp);

void
ofl_structs_free_port(struct ofl_port *port);

void
ofl_structs_free_group_stats(struct ofl_group_stats *stats);

void
ofl_structs_free_group_desc_stats(struct ofl_group_desc_stats *stats, struct ofl_exp *exp);

void
ofl_structs_free_match(struct ofl_match_header *match, struct ofl_exp *exp);

void
ofl_structs_free_meter_band_stats(struct ofl_meter_band_stats* s);

void
ofl_structs_free_meter_stats(struct ofl_meter_stats *stats);

void
ofl_structs_free_meter_config(struct ofl_meter_config *conf);

void
ofl_structs_free_table_features(struct ofl_table_features* features, struct ofl_exp *exp);

void
ofl_structs_free_table_properties(struct ofl_table_feature_prop_header *prop, struct ofl_exp *exp);

/****************************************************************************
 * Utility functions
 ****************************************************************************/

/* Given a list of structures in OpenFlow wire format, these functions return
 * the count of those structures in the passed in byte array. The functions
 * return an ofl_err in case of an error, or 0 on succes. */
ofl_err
ofl_utils_count_ofp_instructions(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_buckets(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_meter_bands(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_ports(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_flow_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_group_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_table_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_bucket_counters(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_port_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_queue_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_group_desc_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_packet_queues(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_queue_props(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_table_features_properties(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_table_features(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_meter_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_meter_band_stats(void *data, size_t data_len, size_t *count);

ofl_err
ofl_utils_count_ofp_meter_config(void *data, size_t data_len, size_t *count);

size_t
ofl_structs_instructions_ofp_total_len(struct ofl_instruction_header **instructions, size_t instructions_num, struct ofl_exp *exp);

size_t
ofl_structs_instructions_ofp_len(struct ofl_instruction_header *instruction, struct ofl_exp *exp);

size_t
ofl_structs_meter_bands_ofp_total_len(struct ofl_meter_band_header **meter_bands, size_t meter_bands_num);

size_t
ofl_structs_meter_band_ofp_len(struct ofl_meter_band_header *meter_band);

size_t
ofl_structs_buckets_ofp_total_len(struct ofl_bucket ** buckets, size_t buckets_num, struct ofl_exp *exp);

size_t
ofl_structs_buckets_ofp_len(struct ofl_bucket *bucket, struct ofl_exp *exp);

size_t
ofl_structs_flow_stats_ofp_total_len(struct ofl_flow_stats ** stats, size_t stats_num, struct ofl_exp *exp);

size_t
ofl_structs_flow_stats_ofp_len(struct ofl_flow_stats *stats, struct ofl_exp *exp);

size_t
ofl_structs_group_stats_ofp_total_len(struct ofl_group_stats ** stats, size_t stats_num);

size_t
ofl_structs_group_stats_ofp_len(struct ofl_group_stats *stats);

size_t
ofl_structs_group_desc_stats_ofp_total_len(struct ofl_group_desc_stats ** stats, size_t stats_num, struct ofl_exp *exp);

size_t
ofl_structs_table_features_properties_ofp_len(struct ofl_table_feature_prop_header *prop, struct ofl_exp *exp);

size_t
ofl_structs_table_features_properties_ofp_total_len(struct ofl_table_feature_prop_header **props, size_t features_num, struct ofl_exp *exp);

size_t ofl_structs_table_features_ofp_total_len(struct ofl_table_features **feat, size_t tables_num, struct ofl_exp * exp);

size_t
ofl_structs_group_desc_stats_ofp_len(struct ofl_group_desc_stats *stats, struct ofl_exp *exp);

size_t
ofl_structs_queue_prop_ofp_total_len(struct ofl_queue_prop_header ** props, size_t props_num);

size_t
ofl_structs_queue_prop_ofp_len(struct ofl_queue_prop_header *prop);

size_t
ofl_structs_packet_queue_ofp_total_len(struct ofl_packet_queue ** queues, size_t queues_num);

size_t
ofl_structs_packet_queue_ofp_len(struct ofl_packet_queue *queue);

size_t
ofl_structs_match_ofp_len(struct ofl_match_header *match, struct ofl_exp *exp);

size_t
ofl_structs_meter_stats_ofp_total_len(struct ofl_meter_stats **stats, size_t stats_num);

size_t
ofl_structs_meter_stats_ofp_len(struct ofl_meter_stats * stats);

size_t
ofl_structs_pack_band_stats(struct ofl_meter_band_stats *src, struct ofp_meter_band_stats *dst);

size_t
ofl_structs_meter_conf_ofp_total_len(struct ofl_meter_config **meter_conf, size_t stats_num);

size_t
ofl_structs_meter_conf_ofp_len(struct ofl_meter_config * meter_conf);



/****************************************************************************
 * Functions for printing structures
 ****************************************************************************/

char *
ofl_structs_port_to_string(struct ofl_port *port);

void
ofl_structs_port_print(FILE *stream, struct ofl_port *port);

char *
ofl_structs_instruction_to_string(struct ofl_instruction_header *inst, struct ofl_exp *exp);

void
ofl_structs_instruction_print(FILE *stream, struct ofl_instruction_header *inst, struct ofl_exp *exp);

char *
ofl_structs_match_to_string(struct ofl_match_header *match, struct ofl_exp *exp);

void
ofl_structs_match_print(FILE *stream, struct ofl_match_header *match, struct ofl_exp *exp);

char *
ofl_structs_oxm_tlv_to_string(struct ofl_match_tlv *f);

void
ofl_structs_oxm_tlv_print(FILE *stream, struct ofl_match_tlv *f);

char *
ofl_structs_oxm_match_to_string(struct ofl_match *m);

void
ofl_structs_oxm_match_print(FILE *stream, const struct ofl_match *omt);

char *
ofl_structs_config_to_string(struct ofl_config *c);

void
ofl_structs_config_print(FILE *stream, struct ofl_config *c);

char *
ofl_structs_bucket_to_string(struct ofl_bucket *b, struct ofl_exp *exp);

void
ofl_structs_bucket_print(FILE *stream, struct ofl_bucket *b, struct ofl_exp *exp);

char *
ofl_structs_queue_to_string(struct ofl_packet_queue *q);

void
ofl_structs_queue_print(FILE *stream, struct ofl_packet_queue *q);

char *
ofl_structs_queue_prop_to_string(struct ofl_queue_prop_header *p);

void
ofl_structs_queue_prop_print(FILE *stream, struct ofl_queue_prop_header *p);

char *
ofl_structs_flow_stats_to_string(struct ofl_flow_stats *s, struct ofl_exp *exp);

void
ofl_structs_flow_stats_print(FILE *stream, struct ofl_flow_stats *s, struct ofl_exp *exp);

char *
ofl_structs_bucket_counter_to_string(struct ofl_bucket_counter *s);

void
ofl_structs_bucket_counter_print(FILE *stream, struct ofl_bucket_counter *c);

char *
ofl_structs_group_stats_to_string(struct ofl_group_stats *s);

void
ofl_structs_group_stats_print(FILE *stream, struct ofl_group_stats *s);

char *
ofl_structs_table_stats_to_string(struct ofl_table_stats *s);

void
ofl_structs_table_stats_print(FILE *stream, struct ofl_table_stats *s);

char *
ofl_structs_table_properties_to_string(struct ofl_table_feature_prop_header *s);

void
ofl_structs_table_properties_print(FILE * stream, struct ofl_table_feature_prop_header* s);

char *
ofl_structs_table_features_to_string(struct ofl_table_features *s);

void
ofl_structs_table_features_print(FILE *stream, struct ofl_table_features *s);

char *
ofl_structs_port_stats_to_string(struct ofl_port_stats *s);

void
ofl_structs_port_stats_print(FILE *stream, struct ofl_port_stats *s);

char *
ofl_structs_queue_stats_to_string(struct ofl_queue_stats *s);

void
ofl_structs_queue_stats_print(FILE *stream, struct ofl_queue_stats *s);

char *
ofl_structs_group_desc_stats_to_string(struct ofl_group_desc_stats *s, struct ofl_exp *exp);

void
ofl_structs_group_desc_stats_print(FILE *stream, struct ofl_group_desc_stats *s, struct ofl_exp *exp);

char*
ofl_structs_meter_band_to_string(struct ofl_meter_band_header* s);

void
ofl_structs_meter_band_print(FILE *stream, struct ofl_meter_band_header* s);

char*
ofl_structs_meter_band_stats_to_string(struct ofl_meter_band_stats* s);

void
ofl_structs_meter_band_stats_print(FILE *stream, struct ofl_meter_band_stats* s);

char*
ofl_structs_meter_features_to_string(struct ofl_meter_features* s);

void
ofl_structs_meter_features_print(FILE *stream, struct ofl_meter_features* s);

char *
ofl_structs_meter_stats_to_string(struct ofl_meter_stats *s);

void
ofl_structs_meter_stats_print(FILE *stream, struct ofl_meter_stats* s);

char*
ofl_structs_meter_config_to_string(struct ofl_meter_config* s);

void
ofl_structs_meter_config_print(FILE *stream, struct ofl_meter_config* s);

char *
ofl_structs_async_config_to_string(struct ofl_async_config *s);

void
ofl_structs_async_config_print(FILE * stream, struct ofl_async_config *s);

#endif /* OFL_STRUCTS_H */
