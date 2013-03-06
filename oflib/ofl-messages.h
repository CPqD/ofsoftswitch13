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

#ifndef OFL_MESSAGES_H
#define OFL_MESSAGES_H 1

#include <sys/types.h>
#include <stdbool.h>
#include <stdio.h>

#include "../include/openflow/openflow.h"
#include "ofl.h"
#include "ofl-structs.h"
#include "ofl-actions.h"


/****************************************************************************
+ * Message structure definitions.
 ****************************************************************************/

/* The common header for messages. All message structures start with this
 * header, therefore they can be safely cast back and forth */
struct ofl_msg_header {
    enum ofp_type   type;   /* One of the OFPT_ constants. */
};


/*********************
 * Immutable messages
 *********************/

 /* The common header for error messages. All error message structures start
  * with this header, therefore they can be safely cast back and forth */
struct ofl_msg_error {
    struct ofl_msg_header   header; /* OFPT_ERROR */

    enum ofp_error_type   type;
    uint16_t              code;
    size_t     data_length;
    uint8_t   *data;          /* textual errors (OFPET_HELLO_FAILED) or original
+                                  request. */
};


/* Echo messages */
struct ofl_msg_echo {
    struct ofl_msg_header   header; /* OFPT_ECHO_REQUEST|REPLY */

    size_t     data_length;
    uint8_t   *data;
};



/********************
 * Symmetric message
 ********************/

struct ofl_msg_experimenter {
    struct ofl_msg_header   header; /* OFPT_EXPERIMENTER */

    uint32_t   experimenter_id;
};

/* Switch configuration messages. */

struct ofl_msg_features_reply {
    struct ofl_msg_header   header; /* OFPT_FEATURES_REPLY */

    uint64_t          datapath_id;  /* Datapath unique ID. The lower 48-bits
                                      are fora MAC address, while the upper
                                      16-bits are implementer-defined. */
    uint32_t          n_buffers;    /* Max packets buffered at once. */
    uint8_t           n_tables;     /* Number of tables supported by
                                      datapath. */
    uint8_t           auxiliary_id; /* Identify auxiliary connections */
    uint32_t          capabilities; /* Bitmap of support ofp_capabilities. */
    uint32_t          reserved;
};

struct ofl_msg_get_config_reply {
    struct ofl_msg_header   header; /* OFPT_GET_CONFIG_REPLY */

    struct ofl_config  *config;
};

struct ofl_msg_set_config {
    struct ofl_msg_header   header;  /* OFPT_SET_CONFIG */

    struct ofl_config  *config;
};

/* Role request and reply message. */
struct ofl_msg_role_request {
	struct ofl_msg_header header; /* Type OFPT_ROLE_REQUEST/OFPT_ROLE_REPLY. */
	uint32_t role;            /* One of OFPCR_ROLE_*. */
	uint64_t generation_id;   /* Master Election Generation Id */
};



/************************
 * Asynchronous messages
 ************************/

struct ofl_msg_packet_in {
    struct ofl_msg_header   header; /* OFPT_PACKET_IN */

    uint32_t                    buffer_id;   /* ID assigned by datapath. */
    uint16_t                    total_len;   /* Full length of frame. */
    enum ofp_packet_in_reason   reason;      /* Reason packet is being sent (one of OFPR_*) */
    uint8_t                     table_id;    /* ID of the table that was looked up */
    uint64_t                    cookie;
    struct ofl_match_header     *match;
    size_t     data_length;
    uint8_t   *data;
};

struct ofl_msg_flow_removed {
    struct ofl_msg_header   header; /* OFPT_FLOW_REMOVED */

    struct ofl_flow_stats         *stats;
    enum ofp_flow_removed_reason   reason;   /* One of OFPRR_*. */
};

struct ofl_msg_port_status {
    struct ofl_msg_header   header; /* OFPT_PORT_STATUS */

    enum ofp_port_reason   reason; /* One of OFPPR_*. */
    struct ofl_port       *desc;
};

/******************************
 * Controller command messages
 ******************************/

/* Asynchronous message configuration. */
struct ofl_msg_async_config {
    struct ofl_msg_header header; /* OFPT_GET_ASYNC_REPLY or OFPT_SET_ASYNC. */
    struct ofl_async_config *config; 
};

struct ofl_msg_packet_out {
    struct ofl_msg_header   header; /* OFPT_PACKET_OUT, */

    uint32_t                   buffer_id;   /* ID assigned by datapath
                                              (0xffffffff if none). */
    uint32_t                   in_port;     /* Packet's input port or
                                              OFPP_CONTROLLER */
    uint32_t                   actions_num;
    struct ofl_action_header **actions;

    size_t                     data_length;
    uint8_t                   *data;        /* Packet data. (Only meaningful
                                              if buffer_id is 0xffffffff.) */
};

struct ofl_msg_flow_mod {
    struct ofl_msg_header   header; /* OFPT_FLOW_MOD, */

    uint64_t                        cookie;      /* Opaque controller-issued identifier. */
    uint64_t                        cookie_mask; /* Mask used to restrict the cookie bits
                                                   that must match when the command is
                                                   OFPFC_MODIFY* or OFPFC_DELETE*. A value
                                                   of 0 indicates no restriction. */
    uint8_t                         table_id;     /* ID of the table to put the flow in */
    enum ofp_flow_mod_command       command;      /* One of OFPFC_*. */
    uint16_t                        idle_timeout; /* Idle time before discarding (secs). */
    uint16_t                        hard_timeout; /* Max time before discarding (secs). */
    uint16_t                        priority;     /* Priority level of flow entry. */
    uint32_t                        buffer_id;    /* Buffered packet to apply to (or -1).
                                                    Not meaningful for OFPFC_DELETE*. */
    uint32_t                        out_port;     /* For OFPFC_DELETE* commands, require
                                                    matching entries to include this as an
                                                    output port. A value of OFPP_ANY
                                                    indicates no restriction. */
    uint32_t                        out_group;    /* For OFPFC_DELETE* commands, require
                                                    matching entries to include this as an
                                                    output group. A value of OFPG_ANY
                                                    indicates no restriction. */
    uint16_t                        flags;        /* One of OFPFF_*. */
    struct ofl_match_header        *match;        /* Fields to match */
    size_t                          instructions_num;
    struct ofl_instruction_header **instructions; /* Instruction set */
};



struct ofl_msg_group_mod {
    struct ofl_msg_header   header; /* OFPT_GROUP_MOD, */

    enum ofp_group_mod_command   command;     /* One of OFPGC_*. */
    uint8_t                      type;        /* One of OFPGT_*. */
    uint32_t                     group_id;    /* Group identifier. */
    size_t                       buckets_num;
    struct ofl_bucket          **buckets;   /* The bucket length is inferred from the
                                               length field in the header. */
};

/* Modify behavior of the physical port */
struct ofl_msg_port_mod {
    struct ofl_msg_header   header; /* OFPT_PORT_MOD */

    uint32_t   port_no;
    uint8_t    hw_addr[OFP_ETH_ALEN]; /* The hardware address is not
                                        configurable. This is used to
                                        sanity-check the request, so it must
                                        be the same as returned in an
                                        ofp_port struct. */
    uint32_t   config;    /* Bitmap of OFPPC_* flags. */
    uint32_t   mask;      /* Bitmap of OFPPC_* flags to be changed. */
    uint32_t   advertise; /* Bitmap of OFPPF_*. Zero all bits to prevent
                            any action taking place. */
};

struct ofl_msg_table_mod {
    struct ofl_msg_header   header;   /* OFPT_TABLE_MOD */

    uint8_t    table_id; /* ID of the table, 0xFF indicates all tables */
    uint32_t   config;   /* Bitmap of OFPTC_* flags */
};

/* Meter configuration. OFPT_METER_MOD. */
struct ofl_msg_meter_mod {
    struct ofl_msg_header header;
    uint16_t command;  /* One of OFPMC_*. */
    uint16_t flags;    /* One of OFPMF_*. */   
    uint32_t meter_id; /* Meter instance. */
    size_t  meter_bands_num; 
    struct ofl_meter_band_header **bands; /* The bands length is
                                              inferred from the length field
                                              in the header. */
};


/**********************
 * Multipart messages
 **********************/

struct ofl_msg_multipart_request_header {
    struct ofl_msg_header   header; /* OFPT_MULTIPART_REQUEST */

    enum ofp_multipart_types   type;  /* One of the OFPMP_* constants. */
    uint16_t               flags;     /* OFPMPF_REQ_* flags. */
};

struct ofl_msg_multipart_request_flow {
    struct ofl_msg_multipart_request_header   header; /* OFPMP_FLOW/AGGREGATE */

    uint8_t                  table_id; /* ID of table to read
                                           (from ofp_table_multipart), 0xff for all
                                           tables. */
    uint32_t                 out_port; /* Require matching entries to include this
                                            as an output port. A value of OFPP_ANY
                                            indicates no restriction. */
    uint32_t                 out_group; /* Require matching entries to include this
                                            as an output group. A value of OFPG_ANY
                                            indicates no restriction. */
    uint64_t                 cookie;      /* Require matching entries to contain
                                            this cookie value */
    uint64_t                 cookie_mask; /* Mask used to restrict the cookie bits
                                            that must match. A value of 0 indicates
                                            no restriction. */
    struct ofl_match_header  *match;       /* Fields to match. */
};

struct ofl_msg_multipart_request_port {
    struct ofl_msg_multipart_request_header   header; /* OFPMP_PORT_STATS */
    uint32_t   port_no; /* OFPMP_PORT_STATS message must request statistics
                          either for a single port (specified in
                          port_no) or for all ports (if port_no ==
                          OFPP_ANY). */
};

struct ofl_msg_multipart_request_queue {
    struct ofl_msg_multipart_request_header   header; /* OFPMP_QUEUE */
    uint32_t   port_no; /* All ports if OFPP_ANY. */
    uint32_t   queue_id; /* All queues if OFPQ_ALL. */
};

struct ofl_msg_multipart_request_group {
    struct ofl_msg_multipart_request_header   header; /* OFPMP_GROUP */
    uint32_t   group_id; /* All groups if OFPG_ALL. */
};

struct ofl_msg_multipart_request_table_features{
    struct ofl_msg_multipart_request_header   header; /* OFPMP_TABLE_FEATURES */
    size_t tables_num;
    struct ofl_table_features **table_features;    
};

struct ofl_msg_multipart_meter_request {
    struct ofl_msg_multipart_request_header   header; /* OFPMP_METER */
    
    uint32_t meter_id; /* Meter instance, or OFPM_ALL. */
};

struct ofl_msg_multipart_request_experimenter {
    struct ofl_msg_multipart_request_header   header; /* OFPMP_EXPERIMENTER */

    uint32_t   experimenter_id;
};

struct ofl_msg_multipart_reply_header {
    struct ofl_msg_header   header; /* OFPT_MULTIPART_REPLY */

    enum ofp_multipart_types   type;  /* One of the OFPMP_* constants. */
    uint16_t               flags;     /* OFPMPF_REPLY_* flags. */
};

struct ofl_msg_reply_desc {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_DESC */

    char  *mfr_desc;     /* Manufacturer description. Max DESC_STR_LEN */
    char  *hw_desc;      /* Hardware description. Max DESC_STR_LEN */
    char  *sw_desc;      /* Software description. Max DESC_STR_LEN */
    char  *serial_num;   /* Serial number. Max SERIAL_NUM_LEN*/
    char  *dp_desc;      /* Human readable description of
                                         datapath. Max DESC_STR_LEN */
};

struct ofl_msg_multipart_reply_flow {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_FLOW */

    size_t                  stats_num;
    struct ofl_flow_stats **stats;
};

struct ofl_msg_multipart_reply_aggregate {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_AGGREGATE */

    uint64_t   packet_count; /* Number of packets in flows. */
    uint64_t   byte_count;   /* Number of bytes in flows. */
    uint32_t   flow_count;   /* Number of flows. */
};

struct ofl_msg_multipart_reply_table {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_TABLE */

    size_t                   stats_num;
    struct ofl_table_stats **stats;
};

struct ofl_msg_multipart_reply_table_features {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_TABLE_FEATURES */
    size_t tables_num;
    struct ofl_table_features ** table_features;

};

struct ofl_msg_multipart_reply_port {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_PORT_STATS */

    size_t                  stats_num;
    struct ofl_port_stats **stats;
};

struct ofl_msg_multipart_reply_queue {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_QUEUE */

    size_t                   stats_num;
    struct ofl_queue_stats **stats;
};

struct ofl_msg_multipart_reply_group {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_GROUP */

    size_t                   stats_num;
    struct ofl_group_stats **stats;
};

struct ofl_msg_multipart_reply_group_desc {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_GROUP_DESC */

    size_t                        stats_num;
    struct ofl_group_desc_stats **stats;
};

struct ofl_msg_multipart_reply_group_features {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_GROUP_FEATURES */

    uint32_t types;
    uint32_t capabilities;
    uint32_t max_groups[4];
    uint32_t actions[4];
};

struct ofl_msg_multipart_reply_meter {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_METER */

    size_t                   stats_num;
    struct ofl_meter_stats **stats;
};

struct ofl_msg_multipart_reply_meter_features {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_METER_FEATURES */
    
    struct ofl_meter_features *features;   
};

struct ofl_msg_multipart_reply_meter_conf {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_METER_CONFIG */

    size_t                        stats_num;
    struct ofl_meter_config **stats;
};

struct ofl_msg_multipart_reply_port_desc {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_PORT_DESC */

    size_t                  stats_num;
    struct ofl_port **stats;
};

struct ofl_msg_multipart_reply_experimenter {
    struct ofl_msg_multipart_reply_header   header; /* OFPMP_EXPERIMENTER */

    uint32_t  experimenter_id;

    size_t    data_length;
    uint8_t  *data;
};

/*******************
 * Barrier messages
 *******************/

struct ofl_msg_queue_get_config_request {
    struct ofl_msg_header   header; /* OFPT_QUEUE_GET_CONFIG_REQUEST */

    uint32_t   port; /* Port to be queried. Should refer
                       to a valid physical port (i.e. < OFPP_MAX) */
};

/************************
 * Queue config messages
 ************************/

struct ofl_msg_queue_get_config_reply {
    struct ofl_msg_header header;   /* OFPT_QUEUE_GET_CONFIG_REPLY */
    uint32_t   port;

    size_t                    queues_num;
    struct ofl_packet_queue **queues; /* List of configured queues. */
};



/****************************************************************************
 * Functions for (un)packing message structures
 ****************************************************************************/

/* Packs the message in msg to an OpenFlow buffer, pointed at by buf. The
 * packet message will have xid as transaction ID. The return value is zero on
 * success. In case of an experimenter features, it uses the passed in
 * experimenter callbacks. */
int
ofl_msg_pack(struct ofl_msg_header *msg, uint32_t xid, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp);

/* Unpacks the wire format message in buf to a new OFLib message pointed at by
 * msg. If xid is not null, it will hold the transaction ID of the received
 * message. Returns zero on success. In case of experimenter features, the
 * function uses the passed in experimenter callback. */
ofl_err
ofl_msg_unpack(uint8_t *buf, size_t buf_len,
               struct ofl_msg_header **msg, uint32_t *xid, struct ofl_exp *exp);




/****************************************************************************
 * Functions for freeing messages
 ****************************************************************************/

/* Calling this function frees the passed in message. In case of experimenter
 * features, it uses the passed in experimenter callback. */
int
ofl_msg_free(struct ofl_msg_header *msg, struct ofl_exp *exp);

/* Calling this function frees the passed meter_mod message.*/
int 
ofl_msg_free_meter_mod(struct ofl_msg_meter_mod * msg, bool with_bands);

/* Calling this function frees the passed in packet_out message. If with_data
 * is true, the data in the packet is also freed. In case of experimenter
 * features, it uses the passed in experimenter callback. */
int
ofl_msg_free_packet_out(struct ofl_msg_packet_out *msg, bool with_data, struct ofl_exp *exp);

/* Calling this function frees the passed in group_mod message. If with_buckets
 * is true, the buckets of the message is also freed. In case of experimenter
 * features, it uses the passed in experimenter callback. */
int
ofl_msg_free_group_mod(struct ofl_msg_group_mod *msg, bool with_buckets, struct ofl_exp *exp);

/* Calling this function frees the passed in flow_modmessage. If with_match is
 * true, the associated match structure is also freed. If with_instructions is
 * true, the associated instructions (and their actions) are also freed. In
 * case of experimenter features, it uses the passed in experimenter callback.
 */
int
ofl_msg_free_flow_mod(struct ofl_msg_flow_mod *msg, bool with_match, bool with_instructions, struct ofl_exp *exp);

/* Calling this function frees the passed in flow_removed message. If
 * with_stats is true, the associated stats structure is also freed. In case of
 * experimenter features, it uses the passed in experimenter callback. */
int
ofl_msg_free_flow_removed(struct ofl_msg_flow_removed *msg, bool with_stats, struct ofl_exp *exp);

/****************************************************************************
 * Functions for merging messages
 ****************************************************************************/

/* Merges two table feature requests messages. Returns true if the merged
 * message was the last in a series of multi-messages. */
bool
ofl_msg_merge_multipart_request_table_features(struct ofl_msg_multipart_request_table_features *orig, struct ofl_msg_multipart_request_table_features *merge);

/* Merges two flow stats reply messages. Returns true if the merged message was
 * the last in a series of multi-messages. */
bool
ofl_msg_merge_multipart_reply_flow(struct ofl_msg_multipart_reply_flow *orig,
                               struct ofl_msg_multipart_reply_flow *merge);

/* Merges two table stats reply messages. Returns true if the merged message
 * was the last in a series of multi-messages. */
bool
ofl_msg_merge_multipart_reply_table(struct ofl_msg_multipart_reply_table *orig,
                                struct ofl_msg_multipart_reply_table *merge);

/* Merges two port stats reply messages. Returns true if the merged message was
 * the last in a series of multi-messages. */
bool
ofl_msg_merge_multipart_reply_port(struct ofl_msg_multipart_reply_port *orig,
                               struct ofl_msg_multipart_reply_port *merge);

/* Merges two flow stats reply messages. Returns true if the merged message was
 * the last in a series of multi-messages. */
bool
ofl_msg_merge_multipart_reply_queue(struct ofl_msg_multipart_reply_queue *orig,
                               struct ofl_msg_multipart_reply_queue *merge);



/****************************************************************************
 * Functions for printing messages
 ****************************************************************************/

/* Converts the passed in message to a string format. In case of experimenter
 * features, it uses the passed in experimenter callbacks. */
char *
ofl_msg_to_string(struct ofl_msg_header *msg, struct ofl_exp *exp);

/* Converts the passed in message to a string format and adds it to the dynamic
 * string. In case of experimenter features, it uses the passed in experimenter
 * callbacks. */
void
ofl_msg_print(FILE *stream, struct ofl_msg_header *msg, struct ofl_exp *exp);


#endif /* OFL_MESSAGES_H */
