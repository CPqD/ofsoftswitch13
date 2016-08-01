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

#include "compiler.h"
#include "dp_capabilities.h"
#include "dp_control.h"
#include "dp_actions.h"
#include "dp_buffers.h"
#include "dp_ports.h"
#include "group_table.h"
#include "meter_table.h"
#include "packets.h"
#include "pipeline.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-log.h"
#include "openflow/openflow.h"

#include "vlog.h"
#define LOG_MODULE VLM_dp_ctrl

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

/* Handles barrier request messages. */
static ofl_err
handle_control_barrier_request(struct datapath *dp,
           struct ofl_msg_header *msg, const struct sender *sender) {

    /* Note: the implementation is single-threaded,
       so a barrier request can simply be replied. */
    struct ofl_msg_header reply =
            {.type = OFPT_BARRIER_REPLY};

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);
    ofl_msg_free(msg, dp->exp);

    return 0;
}

/* Handles features request messages. */
static ofl_err
handle_control_features_request(struct datapath *dp,
          struct ofl_msg_header *msg, const struct sender *sender) {

    struct ofl_msg_features_reply reply =
            {{.type = OFPT_FEATURES_REPLY},
             .datapath_id  = dp->id,
             .n_buffers    = dp_buffers_size(dp->buffers),
             .n_tables     = PIPELINE_TABLES,
             .auxiliary_id = sender->conn_id,
             .capabilities = DP_SUPPORTED_CAPABILITIES,
             .reserved = 0x00000000};

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    ofl_msg_free(msg, dp->exp);

    return 0;
}


/* Handles get config request messages. */
static ofl_err
handle_control_get_config_request(struct datapath *dp,
        struct ofl_msg_header *msg, const struct sender *sender) {

    struct ofl_msg_get_config_reply reply =
            {{.type = OFPT_GET_CONFIG_REPLY},
             .config = &dp->config};
    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    ofl_msg_free(msg, dp->exp);
    return 0;
}

/* Handles set config request messages. */
static ofl_err
handle_control_set_config(struct datapath *dp, struct ofl_msg_set_config *msg,
                                                const struct sender *sender UNUSED) {
    uint16_t flags;

    flags = msg->config->flags & OFPC_FRAG_MASK;
    if ((flags & OFPC_FRAG_MASK) != OFPC_FRAG_NORMAL
        && (flags & OFPC_FRAG_MASK) != OFPC_FRAG_DROP) {
        flags = (flags & ~OFPC_FRAG_MASK) | OFPC_FRAG_DROP;
    }

    dp->config.flags = flags;
    dp->config.miss_send_len = msg->config->miss_send_len;

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

/* Handles packet out messages. */
static ofl_err
handle_control_packet_out(struct datapath *dp, struct ofl_msg_packet_out *msg,
                                                const struct sender *sender) {
    struct packet *pkt;
    int error;
    if(sender->remote->role == OFPCR_ROLE_SLAVE){
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_IS_SLAVE);
    }
    error = dp_actions_validate(dp, msg->actions_num, msg->actions);
    if (error) {
        return error;
    }

    if (msg->buffer_id == NO_BUFFER) {
        struct ofpbuf *buf;
        /* If there is no packet in the message, send error message */
        if (!msg->data_length){
             return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_PACKET);
        }
        /* NOTE: the created packet will take the ownership of data in msg. */
        buf = ofpbuf_new(0);
        ofpbuf_use(buf, msg->data, msg->data_length);
        ofpbuf_put_uninit(buf, msg->data_length);
        pkt = packet_create(dp, msg->in_port, buf, true);
    } else {
        /* NOTE: in this case packet should not have data */
        pkt = dp_buffers_retrieve(dp->buffers, msg->buffer_id);
    }

    if (pkt == NULL) {
        /* This might be a wrong req., or a timed out buffer */
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BUFFER_EMPTY);
    }

    dp_execute_action_list(pkt, msg->actions_num, msg->actions, 0xffffffffffffffff);

    packet_destroy(pkt);
    ofl_msg_free_packet_out(msg, false, dp->exp);
    return 0;
}


/* Handles desc stats request messages. */
static ofl_err
handle_control_stats_request_desc(struct datapath *dp,
                                  struct ofl_msg_multipart_request_header *msg,
                                  const struct sender *sender) {
    struct ofl_msg_reply_desc reply =
            {{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_DESC, .flags = 0x0000},
              .mfr_desc   = dp->mfr_desc,
              .hw_desc    = dp->hw_desc,
              .sw_desc    = dp->sw_desc,
              .serial_num = dp->serial_num,
              .dp_desc    = dp->dp_desc};
    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

/* Dispatches statistic request messages to the appropriate handler functions. */
static ofl_err
handle_control_stats_request(struct datapath *dp,
                                  struct ofl_msg_multipart_request_header *msg,
                                                const struct sender *sender) {
    switch (msg->type) {
        case (OFPMP_DESC): {
            return handle_control_stats_request_desc(dp, msg, sender);
        }
        case (OFPMP_FLOW): {
            return pipeline_handle_stats_request_flow(dp->pipeline, (struct ofl_msg_multipart_request_flow *)msg, sender);
        }
        case (OFPMP_AGGREGATE): {
            return pipeline_handle_stats_request_aggregate(dp->pipeline, (struct ofl_msg_multipart_request_flow *)msg, sender);
        }
        case (OFPMP_TABLE): {
            return pipeline_handle_stats_request_table(dp->pipeline, msg, sender);
        }
        case (OFPMP_TABLE_FEATURES):{
            return pipeline_handle_stats_request_table_features_request(dp->pipeline, msg, sender);
        }
        case (OFPMP_PORT_STATS): {
            return dp_ports_handle_stats_request_port(dp, (struct ofl_msg_multipart_request_port *)msg, sender);
        }
        case (OFPMP_QUEUE): {
            return dp_ports_handle_stats_request_queue(dp, (struct ofl_msg_multipart_request_queue *)msg, sender);
        }
        case (OFPMP_GROUP): {
            return group_table_handle_stats_request_group(dp->groups, (struct ofl_msg_multipart_request_group *)msg, sender);
        }
        case (OFPMP_GROUP_DESC): {
            return group_table_handle_stats_request_group_desc(dp->groups, msg, sender);
        }
		case (OFPMP_GROUP_FEATURES):{
            return group_table_handle_stats_request_group_features(dp->groups, msg, sender);
		}
        case (OFPMP_METER):{
        	return meter_table_handle_stats_request_meter(dp->meters,(struct ofl_msg_multipart_meter_request*)msg, sender);
        }
        case (OFPMP_METER_CONFIG):{
            return meter_table_handle_stats_request_meter_conf(dp->meters,(struct ofl_msg_multipart_meter_request*)msg, sender);
        }
        case OFPMP_METER_FEATURES:{
            return meter_table_handle_features_request(dp->meters, msg, sender);
        }
        case OFPMP_PORT_DESC:{
            return dp_ports_handle_port_desc_request(dp, msg, sender);
        }
        case (OFPMP_EXPERIMENTER): {
            return dp_exp_stats(dp, (struct ofl_msg_multipart_request_experimenter *)msg, sender);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART);
        }
    }
}


/* Handles echo reply messages. */
static ofl_err
handle_control_echo_reply(struct datapath *dp UNUSED,
                                struct ofl_msg_echo *msg,
                                  const struct sender *sender UNUSED) {

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

/* Handles echo request messages. */
static ofl_err
handle_control_echo_request(struct datapath *dp,
                                          struct ofl_msg_echo *msg,
                                                const struct sender *sender) {
    struct ofl_msg_echo reply =
            {{.type = OFPT_ECHO_REPLY},
             .data_length = msg->data_length,
             .data        = msg->data};
    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

/* Dispatches control messages to appropriate handler functions. */
ofl_err
handle_control_msg(struct datapath *dp, struct ofl_msg_header *msg,
                   const struct sender *sender) {

    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *msg_str = ofl_msg_to_string(msg, dp->exp);
        VLOG_DBG_RL(LOG_MODULE, &rl, "received control msg: %.400s", msg_str);
        free(msg_str);
    }

    /* NOTE: It is assumed that if a handler returns with error, it did not use
             any part of the control message, thus it can be freed up.
             If no error is returned however, the message must be freed inside
             the handler (because the handler might keep parts of the message) */
    switch (msg->type) {
        case OFPT_HELLO: {
            ofl_msg_free(msg, dp->exp);
            return 0;
        }
        case OFPT_ERROR: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_BARRIER_REQUEST: {
            return handle_control_barrier_request(dp, msg, sender);
        }
        case OFPT_BARRIER_REPLY: {
            ofl_msg_free(msg, dp->exp);
            return 0;
        }
        case OFPT_FEATURES_REQUEST: {
            return handle_control_features_request(dp, msg, sender);
        }
        case OFPT_FEATURES_REPLY: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_GET_CONFIG_REQUEST: {
            return handle_control_get_config_request(dp, msg, sender);
        }
        case OFPT_GET_CONFIG_REPLY: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_SET_CONFIG: {
            return handle_control_set_config(dp, (struct ofl_msg_set_config *)msg, sender);
        }
        case OFPT_PACKET_IN: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_PACKET_OUT: {
            return handle_control_packet_out(dp, (struct ofl_msg_packet_out *)msg, sender);
            break;
        }
        case OFPT_FLOW_REMOVED: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_PORT_STATUS: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_FLOW_MOD: {
            return pipeline_handle_flow_mod(dp->pipeline, (struct ofl_msg_flow_mod *)msg, sender);
        }
        case OFPT_GROUP_MOD: {
            return group_table_handle_group_mod(dp->groups, (struct ofl_msg_group_mod *)msg, sender);
        }
        case OFPT_PORT_MOD: {
            return dp_ports_handle_port_mod(dp, (struct ofl_msg_port_mod *)msg, sender);
        }
        case OFPT_TABLE_MOD: {
            return pipeline_handle_table_mod(dp->pipeline, (struct ofl_msg_table_mod *)msg, sender);
        }
        case OFPT_MULTIPART_REQUEST: {
            return handle_control_stats_request(dp, (struct ofl_msg_multipart_request_header *)msg, sender);
        }
        case OFPT_MULTIPART_REPLY: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_ECHO_REQUEST: {
            return handle_control_echo_request(dp, (struct ofl_msg_echo *)msg, sender);
        }
        case OFPT_ECHO_REPLY: {
            return handle_control_echo_reply(dp, (struct ofl_msg_echo *)msg, sender);
        }
        case OFPT_QUEUE_GET_CONFIG_REQUEST: {
            return dp_ports_handle_queue_get_config_request(dp, (struct ofl_msg_queue_get_config_request *)msg, sender);
        }
        case OFPT_ROLE_REQUEST: {
            return dp_handle_role_request(dp, (struct ofl_msg_role_request*)msg, sender);
        }
        case OFPT_ROLE_REPLY:{
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_QUEUE_GET_CONFIG_REPLY: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_METER_MOD:{
			return meter_table_handle_meter_mod(dp->meters, (struct ofl_msg_meter_mod *)msg, sender);
		}
        case OFPT_EXPERIMENTER: {
            return dp_exp_message(dp, (struct ofl_msg_experimenter *)msg, sender);
        }
        case OFPT_GET_ASYNC_REPLY:{
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
        case OFPT_GET_ASYNC_REQUEST:
        case OFPT_SET_ASYNC:{
            return dp_handle_async_request(dp, (struct ofl_msg_async_config*)msg, sender);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);
        }
    }
}
