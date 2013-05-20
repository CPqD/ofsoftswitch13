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

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "ofl-actions.h"
#include "ofl-messages.h"
#include "ofl-structs.h"
#include "ofl-log.h"
#include "ofl-utils.h"
#include "openflow/openflow.h"

#define UNUSED __attribute__((__unused__))

#define LOG_MODULE ofl_msg_p
OFL_LOG_INIT(LOG_MODULE)



/****************************************************************************
 * Functions for packing ofl structures to ofp wire format.
 ****************************************************************************/

static int
ofl_msg_pack_error(struct ofl_msg_error *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_error_msg *err;

    *buf_len = sizeof(struct ofp_error_msg) + msg->data_length;
    *buf     = (uint8_t *)malloc(*buf_len);

    err = (struct ofp_error_msg *)(*buf);
    err->type = htons(msg->type);
    err->code = htons(msg->code);
    memcpy(err->data, msg->data, msg->data_length);
    return 0;
}

static int
ofl_msg_pack_echo(struct ofl_msg_echo *msg, uint8_t **buf, size_t *buf_len) {
    uint8_t *data;

    *buf_len = sizeof(struct ofp_header) + msg->data_length;
    *buf     = (uint8_t *)malloc(*buf_len);

    if (msg->data_length > 0) {
        data = (*buf) + sizeof(struct ofp_header);
        memcpy(data, msg->data, msg->data_length);
    }
    return 0;
}

static int
ofl_msg_pack_role_request(struct ofl_msg_role_request *msg, uint8_t **buf, size_t *buf_len) {
        struct ofp_role_request *req;

        *buf_len = sizeof(struct ofp_role_request);
        *buf     = (uint8_t *)malloc(*buf_len);

        req = (struct ofp_role_request *)(*buf);
        req->role =  htonl(msg->role);
        memset(req->pad,0,sizeof(req->pad));
        req->generation_id = hton64(msg->generation_id);

        return 0;
}

static int
ofl_msg_pack_features_reply(struct ofl_msg_features_reply *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_switch_features *features;

    *buf_len = sizeof(struct ofp_switch_features);
    *buf     = (uint8_t *)malloc(*buf_len);

    features = (struct ofp_switch_features *)(*buf);
    features->datapath_id  = hton64(msg->datapath_id);
    features->n_buffers    = htonl( msg->n_buffers);
    features->n_tables     =        msg->n_tables;
    features->auxiliary_id = msg->auxiliary_id;
    memset(features->pad, 0x00, 2);
    features->capabilities = htonl( msg->capabilities);
    features->reserved = 0x00000000;

    return 0;
}

static int
ofl_msg_pack_get_config_reply(struct ofl_msg_get_config_reply *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_switch_config *config;

    *buf_len = sizeof(struct ofp_switch_config);
    *buf     = (uint8_t *)malloc(*buf_len);

    config = (struct ofp_switch_config *)(*buf);
    config->flags         = htons(msg->config->flags);
    config->miss_send_len = htons(msg->config->miss_send_len);

    return 0;
}

static int
ofl_msg_pack_set_config(struct ofl_msg_set_config *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_switch_config *config;

    *buf_len = sizeof(struct ofp_switch_config);
    *buf     = (uint8_t *)malloc(*buf_len);

    config = (struct ofp_switch_config *)(*buf);
    config->miss_send_len = htons(msg->config->miss_send_len);
    config->flags = htons(msg->config->flags);

    return 0;
}

static int
ofl_msg_pack_packet_in(struct ofl_msg_packet_in *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_packet_in *packet_in;
    uint8_t *ptr;

    *buf_len = sizeof(struct ofp_packet_in) + ROUND_UP(msg->match->length - 4 ,8) + msg->data_length + 2;
    *buf     = (uint8_t *)malloc(*buf_len);
    packet_in = (struct ofp_packet_in *)(*buf);
    packet_in->buffer_id   = htonl(msg->buffer_id);
    packet_in->total_len   = htons(msg->total_len);
    packet_in->reason      =       msg->reason;
    packet_in->table_id    =       msg->table_id;
    packet_in->cookie      = hton64(msg->cookie);

    ptr = (*buf) + (sizeof(struct ofp_packet_in) - 4);
    ofl_structs_match_pack(msg->match,&(packet_in->match),ptr, NULL);
    ptr = (*buf) + ROUND_UP((sizeof(struct ofp_packet_in)-4) + msg->match->length,8);
    /*padding bytes*/

    memset(ptr,0,2);
    /* Ethernet frame */
    if (msg->data_length > 0) {
        memcpy(ptr + 2 , msg->data, msg->data_length);
    }

    return 0;
}

static int
ofl_msg_pack_flow_removed(struct ofl_msg_flow_removed *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_flow_removed *ofr;

    uint8_t *ptr;
    *buf_len = ROUND_UP((sizeof(struct ofp_flow_removed) -4) + msg->stats->match->length ,8);
    *buf     = (uint8_t *)malloc(*buf_len);

    ofr = (struct ofp_flow_removed *)(*buf);
    ofr->cookie        = hton64(msg->stats->cookie);
    ofr->priority      = htons(msg->stats->priority);
    ofr->reason        =        msg->reason;
    ofr->table_id      =        msg->stats->table_id;
    ofr->duration_sec  = htonl( msg->stats->duration_sec);
    ofr->duration_nsec = htonl( msg->stats->duration_nsec);
    ofr->idle_timeout  = htons( msg->stats->idle_timeout);
    ofr->packet_count  = hton64(msg->stats->packet_count);
    ofr->byte_count    = hton64(msg->stats->byte_count);

    ptr = (*buf) + (sizeof(struct ofp_flow_removed) - 4);

    ofl_structs_match_pack(msg->stats->match, &(ofr->match),ptr, exp);

    return 0;
}

static int
ofl_msg_pack_port_status(struct ofl_msg_port_status *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_port_status *status;

    *buf_len = sizeof(struct ofp_port_status);
    *buf     = (uint8_t *)malloc(*buf_len);

    status = (struct ofp_port_status *)(*buf);
    status->reason = msg->reason;
    memset(status->pad, 0x00, 7);

    ofl_structs_port_pack(msg->desc, &(status->desc));

    return 0;
}

static int
ofl_msg_pack_packet_out(struct ofl_msg_packet_out *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_packet_out *packet_out;
    size_t act_len;
    uint8_t *ptr;
    int i;

    act_len = ofl_actions_ofp_total_len(msg->actions, msg->actions_num, exp);

    *buf_len = sizeof(struct ofp_packet_out) + act_len + msg->data_length;
    *buf     = (uint8_t *)malloc(*buf_len);

    packet_out = (struct ofp_packet_out *)(*buf);
    packet_out->buffer_id   = htonl(msg->buffer_id);
    packet_out->in_port     = htonl(msg->in_port);
    packet_out->actions_len = htons(act_len);
    memset(packet_out->pad, 0x00, 6);

    ptr = (*buf) + sizeof(struct ofp_packet_out);

    for (i=0; i<msg->actions_num; i++) {
        ptr += ofl_actions_pack(msg->actions[i], (struct ofp_action_header *)ptr,*buf, exp);
    }

    if (msg->data_length > 0) {
        memcpy(ptr, msg->data, msg->data_length);
    }

    return 0;
}

static int
ofl_msg_pack_flow_mod(struct ofl_msg_flow_mod *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_flow_mod *flow_mod;
    uint8_t *ptr;

    int i;

    *buf_len = ROUND_UP(sizeof(struct ofp_flow_mod)- 4 + msg->match->length,8) +
                ofl_structs_instructions_ofp_total_len(msg->instructions, msg->instructions_num, exp);

    *buf     = (uint8_t *)malloc(*buf_len);
    flow_mod = (struct ofp_flow_mod *)(*buf);
    flow_mod->cookie       = hton64(msg->cookie);
    flow_mod->cookie_mask  = hton64(msg->cookie_mask);
    flow_mod->table_id     =        msg->table_id;
    flow_mod->command      =        msg->command;
    flow_mod->idle_timeout = htons( msg->idle_timeout);
    flow_mod->hard_timeout = htons( msg->hard_timeout);
    flow_mod->priority     = htons( msg->priority);
    flow_mod->buffer_id    = htonl( msg->buffer_id);
    flow_mod->out_port     = htonl( msg->out_port);
    flow_mod->out_group    = htonl( msg->out_group);
    flow_mod->flags        = htons( msg->flags);
    memset(flow_mod->pad, 0x00, 2);

    ptr  = (*buf) + sizeof(struct ofp_flow_mod)- 4;
    ofl_structs_match_pack(msg->match, &(flow_mod->match), ptr, exp);
    /* We advance counting the padded bytes */
    ptr = (*buf) + ROUND_UP(sizeof(struct ofp_flow_mod)- 4 + msg->match->length,8);
    for (i=0; i<msg->instructions_num; i++) {
        ptr += ofl_structs_instructions_pack(msg->instructions[i], (struct ofp_instruction *)ptr, exp);
    }
    return 0;
}

static int
ofl_msg_pack_group_mod(struct ofl_msg_group_mod *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_group_mod *group_mod;
    uint8_t *ptr;
    int i;

    *buf_len = sizeof(struct ofp_group_mod) + ofl_structs_buckets_ofp_total_len(msg->buckets, msg->buckets_num, exp);;
    *buf     = (uint8_t *)malloc(*buf_len);

    group_mod = (struct ofp_group_mod *)(*buf);
    group_mod->command  = htons(msg->command);
    group_mod->type     =       msg->type;
    group_mod->pad = 0x00;
    group_mod->group_id = htonl(msg->group_id);

    ptr = (*buf) + sizeof(struct ofp_group_mod);

    for (i=0; i<msg->buckets_num; i++) {
        ptr += ofl_structs_bucket_pack(msg->buckets[i], (struct ofp_bucket *)ptr, exp);
    }

    return 0;
}

static int
ofl_msg_pack_port_mod(struct ofl_msg_port_mod *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_port_mod *port_mod;

    *buf_len = sizeof(struct ofp_port_mod);
    *buf     = (uint8_t *)malloc(*buf_len);

    port_mod = (struct ofp_port_mod *)(*buf);
    port_mod->port_no   = htonl(msg->port_no);
    memset(port_mod->pad, 0x00, 4);
    memcpy(&(port_mod->hw_addr), &(msg->hw_addr), OFP_ETH_ALEN);
    memset(port_mod->pad2, 0x00, 2);
    port_mod->config    = htonl(msg->config);
    port_mod->mask      = htonl(msg->mask);
    port_mod->advertise = htonl(msg->advertise);
    memset(port_mod->pad3, 0x00, 4);

    return 0;
}

static int
ofl_msg_pack_table_mod(struct ofl_msg_table_mod *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_table_mod *table_mod;

    *buf_len = sizeof(struct ofp_table_mod);
    *buf     = (uint8_t *)malloc(*buf_len);

    table_mod = (struct ofp_table_mod *)(*buf);
    table_mod->table_id =       msg->table_id;
    memset(table_mod->pad, 0x00, 3);
    table_mod->config   = htonl(msg->config);

    return 0;
}

static int
ofl_msg_pack_meter_mod(struct ofl_msg_meter_mod *msg, uint8_t ** buf, size_t *buf_len){
    struct ofp_meter_mod *meter_mod;
    uint8_t *ptr;
    int i;

    *buf_len =  sizeof(struct ofp_meter_mod) + ofl_structs_meter_bands_ofp_total_len(msg->bands, msg->meter_bands_num);
    *buf = malloc(*buf_len);

    meter_mod = (struct ofp_meter_mod*) (*buf);
    meter_mod->command = htons(msg->command);
    meter_mod->flags = htons(msg->flags);
    meter_mod->meter_id = ntohl(msg->meter_id);

    ptr = (*buf) + sizeof(struct ofp_meter_mod);
    for (i=0; i < msg->meter_bands_num; i++) {
        ptr += ofl_structs_meter_band_pack(msg->bands[i], (struct ofp_meter_band_header *) ptr);
    }
    return 0;
}

static int
ofl_msg_pack_async_config(struct ofl_msg_async_config *msg, uint8_t **buf, size_t *buf_len){
    struct ofp_async_config *ac;
    int i;
    *buf_len = sizeof(struct ofp_async_config);
    *buf = malloc(*buf_len);

    ac = (struct ofp_async_config*)(*buf);
    for(i = 0; i < 2; i++){
        ac->packet_in_mask[i] = msg->config->packet_in_mask[i];
        ac->port_status_mask[i] = msg->config->port_status_mask[i];
        ac->flow_removed_mask[i] =  msg->config->flow_removed_mask[i];
    }
    return 0;
}

static int
ofl_msg_pack_multipart_request_flow(struct ofl_msg_multipart_request_flow *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {

    struct ofp_multipart_request *req;
    struct ofp_flow_stats_request *stats;
    uint8_t *ptr;

    *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_flow_stats_request) + msg->match->length;
    *buf     = (uint8_t *)malloc(*buf_len);

    req = (struct ofp_multipart_request *)(*buf);
    stats = (struct ofp_flow_stats_request *)req->body;
    stats->table_id    =        msg->table_id;
    memset(stats->pad, 0x00, 3);
    stats->out_port    = htonl( msg->out_port);
    stats->out_group   = htonl( msg->out_group);
    memset(stats->pad2, 0x00, 4);
    stats->cookie      = hton64(msg->cookie);
    stats->cookie_mask = hton64(msg->cookie_mask);

    ptr = (*buf) + sizeof(struct ofp_multipart_request) + sizeof(struct ofp_flow_stats_request);
    ofl_structs_match_pack(msg->match, &(stats->match),ptr, exp);

    return 0;
}

static int
ofl_msg_pack_multipart_request_port(struct ofl_msg_multipart_request_port *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_request *req;
    struct ofp_port_stats_request *stats;

    *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_port_stats_request);
    *buf     = (uint8_t *)malloc(*buf_len);

    req = (struct ofp_multipart_request *)(*buf);
    stats = (struct ofp_port_stats_request *)req->body;
    stats->port_no = htonl(msg->port_no);
    memset(stats->pad, 0x00, 4);

    return 0;
}

static int
ofl_msg_pack_multipart_request_queue(struct ofl_msg_multipart_request_queue *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_request *req;
    struct ofp_queue_stats_request *stats;

    *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_queue_stats_request);
    *buf     = (uint8_t *)malloc(*buf_len);

    req = (struct ofp_multipart_request *)(*buf);
    stats = (struct ofp_queue_stats_request *)req->body;
    stats->port_no = htonl(msg->port_no);
    stats->queue_id = htonl(msg->queue_id);

    return 0;
}

static int
ofl_msg_pack_multipart_request_group(struct ofl_msg_multipart_request_group *msg UNUSED, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_request *req;
    struct ofp_group_stats_request *stats;

    *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_group_stats_request);
    *buf     = (uint8_t *)malloc(*buf_len);

    req = (struct ofp_multipart_request *)(*buf);
    stats = (struct ofp_group_stats_request *)req->body;
    stats->group_id = htonl(msg->group_id);
    memset(stats->pad, 0x00, 4);

    return 0;
}

static int
ofl_msg_pack_multipart_request_table_features(struct ofl_msg_multipart_request_table_features *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_multipart_request *req;
    size_t i, features_len;
    uint8_t *data;

    features_len = ofl_structs_table_features_ofp_total_len(msg->table_features, msg->tables_num, exp);
    *buf_len = sizeof(struct ofp_multipart_request) + features_len;
    *buf = (uint8_t*) malloc(*buf_len);

    req = (struct ofp_multipart_request*) (*buf);

    if (features_len){
        data = (uint8_t*) req->body;
        for(i = 0; i < msg->tables_num; i++ ){
            data += ofl_structs_table_features_pack(msg->table_features[i], (struct ofp_table_features*) data, data, exp);
        }
    }
    return 0;
}

static int
ofl_msg_pack_meter_multipart_request(struct ofl_msg_multipart_meter_request *msg, uint8_t **buf, size_t *buf_len){

    struct ofp_multipart_request *req;
    struct ofp_meter_multipart_request *stats;

    *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_meter_multipart_request);
    *buf = (uint8_t*) malloc(*buf_len);

    req = (struct ofp_multipart_request*) (*buf);
    stats = (struct ofp_meter_multipart_request*) req->body;
    stats->meter_id = htonl(msg->meter_id);
    memset(stats->pad, 0x00, 4);

    return 0;
}

static int
ofl_msg_pack_multipart_request_empty(struct ofl_msg_multipart_request_header *msg UNUSED, uint8_t **buf, size_t *buf_len) {

    *buf_len = sizeof(struct ofp_multipart_request);
    *buf     = (uint8_t *)malloc(*buf_len);

    return 0;
}


static int
ofl_msg_pack_multipart_request(struct ofl_msg_multipart_request_header *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_multipart_request *req;
    int error = 0;

    switch (msg->type) {
    case OFPMP_DESC: {
        error = ofl_msg_pack_multipart_request_empty(msg, buf, buf_len);
        break;
    }
    case OFPMP_FLOW:
    case OFPMP_AGGREGATE: {
        error = ofl_msg_pack_multipart_request_flow((struct ofl_msg_multipart_request_flow *)msg, buf, buf_len, exp);
        break;
    }
    case OFPMP_TABLE: {
        error = ofl_msg_pack_multipart_request_empty(msg, buf, buf_len);
        break;
    }
    case OFPMP_PORT_STATS: {
        error = ofl_msg_pack_multipart_request_port((struct ofl_msg_multipart_request_port *)msg, buf, buf_len);
        break;
    }
    case OFPMP_QUEUE: {
        error = ofl_msg_pack_multipart_request_queue((struct ofl_msg_multipart_request_queue *)msg, buf, buf_len);
        break;
    }
    case OFPMP_GROUP: {
        error = ofl_msg_pack_multipart_request_group((struct ofl_msg_multipart_request_group *)msg, buf, buf_len);
        break;
    }
    case OFPMP_GROUP_DESC: {
        error = ofl_msg_pack_multipart_request_empty(msg, buf, buf_len);
        break;
    }
    case OFPMP_GROUP_FEATURES: {
        error = ofl_msg_pack_multipart_request_empty(msg, buf, buf_len);
        break;
    }
   case OFPMP_METER:
   case OFPMP_METER_CONFIG:{
        error = ofl_msg_pack_meter_multipart_request((struct ofl_msg_multipart_meter_request*)msg, buf, buf_len);
        break;
   }
   case OFPMP_METER_FEATURES:{
        error = ofl_msg_pack_multipart_request_empty(msg, buf, buf_len);
        break;
   }
   case OFPMP_TABLE_FEATURES:{
        ofl_msg_pack_multipart_request_table_features((struct ofl_msg_multipart_request_table_features*)msg, buf, buf_len,exp);
        break;
   }
   case OFPMP_PORT_DESC:{
        error = ofl_msg_pack_multipart_request_empty(msg, buf, buf_len);
        break;
   }
    case OFPMP_EXPERIMENTER: {
        if (exp == NULL || exp->stats == NULL || exp->stats->req_pack == NULL) {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack experimenter stat req, but no callback was given.");
            error = -1;
        } else {
            error = exp->stats->req_pack(msg, buf, buf_len);
        }
        break;
    }
    default: {
        OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown experimenter stat req type.");
        error = -1;
    }
    }

    if (error) {
        return error;
    }

    req = (struct ofp_multipart_request *)(*buf);

    req->type  = htons(msg->type);
    req->flags = htons(msg->flags);
    memset(req->pad, 0x00, 4);

    return 0;
}


static int
ofl_msg_pack_multipart_reply_desc(struct ofl_msg_reply_desc *msg UNUSED, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *req;
    struct ofp_desc *stats;

    *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_desc);
    *buf     = (uint8_t *)malloc(*buf_len);

    req = (struct ofp_multipart_reply *)(*buf);
    stats = (struct ofp_desc *)req->body;
    memset(stats->mfr_desc, 0, DESC_STR_LEN);
    memset(stats->hw_desc, 0, DESC_STR_LEN);
    memset(stats->sw_desc, 0, DESC_STR_LEN);
    memset(stats->serial_num, 0, SERIAL_NUM_LEN);
    memset(stats->dp_desc, 0, DESC_STR_LEN);
    memcpy(stats->mfr_desc,   msg->mfr_desc, DESC_STR_LEN);
    memcpy(stats->hw_desc,    msg->hw_desc, DESC_STR_LEN);
    memcpy(stats->sw_desc,    msg->sw_desc, DESC_STR_LEN);
    memcpy(stats->serial_num, msg->serial_num, SERIAL_NUM_LEN);
    memcpy(stats->dp_desc,    msg->dp_desc, DESC_STR_LEN);

    return 0;
}

static int
ofl_msg_pack_multipart_reply_flow(struct ofl_msg_multipart_reply_flow *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_multipart_reply *resp;
    size_t i;
    uint8_t * data;

    *buf_len = sizeof(struct ofp_multipart_reply) + ofl_structs_flow_stats_ofp_total_len(msg->stats, msg->stats_num, exp);
    *buf     = (uint8_t *)malloc(*buf_len);
    resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t*) resp->body;
    for (i=0; i<msg->stats_num; i++) {
        data += ofl_structs_flow_stats_pack(msg->stats[i], data, exp);
    }
    return 0;
}

static int
ofl_msg_pack_multipart_reply_aggregate(struct ofl_msg_multipart_reply_aggregate *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *resp;
    struct ofp_aggregate_stats_reply *stats;

    *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_aggregate_stats_reply);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    stats = (struct ofp_aggregate_stats_reply *)resp->body;
    stats->packet_count = hton64(msg->packet_count);
    stats->byte_count   = hton64(msg->byte_count);
    stats->flow_count   = htonl( msg->flow_count);
    memset(stats->pad, 0x00, 4);

    return 0;
}

static int
ofl_msg_pack_multipart_reply_table(struct ofl_msg_multipart_reply_table *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *resp;
    size_t i;
    uint8_t *data;

    *buf_len = sizeof(struct ofp_multipart_reply) + msg->stats_num * sizeof(struct ofp_table_stats);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t *)resp->body;

    for (i=0; i<msg->stats_num; i++) {
        data += ofl_structs_table_stats_pack(msg->stats[i], (struct ofp_table_stats *)data);
    }
    return 0;
}

static int
ofl_msg_pack_multipart_reply_port(struct ofl_msg_multipart_reply_port *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *resp;
    size_t i;
    uint8_t *data;

    *buf_len = sizeof(struct ofp_multipart_reply) + msg->stats_num * sizeof(struct ofp_port_stats);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t *)resp->body;

    for (i=0; i<msg->stats_num; i++) {
        data += ofl_structs_port_stats_pack(msg->stats[i], (struct ofp_port_stats *)data);
    }
    return 0;
}


static int
ofl_msg_pack_multipart_reply_queue(struct ofl_msg_multipart_reply_queue *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *resp;
    size_t i;
    uint8_t *data;

    *buf_len = sizeof(struct ofp_multipart_reply) + msg->stats_num * sizeof(struct ofp_queue_stats);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t *)resp->body;

    for (i=0; i<msg->stats_num; i++) {
        data += ofl_structs_queue_stats_pack(msg->stats[i], (struct ofp_queue_stats *)data);
    }
    return 0;
}

static int
ofl_msg_pack_multipart_reply_group(struct ofl_msg_multipart_reply_group *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *resp;
    size_t i;
    uint8_t *data;

    *buf_len = sizeof(struct ofp_multipart_reply) + ofl_structs_group_stats_ofp_total_len(msg->stats, msg->stats_num);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t *)resp->body;

    for (i=0; i<msg->stats_num; i++) {
        data += ofl_structs_group_stats_pack(msg->stats[i], (struct ofp_group_stats *)data);
    }
    return 0;
}

static int
ofl_msg_pack_multipart_reply_group_desc(struct ofl_msg_multipart_reply_group_desc *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_multipart_reply *resp;
    uint8_t *data;
    size_t i;

    *buf_len = sizeof(struct ofp_multipart_reply) + ofl_structs_group_desc_stats_ofp_total_len(msg->stats, msg->stats_num, exp);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t *)resp->body;

    for (i=0; i<msg->stats_num; i++) {
        data += ofl_structs_group_desc_stats_pack(msg->stats[i], (struct ofp_group_desc_stats *)data, exp);
    }

    return 0;
}

static int
ofl_msg_pack_multipart_reply_group_features(struct ofl_msg_multipart_reply_group_features *msg, uint8_t **buf, size_t *buf_len) {
   struct ofp_multipart_reply *resp;
    struct ofp_group_features_stats *stats;
    int i;
    *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_group_features_stats);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    stats = (struct ofp_group_features_stats *)resp->body;
    stats->types = htonl(msg->types);
    stats->capabilities = htonl(msg->capabilities);
    for(i = 0; i < 4; i++){
        stats->max_groups[i] = htonl(msg->max_groups[i]);
        stats->actions[i] = htonl(msg->actions[i]);
    }

    return 0;
}

static int
ofl_msg_pack_multipart_reply_table_features(struct ofl_msg_multipart_reply_table_features *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_multipart_reply *resp;
    size_t i, features_len;
    uint8_t *data;

    features_len = ofl_structs_table_features_ofp_total_len(msg->table_features, msg->tables_num, exp);
    *buf_len = sizeof(struct ofp_multipart_reply) + features_len;
    *buf = (uint8_t*) malloc(*buf_len);

    resp = (struct ofp_multipart_reply*) (*buf);
    if (features_len){
        data = (uint8_t*) resp->body;
        for(i = 0; i < msg->tables_num; i++ ){
           data += ofl_structs_table_features_pack(msg->table_features[i], (struct ofp_table_features*) data, data, exp);
        }
    }
    return 0;
}

static int
ofl_msg_pack_multipart_reply_meter_stats(struct ofl_msg_multipart_reply_meter *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *resp;
    size_t i;
    uint8_t *data;

    *buf_len = sizeof(struct ofp_multipart_reply) + ofl_structs_meter_stats_ofp_total_len(msg->stats, msg->stats_num);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t *)resp->body;

    for (i=0; i<msg->stats_num; i++) {
        data += ofl_structs_meter_stats_pack(msg->stats[i], (struct ofp_meter_stats *)data);
    }
    return 0;
}

static int
ofl_msg_pack_multipart_reply_meter_conf(struct ofl_msg_multipart_reply_meter_conf *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *resp;
    size_t i;
    uint8_t *data;

    *buf_len = sizeof(struct ofp_multipart_reply) + ofl_structs_meter_conf_ofp_total_len(msg->stats, msg->stats_num);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t *)resp->body;

    for (i=0; i<msg->stats_num; i++) {
        data += ofl_structs_meter_conf_pack(msg->stats[i], (struct ofp_meter_config *)data, data);
    }

    return 0;
}


static int
ofl_msg_pack_multipart_reply_port_status_desc(struct ofl_msg_multipart_reply_port_desc *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply * resp;
	uint8_t *data;
	size_t i;
    *buf_len = sizeof(struct ofp_multipart_reply) + msg->stats_num * sizeof(struct ofp_port);
    *buf     = (uint8_t *)malloc(*buf_len);

	resp = (struct ofp_multipart_reply *)(*buf);
    data = (uint8_t *)resp->body;

    for(i = 0; i < msg->stats_num; i++){
		data += ofl_structs_port_pack(msg->stats[i], (struct ofp_port *)data);
	}

    return 0;
}

static int
ofl_msg_pack_multipart_reply_meter_features(struct ofl_msg_multipart_reply_meter_features *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_multipart_reply *resp;
    struct ofp_meter_features *feat;

    *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_meter_features);
    *buf     = (uint8_t *)malloc(*buf_len);
    resp = (struct ofp_multipart_reply *)(*buf);
    feat = (struct ofp_meter_features *)resp->body;
    feat->max_meter = htonl(msg->features->max_meter);
    feat->band_types = htonl(msg->features->band_types);
    feat->capabilities = htonl(msg->features->capabilities);
    feat->max_bands = msg->features->max_bands;
    feat->max_color = msg->features->max_color;
    memset(feat->pad, 0x0, 2);
    return 0;
}


static int
ofl_msg_pack_multipart_reply(struct ofl_msg_multipart_reply_header *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_multipart_reply *resp;
    int error;

    switch (msg->type) {
        case OFPMP_DESC: {
            error = ofl_msg_pack_multipart_reply_desc((struct ofl_msg_reply_desc *)msg, buf, buf_len);
            break;
        }
        case OFPMP_FLOW: {
            error = ofl_msg_pack_multipart_reply_flow((struct ofl_msg_multipart_reply_flow *)msg, buf, buf_len, exp);
            break;
        }
        case OFPMP_AGGREGATE: {
            error = ofl_msg_pack_multipart_reply_aggregate((struct ofl_msg_multipart_reply_aggregate *)msg, buf, buf_len);
            break;
        }
        case OFPMP_TABLE: {
            error = ofl_msg_pack_multipart_reply_table((struct ofl_msg_multipart_reply_table *)msg, buf, buf_len);
            break;
        }
        case OFPMP_TABLE_FEATURES: {
            error = ofl_msg_pack_multipart_reply_table_features((struct ofl_msg_multipart_reply_table_features*)msg, buf, buf_len, exp);
            break;
        }
        case OFPMP_PORT_STATS: {
            error = ofl_msg_pack_multipart_reply_port((struct ofl_msg_multipart_reply_port *)msg, buf, buf_len);
            break;
        }
        case OFPMP_QUEUE: {
            error = ofl_msg_pack_multipart_reply_queue((struct ofl_msg_multipart_reply_queue *)msg, buf, buf_len);
            break;
        }
        case OFPMP_GROUP: {
            error = ofl_msg_pack_multipart_reply_group((struct ofl_msg_multipart_reply_group *)msg, buf, buf_len);
            break;
        }
        case OFPMP_GROUP_DESC: {
            error = ofl_msg_pack_multipart_reply_group_desc((struct ofl_msg_multipart_reply_group_desc *)msg, buf, buf_len, exp);
            break;
        }
        case OFPMP_GROUP_FEATURES:{
            error = ofl_msg_pack_multipart_reply_group_features((struct ofl_msg_multipart_reply_group_features *) msg, buf, buf_len);
            break;
        }
        case OFPMP_METER:{
            error = ofl_msg_pack_multipart_reply_meter_stats((struct ofl_msg_multipart_reply_meter*)msg, buf, buf_len);
            break;
        }
        case OFPMP_METER_CONFIG:{
            error = ofl_msg_pack_multipart_reply_meter_conf((struct ofl_msg_multipart_reply_meter_conf*)msg, buf, buf_len);
            break;
        }
        case OFPMP_METER_FEATURES:{
            error =  ofl_msg_pack_multipart_reply_meter_features((struct ofl_msg_multipart_reply_meter_features*)msg, buf, buf_len);
            break;
        }
		case OFPMP_PORT_DESC:{
			error = ofl_msg_pack_multipart_reply_port_status_desc((struct ofl_msg_multipart_reply_port_desc*)msg, buf, buf_len);
			break;
		}
        case OFPMP_EXPERIMENTER: {
            if (exp == NULL || exp->stats == NULL || exp->stats->reply_pack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to pack experimenter stat resp, but no callback was given.");
                error = -1;
            } else {
                error = exp->stats->reply_pack(msg, buf, buf_len);
            }
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown stat resp type.");
            error = -1;
        }
    }

    if (error) {
        return error;
    }
    resp = (struct ofp_multipart_reply *)(*buf);
    resp->type  = htons(msg->type);
    resp->flags = htons(msg->flags);
    memset(resp->pad, 0x00, 4);

    return 0;
}

static int
ofl_msg_pack_queue_get_config_request(struct ofl_msg_queue_get_config_request *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_queue_get_config_request *req;

    *buf_len = sizeof(struct ofp_queue_get_config_request);
    *buf     = (uint8_t *)malloc(*buf_len);

    req = (struct ofp_queue_get_config_request *)(*buf);
    req->port = htonl(msg->port);
    memset(req->pad, 0x00, 4);

    return 0;
}

static int
ofl_msg_pack_queue_get_config_reply(struct ofl_msg_queue_get_config_reply *msg, uint8_t **buf, size_t *buf_len) {
    struct ofp_queue_get_config_reply *resp;
    uint8_t *data;
    size_t i;

    *buf_len = sizeof(struct ofp_queue_get_config_reply) + ofl_structs_packet_queue_ofp_total_len(msg->queues, msg->queues_num);
    *buf     = (uint8_t *)malloc(*buf_len);

    resp = (struct ofp_queue_get_config_reply *)(*buf);
    resp->port = htonl(msg->port);
    memset(resp->pad, 0x00, 4);

    data = (uint8_t *)resp->queues;

    for (i=0; i<msg->queues_num; i++) {
        data += ofl_structs_packet_queue_pack(msg->queues[i], (struct ofp_packet_queue *)data);
    }

    return 0;
}

static int
ofl_msg_pack_empty(struct ofl_msg_header *msg UNUSED, uint8_t **buf, size_t *buf_len) {

    *buf_len = sizeof(struct ofp_header);
    *buf     = (uint8_t *)malloc(*buf_len);
    return 0;
}


int
ofl_msg_pack(struct ofl_msg_header *msg, uint32_t xid, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) {
    struct ofp_header *oh;
    int error = 0;
    switch (msg->type) {

        case OFPT_HELLO: {
            error = ofl_msg_pack_empty(msg, buf, buf_len);
            break;
        }
        case OFPT_ERROR: {
            error = ofl_msg_pack_error((struct ofl_msg_error *)msg, buf, buf_len);
            break;
        }
        case OFPT_ECHO_REQUEST:
        case OFPT_ECHO_REPLY: {
            error = ofl_msg_pack_echo((struct ofl_msg_echo *)msg, buf, buf_len);
            break;
        }
        case OFPT_EXPERIMENTER: {
            if (exp == NULL || exp->msg == NULL || exp->msg->pack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to pack experimenter msg, but no callback was given.");
                error = -1;
            } else {
                error = exp->msg->pack((struct ofl_msg_experimenter *)msg, buf, buf_len);
            }
            break;
        }
        /* Switch configuration messages. */
        case OFPT_FEATURES_REQUEST: {
            error = ofl_msg_pack_empty(msg, buf, buf_len);
            break;
        }
        case OFPT_FEATURES_REPLY: {
            error = ofl_msg_pack_features_reply((struct ofl_msg_features_reply *)msg, buf, buf_len);
            break;
        }
        case OFPT_GET_CONFIG_REQUEST: {
            error = ofl_msg_pack_empty(msg, buf, buf_len);
            break;
        }
        case OFPT_GET_CONFIG_REPLY: {
            error = ofl_msg_pack_get_config_reply((struct ofl_msg_get_config_reply *)msg, buf, buf_len);
            break;
        }
        case OFPT_SET_CONFIG: {
            error = ofl_msg_pack_set_config((struct ofl_msg_set_config *)msg, buf, buf_len);
            break;
        }

        /* Asynchronous messages. */
        case OFPT_PACKET_IN: {
            error = ofl_msg_pack_packet_in((struct ofl_msg_packet_in *)msg, buf, buf_len);
            break;
        }
        case OFPT_FLOW_REMOVED: {
            error = ofl_msg_pack_flow_removed((struct ofl_msg_flow_removed *)msg, buf, buf_len, exp);
            break;
        }
        case OFPT_PORT_STATUS: {
            error = ofl_msg_pack_port_status((struct ofl_msg_port_status *)msg, buf, buf_len);
            break;
        }
        /* Controller command messages. */
        case OFPT_GET_ASYNC_REQUEST:{
            error = ofl_msg_pack_empty(msg, buf, buf_len);
            break;
        }
        case OFPT_GET_ASYNC_REPLY:
        case OFPT_SET_ASYNC:{
            error = ofl_msg_pack_async_config((struct ofl_msg_async_config *)msg, buf, buf_len);
            break;
        }
        case OFPT_PACKET_OUT: {
            error = ofl_msg_pack_packet_out((struct ofl_msg_packet_out *)msg, buf, buf_len, exp);
            break;
        }
        case OFPT_FLOW_MOD: {
            error = ofl_msg_pack_flow_mod((struct ofl_msg_flow_mod *)msg, buf, buf_len, exp);
            break;
        }
        case OFPT_GROUP_MOD: {
            error = ofl_msg_pack_group_mod((struct ofl_msg_group_mod *)msg, buf, buf_len, exp);
            break;
        }
        case OFPT_PORT_MOD: {
            error = ofl_msg_pack_port_mod((struct ofl_msg_port_mod *)msg, buf, buf_len);
            break;
        }
        case OFPT_TABLE_MOD: {
            error = ofl_msg_pack_table_mod((struct ofl_msg_table_mod *)msg, buf, buf_len);
            break;
        }
        case OFPT_METER_MOD:{
            error =  ofl_msg_pack_meter_mod((struct ofl_msg_meter_mod *)msg, buf, buf_len);
			break;
		}

        /* Statistics messages. */
        case OFPT_MULTIPART_REQUEST: {
            error = ofl_msg_pack_multipart_request((struct ofl_msg_multipart_request_header *)msg, buf, buf_len, exp);
            break;
        }
        case OFPT_MULTIPART_REPLY: {
            error = ofl_msg_pack_multipart_reply((struct ofl_msg_multipart_reply_header *)msg, buf, buf_len, exp);
            break;
        }

        /* Barrier messages. */
        case OFPT_BARRIER_REQUEST: {
            error = ofl_msg_pack_empty(msg, buf, buf_len);
            break;
        }
        case OFPT_BARRIER_REPLY: {
            error = ofl_msg_pack_empty(msg, buf, buf_len);
            break;
        }

        /* Queue Configuration messages. */
        case OFPT_QUEUE_GET_CONFIG_REQUEST: {
            error = ofl_msg_pack_queue_get_config_request((struct ofl_msg_queue_get_config_request *)msg, buf, buf_len);
            break;
        }
        case OFPT_QUEUE_GET_CONFIG_REPLY: {
            error = ofl_msg_pack_queue_get_config_reply((struct ofl_msg_queue_get_config_reply *)msg, buf, buf_len);
            break;
        }
        case OFPT_ROLE_REQUEST:
        case OFPT_ROLE_REPLY:
            error = ofl_msg_pack_role_request((struct ofl_msg_role_request*)msg, buf, buf_len);
            break;
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown message type.");
            error = -1;
        }
    }

    if (error) {
        return error;
        // TODO Zoltan: free buffer?
    }

    oh = (struct ofp_header *)(*buf);
    oh->version =        OFP_VERSION;
    oh->type    =        msg->type;
    oh->length  = htons(*buf_len);
    oh->xid     = htonl(xid);

    return 0;
}
