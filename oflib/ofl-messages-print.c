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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

#include "ofl.h"
#include "ofl-actions.h"
#include "ofl-messages.h"
#include "ofl-structs.h"
#include "ofl-print.h"
#include "ofl-log.h"
#include "../include/openflow/openflow.h"



#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]


#define LOG_MODULE ofl_msg_d
OFL_LOG_INIT(LOG_MODULE)



static void
ofl_msg_print_error(struct ofl_msg_error const *msg, FILE *stream, struct ofl_exp const *exp)
{
    // int error = 0;
    switch (msg->type) {
        case (OFPET_EXPERIMENTER): {
            struct ofl_msg_exp_error *exp_err = (struct ofl_msg_exp_error *) msg;
            if (exp == NULL || exp->err == NULL || exp->err->to_string == NULL) {
                fprintf(stream, "{id=\"0x%"PRIx32"\"}", exp_err->experimenter);
            } else {
                char *c = exp->err->to_string(exp_err);
                fprintf(stream, "%s", c);
                free(c);
            }
            return;
         }
        default:{
    fprintf(stream, "{type=\"");
    ofl_error_type_print(stream, msg->type);
    fprintf(stream, "\", code=\"");
    ofl_error_code_print(stream, msg->type, msg->code);
    fprintf(stream, "\", dlen=\"%zu\"}", msg->data_length);
}
    }
}

static void
ofl_msg_print_echo(struct ofl_msg_echo const *msg, FILE *stream)
{
    fprintf(stream, "{dlen=\"%zu\"}", msg->data_length);
}

static void
ofl_msg_print_experimenter(struct ofl_msg_experimenter const *msg, FILE *stream)
{
    fprintf(stream, "{id=\"0x%"PRIx32"\"}", msg->experimenter_id);
}

static void
ofl_msg_print_features_reply(struct ofl_msg_features_reply const *msg, FILE *stream)
{

    fprintf(stream, "{dpid=\"0x%016"PRIx64"\", buffs=\"%u\", tabs=\"%u\", "
                          "aux_id=\"%u\", caps=\"0x%"PRIx32"\"",
                  msg->datapath_id, msg->n_buffers, msg->n_tables,
                  msg->auxiliary_id, msg->capabilities);

    fprintf(stream, "]}");
}

static void
ofl_msg_print_get_config_reply(struct ofl_msg_get_config_reply const *msg, FILE *stream)
{
    fprintf(stream, "{conf=");
    ofl_structs_config_print(stream, msg->config);
    fprintf(stream, "}");
}


static void
ofl_msg_print_set_config(struct ofl_msg_set_config const *msg, FILE *stream)
{
    fprintf(stream, "{conf=");
    ofl_structs_config_print(stream, msg->config);
    fprintf(stream, "}");
}

static void
ofl_msg_print_packet_in(struct ofl_msg_packet_in const *msg, FILE *stream)
{
    fprintf(stream, "{buffer=\"");
    ofl_buffer_print(stream, msg->buffer_id);
    fprintf(stream, "\", tlen=\"%u\", reas=\"", msg->total_len);
    ofl_packet_in_reason_print(stream, msg->reason);
    fprintf(stream, "\", table=\"");
    ofl_table_print(stream, msg->table_id);
    fprintf(stream, "\", dlen=\"%zu\"}", msg->data_length);
}


static void
ofl_msg_print_flow_removed(struct ofl_msg_flow_removed const *msg, FILE *stream, struct ofl_exp const *exp)
{
    fprintf(stream, "{reas=\"");
    ofl_flow_removed_reason_print(stream, msg->reason);
    fprintf(stream, "\", stats=");
    ofl_structs_flow_stats_print(stream, msg->stats, exp);
    fprintf(stream, "}");
}

static void
ofl_msg_print_port_status(struct ofl_msg_port_status const *msg, FILE *stream)
{

    fprintf(stream, "{reas=");
    ofl_port_status_reason_print(stream, msg->reason);
    fprintf(stream, ", desc=");
    ofl_structs_port_print(stream, msg->desc);
    fprintf(stream, "}");
}

static void
ofl_msg_print_packet_out(struct ofl_msg_packet_out const *msg, FILE *stream, struct ofl_exp const *exp)
{
    size_t i;
    fprintf(stream, "{buffer=\"");
    ofl_buffer_print(stream, msg->buffer_id);
    fprintf(stream, "\", port=\"");
    ofl_port_print(stream, msg->in_port);
    fprintf(stream, "\", actions=[");

    for (i=0; i<msg->actions_num; i++) {
        ofl_action_print(stream, msg->actions[i], exp);
        if (i < msg->actions_num - 1) { fprintf(stream, ", "); }
    }

    fprintf(stream, "]}");
}

static void
ofl_msg_print_flow_mod(struct ofl_msg_flow_mod const *msg, FILE *stream, struct ofl_exp const *exp)
{
    size_t i;

    fprintf(stream, "{table=\"");
    ofl_table_print(stream, msg->table_id);
    fprintf(stream, "\", cmd=\"");
    ofl_flow_mod_command_print(stream, msg->command);
    fprintf(stream, "\", cookie=\"0x%"PRIx64"\", mask=\"0x%"PRIx64"\", "
                          "idle=\"%u\", hard=\"%u\", prio=\"%u\", buf=\"",
                  msg->cookie, msg->cookie_mask,
                  msg->idle_timeout, msg->hard_timeout, msg->priority);
    ofl_buffer_print(stream, msg->buffer_id);
    fprintf(stream, "\", port=\"");
    ofl_port_print(stream, msg->out_port);
    fprintf(stream, "\", group=\"");
    ofl_group_print(stream, msg->out_group);
    fprintf(stream, "\", flags=\"0x%"PRIx16"\", match=",msg->flags);
    ofl_structs_match_print(stream, msg->match, exp);
    fprintf(stream, ", insts=[");
    for(i=0; i<msg->instructions_num; i++) {
        ofl_structs_instruction_print(stream, msg->instructions[i], exp);
        if (i < msg->instructions_num - 1) { fprintf(stream, ", "); }
    }
    fprintf(stream, "]}");
}

static void
ofl_msg_print_group_mod(struct ofl_msg_group_mod const *msg, FILE *stream, struct ofl_exp const *exp)
{
    size_t i;

    fprintf(stream,"{group=\"");
    ofl_group_print(stream, msg->group_id);
    fprintf(stream,"\", cmd=\"");
    ofl_group_mod_command_print(stream, msg->command);
    fprintf(stream, "\", type=\"");
    ofl_group_type_print(stream, msg->type);
    fprintf(stream,"\", buckets=[");

    for (i=0; i<msg->buckets_num; i++) {
        ofl_structs_bucket_print(stream, msg->buckets[i], exp);

        if (i < msg->buckets_num - 1) { fprintf(stream, ", "); }
    }

    fprintf(stream, "]}");
}

static void
ofl_msg_print_meter_mod(struct ofl_msg_meter_mod const *msg, FILE *stream)
{
    size_t i;

    fprintf(stream,"{cmd=\"");
    ofl_meter_mod_command_print(stream, msg->command);
    fprintf(stream, "\", flags=\"0x%"PRIx16"\"",msg->flags);
    fprintf(stream, "\", meter_id=\"%"PRIx32"\"",msg->meter_id);
    fprintf(stream,"\", bands=[");

    for (i=0; i<msg->meter_bands_num; i++) {
        ofl_structs_meter_band_print(stream, msg->bands[i]);

        if (i < msg->meter_bands_num - 1) { fprintf(stream, ", "); }
    }

    fprintf(stream, "]}");
}

static void
ofl_msg_print_meter_stats_request(struct ofl_msg_multipart_meter_request const *msg, FILE *stream)
{
    fprintf(stream, "{meter_id= %x", msg->meter_id);
    fprintf(stream, "\"");
}

static void
ofl_msg_print_port_mod(struct ofl_msg_port_mod const *msg, FILE *stream)
{

    fprintf(stream, "{port=\"");
    ofl_port_print(stream, msg->port_no);
    fprintf(stream, "\", hwaddr=\""ETH_ADDR_FMT"\", config=\"0x%08"PRIx32"\", "
                          "mask=\"0x%"PRIx32"\", adv=\"0x%"PRIx32"\"}",
                  ETH_ADDR_ARGS(msg->hw_addr), msg->config, msg->mask, msg->advertise);
}

static void
ofl_msg_print_table_mod(struct ofl_msg_table_mod const *msg, FILE *stream)
{
    fprintf(stream, "{id=\"");
    ofl_table_print(stream, msg->table_id);
    fprintf(stream, "\", config=\"0x%08"PRIx32"\"}", msg->config);
}

static void
ofl_msg_print_stats_request_flow(struct ofl_msg_multipart_request_flow const *msg, FILE *stream, struct ofl_exp const *exp)
{
    fprintf(stream, ", table=\"");
    ofl_table_print(stream, msg->table_id);
    fprintf(stream, "\", oport=\"");
    ofl_port_print(stream, msg->out_port);
    fprintf(stream, "\", ogrp=\"");
    ofl_group_print(stream, msg->out_group);
    fprintf(stream, "\", cookie=0x%"PRIx64"\", mask=0x%"PRIx64"\", match=",
                  msg->cookie, msg->cookie_mask);
    ofl_structs_match_print(stream, msg->match, exp);
}

static void
ofl_msg_print_stats_request_port(struct ofl_msg_multipart_request_port const *msg, FILE *stream)
{
    fprintf(stream, ", port=\"");
    ofl_port_print(stream, msg->port_no);
    fprintf(stream, "\"");
}

static void
ofl_msg_print_stats_request_queue(struct ofl_msg_multipart_request_queue const *msg, FILE *stream)
{
    fprintf(stream, ", port=\"");
    ofl_port_print(stream, msg->port_no);
    fprintf(stream, "\", q=\"");
    ofl_queue_print(stream, msg->queue_id);
    fprintf(stream, "\"");
}

static void
ofl_msg_print_stats_request_group(struct ofl_msg_multipart_request_group const *msg, FILE *stream)
{
    fprintf(stream, ", group=\"");
    ofl_group_print(stream, msg->group_id);
    fprintf(stream, "\"");
}

static void
ofl_msg_print_table_features_request(struct ofl_msg_multipart_request_table_features const *msg, FILE *stream)
{

    size_t i;
    if (msg->table_features == NULL){
        return;
    }
    else {
        fprintf(stream, ", table_features=\"");
        for(i = 0; i < msg->tables_num; i++)
            ofl_structs_table_features_print(stream, msg->table_features[i]);
        fprintf(stream, "\"");
    }
}

static void
ofl_msg_print_stats_request_experimenter(struct ofl_msg_multipart_request_experimenter const *msg, FILE *stream)
{
    fprintf(stream, ", exp_id=\"");
    ofl_group_print(stream, msg->experimenter_id);
    fprintf(stream, "\"");
}

static void
ofl_msg_print_multipart_request(struct ofl_msg_multipart_request_header const *msg, FILE *stream, struct ofl_exp const *exp)
{
    if (msg->type == OFPMP_EXPERIMENTER) {
        if (exp != NULL && exp->stats != NULL && exp->stats->req_to_string != NULL) {
            char *c = exp->stats->req_to_string(msg, exp);
            fputs(c, stream);
            free(c);
            fprintf(stream, "}");
            return;
        } else {
            OFL_LOG_WARN(LOG_MODULE, "Trying to print EXPERIMENTER stats request, but no callback was given.");
        }
    }

    fprintf(stream, "{type=\"");
    ofl_stats_type_print(stream, msg->type);
    fprintf(stream, "\", flags=\"0x%"PRIx32"\"", msg->flags);

    switch (msg->type) {
        case OFPMP_DESC: {
            break;
        }
        case OFPMP_FLOW:
        case OFPMP_AGGREGATE: {
            ofl_msg_print_stats_request_flow((struct ofl_msg_multipart_request_flow const *)msg, stream, exp);
            break;
        }
        case OFPMP_TABLE: {
            break;
        }
        case OFPMP_TABLE_FEATURES: {
            ofl_msg_print_table_features_request((struct ofl_msg_multipart_request_table_features const *)msg, stream);
            break;
        }
        case OFPMP_PORT_STATS: {
            ofl_msg_print_stats_request_port((struct ofl_msg_multipart_request_port const *)msg, stream);
            break;
        }
        case OFPMP_QUEUE: {
            ofl_msg_print_stats_request_queue((struct ofl_msg_multipart_request_queue const *)msg, stream);
            break;
        }
        case OFPMP_GROUP: {
            ofl_msg_print_stats_request_group((struct ofl_msg_multipart_request_group const *)msg, stream);
            break;
        }
        case OFPMP_GROUP_DESC: {
            break;
        }
        case OFPMP_GROUP_FEATURES:{
            break;
        }
        case OFPMP_METER:
        case OFPMP_METER_CONFIG:{
            ofl_msg_print_meter_stats_request((struct ofl_msg_multipart_meter_request const*)msg, stream);
            break;
        }
        case OFPMP_METER_FEATURES:{
            break;
        }
        case OFPMP_PORT_DESC:{
            break;
        }
        case OFPMP_EXPERIMENTER: {
            ofl_msg_print_stats_request_experimenter((struct ofl_msg_multipart_request_experimenter const *)msg, stream);
            break;
        }
    }
    fprintf(stream, "}");
}

static void
ofl_msg_print_stats_reply_desc(struct ofl_msg_reply_desc const *msg, FILE *stream)
{
    fprintf(stream, ", mfr=\"%s\", hw=\"%s\", sw=\"%s\", sn=\"%s\", dp=\"%s\"",
                  msg->mfr_desc, msg->hw_desc, msg->sw_desc, msg->serial_num, msg->dp_desc);
}

static void
ofl_msg_print_stats_reply_flow(struct ofl_msg_multipart_reply_flow const *msg, FILE *stream, struct ofl_exp const *exp)
{
    size_t i;
    size_t last_table_id = -1;

    fprintf(stream, ", stats=[");
    
    for (i=0; i<msg->stats_num; i++) {

        if(last_table_id != msg->stats[i]->table_id && ofl_colored_output())
            fprintf(stream, "\n\n\x1B[33mTABLE = %d\x1B[0m\n\n",msg->stats[i]->table_id);
        last_table_id = msg->stats[i]->table_id;
        ofl_structs_flow_stats_print(stream, msg->stats[i], exp);
        if (i < msg->stats_num - 1) { 
            if(ofl_colored_output())
                fprintf(stream, ",\n\n");
            else
                fprintf(stream, ",\n"); };
    }

    fprintf(stream, "]");
}

static void
ofl_msg_print_stats_reply_aggregate(struct ofl_msg_multipart_reply_aggregate const *msg, FILE *stream)
{
    fprintf(stream, ", pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\", flow_cnt=\"%u\"",
                  msg->packet_count, msg->byte_count, msg->flow_count);
}

static void
ofl_msg_print_stats_reply_table(struct ofl_msg_multipart_reply_table const *msg, FILE *stream)
{
    size_t i;

    fprintf(stream, ", stats=[");

    for (i=0; i<msg->stats_num; i++) {
        ofl_structs_table_stats_print(stream, msg->stats[i]);
        if (i < msg->stats_num - 1) { fprintf(stream, ",\n"); };
    }

    fprintf(stream, "]");
}

static void
ofl_msg_print_stats_reply_port(struct ofl_msg_multipart_reply_port const *msg, FILE *stream)
{
    size_t i;

    fprintf(stream, ", stats=[");

    for (i=0; i<msg->stats_num; i++) {
        ofl_structs_port_stats_print(stream, msg->stats[i]);
        if (i < msg->stats_num - 1)
		{ fprintf(stream, ",\n"); };
    }

    fprintf(stream, "]");
}

static void
ofl_msg_print_stats_reply_queue(struct ofl_msg_multipart_reply_queue const *msg, FILE *stream)
{
    size_t i;

    fprintf(stream, ", stats=[");

    for (i=0; i<msg->stats_num; i++) {
        ofl_structs_queue_stats_print(stream, msg->stats[i]);
        if (i < msg->stats_num - 1) {
            if(ofl_colored_output())
                fprintf(stream, ",\n\n");
            else
                fprintf(stream, ",\n"); };
    }
    fprintf(stream, "]");
}

static void
ofl_msg_print_stats_reply_group(struct ofl_msg_multipart_reply_group const *msg, FILE *stream)
{
    size_t i;

    fprintf(stream, ", stats=[");

    for (i=0; i<msg->stats_num; i++) {
        ofl_structs_group_stats_print(stream, msg->stats[i]);
        if (i < msg->stats_num - 1)
		{ fprintf(stream, ",\n"); };
    }

    fprintf(stream, "]");
}

static void
ofl_msg_print_stats_reply_meter(struct ofl_msg_multipart_reply_meter const *msg, FILE *stream)
{
    size_t i;

    fprintf(stream, ", stats=[");

    for (i=0; i<msg->stats_num; i++) {
        ofl_structs_meter_stats_print(stream, msg->stats[i]);
        if (i < msg->stats_num - 1)
		{ fprintf(stream, ",\n"); };
    }

    fprintf(stream, "]");
}

static void
ofl_msg_print_stats_reply_meter_conf(struct ofl_msg_multipart_reply_meter_conf const *msg, FILE *stream)
{
    size_t i;

    fprintf(stream, ", stats=[");

    for (i=0; i<msg->stats_num; i++) {
        ofl_structs_meter_config_print(stream, msg->stats[i]);
        if (i < msg->stats_num - 1)
		{ fprintf(stream, ",\n"); };
    }

    fprintf(stream, "]");
}

static void
ofl_msg_print_reply_meter_features(struct ofl_msg_multipart_reply_meter_features const *msg, FILE *stream)
{

    ofl_structs_meter_features_print(stream, msg->features);

}
static void
ofl_msg_print_stats_reply_group_desc(struct ofl_msg_multipart_reply_group_desc const *msg, FILE *stream, struct ofl_exp const *exp)
{
    size_t i;

    fprintf(stream, ", stats=[");

    for (i=0; i<msg->stats_num; i++) {
        ofl_structs_group_desc_stats_print(stream, msg->stats[i], exp);
        if (i < msg->stats_num - 1)
		{ fprintf(stream, ",\n"); };
    }

    fprintf(stream, "]");
}

static void ofl_msg_print_stats_reply_group_features(struct ofl_msg_multipart_reply_group_features const *msg, FILE *stream)
{
    size_t i;
    enum ofp_action_type j;

    fprintf(stream, ", types=\"%d\", capabilities=\"%d [",
                  msg->types, msg->capabilities);

    for(i = 0; i < 4; i++){
        ofl_group_type_print(stream, i);
        fprintf(stream, ": max_groups=%d, actions= ", msg->max_groups[i]);
        if(msg->actions[i] & 1){
            ofl_action_type_print(stream, OFPAT_OUTPUT);
            fprintf(stream, "/");

        }
        if(msg->actions[i] & OFPAT_COPY_TTL_OUT){
            ofl_action_type_print(stream, OFPAT_COPY_TTL_OUT);
            fprintf(stream, "/");

        }
        if(msg->actions[i] & OFPAT_COPY_TTL_IN){
            ofl_action_type_print(stream, OFPAT_COPY_TTL_IN);
            fprintf(stream, "/");
        }
        for(j = OFPAT_SET_MPLS_TTL; j < OFPAT_POP_PBB; j++){
            if (msg->actions[i] & j){
                ofl_action_type_print(stream, j);
                fprintf(stream, "/");
            }
        }
        if (i < 3)
            fprintf(stream, ",\n");
    }
}

static void
ofl_msg_print_stats_reply_experimenter(struct ofl_msg_multipart_reply_experimenter const *msg, FILE *stream)
{
    fprintf(stream, ", exp_id=\"");
    ofl_group_print(stream, msg->experimenter_id);
    fprintf(stream, "\"");
}

static void
ofl_msg_print_table_features_reply(struct ofl_msg_multipart_reply_table_features const * msg, FILE *stream)
{
    size_t i;
    if (msg->table_features == NULL){
        return;
    }
    else {
        fprintf(stream, ", table_features=\"");
        for(i = 0; i < msg->tables_num; i++)
            ofl_structs_table_features_print(stream, msg->table_features[i]);
        fprintf(stream, "\"");
    }
}

static void
ofl_msg_print_port_desc_reply(struct ofl_msg_multipart_reply_port_desc const *msg, FILE *stream)
{
    size_t i;

    for(i = 0; i < msg->stats_num; i++){
        ofl_structs_port_print(stream, msg->stats[i]);
        if (i < msg->stats_num - 1) { fprintf(stream, ",\n"); };
    }
    fprintf(stream, "}");
}

static void
ofl_msg_print_multipart_reply(struct ofl_msg_multipart_reply_header const *msg, FILE *stream, struct ofl_exp const *exp)
{
    if (msg->type == OFPMP_EXPERIMENTER) {
        if (exp != NULL && exp->stats != NULL && exp->stats->reply_to_string != NULL) {
            char *c = exp->stats->reply_to_string(msg, exp);
            fputs(c, stream);
            free(c);
            fprintf(stream, "}");
            return;
        } else {
            OFL_LOG_WARN(LOG_MODULE, "Trying to print EXPERIMENTER stats reply, but no callback was given.");
        }
    }

    fprintf(stream, "{type=\"");
    ofl_stats_type_print(stream, msg->type);
    fprintf(stream, "\", flags=\"0x%"PRIx32"\"", msg->flags);

    switch (msg->type) {
        case (OFPMP_DESC): {
            ofl_msg_print_stats_reply_desc((struct ofl_msg_reply_desc const *)msg, stream);
            break;
        }
        case (OFPMP_FLOW): {
            ofl_msg_print_stats_reply_flow((struct ofl_msg_multipart_reply_flow const *)msg, stream, exp);
            break;
        }
        case OFPMP_AGGREGATE: {
            ofl_msg_print_stats_reply_aggregate((struct ofl_msg_multipart_reply_aggregate const *)msg, stream);
            break;
        }
        case (OFPMP_TABLE): {
            ofl_msg_print_stats_reply_table((struct ofl_msg_multipart_reply_table const *)msg, stream);
            break;
        }
        case (OFPMP_TABLE_FEATURES):{
            ofl_msg_print_table_features_reply((struct ofl_msg_multipart_reply_table_features const *)msg, stream);
            break;
        }
        case OFPMP_PORT_STATS: {
            ofl_msg_print_stats_reply_port((struct ofl_msg_multipart_reply_port const *)msg, stream);
            break;
        }
        case OFPMP_QUEUE: {
            ofl_msg_print_stats_reply_queue((struct ofl_msg_multipart_reply_queue const *)msg, stream);
            break;
        }
        case (OFPMP_GROUP): {
            ofl_msg_print_stats_reply_group((struct ofl_msg_multipart_reply_group const *)msg, stream);
            break;
        }
        case OFPMP_GROUP_DESC: {
            ofl_msg_print_stats_reply_group_desc((struct ofl_msg_multipart_reply_group_desc const *)msg, stream, exp);
            break;
        }
        case OFPMP_GROUP_FEATURES:{
            ofl_msg_print_stats_reply_group_features((struct ofl_msg_multipart_reply_group_features const *)msg, stream);
            break;
        }
        case OFPMP_METER:{
            ofl_msg_print_stats_reply_meter((struct ofl_msg_multipart_reply_meter const *)msg, stream);
            break;
        }
        case OFPMP_METER_CONFIG:{
            ofl_msg_print_stats_reply_meter_conf((struct ofl_msg_multipart_reply_meter_conf const *)msg, stream);
            break;
        }
        case OFPMP_METER_FEATURES:{
            ofl_msg_print_reply_meter_features((struct ofl_msg_multipart_reply_meter_features const *)msg, stream);
            break;
        }
        case OFPMP_PORT_DESC:{
            ofl_msg_print_port_desc_reply((struct ofl_msg_multipart_reply_port_desc const *)msg, stream);
            break;
        }
        case OFPMP_EXPERIMENTER: {
            ofl_msg_print_stats_reply_experimenter((struct ofl_msg_multipart_reply_experimenter const *)msg, stream);
            break;
        }
    }

    fprintf(stream, "}");
}

static void
ofl_msg_print_queue_get_config_request(struct ofl_msg_queue_get_config_request const *msg, FILE *stream)
{
    fprintf(stream, "{port=\"");
    ofl_port_print(stream, msg->port);
    fprintf(stream, "\"}");
}

static void
ofl_msg_print_queue_get_config_reply(struct ofl_msg_queue_get_config_reply const *msg, FILE *stream)
{
    size_t i;

    fprintf(stream, "{port=\"");
    ofl_port_print(stream, msg->port);
    fprintf(stream, "\" queues=[");

    for (i=0; i<msg->queues_num; i++) {
        ofl_structs_queue_print(stream, msg->queues[i]);
        if (i < msg->queues_num - 1)
		fprintf(stream, ", ");
    }

    fprintf(stream, "]}");
}

static void
ofl_msg_print_role_msg(struct ofl_msg_role_request const *msg, FILE *stream)
{

    fprintf(stream, "{role= %d, generation_id= %"PRIu64"}", msg->role, msg->generation_id);

}

static void
ofl_msg_print_async(struct ofl_msg_async_config const * msg, FILE *stream)
{
    fprintf(stream, "{");
    ofl_structs_async_config_print(stream, msg->config);
    fprintf(stream, "}");

}

char *
ofl_msg_to_string(struct ofl_msg_header const *msg, struct ofl_exp const *exp)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_msg_print(stream, msg, exp);
    fclose(stream);
    return str;
}

void
ofl_msg_print(FILE *stream, struct ofl_msg_header const *msg, struct ofl_exp const *exp)
{
    ofl_message_type_print(stream, msg->type);
    switch (msg->type) {
        case OFPT_HELLO: { return; }
        case OFPT_ERROR: { ofl_msg_print_error((struct ofl_msg_error const *)msg, stream, exp); return; }
        case OFPT_ECHO_REQUEST:
        case OFPT_ECHO_REPLY: { ofl_msg_print_echo((struct ofl_msg_echo const *)msg, stream); return; }
        case OFPT_EXPERIMENTER: {
            if (exp == NULL || exp->msg == NULL || exp->msg->to_string == NULL) {
                ofl_msg_print_experimenter((struct ofl_msg_experimenter const *)msg, stream);
            } else {
                char *c = exp->msg->to_string((struct ofl_msg_experimenter *)msg, exp);
                fprintf(stream, "%s", c);
                free(c);
            }
            return;
        }

        /* Switch configuration messages. */
        case OFPT_FEATURES_REQUEST: { return; }
        case OFPT_FEATURES_REPLY: { ofl_msg_print_features_reply((struct ofl_msg_features_reply const *)msg, stream); return; }
        case OFPT_GET_CONFIG_REQUEST: { return; }
        case OFPT_GET_CONFIG_REPLY: { ofl_msg_print_get_config_reply((struct ofl_msg_get_config_reply const *)msg, stream); return; }
        case OFPT_SET_CONFIG: { ofl_msg_print_set_config((struct ofl_msg_set_config const *)msg, stream); return; }

        /* Asynchronous messages. */
        case OFPT_PACKET_IN: { ofl_msg_print_packet_in((struct ofl_msg_packet_in const *)msg, stream); return; }
        case OFPT_FLOW_REMOVED: { ofl_msg_print_flow_removed((struct ofl_msg_flow_removed const *)msg, stream, exp); return; }
        case OFPT_PORT_STATUS: { ofl_msg_print_port_status((struct ofl_msg_port_status const *)msg, stream); return; }

        /* Controller command messages. */
        case OFPT_PACKET_OUT: { ofl_msg_print_packet_out((struct ofl_msg_packet_out const *)msg, stream, exp); return; }
        case OFPT_FLOW_MOD: { ofl_msg_print_flow_mod((struct ofl_msg_flow_mod const *)msg, stream, exp); return; }
        case OFPT_GROUP_MOD: { ofl_msg_print_group_mod((struct ofl_msg_group_mod const *)msg, stream, exp); return; }
        case OFPT_PORT_MOD: { ofl_msg_print_port_mod((struct ofl_msg_port_mod const *)msg, stream); return; }
        case OFPT_TABLE_MOD: { ofl_msg_print_table_mod((struct ofl_msg_table_mod const *)msg, stream); return; }

        /* Statistics messages. */
        case OFPT_MULTIPART_REQUEST: { ofl_msg_print_multipart_request((struct ofl_msg_multipart_request_header const *)msg, stream, exp); return; }
        case OFPT_MULTIPART_REPLY: { ofl_msg_print_multipart_reply((struct ofl_msg_multipart_reply_header const *)msg, stream, exp); return; }

        /* Barrier messages. */
        case OFPT_BARRIER_REQUEST: { return; }
        case OFPT_BARRIER_REPLY: { return; }

        /*Role messages */
        case OFPT_ROLE_REQUEST:
        case OFPT_ROLE_REPLY:{
            ofl_msg_print_role_msg((struct ofl_msg_role_request const *)msg, stream);
        }
        /* Queue Configuration messages. */
        case OFPT_QUEUE_GET_CONFIG_REQUEST: { ofl_msg_print_queue_get_config_request((struct ofl_msg_queue_get_config_request const *)msg, stream); return; }
        case OFPT_QUEUE_GET_CONFIG_REPLY: { ofl_msg_print_queue_get_config_reply((struct ofl_msg_queue_get_config_reply const *)msg, stream); return; }

        /* Asynchronous message configuration. */
        case OFPT_GET_ASYNC_REQUEST:{return;}
        case OFPT_GET_ASYNC_REPLY:
        case OFPT_SET_ASYNC:{ofl_msg_print_async((struct ofl_msg_async_config const *)msg, stream); return;}

        case OFPT_METER_MOD: {ofl_msg_print_meter_mod((struct ofl_msg_meter_mod const *)msg, stream); return;}
    }
}

