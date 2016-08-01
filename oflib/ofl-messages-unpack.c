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
 */

#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <endian.h>
#include "ofl-actions.h"
#include "ofl-messages.h"
#include "ofl-structs.h"
#include "ofl-utils.h"
#include "ofl-print.h"
#include "ofl-log.h"
#include "openflow/openflow.h"

#define UNUSED __attribute__((__unused__))

#define LOG_MODULE ofl_msg_u
OFL_LOG_INIT(LOG_MODULE)

/****************************************************************************
 * Functions for unpacking ofp wire format to ofl structures.
 ****************************************************************************/


static ofl_err
ofl_msg_unpack_error(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_error_msg *se;
    struct ofp_error_experimenter_msg *sexpe;
    struct ofl_msg_error *de;
    struct ofl_msg_exp_error *dexpe;

    /*sizeof(struct ofp_error_msg) < sizeof(struct ofp_error_experimenter_msg)*/
    if (*len < sizeof(struct ofp_error_msg)) {
        OFL_LOG_WARN(LOG_MODULE, "Received ERROR message invalid length (%zu).", *len);
        return OFL_ERROR;
    }

    se = (struct ofp_error_msg *)src;

    switch(se->type){
        case (OFPET_EXPERIMENTER):{
            sexpe = (struct ofp_error_experimenter_msg *)src;
            dexpe = (struct ofl_msg_exp_error *)malloc(sizeof(struct ofl_msg_exp_error));
            *len -= sizeof(struct ofp_error_experimenter_msg);

            dexpe->type = (enum ofp_error_type)ntohs(sexpe->type);
            dexpe->exp_type = ntohs(sexpe->exp_type);
            dexpe->experimenter = ntohl(sexpe->experimenter);
            dexpe->data_length = *len;
            dexpe->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), sexpe->data, *len) : NULL;
            *len = 0;

            (*msg) = (struct ofl_msg_header *)dexpe;

            break;
            }

        default: {
    de = (struct ofl_msg_error *)malloc(sizeof(struct ofl_msg_error));

            *len -= sizeof(struct ofp_error_msg);

    de->type = (enum ofp_error_type)ntohs(se->type);
    de->code = ntohs(se->code);
    de->data_length = *len;
    de->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), se->data, *len) : NULL;
    *len = 0;

    (*msg) = (struct ofl_msg_header *)de;
            break;
        }
    }
    return 0;
}


static ofl_err
ofl_msg_unpack_echo(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofl_msg_echo *e = (struct ofl_msg_echo *)malloc(sizeof(struct ofl_msg_echo));
    uint8_t *data;

    // ofp_header length was checked at ofl_msg_unpack
    *len -= sizeof(struct ofp_header);

    data = (uint8_t *)src + sizeof(struct ofp_header);
    e->data_length = *len;
    e->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), data, *len) : NULL;
    *len = 0;

    *msg = (struct ofl_msg_header *)e;
    return 0;
}

static ofl_err
ofl_msg_unpack_role_request(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_role_request *srl;
    struct ofl_msg_role_request *drl;

    if (*len < sizeof(struct ofp_role_request)){
        OFL_LOG_WARN(LOG_MODULE, "Received ROLE message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_role_request);

    srl = (struct ofp_role_request *) src;
    drl = (struct ofl_msg_role_request *) malloc(sizeof(struct ofl_msg_role_request));

    drl->role = ntohl(srl->role);
    drl->generation_id = ntoh64(srl->generation_id);

    *msg = (struct ofl_msg_header *)drl;
    return 0;
}

static ofl_err
ofl_msg_unpack_features_reply(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_switch_features *sr;
    struct ofl_msg_features_reply *dr;

    if (*len < sizeof(struct ofp_switch_features)) {
        OFL_LOG_WARN(LOG_MODULE, "Received FEATURES_REPLY message has invalid length (%zu).", *len);

    }
    *len -= sizeof(struct ofp_switch_features);

    sr = (struct ofp_switch_features *)src;
    dr = (struct ofl_msg_features_reply *)malloc(sizeof(struct ofl_msg_features_reply));

    dr->datapath_id  = ntoh64(sr->datapath_id);
    dr->n_buffers    = ntohl( sr->n_buffers);
    dr->n_tables     =  sr->n_tables;
    dr->auxiliary_id = sr->auxiliary_id;
    dr->capabilities = ntohl( sr->capabilities);

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}


static ofl_err
ofl_msg_unpack_get_config_reply(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_switch_config *sr;
    struct ofl_msg_get_config_reply *dr;

    if (*len < sizeof(struct ofp_switch_config)) {
        OFL_LOG_WARN(LOG_MODULE, "Received GET_CONFIG_REPLY message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_switch_config);

    sr = (struct ofp_switch_config *)src;
    dr = (struct ofl_msg_get_config_reply *)malloc(sizeof(struct ofl_msg_get_config_reply));

    dr->config = (struct ofl_config *)malloc(sizeof(struct ofl_config));
    dr->config->miss_send_len = ntohs(sr->miss_send_len);
    dr->config->flags = ntohs(sr->flags);

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}

static ofl_err
ofl_msg_unpack_set_config(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_switch_config *sr;
    struct ofl_msg_set_config *dr;

     if (*len < sizeof(struct ofp_switch_config)) {
         OFL_LOG_WARN(LOG_MODULE, "Received SET_CONFIG message has invalid length (%zu).", *len);
         return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
     }
     *len -= sizeof(struct ofp_switch_config);

     sr = (struct ofp_switch_config *)src;
     dr = (struct ofl_msg_set_config *)malloc(sizeof(struct ofl_msg_set_config));

     dr->config = (struct ofl_config *)malloc(sizeof(struct ofl_config));
     // TODO Zoltan: validate flags
     dr->config->miss_send_len = ntohs(sr->miss_send_len);
     dr->config->flags = ntohs(sr->flags);

     *msg = (struct ofl_msg_header *)dr;
     return 0;
}

static ofl_err
ofl_msg_unpack_async_config(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_async_config *sac;
    struct ofl_msg_async_config *dac;
    int i;

    if (*len < sizeof(struct ofp_async_config)) {
        OFL_LOG_WARN(LOG_MODULE, "Received ASYNC CONFIG message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= sizeof(struct ofp_async_config);

    sac = (struct ofp_async_config*)src;
    dac = (struct ofl_msg_async_config*)malloc(sizeof(struct ofl_msg_async_config));
    dac->config = (struct ofl_async_config*) malloc(sizeof(struct ofl_async_config));
    for(i = 0; i < 2; i++){
        dac->config->packet_in_mask[i] = ntohl(sac->packet_in_mask[i]);
        dac->config->port_status_mask[i] = ntohl(sac->port_status_mask[i]);
        dac->config->flow_removed_mask[i] =  ntohl(sac->flow_removed_mask[i]);
    }

    *msg = (struct ofl_msg_header*)dac;
    return 0;
}


static ofl_err
ofl_msg_unpack_packet_in(struct ofp_header const *src, uint8_t const* buf, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofp_packet_in *sp;
    struct ofl_msg_packet_in *dp;
    uint8_t const *ptr;

    if (*len < sizeof(struct ofp_packet_in)) {
        OFL_LOG_WARN(LOG_MODULE, "Received PACKET_IN message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sp = (struct ofp_packet_in *)src;

    /* TODO: Check in_port oxm_field */
    /*if (ntohl(sp->in_port) == 0 ||
        (ntohl(sp->in_port) > OFPP_MAX &&
         ntohl(sp->in_port) != OFPP_LOCAL)) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ps = ofl_port_to_string(ntohl(sp->in_port));
            OFL_LOG_WARN(LOG_MODULE, "Received PACKET_IN message has invalid in_port (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_PORT);
    }*/

    if (sp->table_id == PIPELINE_TABLES) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(sp->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received PACKET_IN has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }
    *len -= sizeof(struct ofp_packet_in) - sizeof(struct ofp_match);
    dp = (struct ofl_msg_packet_in *)malloc(sizeof(struct ofl_msg_packet_in));
    dp->buffer_id = ntohl(sp->buffer_id);
    dp->total_len = ntohs(sp->total_len);
    dp->reason = (enum ofp_packet_in_reason)sp->reason;
    dp->table_id = sp->table_id;
    dp->cookie = ntoh64(sp->cookie);

    ptr = buf + (sizeof(struct ofp_packet_in)-4);
    ofl_structs_match_unpack(&(sp->match),ptr, len ,&(dp->match), 1, exp);

    ptr = buf + ROUND_UP(sizeof(struct ofp_packet_in)-4 + dp->match->length,8) + 2;
    /* Minus padding bytes */
    *len -= 2;
    dp->data_length = *len;
    dp->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), ptr, *len) : NULL;
    *len = 0;

    *msg = (struct ofl_msg_header *)dp;
    return 0;
}

static ofl_err
ofl_msg_unpack_flow_removed(struct ofp_header const *src, uint8_t const *buf, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofp_flow_removed *sr;
    struct ofl_msg_flow_removed *dr;
    ofl_err error;
    int match_pos;

    if (*len < (sizeof(struct ofp_flow_removed) - sizeof(struct ofp_match))) {
        OFL_LOG_WARN(LOG_MODULE, "Received FLOW_REMOVED message has invalid length (%zu).", *len);
        return OFL_ERROR;
    }

    sr = (struct ofp_flow_removed *)src ;

    if (sr->table_id >= PIPELINE_TABLES) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(sr->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received FLOW_REMOVED message has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }
    *len -=  sizeof(struct ofp_flow_removed) - sizeof(struct ofp_match) ;

    dr = (struct ofl_msg_flow_removed *)malloc(sizeof(struct ofl_msg_flow_removed));
    dr->reason = (enum ofp_flow_removed_reason)sr->reason;

    dr->stats = (struct ofl_flow_stats *)malloc(sizeof(struct ofl_flow_stats));
    dr->stats->table_id         =        sr->table_id;
    dr->stats->duration_sec     = ntohl( sr->duration_sec);
    dr->stats->duration_nsec    = ntohl( sr->duration_nsec);
    dr->stats->priority         = ntohs(sr->priority);
    dr->stats->idle_timeout     = ntohs( sr->idle_timeout);
    dr->stats->hard_timeout     = 0;
    dr->stats->cookie           = ntoh64(sr->cookie);
    dr->stats->packet_count     = ntoh64(sr->packet_count);
    dr->stats->byte_count       = ntoh64(sr->byte_count);
    dr->stats->instructions_num = 0;
    dr->stats->instructions     = NULL;

    match_pos = sizeof(struct ofp_flow_removed) - 4;

    error = ofl_structs_match_unpack(&(sr->match),buf + match_pos, len, &(dr->stats->match), 1, exp);
    if (error) {
        free(dr->stats);
        free(dr);
        return error;
    }
    *msg = (struct ofl_msg_header *)dr;
    return 0;
}

static ofl_err
ofl_msg_unpack_port_status(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_port_status *ss;
    struct ofl_msg_port_status *ds;
    ofl_err error;

    if (*len < sizeof(struct ofp_port_status)) {
        OFL_LOG_WARN(LOG_MODULE, "Received PORT_STATUS message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= (sizeof(struct ofp_port_status) - sizeof(struct ofp_port));

    ss = (struct ofp_port_status *)src;
    ds = (struct ofl_msg_port_status *)malloc(sizeof(struct ofl_msg_port_status));

    ds->reason = (enum ofp_port_reason) ss->reason;

    error = ofl_structs_port_unpack(&(ss->desc), len, &(ds->desc));
    if (error) {
        free(ds);
        return error;
    }

    *msg = (struct ofl_msg_header *)ds;
    return 0;
}

static ofl_err
ofl_msg_unpack_packet_out(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{

    struct ofp_packet_out *sp;
    struct ofl_msg_packet_out *dp;
    struct ofp_action_header *act;
    uint8_t *data;
    ofl_err error;
    size_t i, actions_num;

    if (*len < sizeof(struct ofp_packet_out)) {
        OFL_LOG_WARN(LOG_MODULE, "Received PACKET_OUT message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sp = (struct ofp_packet_out *)src;

    /*if (ntohl(sp->in_port) == 0 ||
        (ntohl(sp->in_port) > OFPP_MAX && ntohl(sp->in_port) != OFPP_CONTROLLER)) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ps = ofl_port_to_string(ntohl(sp->in_port));
            OFL_LOG_WARN(LOG_MODULE, "Received PACKET_OUT message with invalid in_port (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_PORT);
    }*/

    if (ntohl(sp->buffer_id) != 0xffffffff &&
        *len != sizeof(struct ofp_packet_out) + ntohs(sp->actions_len)) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *bs = ofl_buffer_to_string(ntohl(sp->buffer_id));
            OFL_LOG_WARN(LOG_MODULE, "Received PACKET_OUT message with data and buffer_id (%s).", bs);
            free(bs);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_packet_out);

    dp = (struct ofl_msg_packet_out *)malloc(sizeof(struct ofl_msg_packet_out));

    dp->buffer_id = ntohl(sp->buffer_id);
    dp->in_port = ntohl(sp->in_port);
    if (*len < ntohs(sp->actions_len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received PACKET_OUT message has invalid action length (%zu).", *len);
        free(dp);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    error = ofl_utils_count_ofp_actions(&(sp->actions), ntohs(sp->actions_len), &actions_num);
    if (error) {
        free(dp);
        return error;
    }
    dp->actions_num = actions_num;
    dp->actions = (struct ofl_action_header **)malloc(dp->actions_num * sizeof(struct ofp_action_header *));

    // TODO Zoltan: Output actions can contain OFPP_TABLE
    act = sp->actions;
    for (i = 0; i < dp->actions_num; i++) {
        error = ofl_actions_unpack(act, len, &(dp->actions[i]), exp);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(dp->actions, i,
                                    ofl_actions_free, exp);
            free(dp);
        }
        act = (struct ofp_action_header *)((uint8_t *)act + ntohs(act->len));
    }

    data = ((uint8_t *)sp->actions) + ntohs(sp->actions_len);
    dp->data_length = *len;
    dp->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), data, *len) : NULL;
    *len = 0;

    *msg = (struct ofl_msg_header *)dp;

    return 0;
}


static ofl_err
ofl_msg_unpack_flow_mod(struct ofp_header const *src, uint8_t const* buf, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofp_flow_mod *sm;
    struct ofl_msg_flow_mod *dm;
    struct ofp_instruction *inst;
    ofl_err error;
    size_t i;
    int match_pos;

    if (*len < (sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match))) {
        OFL_LOG_WARN(LOG_MODULE, "Received FLOW_MOD message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= (sizeof(struct ofp_flow_mod) - sizeof(struct ofp_match));

    sm = (struct ofp_flow_mod *)src;
    dm = (struct ofl_msg_flow_mod *)malloc(sizeof(struct ofl_msg_flow_mod));

    if (sm->table_id >= PIPELINE_TABLES && ((sm->command != OFPFC_DELETE
    || sm->command != OFPFC_DELETE_STRICT) && sm->table_id != OFPTT_ALL)) {
        OFL_LOG_WARN(LOG_MODULE, "Received FLOW_MOD message has invalid table id (%d).", sm->table_id );
        free(dm);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }

    dm->cookie =       ntoh64(sm->cookie);
    dm->cookie_mask =  ntoh64(sm->cookie_mask);
    dm->table_id =            sm->table_id;
    dm->command =             (enum ofp_flow_mod_command)sm->command;
    dm->idle_timeout = ntohs( sm->idle_timeout);
    dm->hard_timeout = ntohs( sm->hard_timeout);
    dm->priority =     ntohs( sm->priority);
    dm->buffer_id =    ntohl( sm->buffer_id);
    dm->out_port =     ntohl( sm->out_port);
    dm->out_group =    ntohl( sm->out_group);
    dm->flags =        ntohs( sm->flags);

    match_pos = sizeof(struct ofp_flow_mod) - 4;
    error = ofl_structs_match_unpack(&(sm->match), buf + match_pos, len, &(dm->match), 1, exp);
    *msg = (struct ofl_msg_header *)dm;
    if (error) {
        return error;
    }

    error = ofl_utils_count_ofp_instructions((struct ofp_instruction *)(buf + ROUND_UP(match_pos + dm->match->length,8)), *len, &dm->instructions_num);
    if (error) {
        return error;
    }

    dm->instructions = (struct ofl_instruction_header **)malloc(dm->instructions_num * sizeof(struct ofl_instruction_header *));
    inst = (struct ofp_instruction *) (buf + ROUND_UP(match_pos + dm->match->length,8));
    for (i = 0; i < dm->instructions_num; i++) {
        error = ofl_structs_instructions_unpack(inst, len, &(dm->instructions[i]), exp);
        if (error) {
            return error;
        }
        inst = (struct ofp_instruction *)((uint8_t *)inst + ntohs(inst->len));
    }
    return 0;
}

static ofl_err
ofl_msg_unpack_group_mod(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofp_group_mod *sm;
    struct ofl_msg_group_mod *dm;
    struct ofp_bucket *bucket;
    ofl_err error;
    size_t i;

    if (*len < sizeof(struct ofp_group_mod)) {
        OFL_LOG_WARN(LOG_MODULE, "Received GROUP_MOD message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_group_mod);

    sm = (struct ofp_group_mod *)src;

    if (ntohs(sm->command) > OFPGC_DELETE) {
        OFL_LOG_WARN(LOG_MODULE, "Received GROUP_MOD message with invalid command (%u).", ntohs(sm->command));
        return ofl_error(OFPET_BAD_REQUEST, OFPGMFC_BAD_COMMAND);
    }

    if (ntohs(sm->type) > OFPGT_FF && ntohs(sm->type) < 128 /* experimenter */) {
        OFL_LOG_WARN(LOG_MODULE, "Received GROUP_MOD message with invalid type (%u).", ntohs(sm->type));
        return ofl_error(OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
    }

    if (ntohl(sm->group_id) > OFPG_MAX &&
                       !(ntohs(sm->command) == OFPGC_DELETE && ntohl(sm->group_id) == OFPG_ALL)) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *gs = ofl_group_to_string(ntohl(sm->group_id));
            OFL_LOG_WARN(LOG_MODULE, "Received GROUP_MOD message with invalid group id (%s).", gs);
            free(gs);
        }
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    dm = (struct ofl_msg_group_mod *)malloc(sizeof(struct ofl_msg_group_mod));

    dm->command = (enum ofp_group_mod_command)ntohs(sm->command);
    dm->type = sm->type;
    dm->group_id = ntohl(sm->group_id);

    error = ofl_utils_count_ofp_buckets(&(sm->buckets), *len, &dm->buckets_num);
    if (error) {
        free(dm);
        return error;
    }

    if (dm->command == OFPGC_DELETE && dm->buckets_num > 0) {
        OFL_LOG_WARN(LOG_MODULE, "Received DELETE group command with buckets (%zu).", dm->buckets_num);
        free(dm);
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    if (dm->type == OFPGT_INDIRECT && dm->buckets_num != 1) {
        OFL_LOG_WARN(LOG_MODULE, "Received INDIRECT group doesn't have exactly one bucket (%zu).", dm->buckets_num);
        free(dm);
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    dm->buckets = (struct ofl_bucket **)malloc(dm->buckets_num * sizeof(struct ofl_bucket *));

    bucket = sm->buckets;
    for (i = 0; i < dm->buckets_num; i++) {
        error = ofl_structs_bucket_unpack(bucket, len, dm->type, &(dm->buckets[i]), exp);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(dm->buckets, i,
                                    ofl_structs_free_bucket, exp);
            free(dm);
            return error;
        }
        bucket = (struct ofp_bucket *)((uint8_t *)bucket + ntohs(bucket->len));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_meter_mod(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
   struct ofp_meter_mod *sm;
    struct ofl_msg_meter_mod *dm;
    struct ofp_meter_band_header *band;
    ofl_err error;
    size_t i;
    if (*len < sizeof(struct ofp_meter_mod)) {
        OFL_LOG_WARN(LOG_MODULE, "Received METER_MOD message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_meter_mod);

    sm = (struct ofp_meter_mod *)src;

    if (ntohs(sm->command) > OFPMC_DELETE) {
        OFL_LOG_WARN(LOG_MODULE, "Received METER_MOD message with invalid command (%u).", ntohs(sm->command));
        return ofl_error(OFPET_BAD_REQUEST, OFPMMFC_BAD_COMMAND);
    }

    if ((ntohs(sm->flags) >> 3) > 1 ) {
        OFL_LOG_WARN(LOG_MODULE, "Received METER_MOD message with invalid flags(%u).", ntohs(sm->flags));
        return ofl_error(OFPET_BAD_REQUEST, OFPMMFC_BAD_FLAGS);
    }

    if (ntohl(sm->meter_id) > OFPM_MAX &&
                       !(ntohs(sm->command) == OFPMC_DELETE && ntohl(sm->meter_id) == OFPM_ALL)) {

        return ofl_error(OFPET_METER_MOD_FAILED, OFPMMFC_INVALID_METER);
    }

    dm = (struct ofl_msg_meter_mod *)malloc(sizeof(struct ofl_msg_meter_mod));

    dm->command = ntohs(sm->command);
    dm->flags = ntohs(sm->flags);
    dm->meter_id = ntohl(sm->meter_id);

    error = ofl_utils_count_ofp_meter_bands(&(sm->bands), *len, &dm->meter_bands_num);
    if (error) {
        free(dm);
        return error;
    }

    dm->bands = (struct ofl_meter_band_header **)malloc(dm->meter_bands_num * sizeof(struct ofl_meter_band_header *));

    band = sm->bands;
    for (i = 0; i < dm->meter_bands_num; i++) {
        error = ofl_structs_meter_band_unpack(band, len, &(dm->bands[i]));
        if (error) {
            OFL_UTILS_FREE_ARR_FUN(dm->bands, i, ofl_structs_free_meter_bands);
            free(dm);
            return error;
        }
        band = (struct ofp_meter_band_header *)((uint8_t *)band + ntohs(band->len));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_port_mod(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_port_mod *sm;
    struct ofl_msg_port_mod *dm;

    if (*len < sizeof(struct ofp_port_mod)) {
        OFL_LOG_WARN(LOG_MODULE, "Received PORT_MOD has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sm = (struct ofp_port_mod *)src;

    /*if (ntohl(sm->port_no) == 0 || ntohl(sm->port_no) > OFPP_MAX) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ps = ofl_port_to_string(ntohl(sm->port_no));
            OFL_LOG_WARN(LOG_MODULE, "Received PORT_MOD message has invalid in_port (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_PORT);
    }*/
    *len -= sizeof(struct ofp_port_mod);

    dm = (struct ofl_msg_port_mod *)malloc(sizeof(struct ofl_msg_port_mod));

    dm->port_no =   ntohl(sm->port_no);
    memcpy(dm->hw_addr, sm->hw_addr, OFP_ETH_ALEN);
    dm->config =    ntohl(sm->config);
    dm->mask =      ntohl(sm->mask);
    dm->advertise = ntohl(sm->advertise);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_table_mod(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_table_mod *sm;
    struct ofl_msg_table_mod *dm;

    if (*len < sizeof(struct ofp_table_mod)) {
        OFL_LOG_WARN(LOG_MODULE, "Received TABLE_MOD message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_table_mod);

    sm = (struct ofp_table_mod *)src;
    dm = (struct ofl_msg_table_mod *)malloc(sizeof(struct ofl_msg_table_mod));
    if (sm->table_id >= PIPELINE_TABLES) {
        OFL_LOG_WARN(LOG_MODULE, "Received TABLE_MOD message has invalid table id (%d).", sm->table_id );
        free(dm);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }

    dm->table_id = sm->table_id;
    dm->config = ntohl(sm->config);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_request_flow(struct ofp_multipart_request const *os, uint8_t const * buf, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofp_flow_stats_request *sm;
    struct ofl_msg_multipart_request_flow *dm;
    ofl_err error = 0;
    int match_pos;

    // ofp_multipart_request length was checked at ofl_msg_unpack_multipart_request

    if (*len < (sizeof(struct ofp_flow_stats_request) - sizeof(struct ofp_match))) {
        OFL_LOG_WARN(LOG_MODULE, "Received FLOW stats request has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= (sizeof(struct ofp_flow_stats_request) - sizeof(struct ofp_match));

    sm = (struct ofp_flow_stats_request *)os->body;
    dm = (struct ofl_msg_multipart_request_flow *) malloc(sizeof(struct ofl_msg_multipart_request_flow));

    if (sm->table_id != OFPTT_ALL && sm->table_id >= PIPELINE_TABLES) {
         OFL_LOG_WARN(LOG_MODULE, "Received MULTIPART REQUEST FLOW message has invalid table id (%d).", sm->table_id );
         free(dm);
         return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }

    dm->table_id = sm->table_id;
    dm->out_port = ntohl(sm->out_port);
    dm->out_group = ntohl(sm->out_group);
    dm->cookie = ntoh64(sm->cookie);
    dm->cookie_mask = ntoh64(sm->cookie_mask);

    match_pos = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_flow_stats_request) - 4;
    error = ofl_structs_match_unpack(&(sm->match),buf + match_pos, len, &(dm->match), 1, exp);
    if (error) {
        free(dm);
        return error;
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_request_port(struct ofp_multipart_request *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_port_stats_request *sm;
    struct ofl_msg_multipart_request_port *dm;

    // ofp_multipart_request length was checked at ofl_msg_unpack_multipart_request

    if (*len < sizeof(struct ofp_port_stats_request)) {
        OFL_LOG_WARN(LOG_MODULE, "Received PORT stats request has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sm = (struct ofp_port_stats_request *)os->body;

    if (ntohl(sm->port_no) == 0 ||
        (ntohl(sm->port_no) > OFPP_MAX && ntohl(sm->port_no) != OFPP_ANY)) {
        OFL_LOG_WARN(LOG_MODULE, "Received PORT stats request has invalid port (%u).", ntohl(sm->port_no));
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= sizeof(struct ofp_port_stats_request);

    dm = (struct ofl_msg_multipart_request_port *) malloc(sizeof(struct ofl_msg_multipart_request_port));

    dm->port_no = ntohl(sm->port_no);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_request_empty(struct ofp_multipart_request *os UNUSED, size_t *len, struct ofl_msg_header **msg)
{
    // ofp_multipart_request length was checked at ofl_msg_unpack_multipart_request
    len -= sizeof(struct ofp_multipart_request);

    *msg = (struct ofl_msg_header *)malloc(sizeof(struct ofl_msg_multipart_request_header));
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_request_table_features(struct ofp_multipart_request *os, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofl_msg_multipart_request_table_features *dm;
    ofl_err error;
    uint8_t *features;
    size_t i;

    dm = (struct ofl_msg_multipart_request_table_features*) malloc(sizeof(struct ofl_msg_multipart_request_table_features));
    if (!(*len)){
        dm->tables_num = 0;
        dm->table_features = NULL;
        *msg = (struct ofl_msg_header*) dm;
        return 0;
    }

    error = ofl_utils_count_ofp_table_features((uint8_t*) os->body, *len, &dm->tables_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->table_features = (struct ofl_table_features **) malloc(sizeof(struct ofl_table_features *) * dm->tables_num);
    features = (uint8_t* ) os->body;

    for(i = 0; i < dm->tables_num; i++){
        error = ofl_structs_table_features_unpack((struct ofp_table_features*) features, len, &dm->table_features[i] , exp);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(dm->table_features, i,
                                    ofl_structs_free_table_features, exp);
            free(dm);
            return error;
        }
        features += ntohs(((struct ofp_table_features*) features)->length);
    }
    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_request_queue(struct ofp_multipart_request *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_queue_stats_request *sm;
    struct ofl_msg_multipart_request_queue *dm;

    // ofp_multipart_request length was checked at ofl_msg_unpack_multipart_request

    if (*len < sizeof(struct ofp_queue_stats_request)) {
        OFL_LOG_WARN(LOG_MODULE, "Received QUEUE stats request has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sm = (struct ofp_queue_stats_request *)os->body;

    if (ntohl(sm->port_no) == 0 ||
        (ntohl(sm->port_no) > OFPP_MAX && ntohl(sm->port_no) != OFPP_ANY)) {
        OFL_LOG_WARN(LOG_MODULE, "Received QUEUE stats request has invalid port (%u).", ntohl(sm->port_no));
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_queue_stats_request);

    dm = (struct ofl_msg_multipart_request_queue *) malloc(sizeof(struct ofl_msg_multipart_request_queue));

    dm->port_no = ntohl(sm->port_no);
    dm->queue_id = ntohl(sm->queue_id);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_request_group(struct ofp_multipart_request *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_group_stats_request *sm;
    struct ofl_msg_multipart_request_group *dm;

    // ofp_multipart_request length was checked at ofl_msg_unpack_multipart_request

    if (*len < sizeof(struct ofp_group_stats_request)) {
        OFL_LOG_WARN(LOG_MODULE, "Received GROUP stats request has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_group_stats_request);

    sm = (struct ofp_group_stats_request *)os->body;
    dm = (struct ofl_msg_multipart_request_group *) malloc(sizeof(struct ofl_msg_multipart_request_group));

    dm->group_id = ntohl(sm->group_id);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_meter_multipart_request(struct ofp_multipart_request *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_meter_multipart_request *sm;
    struct ofl_msg_multipart_meter_request *dm;

    // ofp_multipart_request length was checked at ofl_msg_unpack_multipart_request

    if (*len < sizeof(struct ofp_meter_multipart_request)) {
        OFL_LOG_WARN(LOG_MODULE, "Received METER multipart request has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_meter_multipart_request);

    sm = (struct ofp_meter_multipart_request *)os->body;
    dm = (struct ofl_msg_multipart_meter_request *) malloc(sizeof(struct ofl_msg_multipart_meter_request));

    dm->meter_id = ntohl(sm->meter_id);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_request(struct ofp_header const *src, uint8_t const *buf, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofl_msg_multipart_request_header *ofls;
    struct ofp_multipart_request *os;
    int error;

    if (*len < sizeof(struct ofp_multipart_request)) {
        OFL_LOG_WARN(LOG_MODULE, "Received STATS_REQUEST message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_multipart_request);

    os = (struct ofp_multipart_request *)src;

    switch (ntohs(os->type)) {
        case OFPMP_DESC: {
            error = ofl_msg_unpack_multipart_request_empty(os, len, msg);
            break;
        }
        case OFPMP_FLOW:
        case OFPMP_AGGREGATE: {
            error = ofl_msg_unpack_multipart_request_flow(os,buf, len, msg, exp);
            break;
        }
        case OFPMP_TABLE: {
            error = ofl_msg_unpack_multipart_request_empty(os, len, msg);
            break;
        }
        case OFPMP_TABLE_FEATURES:{
            error = ofl_msg_unpack_multipart_request_table_features(os, len, msg, exp);
            break;
        }
        case OFPMP_PORT_STATS: {
            error = ofl_msg_unpack_multipart_request_port(os, len, msg);
            break;
        }
        case OFPMP_QUEUE: {
            error = ofl_msg_unpack_multipart_request_queue(os, len, msg);
            break;
        }
        case OFPMP_GROUP: {
            error = ofl_msg_unpack_multipart_request_group(os, len, msg);
            break;
        }
        case OFPMP_GROUP_DESC: {
            error = ofl_msg_unpack_multipart_request_empty(os, len, msg);
            break;
        }
        case OFPMP_GROUP_FEATURES:{
            error = ofl_msg_unpack_multipart_request_empty(os, len, msg);
            break;
        }
        case OFPMP_METER:
        case OFPMP_METER_CONFIG:{
            error = ofl_msg_unpack_meter_multipart_request(os, len, msg);
            break;
        }
        case OFPMP_METER_FEATURES:{
            error = ofl_msg_unpack_multipart_request_empty(os, len, msg);
            break;
        }
        case OFPMP_PORT_DESC: {
            error = ofl_msg_unpack_multipart_request_empty(os, len, msg);
            break;
        }
        case OFPMP_EXPERIMENTER: {
            if (exp == NULL || exp->stats == NULL || exp->stats->reply_unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER stats request, but no callback was given.");
                error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART);
            } else {
                error = exp->stats->req_unpack(os, buf, len, (struct ofl_msg_multipart_request_header **)msg, exp);
            }
            break;
        }
        default: {
            error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART);
        }
    }

    if (error) {
        return error;
    }

    ofls = (struct ofl_msg_multipart_request_header *)(*msg);
    ofls->type = (enum ofp_multipart_types)ntohs(os->type);
    ofls->flags = ntohs(os->flags);

    return 0;
}

static ofl_err
ofl_msg_unpack_reply_desc(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_desc *sm;
    struct ofl_msg_reply_desc *dm;

    if (*len < sizeof(struct ofp_desc)) {
        OFL_LOG_WARN(LOG_MODULE, "Received DESC stats reply has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_desc);

    sm = (struct ofp_desc *)os->body;
    dm = (struct ofl_msg_reply_desc *) malloc(sizeof(struct ofl_msg_reply_desc));

    dm->mfr_desc =   (char *)strcpy((char *)malloc(strlen(sm->mfr_desc) + 1), sm->mfr_desc);
    dm->hw_desc =    (char *)strcpy((char *)malloc(strlen(sm->hw_desc) + 1), sm->hw_desc);
    dm->sw_desc =    (char *)strcpy((char *)malloc(strlen(sm->sw_desc) + 1), sm->sw_desc);
    dm->serial_num = (char *)strcpy((char *)malloc(strlen(sm->serial_num) + 1), sm->serial_num);
    dm->dp_desc =    (char *)strcpy((char *)malloc(strlen(sm->dp_desc) + 1), sm->dp_desc);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}


static ofl_err
ofl_msg_unpack_multipart_reply_flow(struct ofp_multipart_reply const *os, uint8_t const *buf, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofp_flow_stats *stat;
    struct ofl_msg_multipart_reply_flow *dm;
    ofl_err error;
    size_t i, ini_len;
    uint8_t const *ptr;

    // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply
    stat = (struct ofp_flow_stats *)os->body;
    dm = (struct ofl_msg_multipart_reply_flow *)malloc(sizeof(struct ofl_msg_multipart_reply_flow));

    error = ofl_utils_count_ofp_flow_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_flow_stats **)malloc(dm->stats_num * sizeof(struct ofl_flow_stats *));

    ini_len = *len;
    ptr = buf + sizeof(struct ofp_multipart_reply);
    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_flow_stats_unpack(stat, ptr, len, &(dm->stats[i]), exp);
        ptr += ini_len - *len;
        ini_len = *len;
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(dm->stats, i,
                                    ofl_structs_free_flow_stats, exp);
            free (dm);
            return error;
        }
        stat = (struct ofp_flow_stats *)((uint8_t *)stat + ntohs(stat->length));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_aggregate(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_aggregate_stats_reply *sm;
    struct ofl_msg_multipart_reply_aggregate *dm;

    // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply

    if (*len < sizeof(struct ofp_aggregate_stats_reply)) {
        OFL_LOG_WARN(LOG_MODULE, "Received AGGREGATE stats reply has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_aggregate_stats_reply);

    sm = (struct ofp_aggregate_stats_reply *)os->body;
    dm = (struct ofl_msg_multipart_reply_aggregate *) malloc(sizeof(struct ofl_msg_multipart_reply_aggregate));

    dm->packet_count = ntoh64(sm->packet_count);
    dm->byte_count =   ntoh64(sm->byte_count);
    dm->flow_count =   ntohl( sm->flow_count);

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_table(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_table_stats *stat;
    struct ofl_msg_multipart_reply_table *dm;
    ofl_err error;
    size_t i;

    // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply

    stat = (struct ofp_table_stats *)os->body;
    dm = (struct ofl_msg_multipart_reply_table *) malloc(sizeof(struct ofl_msg_multipart_reply_table));

    error = ofl_utils_count_ofp_table_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_table_stats **)malloc(dm->stats_num * sizeof(struct ofl_table_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_table_stats_unpack(stat, len, &(dm->stats[i]));
        if (error) {
            OFL_UTILS_FREE_ARR(dm->stats, i);
            free(dm);
            return error;
        }
        stat = (struct ofp_table_stats *)((uint8_t *)stat + sizeof(struct ofp_table_stats));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_port(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_port_stats *stat = (struct ofp_port_stats *)os->body;
    struct ofl_msg_multipart_reply_port *dm = (struct ofl_msg_multipart_reply_port *) malloc(sizeof(struct ofl_msg_multipart_reply_port));
    ofl_err error;
    size_t i;

    // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply

    stat = (struct ofp_port_stats *)os->body;

    error = ofl_utils_count_ofp_port_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }

    dm->stats = (struct ofl_port_stats **)malloc(dm->stats_num * sizeof(struct ofl_port_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_port_stats_unpack(stat, len, &(dm->stats[i]));
        if (error) {
            OFL_UTILS_FREE_ARR(dm->stats, i);
            free(dm);
            return error;
        }
        stat = (struct ofp_port_stats *)((uint8_t *)stat + sizeof(struct ofp_port_stats));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_queue(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_queue_stats *stat = (struct ofp_queue_stats *)os->body;
    struct ofl_msg_multipart_reply_queue *dm = (struct ofl_msg_multipart_reply_queue *) malloc(sizeof(struct ofl_msg_multipart_reply_queue));
    ofl_err error;
    size_t i;

    // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply

    stat = (struct ofp_queue_stats *)os->body;

    error = ofl_utils_count_ofp_queue_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_queue_stats **)malloc(dm->stats_num * sizeof(struct ofl_queue_stats *));
    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_queue_stats_unpack(stat, len, &(dm->stats[i]));
        if (error) {
            OFL_UTILS_FREE_ARR(dm->stats, i);
            free(dm);
            return error;
        }
        stat = (struct ofp_queue_stats *)((uint8_t *)stat + sizeof(struct ofp_queue_stats));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_group(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_group_stats *stat;
    struct ofl_msg_multipart_reply_group *dm;
    ofl_err error;
    size_t i;

    // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply

    stat = (struct ofp_group_stats *)os->body;
    dm = (struct ofl_msg_multipart_reply_group *) malloc(sizeof(struct ofl_msg_multipart_reply_group));

    error = ofl_utils_count_ofp_group_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_group_stats **)malloc(dm->stats_num * sizeof(struct ofl_group_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_group_stats_unpack(stat, len, &(dm->stats[i]));
        if (error) {
            OFL_UTILS_FREE_ARR_FUN(dm->stats, i,
                                   ofl_structs_free_group_stats);
            free (dm);
            return error;
        }
        stat = (struct ofp_group_stats *)((uint8_t *)stat + ntohs(stat->length));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_group_desc(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofp_group_desc_stats *stat;
    struct ofl_msg_multipart_reply_group_desc *dm;
    ofl_err error;
    size_t i;

    // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply

    stat = (struct ofp_group_desc_stats *)os->body;
    dm = (struct ofl_msg_multipart_reply_group_desc *) malloc(sizeof(struct ofl_msg_multipart_reply_group_desc));

    error = ofl_utils_count_ofp_group_desc_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_group_desc_stats **)malloc(dm->stats_num * sizeof(struct ofl_group_desc_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_group_desc_stats_unpack(stat, len, &(dm->stats[i]), exp);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(dm->stats, i,
                                    ofl_structs_free_group_desc_stats, exp);
            free (dm);
            return error;
        }
        stat = (struct ofp_group_desc_stats *)((uint8_t *)stat + ntohs(stat->length));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_group_features(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_group_features_stats *sm;
    struct ofl_msg_multipart_reply_group_features *dm;
    int i;
    if (*len < sizeof(struct ofp_group_features_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received OFPMP_GROUP_FEATURES stats reply has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_group_features_stats);

    sm = (struct ofp_group_features_stats *)os->body;
    dm = (struct ofl_msg_multipart_reply_group_features *) malloc(sizeof(struct ofl_msg_multipart_reply_group_features));

    dm->types = ntohl(sm->types);
    dm->capabilities = ntohl(sm->capabilities);
    for(i = 0; i < 4; i++){
        dm->max_groups[i] = ntohl(sm->max_groups[i]);
        dm->actions[i] = ntohl(sm->actions[i]);
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_table_features(struct ofp_multipart_reply const *src, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofl_msg_multipart_reply_table_features *dm;
	int i;
	ofl_err error;
	uint8_t *features;

    dm = (struct ofl_msg_multipart_reply_table_features*) malloc(sizeof(struct ofl_msg_multipart_reply_table_features) );

    error = ofl_utils_count_ofp_table_features((uint8_t*) src->body, *len, &dm->tables_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->table_features = (struct ofl_table_features **) malloc(sizeof(struct ofl_table_features *) * dm->tables_num);
    features = (uint8_t* ) src->body;

    for(i = 0; i < dm->tables_num; i++){
        error = ofl_structs_table_features_unpack((struct ofp_table_features*) features, len, &dm->table_features[i] , exp);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(dm->table_features, i,
                                    ofl_structs_free_table_features, exp);
            free(dm);
            return error;
        }
        features += ntohs(((struct ofp_table_features*) features)->length);
    }
    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_meter_stats(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_meter_stats *stat;
    struct ofl_msg_multipart_reply_meter *dm;
    ofl_err error;
    size_t i;

    // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply

    stat = (struct ofp_meter_stats *)os->body;
    dm = (struct ofl_msg_multipart_reply_meter *) malloc(sizeof(struct ofl_msg_multipart_reply_meter));

    error = ofl_utils_count_ofp_meter_stats(stat, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->stats = (struct ofl_meter_stats **)malloc(dm->stats_num * sizeof(struct ofl_meter_stats *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_meter_stats_unpack(stat, len, &(dm->stats[i]));
        if (error) {
           OFL_UTILS_FREE_ARR_FUN(dm->stats, i,
                                   ofl_structs_free_meter_stats);
            free (dm);
            return error;
        }
        stat = (struct ofp_meter_stats *)((uint8_t *)stat + ntohs(stat->len));
    }

    *msg = (struct ofl_msg_header *)dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_meter_config(struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_meter_config *conf;
    struct ofl_msg_multipart_reply_meter_conf *dm;
    ofl_err error;
    size_t i;

    conf = (struct ofp_meter_config*) os->body;
    dm =  (struct ofl_msg_multipart_reply_meter_conf *) malloc(sizeof(struct ofl_msg_multipart_reply_meter_conf));

    error = ofl_utils_count_ofp_meter_config(conf, *len, &dm->stats_num);
    if (error) {
        free(dm);
        return error;
    }

    dm->stats = (struct ofl_meter_config **)malloc(dm->stats_num * sizeof(struct ofl_meter_config *));

    for (i = 0; i < dm->stats_num; i++) {
        error = ofl_structs_meter_config_unpack(conf, len, &(dm->stats[i]));
        if (error) {
            OFL_UTILS_FREE_ARR_FUN(dm->stats, i,
                                   ofl_structs_free_meter_config);
            free (dm);
            return error;
        }
        conf = (struct ofp_meter_config *)((uint8_t *)conf + ntohs(conf->length));
    }


    *msg = (struct ofl_msg_header*) dm;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply_port_desc(struct ofp_multipart_reply const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_port *port;
    struct ofl_msg_multipart_reply_port_desc *pd;
    ofl_err error;
	size_t i;
	port = (struct ofp_port* )src->body;
	pd = (struct ofl_msg_multipart_reply_port_desc*) malloc(sizeof(struct ofl_msg_multipart_reply_port_desc));

	error = ofl_utils_count_ofp_ports(port, *len, &pd->stats_num);
    if (error) {
        free(pd);
        return error;
    }

    pd->stats = (struct ofl_port**) malloc(pd->stats_num * sizeof(struct ofl_port));
	for(i = 0; i < pd->stats_num; i++){
		error = ofl_structs_port_unpack(port, len, &pd->stats[i]);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN(pd->stats, i,
                                   ofl_structs_free_port);
            free (pd);
            return error;
        }
        port = (struct ofp_port *)((uint8_t *)port + sizeof(struct ofp_port));
	}
    *msg = (struct ofl_msg_header *)pd;
    return 0;
}


static ofl_err
ofl_msg_unpack_multipart_reply_meter_features(struct ofp_multipart_reply const *os, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_meter_features const *src;
    struct ofl_msg_multipart_reply_meter_features *dst;

    if(*len < sizeof(struct ofp_meter_features)){
        OFL_LOG_WARN(LOG_MODULE, "Received MULTIPART REPLY message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= sizeof(struct ofp_meter_features);
    src = (struct ofp_meter_features const*) os->body;
    dst = (struct ofl_msg_multipart_reply_meter_features*) malloc(sizeof(struct ofl_msg_multipart_reply_meter_features));
    dst->features = (struct ofl_meter_features*) malloc(sizeof(struct ofl_meter_features));

    dst->features->max_meter = ntohl(src->max_meter);
    dst->features->band_types = ntohl(src->band_types);
    dst->features->capabilities = ntohl(src->capabilities);
    dst->features->max_bands = src->max_bands;
    dst->features->max_color =  src->max_color;

    *msg = (struct ofl_msg_header*) dst;
    return 0;
}

static ofl_err
ofl_msg_unpack_multipart_reply(struct ofp_header const *src, uint8_t const *buf, size_t *len, struct ofl_msg_header **msg, struct ofl_exp const *exp)
{
    struct ofl_msg_multipart_reply_header *ofls;
    struct ofp_multipart_reply *os;
    int error;

    if (*len < sizeof(struct ofp_multipart_reply)) {
        OFL_LOG_WARN(LOG_MODULE, "Received MULTIPART REPLY message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_multipart_reply);
    os = (struct ofp_multipart_reply *)src;
    switch (ntohs(os->type)) {
        case OFPMP_DESC: {
            error = ofl_msg_unpack_reply_desc(os, len, msg);
            break;
        }
        case OFPMP_FLOW: {
            error = ofl_msg_unpack_multipart_reply_flow(os,buf, len, msg, exp);
            break;
        }
        case OFPMP_AGGREGATE: {
            error = ofl_msg_unpack_multipart_reply_aggregate(os, len, msg);
            break;
        }
        case OFPMP_TABLE: {
            error = ofl_msg_unpack_multipart_reply_table(os, len, msg);
            break;
        }
        case OFPMP_TABLE_FEATURES: {
            error = ofl_msg_unpack_multipart_reply_table_features(os, len, msg, exp);
            break;
        }
        case OFPMP_PORT_STATS: {
            error = ofl_msg_unpack_multipart_reply_port(os, len, msg);
            break;
        }
        case OFPMP_QUEUE: {
            error = ofl_msg_unpack_multipart_reply_queue(os, len, msg);
            break;
        }
        case OFPMP_GROUP: {
            error = ofl_msg_unpack_multipart_reply_group(os, len, msg);
            break;
        }
        case OFPMP_GROUP_DESC: {
            error = ofl_msg_unpack_multipart_reply_group_desc(os, len, msg, exp);
            break;
        }
        case OFPMP_GROUP_FEATURES:{
            error = ofl_msg_unpack_multipart_reply_group_features(os, len, msg);
            break;
        }
        case OFPMP_METER:{
            error = ofl_msg_unpack_multipart_reply_meter_stats(os, len, msg);
            break;
        }
        case OFPMP_METER_CONFIG:{
            error = ofl_msg_unpack_multipart_reply_meter_config(os, len, msg);
            break;
        }
        case OFPMP_METER_FEATURES:{
            error = ofl_msg_unpack_multipart_reply_meter_features(os, len, msg);
            break;
        }
		case OFPMP_PORT_DESC:{
			error = ofl_msg_unpack_multipart_reply_port_desc(os, len, msg);
			break;
		}
        case OFPMP_EXPERIMENTER: {
            if (exp == NULL || exp->stats == NULL || exp->stats->reply_unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER stats reply, but no callback was given.");
                error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART);
            } else {
                error = exp->stats->reply_unpack(os, buf, len, (struct ofl_msg_multipart_reply_header **)msg, exp);
            }
            break;
        }
        default: {
            error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_MULTIPART);
        }
    }

    if (error) {
        return error;
    }

    ofls = (struct ofl_msg_multipart_reply_header *)(*msg);
    ofls->type = (enum ofp_multipart_types)ntohs(os->type);
    ofls->flags = ntohs(os->flags);

    return 0;
}

static ofl_err
ofl_msg_unpack_queue_get_config_request(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_queue_get_config_request *sr;
    struct ofl_msg_queue_get_config_request *dr;

    if (*len < sizeof(struct ofp_group_desc_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received GET_CONFIG_REQUEST message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    sr = (struct ofp_queue_get_config_request *)src;

    if (ntohl(sr->port) == 0 || ntohl(sr->port) > OFPP_ANY) {
        OFL_LOG_WARN(LOG_MODULE, "Received GET_CONFIG_REQUEST message has invalid port (%u).", ntohl(sr->port));
        return ofl_error(OFPET_QUEUE_OP_FAILED, OFPQOFC_BAD_PORT);
    }
    *len -= sizeof(struct ofp_queue_get_config_request);

    dr = (struct ofl_msg_queue_get_config_request *)malloc(sizeof(struct ofl_msg_queue_get_config_request));

    dr->port = ntohl(sr->port);

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}

static ofl_err
ofl_msg_unpack_queue_get_config_reply(struct ofp_header const *src, size_t *len, struct ofl_msg_header **msg)
{
    struct ofp_queue_get_config_reply *sr;
    struct ofl_msg_queue_get_config_reply *dr;
    struct ofp_packet_queue *queue;
    ofl_err error;
    size_t i;

    if (*len < sizeof(struct ofp_queue_get_config_reply)) {
        OFL_LOG_WARN(LOG_MODULE, "Received GET_CONFIG_REPLY has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_queue_get_config_reply);

    sr = (struct ofp_queue_get_config_reply *)src;
    dr = (struct ofl_msg_queue_get_config_reply *)malloc(sizeof(struct ofl_msg_queue_get_config_reply));

    dr->port = ntohl(sr->port);

    error = ofl_utils_count_ofp_packet_queues(&(sr->queues), *len, &dr->queues_num);
    if (error) {
        free(dr);
        return error;
    }
    dr->queues = (struct ofl_packet_queue **)malloc(dr->queues_num * sizeof(struct ofl_packet_queue *));

    queue = sr->queues;
    for (i = 0; i < dr->queues_num; i++) {
        error = ofl_structs_packet_queue_unpack(queue, len, &(dr->queues[i]));
        if (error) {
            OFL_UTILS_FREE_ARR_FUN(dr->queues, i,
                                   ofl_structs_free_packet_queue);
            free (dr);
            return error;
        }
        queue = (struct ofp_packet_queue *)((uint8_t *)queue + ntohs(queue->len));
    }

    *msg = (struct ofl_msg_header *)dr;
    return 0;
}


static ofl_err
ofl_msg_unpack_empty(struct ofp_header const *src UNUSED, size_t *len, struct ofl_msg_header **msg)
{
    // ofp_header length was checked at ofl_msg_unpack
    *len -= sizeof(struct ofp_header);

    *msg = (struct ofl_msg_header *)malloc(sizeof(struct ofl_msg_header));
    return 0;
}


ofl_err
ofl_msg_unpack(uint8_t const *buf, size_t buf_len, struct ofl_msg_header **msg, uint32_t *xid, struct ofl_exp const *exp)
{
    struct ofp_header const *oh;
    size_t len = buf_len;
    ofl_err error = 0;
    if (len < sizeof(struct ofp_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received message is shorter than ofp_header.");
        if (xid != NULL) {
            *xid = 0x00000000;
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    oh = (struct ofp_header const *)buf;

    if (oh->version != OFP_VERSION) {
        OFL_LOG_WARN(LOG_MODULE, "Received message has wrong version.");
        return ofl_error(OFPET_HELLO_FAILED, OFPHFC_INCOMPATIBLE);
    }

    if (xid != NULL) {
        *xid = ntohl(oh->xid);
    }

    if (len != ntohs(oh->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received message length does not match the length field.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch (oh->type) {
        case OFPT_HELLO:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;
        case OFPT_ERROR:
            error = ofl_msg_unpack_error(oh, &len, msg);
            break;
        case OFPT_ECHO_REQUEST:
        case OFPT_ECHO_REPLY:
            error = ofl_msg_unpack_echo(oh, &len, msg);
            break;
        case OFPT_EXPERIMENTER:
            if (exp == NULL || exp->msg == NULL || exp->msg->unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message, but no callback was given.");
                error = ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            } else {
                error = exp->msg->unpack(oh, &len, (struct ofl_msg_experimenter **)msg, exp);
            }
            break;

        /* Switch configuration messages. */
        case OFPT_FEATURES_REQUEST:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;
        case OFPT_FEATURES_REPLY:
            error = ofl_msg_unpack_features_reply(oh, &len, msg);
            break;
        case OFPT_GET_CONFIG_REQUEST:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;
        case OFPT_GET_CONFIG_REPLY:
            error = ofl_msg_unpack_get_config_reply(oh, &len, msg);
            break;
        case OFPT_SET_CONFIG:
            error = ofl_msg_unpack_set_config(oh, &len, msg);
            break;

        /* Asynchronous messages. */
        case OFPT_PACKET_IN:
            error = ofl_msg_unpack_packet_in(oh,buf, &len, msg, exp);
            break;
        case OFPT_FLOW_REMOVED:
            error = ofl_msg_unpack_flow_removed(oh,buf, &len, msg, exp);
            break;
        case OFPT_PORT_STATUS:
            error = ofl_msg_unpack_port_status(oh, &len, msg);
            break;

        /* Controller command messages. */
        case OFPT_GET_ASYNC_REQUEST:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;
        case OFPT_GET_ASYNC_REPLY:
        case OFPT_SET_ASYNC:{
            error =  ofl_msg_unpack_async_config(oh, &len, msg);
            break;
        }
        case OFPT_PACKET_OUT:
            error = ofl_msg_unpack_packet_out(oh, &len, msg, exp);
            break;
        case OFPT_FLOW_MOD:
            error = ofl_msg_unpack_flow_mod(oh,buf, &len, msg, exp);
            break;
        case OFPT_GROUP_MOD:
            error = ofl_msg_unpack_group_mod(oh, &len, msg, exp);
            break;
        case OFPT_PORT_MOD:
            error = ofl_msg_unpack_port_mod(oh, &len, msg);
            break;
        case OFPT_TABLE_MOD:
            error = ofl_msg_unpack_table_mod(oh, &len, msg);
            break;

        /* Statistics messages. */
        case OFPT_MULTIPART_REQUEST:
            error = ofl_msg_unpack_multipart_request(oh,buf, &len, msg, exp);
            break;
        case OFPT_MULTIPART_REPLY:
            error = ofl_msg_unpack_multipart_reply(oh,buf, &len, msg, exp);
            break;

        /* Barrier messages. */
        case OFPT_BARRIER_REQUEST:
        case OFPT_BARRIER_REPLY:
            error = ofl_msg_unpack_empty(oh, &len, msg);
            break;

        /* Role messages. */
        case OFPT_ROLE_REQUEST:
        case OFPT_ROLE_REPLY:
            error = ofl_msg_unpack_role_request(oh, &len, msg);
            break;

        /* Queue Configuration messages. */
        case OFPT_QUEUE_GET_CONFIG_REQUEST:
            error = ofl_msg_unpack_queue_get_config_request(oh, &len, msg);
            break;
        case OFPT_QUEUE_GET_CONFIG_REPLY:
            error = ofl_msg_unpack_queue_get_config_reply(oh, &len, msg);
            break;
        case OFPT_METER_MOD:
		error = ofl_msg_unpack_meter_mod(oh, &len, msg);
		break;
	default: {
            error = ofl_error(OFPET_BAD_REQUEST, OFPGMFC_BAD_TYPE);
        }
    }

    if (error) {
        if (OFL_LOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *str = ofl_hex_to_string(buf, buf_len < 1024 ? buf_len : 1024);

            OFL_LOG_DBG(LOG_MODULE, "Error happened after processing %zu bytes of packet.", ntohs(oh->length) - len);
            OFL_LOG_DBG(LOG_MODULE, "\n%s\n", str);
            free(str);
        }
        return error;
    }

    /* Note: len must be decreased by the amount of buffer used by the
             unpack functions. At this point the whole message must be
             consumed, and len should equal to zero. */
    if (len != 0) {
        OFL_LOG_WARN(LOG_MODULE, "Received message seemed to be valid, but it contained unused data (%zu).", len);
        if (OFL_LOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *str = ofl_hex_to_string(buf, buf_len < 1024 ? buf_len : 1024);

            OFL_LOG_DBG(LOG_MODULE, "Error happened after processing %zu bytes of packet.", ntohs(oh->length) - len);
            OFL_LOG_DBG(LOG_MODULE, "\n%s\n", str);
            free(str);
        }
    }

    (*msg)->type = (enum ofp_type)oh->type;

    return 0;
}
