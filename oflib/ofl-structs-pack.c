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

#include "include/openflow/openflow.h"
#include "oxm-match.h"
#include "ofl.h"
#include "ofl-actions.h"
#include "ofl-structs.h"
#include "ofl-utils.h"
#include "ofl-log.h"
#include "ofl-packets.h"


#define LOG_MODULE ofl_str_p
OFL_LOG_INIT(LOG_MODULE)


size_t
ofl_structs_instructions_ofp_len(struct ofl_instruction_header const *instruction, struct ofl_exp const *exp)
{
    switch (instruction->type) {
        case OFPIT_GOTO_TABLE: {
            return sizeof(struct ofp_instruction_goto_table);
        }
        case OFPIT_WRITE_METADATA: {
            return sizeof(struct ofp_instruction_write_metadata);
        }
        case OFPIT_WRITE_ACTIONS:
        case OFPIT_APPLY_ACTIONS: {
            struct ofl_instruction_actions *i = (struct ofl_instruction_actions *)instruction;

            return sizeof(struct ofp_instruction_actions)
                   + ofl_actions_ofp_total_len((struct ofl_action_header const **)i->actions, i->actions_num, exp);
        }
        case OFPIT_CLEAR_ACTIONS: {
            return sizeof(struct ofp_instruction_actions);
        }
        case OFPIT_METER:{
            return sizeof(struct ofp_instruction_meter);
        }
        case OFPIT_EXPERIMENTER: {
            if (exp == NULL || exp->inst == NULL || exp->inst->ofp_len == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to len experimenter instruction, but no callback was given.");
                return -1;
            }
            return exp->inst->ofp_len(instruction);
        }
        default:
            OFL_LOG_WARN(LOG_MODULE, "Trying to len unknown instruction type.");
            return 0;
    }
}

size_t
ofl_structs_instructions_ofp_total_len(struct ofl_instruction_header const **instructions, size_t instructions_num, struct ofl_exp const *exp)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN2(sum, instructions, instructions_num,
            ofl_structs_instructions_ofp_len, exp);
    return sum;
}

size_t
ofl_structs_instructions_pack(struct ofl_instruction_header const *src, struct ofp_instruction *dst, struct ofl_exp const *exp)
{

    dst->type = htons(src->type);
    memset(dst->pad, 0x00, 4);

    switch (src->type) {
        case OFPIT_GOTO_TABLE: {
            struct ofl_instruction_goto_table *si = (struct ofl_instruction_goto_table *)src;
            struct ofp_instruction_goto_table *di = (struct ofp_instruction_goto_table *)dst;

            di->len = htons(sizeof(struct ofp_instruction_goto_table));
            di->table_id = si->table_id;
            memset(di->pad, 0x00, 3);

            return sizeof(struct ofp_instruction_goto_table);
        }
        case OFPIT_WRITE_METADATA: {
            struct ofl_instruction_write_metadata *si = (struct ofl_instruction_write_metadata *)src;
            struct ofp_instruction_write_metadata *di = (struct ofp_instruction_write_metadata *)dst;

            di->len = htons(sizeof(struct ofp_instruction_write_metadata));
            memset(di->pad, 0x00, 4);
            di->metadata = hton64(si->metadata);
            di->metadata_mask = hton64(si->metadata_mask);

            return sizeof(struct ofp_instruction_write_metadata);
        }
        case OFPIT_WRITE_ACTIONS:
        case OFPIT_APPLY_ACTIONS: {
            size_t total_len, len;
            uint8_t *data;
            size_t i;

            struct ofl_instruction_actions *si = (struct ofl_instruction_actions *)src;
            struct ofp_instruction_actions *di = (struct ofp_instruction_actions *)dst;

            total_len = sizeof(struct ofp_instruction_actions) + ofl_actions_ofp_total_len((struct ofl_action_header const **)si->actions, si->actions_num, exp);

            di->len = htons(total_len);
            memset(di->pad, 0x00, 4);
            data = (uint8_t *)dst + sizeof(struct ofp_instruction_actions);

            for (i=0; i<si->actions_num; i++) {
                len = ofl_actions_pack(si->actions[i], (struct ofp_action_header *)data, data, exp);
                data += len;
            }
            return total_len;
        }
        case OFPIT_CLEAR_ACTIONS: {
            size_t total_len;

            struct ofp_instruction_actions *di = (struct ofp_instruction_actions *)dst;

            total_len = sizeof(struct ofp_instruction_actions);

            di->len = htons(total_len);
            memset(di->pad, 0x00, 4);

            return total_len;
        }
        case OFPIT_METER: {
            struct ofl_instruction_meter *si = (struct ofl_instruction_meter *) src;
            struct ofp_instruction_meter *di = (struct ofp_instruction_meter *) dst;

            di->len = htons(sizeof(struct ofp_instruction_meter));
            di->meter_id = htonl(si->meter_id);

            return sizeof(struct ofp_instruction_meter);
        }
        case OFPIT_EXPERIMENTER: {
            if (exp == NULL || exp->inst == NULL || exp->inst->pack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to pack experimenter instruction, but no callback was given.");
                return -1;
            }
            return exp->inst->pack((struct ofl_instruction_header *)src, dst);
        }
        default:
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown instruction type.");
            return 0;
    }
}

size_t
ofl_structs_meter_band_ofp_len(struct ofl_meter_band_header const *meter_band)
{
    switch (meter_band->type) {
        case OFPMBT_DROP:
            return sizeof(struct ofp_meter_band_drop);
        case OFPMBT_DSCP_REMARK:
            return sizeof(struct ofp_meter_band_dscp_remark);
        case OFPMBT_EXPERIMENTER:
            return sizeof(struct ofp_meter_band_experimenter);
        default:
             OFL_LOG_WARN(LOG_MODULE, "Trying to len unknown meter type.");
            return 0;
    }
}

size_t
ofl_structs_meter_bands_ofp_total_len(struct ofl_meter_band_header const **meter_bands, size_t meter_bands_num)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN(sum, meter_bands, meter_bands_num,
            ofl_structs_meter_band_ofp_len);
    return sum;
}

size_t
ofl_structs_meter_band_pack(struct ofl_meter_band_header const *src, struct ofp_meter_band_header *dst)
{

    dst->type = htons(src->type);
    dst->rate = htonl(src->rate);
    dst->burst_size = htonl(src->burst_size);
    switch (src->type) {
        case OFPMBT_DROP:{
            struct ofp_meter_band_drop *di = (struct ofp_meter_band_drop *)dst;
            di->len = htons(sizeof(struct ofp_meter_band_drop));
            memset(di->pad, 0x0, 4);
            return sizeof(struct ofp_meter_band_drop);
        }
        case OFPMBT_DSCP_REMARK:{
            struct ofl_meter_band_dscp_remark *si = (struct ofl_meter_band_dscp_remark*)src;
            struct ofp_meter_band_dscp_remark *di = (struct ofp_meter_band_dscp_remark *)dst;
            di->len = htons(sizeof(struct ofp_meter_band_dscp_remark));
            di->prec_level = si->prec_level;
            memset(di->pad,0x0,3);
            return sizeof(struct ofp_meter_band_dscp_remark);
        }
        case OFPMBT_EXPERIMENTER:{
            struct ofl_meter_band_experimenter *si = (struct ofl_meter_band_experimenter*)src;
            struct ofp_meter_band_experimenter *di = (struct ofp_meter_band_experimenter *)dst;
            di->len = htons(sizeof(struct ofp_meter_band_experimenter));
            di->experimenter = htonl(si->experimenter);
            return sizeof(struct ofp_meter_band_experimenter);
        }
        default:
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown meter band.");
            return 0;
    }
}

size_t
ofl_structs_table_features_properties_ofp_len(struct ofl_table_feature_prop_header const *prop, struct ofl_exp const *exp)
{

    switch(prop->type){
        case OFPTFPT_INSTRUCTIONS:
        case OFPTFPT_INSTRUCTIONS_MISS:{
             struct ofl_table_feature_prop_instructions *inst_prop = (struct ofl_table_feature_prop_instructions*) prop;
             int len = 0;
             int i;
             for(i = 0; i < inst_prop->ids_num; i++){
				if (inst_prop->instruction_ids[i].type == OFPIT_EXPERIMENTER) {
                     if (exp == NULL || exp->inst == NULL || exp->inst->unpack == NULL) {
                        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER instruction, but no callback was given.");
                        return ofl_error(OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST);
                    }
                     len += sizeof(struct ofp_instruction) + exp->inst->ofp_len(&inst_prop->instruction_ids[i]);
                 }
                 else {
                     len += sizeof(struct ofp_instruction) - 4;
                 }
             }
            /* The size is rounded in order to comply with padding bytes */
            return sizeof(struct ofp_table_feature_prop_instructions) + len ;
        }
        case OFPTFPT_NEXT_TABLES:
        case OFPTFPT_NEXT_TABLES_MISS:{
             struct ofl_table_feature_prop_next_tables * table_prop = (struct ofl_table_feature_prop_next_tables *) prop;
             return sizeof(struct ofp_table_feature_prop_next_tables) + (table_prop->table_num * sizeof(uint8_t));
        }

        case OFPTFPT_WRITE_ACTIONS:
        case OFPTFPT_WRITE_ACTIONS_MISS:
        case OFPTFPT_APPLY_ACTIONS:
        case OFPTFPT_APPLY_ACTIONS_MISS:{
             struct ofl_table_feature_prop_actions *act_prop = (struct ofl_table_feature_prop_actions*) prop;
             int len = 0;
             int i;
             for(i = 0; i < act_prop->actions_num; i++){
				 if (act_prop->action_ids[i].type == OFPAT_EXPERIMENTER)
                     len += 8;
                 else
                     len += 4;
             }
            return sizeof(struct ofp_table_feature_prop_actions) + len;
        }
        case OFPTFPT_MATCH:
        case OFPTFPT_WILDCARDS:
        case OFPTFPT_WRITE_SETFIELD:
        case OFPTFPT_WRITE_SETFIELD_MISS:
        case OFPTFPT_APPLY_SETFIELD:
        case OFPTFPT_APPLY_SETFIELD_MISS:{
             struct ofl_table_feature_prop_oxm * oxm_prop = (struct ofl_table_feature_prop_oxm *) prop;
             return sizeof(struct ofp_table_feature_prop_oxm) + (oxm_prop->oxm_num * sizeof(uint32_t));
        }
        case OFPTFPT_EXPERIMENTER:
        case OFPTFPT_EXPERIMENTER_MISS:{

        }
        default:
            return 0;
    }
}

size_t
ofl_structs_table_features_properties_ofp_total_len(struct ofl_table_feature_prop_header const **props, size_t features_num, struct ofl_exp const *exp)
{
    int i;
    size_t sum = 0;
    size_t sum_check;
    for(i = 0; i < features_num; i++){
        /* Length is padded to 8  bytes */
        sum += ROUND_UP(props[i]->length, 8);

	/* Sanity check ! Jean II */
	sum_check = ofl_structs_table_features_properties_ofp_len(props[i], exp);
	if(props[i]->length != sum_check)
	  OFL_LOG_WARN(LOG_MODULE, "Table feature property %X has unexpected length, %u != %zu.", props[i]->type, props[i]->length, sum_check);

    }
	return sum;
}

size_t ofl_structs_table_features_ofp_total_len(struct ofl_table_features const **feat, size_t tables_num, struct ofl_exp const * exp)
{
    int i, total_len;
    total_len = 0;
    for(i = 0; i < tables_num; i++){
        total_len +=  sizeof(struct ofp_table_features) + ofl_structs_table_features_properties_ofp_total_len((struct ofl_table_feature_prop_header const **)feat[i]->properties, feat[i]->properties_num, exp);
    }
    return total_len;
}

size_t
ofl_structs_table_properties_pack(struct ofl_table_feature_prop_header const * src, struct ofp_table_feature_prop_header *dst, uint8_t *data, struct ofl_exp const *exp)
{

    dst->type = htons(src->type);
    switch (src->type){
        case OFPTFPT_INSTRUCTIONS:
        case OFPTFPT_INSTRUCTIONS_MISS:{
            int i;
            struct ofl_table_feature_prop_instructions *sp = (struct ofl_table_feature_prop_instructions*) src;
            struct ofp_table_feature_prop_instructions *dp = (struct ofp_table_feature_prop_instructions*) dst;
            uint8_t *ptr;

            dp->length = htons(sp->header.length);
            ptr = (uint8_t*) data + (sizeof(struct ofp_table_feature_prop_header));
            for(i = 0; i < sp->ids_num; i++){
                if(sp->instruction_ids[i].type == OFPIT_EXPERIMENTER){
                    struct ofp_instruction inst;

                    inst.type = sp->instruction_ids[i].type;
                    if (exp == NULL || exp->inst == NULL || exp->inst->unpack == NULL) {
                        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER instruction, but no callback was given.");
                        return ofl_error(OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST);
                    }
                    inst.len = ROUND_UP(sizeof(struct ofp_instruction) + exp->inst->ofp_len(&sp->instruction_ids[i]),8);
                    memcpy(ptr, &inst, sizeof(struct ofp_instruction) - 4);
                    ptr += sizeof(struct ofp_instruction) - 4;
                }
                else {
                    struct ofp_instruction inst;
                    inst.type = htons(sp->instruction_ids[i].type);
                    inst.len = htons(sizeof(struct ofp_instruction) - 4);
                    memcpy(ptr, &inst, sizeof(struct ofp_instruction) - 4);
                    ptr += sizeof(struct ofp_instruction) - 4;
                }
            }
           memset(ptr, 0x0, ROUND_UP(sp->header.length,8) - sp->header.length);
           return ROUND_UP(ntohs(dp->length),8);
        }
        case OFPTFPT_NEXT_TABLES:
        case OFPTFPT_NEXT_TABLES_MISS:{
            int i;
            uint8_t *ptr;
            struct ofl_table_feature_prop_next_tables *sp = (struct ofl_table_feature_prop_next_tables*) src;
            struct ofp_table_feature_prop_next_tables *dp = (struct ofp_table_feature_prop_next_tables*) dst;

            dp->length = htons(sp->header.length);
            ptr = data + (sizeof(struct ofp_table_feature_prop_header));
            for(i = 0; i < sp->table_num; i++){
                memcpy(ptr, &sp->next_table_ids[i], sizeof(uint8_t));
                ptr += sizeof(uint8_t);
            }
            memset(ptr, 0x0, ROUND_UP(sp->header.length,8)-sp->header.length);
           return ROUND_UP(ntohs(dp->length),8);
        }
        case OFPTFPT_WRITE_ACTIONS:
        case OFPTFPT_WRITE_ACTIONS_MISS:
        case OFPTFPT_APPLY_ACTIONS:
        case OFPTFPT_APPLY_ACTIONS_MISS:{
            int i;
            uint8_t *ptr;

            struct ofl_table_feature_prop_actions *sp = (struct ofl_table_feature_prop_actions*) src;
            struct ofp_table_feature_prop_actions *dp = (struct ofp_table_feature_prop_actions*) dst;

            dp->length = htons(sp->header.length);
            ptr = data + (sizeof(struct ofp_table_feature_prop_header));
            for(i = 0; i < sp->actions_num; i++){
                if(sp->action_ids[i].type == OFPAT_EXPERIMENTER){
                    memcpy(ptr, &sp->action_ids[i], sizeof(struct ofp_action_header));
                    ptr += sizeof(struct ofp_action_header);
                }
                else {
                    struct ofp_action_header action;
                    action.type = htons(sp->action_ids[i].type);
                    action.len = htons(sp->action_ids[i].len);
                    memcpy(ptr, &action, sizeof(struct ofp_action_header) -4);
                    ptr += sizeof(struct ofp_action_header) -4;
                }
            }
           memset(ptr, 0x0, ROUND_UP(sp->header.length,8)- sp->header.length);
           return ROUND_UP(ntohs(dp->length),8);
        }
        case OFPTFPT_MATCH:
        case OFPTFPT_WILDCARDS:
        case OFPTFPT_WRITE_SETFIELD:
        case OFPTFPT_WRITE_SETFIELD_MISS:
        case OFPTFPT_APPLY_SETFIELD:
        case OFPTFPT_APPLY_SETFIELD_MISS:{
            int i;
            struct ofl_table_feature_prop_oxm *sp = (struct ofl_table_feature_prop_oxm*) src;
            struct ofp_table_feature_prop_oxm *dp = (struct ofp_table_feature_prop_oxm*) dst;

            dp->length = htons(sp->header.length);
            data += sizeof(struct ofp_table_feature_prop_header);
            for(i = 0; i < sp->oxm_num; i++){
                uint32_t header = htonl(sp->oxm_ids[i]);
                memcpy(data, &header, sizeof(uint32_t));
                data += sizeof(uint32_t);
            }
           memset(data, 0x0, ROUND_UP(sp->header.length,8)- sp->header.length);
           return ROUND_UP(ntohs(dp->length),8);
        }
        case OFPTFPT_EXPERIMENTER:
        case OFPTFPT_EXPERIMENTER_MISS:{

        }
        default:
            return 0;
    }
}

size_t
ofl_structs_table_features_pack(struct ofl_table_features const *src, struct ofp_table_features *dst, uint8_t *data,  struct ofl_exp const *exp)
{
    size_t total_len;
    uint8_t *ptr;
    int i;


    total_len = sizeof(struct ofp_table_features) + ofl_structs_table_features_properties_ofp_total_len((struct ofl_table_feature_prop_header const **)src->properties,src->properties_num,exp);
    dst->table_id = src->table_id;
    memset(dst->pad, 0x0,5);
    strncpy(dst->name,src->name, OFP_MAX_TABLE_NAME_LEN);
    dst->metadata_match = hton64(src->metadata_match);
    dst->metadata_write = hton64(src->metadata_write);
    dst->config = htonl(src->config);
    dst->max_entries = htonl(src->max_entries);

    ptr = (uint8_t*) (data + sizeof(struct ofp_table_features));
    for(i = 0; i < src->properties_num; i++){
        ptr += ofl_structs_table_properties_pack(src->properties[i], (struct ofp_table_feature_prop_header*) ptr, ptr, exp);
    }
    dst->length = htons(total_len);
    return total_len;
}

size_t
ofl_structs_buckets_ofp_len(struct ofl_bucket const *bucket, struct ofl_exp const *exp)
{
    size_t total_len, rem;

    total_len = sizeof(struct ofp_bucket) + ofl_actions_ofp_total_len((struct ofl_action_header const **)bucket->actions, bucket->actions_num, exp);
    /* Note: buckets are 64 bit aligned according to spec 1.1 */
    rem = total_len % 8;
    return total_len + (rem == 0 ? 0 : (8 - rem));
}

size_t
ofl_structs_buckets_ofp_total_len(struct ofl_bucket const **buckets, size_t buckets_num, struct ofl_exp const *exp)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN2(sum, buckets, buckets_num,
            ofl_structs_buckets_ofp_len, exp);
    return sum;
}

size_t
ofl_structs_bucket_pack(struct ofl_bucket const *src, struct ofp_bucket *dst, struct ofl_exp const *exp)
{
    size_t total_len, rem, align, len;
    uint8_t *data;
    size_t i;

    total_len = sizeof(struct ofp_bucket) + ofl_actions_ofp_total_len((struct ofl_action_header const **)src->actions, src->actions_num, exp);
    /* Note: buckets are 64 bit aligned according to spec 1.1 draft 3 */
    rem = total_len % 8;
    align = rem == 0 ? 0 : (8-rem);
    total_len += align;

    dst->len = htons(total_len);
    dst->weight = htons(src->weight);
    dst->watch_port = htonl(src->watch_port);
    dst->watch_group = htonl(src->watch_group);
    memset(dst->pad, 0x00, 4);

    data = (uint8_t *)dst + sizeof(struct ofp_bucket);

    for (i=0; i<src->actions_num; i++) {
        len = ofl_actions_pack(src->actions[i], (struct ofp_action_header *)data, data, exp);
        data += len;
    }

    memset(data, 0x00, align);

    return total_len;
}


size_t
ofl_structs_flow_stats_ofp_len(struct ofl_flow_stats const *stats, struct ofl_exp const *exp)
{

    return ROUND_UP((sizeof(struct ofp_flow_stats) - 4) + stats->match->length,8) +
           ofl_structs_instructions_ofp_total_len((struct ofl_instruction_header const **)stats->instructions, stats->instructions_num, exp);
}

size_t
ofl_structs_flow_stats_ofp_total_len(struct ofl_flow_stats const ** stats, size_t stats_num, struct ofl_exp const *exp)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN2(sum, stats, stats_num,
            ofl_structs_flow_stats_ofp_len, exp);
    return sum;
}


size_t
ofl_structs_flow_stats_pack(struct ofl_flow_stats const *src, uint8_t *dst, struct ofl_exp const *exp)
{

    struct ofp_flow_stats *flow_stats;
    size_t total_len;
    uint8_t *data;
    size_t  i;

    total_len = ROUND_UP(sizeof(struct ofp_flow_stats) -4 + src->match->length,8) +
                ofl_structs_instructions_ofp_total_len((struct ofl_instruction_header const **)src->instructions, src->instructions_num, exp);

    flow_stats = (struct ofp_flow_stats*) dst;

    flow_stats->length = htons(total_len);
    flow_stats->table_id = src->table_id;
    flow_stats->pad = 0x00;
    flow_stats->duration_sec = htonl(src->duration_sec);
    flow_stats->duration_nsec = htonl(src->duration_nsec);
    flow_stats->priority = htons(src->priority);
    flow_stats->idle_timeout = htons(src->idle_timeout);
    flow_stats->hard_timeout = htons(src->hard_timeout);
    flow_stats->flags = htons(src->flags);
    memset(flow_stats->pad2, 0x00, 4);
    flow_stats->cookie = hton64(src->cookie);
    flow_stats->packet_count = hton64(src->packet_count);
    flow_stats->byte_count = hton64(src->byte_count);
    data = (dst) + sizeof(struct ofp_flow_stats) - 4;

    ofl_structs_match_pack(src->match, &(flow_stats->match), data, exp);
    data = (dst) + ROUND_UP(sizeof(struct ofp_flow_stats) -4 + src->match->length, 8);

    for (i=0; i < src->instructions_num; i++) {
        data += ofl_structs_instructions_pack(src->instructions[i], (struct ofp_instruction *) data, exp);
    }
    return total_len;
}

size_t
ofl_structs_group_stats_ofp_len(struct ofl_group_stats const *stats)
{
    return sizeof(struct ofp_group_stats) +
           sizeof(struct ofp_bucket_counter) * stats->counters_num;
}

size_t
ofl_structs_group_stats_ofp_total_len(struct ofl_group_stats const ** stats, size_t stats_num)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN(sum, stats, stats_num,
            ofl_structs_group_stats_ofp_len);
    return sum;
}

size_t
ofl_structs_group_stats_pack(struct ofl_group_stats const *src, struct ofp_group_stats *dst)
{
    size_t total_len, len;
    uint8_t *data;
    size_t i;

    total_len = sizeof(struct ofp_group_stats) +
                sizeof(struct ofp_bucket_counter) * src->counters_num;

    dst->length =       htons( total_len);
    memset(dst->pad, 0x00, 2);
    dst->group_id =     htonl( src->group_id);
    dst->ref_count =    htonl( src->ref_count);
    memset(dst->pad2, 0x00, 4);
    dst->packet_count = hton64(src->packet_count);
    dst->byte_count =   hton64(src->byte_count);
    dst->duration_sec =  htonl(src->duration_sec);
    dst->duration_nsec =  htonl(src->duration_nsec);

    data = (uint8_t *)dst->bucket_stats;

    for (i=0; i<src->counters_num; i++) {
        len = ofl_structs_bucket_counter_pack(src->counters[i], (struct ofp_bucket_counter *)data);
        data += len;
    }

    return total_len;
}

size_t
ofl_structs_meter_stats_ofp_len(struct ofl_meter_stats const *stats)
{
    return sizeof(struct ofp_meter_stats) +
                sizeof(struct ofp_meter_band_stats) * stats->meter_bands_num;
}

size_t
ofl_structs_pack_band_stats(struct ofl_meter_band_stats const *src, struct ofp_meter_band_stats *dst)
{

    dst->packet_band_count = hton64(src->packet_band_count);
    dst->byte_band_count = hton64(src->byte_band_count);

    return sizeof(struct ofp_meter_band_stats);
}

size_t
ofl_structs_meter_stats_ofp_total_len(struct ofl_meter_stats const **stats, size_t stats_num)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN(sum, stats, stats_num,
            ofl_structs_meter_stats_ofp_len);
    return sum;
}

size_t
ofl_structs_meter_stats_pack(struct ofl_meter_stats const *src, struct ofp_meter_stats *dst)
{
    size_t total_len;
    size_t i;

    total_len = sizeof(struct ofp_meter_stats) +
                sizeof(struct ofp_meter_band_stats) * src->meter_bands_num;

    dst->meter_id = htonl(src->meter_id);
    dst->len =       htons( total_len);
    memset(dst->pad, 0x00, 6);
    dst->flow_count =     htonl(src->flow_count);
    dst->packet_in_count =    hton64( src->packet_in_count);
    dst->byte_in_count = hton64(src->byte_in_count);
    dst->duration_sec =  htonl(src->duration_sec);
    dst->duration_nsec =  htonl(src->duration_nsec);

    for(i = 0; i < src->meter_bands_num; i++){
        ofl_structs_pack_band_stats(src->band_stats[i], &dst->band_stats[i]);
    }
    return total_len;


}

size_t
ofl_structs_meter_conf_ofp_len(struct ofl_meter_config const * meter_conf)
{
    return sizeof(struct ofp_meter_config) +
        ofl_structs_meter_bands_ofp_total_len((struct ofl_meter_band_header const **)meter_conf->bands, meter_conf->meter_bands_num);
}

size_t
ofl_structs_meter_conf_ofp_total_len(struct ofl_meter_config const **meter_conf, size_t stats_num)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN(sum, meter_conf, stats_num,
            ofl_structs_meter_conf_ofp_len);
    return sum;
}

size_t
ofl_structs_meter_conf_pack(struct ofl_meter_config const *src, struct ofp_meter_config *dst, uint8_t* data)
{
    size_t total_len, len;
    int i;

    total_len = sizeof(struct ofp_meter_config) +
        ofl_structs_meter_bands_ofp_total_len((struct ofl_meter_band_header const **)src->bands, src->meter_bands_num);

    dst->length = ntohs(total_len);
    dst->flags = ntohs(src->flags);
    dst->meter_id = ntohl(src->meter_id);

    data = (uint8_t *)dst->bands;

    for (i=0; i<src->meter_bands_num; i++) {
        len = ofl_structs_meter_band_pack(src->bands[i], (struct ofp_meter_band_header *)data);
        data += len;
    }
    return total_len;
}

size_t
ofl_structs_group_desc_stats_ofp_len(struct ofl_group_desc_stats const *stats, struct ofl_exp const *exp)
{
    return sizeof(struct ofp_group_desc_stats) +
           ofl_structs_buckets_ofp_total_len((struct ofl_bucket const **)stats->buckets, stats->buckets_num, exp);
}

size_t
ofl_structs_group_desc_stats_ofp_total_len(struct ofl_group_desc_stats const ** stats, size_t stats_num, struct ofl_exp const *exp)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN2(sum, stats, stats_num,
            ofl_structs_group_desc_stats_ofp_len, exp);
    return sum;
}

size_t
ofl_structs_group_desc_stats_pack(struct ofl_group_desc_stats const *src, struct ofp_group_desc_stats *dst, struct ofl_exp const *exp)
{
    size_t total_len, len;
    uint8_t *data;
    size_t i;

    total_len = sizeof(struct ofp_group_desc_stats) +
            ofl_structs_buckets_ofp_total_len((struct ofl_bucket const **)src->buckets, src->buckets_num, exp);

    dst->length =       htons( total_len);
    dst->type =                src->type;
    dst->pad = 0x00;
    dst->group_id =     htonl( src->group_id);

    data = (uint8_t *)dst->buckets;

    for (i=0; i<src->buckets_num; i++) {
        len = ofl_structs_bucket_pack(src->buckets[i], (struct ofp_bucket *)data, exp);
        data += len;
    }

    return total_len;
}


size_t
ofl_structs_queue_prop_ofp_total_len(struct ofl_queue_prop_header const ** props, size_t props_num)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN(sum, props, props_num,
            ofl_structs_queue_prop_ofp_len);
    return sum;
}

size_t
ofl_structs_queue_prop_ofp_len(struct ofl_queue_prop_header const *prop)
{
    switch (prop->type) {

        case OFPQT_MIN_RATE: {
            return sizeof(struct ofp_queue_prop_min_rate);
        }
        case OFPQT_MAX_RATE:{
           return sizeof(struct ofp_queue_prop_max_rate);
        }
        case OFPQT_EXPERIMENTER:{
           return sizeof(struct ofp_queue_prop_experimenter);
        }
    }
    return 0;
}

size_t
ofl_structs_queue_prop_pack(struct ofl_queue_prop_header const *src, struct ofp_queue_prop_header *dst)
{
    dst->property = htons(src->type);
    memset(dst->pad, 0x00, 4);

    switch (src->type) {

        case OFPQT_MIN_RATE: {
            struct ofl_queue_prop_min_rate *sp = (struct ofl_queue_prop_min_rate *)src;
            struct ofp_queue_prop_min_rate *dp = (struct ofp_queue_prop_min_rate *)dst;

            dp->prop_header.len = htons(sizeof(struct ofp_queue_prop_min_rate));
            dp->rate            = htons(sp->rate);
            memset(dp->pad, 0x00, 6);

            return sizeof(struct ofp_queue_prop_min_rate);
        }
        case OFPQT_MAX_RATE:{
            struct ofl_queue_prop_max_rate *sp = (struct ofl_queue_prop_max_rate *)src;
            struct ofp_queue_prop_max_rate *dp = (struct ofp_queue_prop_max_rate *)dst;
            dp->prop_header.len = htons(sizeof(struct ofp_queue_prop_max_rate));
            dp->rate            = htons(sp->rate);
            memset(dp->pad, 0x00, 6);

            return sizeof(struct ofp_queue_prop_max_rate);
        }
        case OFPQT_EXPERIMENTER:{
            //struct ofl_queue_prop_experimenter *sp = (struct ofl_queue_prop_experimenter *)src;
            struct ofp_queue_prop_experimenter *dp = (struct ofp_queue_prop_experimenter*)dst;
            dp->prop_header.len = htons(sizeof(struct ofp_queue_prop_experimenter));
            memset(dp->pad, 0x00, 4);
            /*TODO Eder: How to copy without a know len?? */
            //dp->data = sp->data;
            return sizeof(struct ofp_queue_prop_experimenter);
        }
        default: {
            return 0;
        }
    }

}

size_t
ofl_structs_packet_queue_ofp_total_len(struct ofl_packet_queue const ** queues, size_t queues_num)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN(sum, queues, queues_num,
            ofl_structs_packet_queue_ofp_len);
    return sum;
}

size_t
ofl_structs_packet_queue_ofp_len(struct ofl_packet_queue const *queue)
{
    return sizeof(struct ofp_packet_queue) +
           ofl_structs_queue_prop_ofp_total_len((struct ofl_queue_prop_header const **)queue->properties,
                                                queue->properties_num);
}

size_t
ofl_structs_packet_queue_pack(struct ofl_packet_queue const *src, struct ofp_packet_queue *dst)
{
    size_t total_len, len;
    uint8_t *data;
    size_t i;

    total_len = sizeof(struct ofp_packet_queue) +
                ofl_structs_queue_prop_ofp_total_len((struct ofl_queue_prop_header const **)src->properties,
                                                     src->properties_num);

    dst->len = htons(total_len);
    memset(dst->pad, 0x00, 2);
    dst->queue_id = htonl(src->queue_id);

    data = (uint8_t *)dst + sizeof(struct ofp_packet_queue);

    for (i=0; i<src->properties_num; i++) {
        len = ofl_structs_queue_prop_pack(src->properties[i],
                                        (struct ofp_queue_prop_header *)data);
        data += len;
    }

    return total_len;
}


size_t
ofl_structs_port_pack(struct ofl_port const *src, struct ofp_port *dst)
{
    dst->port_no    = htonl(src->port_no);
    memset(dst->pad, 0x00, 4);
    memcpy(dst->hw_addr, src->hw_addr, ETH_ADDR_LEN);
    memset(dst->pad2, 0x00, 2);
    strncpy(dst->name, src->name, OFP_MAX_PORT_NAME_LEN);
    dst->config     = htonl(src->config);
    dst->state      = htonl(src->state);
    dst->curr       = htonl(src->curr);
    dst->advertised = htonl(src->advertised);
    dst->supported  = htonl(src->supported);
    dst->peer       = htonl(src->peer);
    dst->curr_speed = htonl(src->curr_speed);
    dst->max_speed  = htonl(src->max_speed);

    return sizeof(struct ofp_port);
}

size_t
ofl_structs_table_stats_pack(struct ofl_table_stats const *src, struct ofp_table_stats *dst)
{
    dst->table_id =    src->table_id;
    memset(dst->pad, 0x00, 3);
    dst->active_count =  htonl( src->active_count);
    dst->lookup_count =  hton64(src->lookup_count);
    dst->matched_count = hton64(src->matched_count);

    return sizeof(struct ofp_table_stats);
}

size_t
ofl_structs_port_stats_pack(struct ofl_port_stats const *src, struct ofp_port_stats *dst)
{
    dst->port_no      = htonl( src->port_no);
    memset(dst->pad, 0x00, 4);
    dst->rx_packets   = hton64(src->rx_packets);
    dst->tx_packets   = hton64(src->tx_packets);
    dst->rx_bytes     = hton64(src->rx_bytes);
    dst->tx_bytes     = hton64(src->tx_bytes);
    dst->rx_dropped   = hton64(src->rx_dropped);
    dst->tx_dropped   = hton64(src->tx_dropped);
    dst->rx_errors    = hton64(src->rx_errors);
    dst->tx_errors    = hton64(src->tx_errors);
    dst->rx_frame_err = hton64(src->rx_frame_err);
    dst->rx_over_err  = hton64(src->rx_over_err);
    dst->rx_crc_err   = hton64(src->rx_crc_err);
    dst->collisions   = hton64(src->collisions);
    dst->duration_sec =  htonl(src->duration_sec);
    dst->duration_nsec =  htonl(src->duration_nsec);

    return sizeof(struct ofp_port_stats);
}

size_t
ofl_structs_queue_stats_pack(struct ofl_queue_stats const *src, struct ofp_queue_stats *dst)
{
    dst->port_no = htonl(src->port_no);
    dst->queue_id = htonl(src->queue_id);
    dst->tx_bytes = hton64(src->tx_bytes);
    dst->tx_packets = hton64(src->tx_packets);
    dst->tx_errors = hton64(src->tx_errors);
    dst->duration_sec = ntohl(src->duration_sec);
    dst->duration_nsec = ntohl(src->duration_nsec);

    return sizeof(struct ofp_queue_stats);
}

size_t
ofl_structs_bucket_counter_pack(struct ofl_bucket_counter const *src, struct ofp_bucket_counter *dst)
{
    dst->packet_count = hton64(src->packet_count);
    dst->byte_count = hton64(src->byte_count);

    return sizeof(struct ofp_bucket_counter);
}


size_t
ofl_structs_match_ofp_len(struct ofl_match_header const *match, struct ofl_exp const *exp)
{
    switch (match->type) {
        case (OFPMT_STANDARD): {
            return (sizeof(struct ofp_match));
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->ofp_len == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to len experimenter match, but no callback was given.");
                return 0;
            }
            return exp->match->ofp_len(match);
        }
    }
}

size_t
ofl_structs_match_pack(struct ofl_match_header const *src, struct ofp_match *dst, uint8_t * oxm_fields, struct ofl_exp const *exp)
{
    switch (src->type) {
        case (OFPMT_OXM): {
            struct ofl_match *m = (struct ofl_match *)src;
            struct ofpbuf *b = ofpbuf_new(0);
            int oxm_len;
            dst->type = htons(m->header.type);
            oxm_fields = (uint8_t*) &dst->oxm_fields;
            dst->length = htons(sizeof(struct ofp_match) - 4);
            if (src->length){
                oxm_len = oxm_put_match(b, m, exp);
                memcpy(oxm_fields, (uint8_t*) ofpbuf_pull(b, oxm_len), oxm_len);
                dst->length = htons(oxm_len + ((sizeof(struct ofp_match )-4)));
                ofpbuf_delete(b);
                return ntohs(dst->length);
            }
            else return 0;
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->pack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to pack experimenter match, but no callback was given.");
                return -1;
            }
            return exp->match->pack(src, dst);
        }
    }
}

