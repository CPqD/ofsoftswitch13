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
#include "ofl.h"
#include "ofl-structs.h"
#include "ofl-actions.h"
#include "ofl-utils.h"
#include "ofl-log.h"
#include "hmap.h"
#include "openflow/openflow.h"

#define UNUSED __attribute__((__unused__))

#define LOG_MODULE ofl_str
OFL_LOG_INIT(LOG_MODULE)

ofl_err
ofl_utils_count_ofp_table_features_properties(void const *data, size_t data_len, size_t *count)
{

    struct ofp_table_feature_prop_header *prop;
    uint8_t *d;

    d = (uint8_t*) data;
    *count = 0;
    while (data_len >= sizeof(struct ofp_table_feature_prop_header)){
        prop = (struct ofp_table_feature_prop_header *) d;
        if (data_len < ntohs(prop->length) || ntohs(prop->length) < sizeof(struct ofp_table_feature_prop_header) ){
             OFL_LOG_WARN(LOG_MODULE, "Received property has invalid length (prop->length=%d, data_len=%d).", ntohs(prop->length), (int) data_len);
             return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
        }
        data_len -= ROUND_UP(ntohs(prop->length), 8);
        d += ROUND_UP(ntohs(prop->length), 8);
        (*count)++;
    }
    return 0;
}

ofl_err
ofl_utils_count_ofp_table_features(void const *data, size_t data_len, size_t *count)
{
    struct ofp_table_features *feature;
    uint8_t *d;

    d = (uint8_t*) data;
    *count = 0;
    while (data_len >= sizeof(struct ofp_table_features)){
        feature = (struct ofp_table_features *) d;
        if (data_len < ntohs(feature->length) || ntohs(feature->length) < sizeof(struct ofp_table_features) ){
             OFL_LOG_WARN(LOG_MODULE, "Received feature has invalid length (feat->length=%d, data_len=%d).", ntohs(feature->length), (int) data_len);
             return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
        }
        data_len -= ntohs(feature->length);
        d += ntohs(feature->length);
        (*count)++;
    }
    return 0;
}



ofl_err
ofl_utils_count_ofp_instructions(void const *data, size_t data_len, size_t *count)
{
    struct ofp_instruction *inst;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;
    /* this is needed so that buckets are handled correctly */
    while (data_len >= sizeof(struct ofp_instruction)- 4) {
        inst = (struct ofp_instruction *)d;
        if (data_len < ntohs(inst->len) || ntohs(inst->len) < sizeof(struct ofp_instruction) - 4) {
            OFL_LOG_WARN(LOG_MODULE, "Received instruction has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);

        }
        data_len -= ntohs(inst->len);
        d += ntohs(inst->len);
        (*count)++;

    }

    return 0;
}


ofl_err
ofl_utils_count_ofp_buckets(void const *data, size_t data_len, size_t *count)
{
    struct ofp_bucket *bucket;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_bucket)) {
        bucket = (struct ofp_bucket *)d;

        if (data_len < ntohs(bucket->len) || ntohs(bucket->len) < sizeof(struct ofp_bucket)) {
            OFL_LOG_WARN(LOG_MODULE, "Received bucket has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(bucket->len);
        d += ntohs(bucket->len);
        (*count)++;
    }

    return 0;
}


ofl_err
ofl_utils_count_ofp_meter_bands(void const *data, size_t data_len, size_t *count)
{
    struct ofp_meter_band_header *mb;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_meter_band_header)) {
        mb = (struct ofp_meter_band_header *)d;

        if (data_len < ntohs(mb->len) || ntohs(mb->len) < sizeof(struct ofp_meter_band_header)) {
            OFL_LOG_WARN(LOG_MODULE, "Received meter band has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(mb->len);
        d += ntohs(mb->len);
        (*count)++;
    }

    return 0;
}

ofl_err
ofl_utils_count_ofp_ports(void const *data UNUSED, size_t data_len, size_t *count)
{
    *count = data_len / sizeof(struct ofp_port);
    return 0;
}


ofl_err
ofl_utils_count_ofp_packet_queues(void const *data, size_t data_len, size_t *count)
{
    struct ofp_packet_queue *queue;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_packet_queue)) {
        queue = (struct ofp_packet_queue *)d;

        if (data_len < ntohs(queue->len) || ntohs(queue->len) < sizeof(struct ofp_packet_queue)) {
            OFL_LOG_WARN(LOG_MODULE, "Received queue has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(queue->len);
        d += ntohs(queue->len);
        (*count)++;
    }

    return 0;

}

ofl_err
ofl_utils_count_ofp_flow_stats(void const *data, size_t data_len, size_t *count)
{
    struct ofp_flow_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;
    while (data_len >= sizeof(struct ofp_flow_stats)) {
        stat = (struct ofp_flow_stats *)d;
        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_flow_stats)) {
            OFL_LOG_WARN(LOG_MODULE, "Received flow stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;
}

ofl_err
ofl_utils_count_ofp_group_stats(void const *data, size_t data_len, size_t *count)
{
    struct ofp_group_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_group_stats)) {
        stat = (struct ofp_group_stats *)d;

        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_group_stats)) {
            OFL_LOG_WARN(LOG_MODULE, "Received group stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;
}


ofl_err
ofl_utils_count_ofp_table_stats(void const *data UNUSED, size_t data_len, size_t *count)
{
    *count = data_len / sizeof(struct ofp_table_stats);
    return 0;

}

ofl_err
ofl_utils_count_ofp_bucket_counters(void const *data UNUSED, size_t data_len, size_t *count)
{
    *count = data_len / sizeof(struct ofp_bucket_counter);
    return 0;
}

ofl_err
ofl_utils_count_ofp_port_stats(void const *data UNUSED, size_t data_len, size_t *count)
{
    *count = data_len / sizeof(struct ofp_port_stats);
    return 0;
}

ofl_err
ofl_utils_count_ofp_queue_stats(void const *data UNUSED, size_t data_len, size_t *count)
{
    *count = data_len / sizeof(struct ofp_queue_stats);
    return 0;
}

ofl_err
ofl_utils_count_ofp_group_desc_stats(void const *data UNUSED, size_t data_len, size_t *count)
{
    struct ofp_group_desc_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;

    while (data_len >= sizeof(struct ofp_group_desc_stats)) {
        stat = (struct ofp_group_desc_stats *)d;

        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_group_desc_stats)) {
            OFL_LOG_WARN(LOG_MODULE, "Received group desc stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;
}

ofl_err
ofl_utils_count_ofp_queue_props(void const *data, size_t data_len, size_t *count)
{
    struct ofp_queue_prop_header *prop;
    uint8_t *d;

    d = (uint8_t *)data;
    (*count) = 0;

    while (data_len >= sizeof(struct ofp_queue_prop_header)) {
        prop = (struct ofp_queue_prop_header *)d;

        if (data_len < ntohs(prop->len) || ntohs(prop->len) < sizeof(struct ofp_queue_prop_header)) {
            OFL_LOG_WARN(LOG_MODULE, "Received queue prop has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(prop->len);
        d += ntohs(prop->len);
        (*count)++;
    }

    return 0;
}

ofl_err
ofl_utils_count_ofp_meter_stats(void const *data, size_t data_len, size_t *count)
{
    struct ofp_meter_stats *stats;
    uint8_t *d;

    d = (uint8_t *)data;
    (*count) = 0;

    while (data_len >= sizeof(struct ofp_meter_stats)) {
        stats = (struct ofp_meter_stats *)d;

        if (data_len < ntohs(stats->len) || ntohs(stats->len) < sizeof(struct ofp_meter_stats)) {
            OFL_LOG_WARN(LOG_MODULE, "Received meter stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stats->len);
        d += ntohs(stats->len);
        (*count)++;
    }
    return 0;
}

ofl_err
ofl_utils_count_ofp_meter_band_stats(void const *data, size_t data_len, size_t *count)
{
    uint8_t *d;

    d = (uint8_t *)data;
    (*count) = 0;

    while (data_len >= sizeof(struct ofp_meter_band_stats)) {

        if (data_len < sizeof(struct ofp_meter_band_stats)) {
            OFL_LOG_WARN(LOG_MODULE, "Received band meter stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= sizeof(struct ofp_meter_band_stats);
        d += sizeof(struct ofp_meter_band_stats);
        (*count)++;
    }
    return 0;
}

ofl_err
ofl_utils_count_ofp_meter_config(void const *data, size_t data_len, size_t *count)
{
    struct ofp_meter_config *config;
    uint8_t *d;

    d = (uint8_t *)data;
    (*count) = 0;

    while (data_len >= sizeof(struct ofp_meter_config)) {
        config = (struct ofp_meter_config *)d;
        if (data_len < ntohs(config->length) || ntohs(config->length) < sizeof(struct ofp_meter_config)) {
            OFL_LOG_WARN(LOG_MODULE, "Received meter stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(config->length);
        d += ntohs(config->length);
        (*count)++;
    }
    return 0;
}

void
ofl_structs_free_packet_queue(struct ofl_packet_queue *queue)
{
    OFL_UTILS_FREE_ARR(queue->properties, queue->properties_num);
    free(queue);
}

void
ofl_structs_free_instruction(struct ofl_instruction_header *inst, struct ofl_exp const *exp)
{
    switch (inst->type) {
        case OFPIT_GOTO_TABLE:
        case OFPIT_WRITE_METADATA:
        case OFPIT_METER:
            break;
        case OFPIT_WRITE_ACTIONS:
        case OFPIT_APPLY_ACTIONS: {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)inst;
            OFL_UTILS_FREE_ARR_FUN2(ia->actions, ia->actions_num,
                                    ofl_actions_free, exp);
            break;
        }
        case OFPIT_CLEAR_ACTIONS: {
            break;
        }
        case OFPIT_EXPERIMENTER: {
            if (exp == NULL || exp->inst == NULL || exp->inst->free == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free experimented instruction, but no callback was given.");
            } else {
                exp->inst->free(inst);
                return;
            }
        }
    }
    free(inst);
}

void ofl_structs_free_meter_bands(struct ofl_meter_band_header *meter_band)
{
    free(meter_band);
}

void
ofl_structs_free_meter_band_stats(struct ofl_meter_band_stats* s)
{
    free(s);
}

void
ofl_structs_free_meter_stats(struct ofl_meter_stats *stats)
{
    OFL_UTILS_FREE_ARR_FUN(stats->band_stats, stats->meter_bands_num,
                            ofl_structs_free_meter_band_stats);
    free(stats);
}

void
ofl_structs_free_meter_config(struct ofl_meter_config *conf)
{
    OFL_UTILS_FREE_ARR_FUN(conf->bands, conf->meter_bands_num,
                            ofl_structs_free_meter_bands);
    free(conf);
}

void
ofl_structs_free_table_stats(struct ofl_table_stats *stats)
{
    free(stats);
}

void
ofl_structs_free_bucket(struct ofl_bucket *bucket, struct ofl_exp const *exp)
{
    OFL_UTILS_FREE_ARR_FUN2(bucket->actions, bucket->actions_num,
                            ofl_actions_free, exp);
    free(bucket);
}


void
ofl_structs_free_flow_stats(struct ofl_flow_stats *stats, struct ofl_exp const *exp)
{
    OFL_UTILS_FREE_ARR_FUN2(stats->instructions, stats->instructions_num,
                            ofl_structs_free_instruction, exp);
    ofl_structs_free_match(stats->match, exp);
    free(stats);
}

void
ofl_structs_free_port(struct ofl_port *port)
{
    free(port->name);
    free(port);
}

void
ofl_structs_free_group_stats(struct ofl_group_stats *stats)
{
    OFL_UTILS_FREE_ARR(stats->counters, stats->counters_num);
    free(stats);
}

void
ofl_structs_free_group_desc_stats(struct ofl_group_desc_stats *stats, struct ofl_exp const *exp)
{
    OFL_UTILS_FREE_ARR_FUN2(stats->buckets, stats->buckets_num,
                            ofl_structs_free_bucket, exp);
    free(stats);
}

void
ofl_structs_free_table_features(struct ofl_table_features* features, struct ofl_exp const *exp)
{
    /* We sometime sets it to NULL (see set feature request). Jean II */
    if (features == NULL)
        return;

    OFL_UTILS_FREE_ARR_FUN2(features->properties, features->properties_num,
                            ofl_structs_free_table_properties, exp);
    free(features->name);
    free(features);
}

void
ofl_structs_free_table_properties(struct ofl_table_feature_prop_header *prop, struct ofl_exp const *exp UNUSED)
{
    switch(prop->type){
        case (OFPTFPT_INSTRUCTIONS):
        case (OFPTFPT_INSTRUCTIONS_MISS):{
            struct ofl_table_feature_prop_instructions *inst = (struct ofl_table_feature_prop_instructions *)prop;
            free(inst->instruction_ids);
            break;
        }
        case (OFPTFPT_NEXT_TABLES_MISS):
        case (OFPTFPT_NEXT_TABLES):{
            struct ofl_table_feature_prop_next_tables *tables = (struct ofl_table_feature_prop_next_tables *)prop ;
            free(tables->next_table_ids);
            break;
        }
        case (OFPTFPT_WRITE_ACTIONS):
        case (OFPTFPT_WRITE_ACTIONS_MISS):
        case (OFPTFPT_APPLY_ACTIONS):
        case (OFPTFPT_APPLY_ACTIONS_MISS):{
            struct ofl_table_feature_prop_actions *act = (struct ofl_table_feature_prop_actions *)prop;
            free(act->action_ids);
            break;
        }
        case (OFPTFPT_APPLY_SETFIELD):
        case (OFPTFPT_APPLY_SETFIELD_MISS):
        case (OFPTFPT_WRITE_SETFIELD):
        case (OFPTFPT_WRITE_SETFIELD_MISS):
        case (OFPTFPT_WILDCARDS):
        case (OFPTFPT_MATCH):{
            struct ofl_table_feature_prop_oxm *oxm = (struct ofl_table_feature_prop_oxm *)prop;
            free(oxm->oxm_ids);
            break;
        }
    }
    free(prop);
}

void
ofl_structs_free_match(struct ofl_match_header *match, struct ofl_exp const *exp)
{
    switch (match->type) {
        case (OFPMT_OXM): {
            if (match->length > sizeof(struct ofp_match)){
                struct ofl_match *m = (struct ofl_match*) match;
                struct ofl_match_tlv *tlv, *next;
                HMAP_FOR_EACH_SAFE(tlv, next, struct ofl_match_tlv, hmap_node, &m->match_fields)
                {
                	if (tlv->ownership) {
						free(tlv->value);
						free(tlv);
					}
                }
                hmap_destroy(&m->match_fields);
                free(m);
            }
            else free(match);

            break;
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->free == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free experimented instruction, but no callback was given.");
                free(match);
            } else {
                exp->match->free(match);
            }
        }
    }
}


