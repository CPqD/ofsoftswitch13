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
#include <stdbool.h>
#include <netinet/in.h>
#include "ofl.h"
#include "ofl-actions.h"
#include "ofl-messages.h"
#include "ofl-structs.h"
#include "ofl-utils.h"
#include "ofl-log.h"


#define LOG_MODULE ofl_msg
OFL_LOG_INIT(LOG_MODULE)

/* Frees the OFlib stats request message along with any dynamically allocated
 * structures. */
static int
ofl_msg_free_error(struct ofl_msg_error *msg) {
    free(msg->data);
    free(msg);

    return 0;
}

static int
ofl_msg_free_multipart_request(struct ofl_msg_multipart_request_header *msg, struct ofl_exp *exp) {
    switch (msg->type) {
        case OFPMP_DESC: {
            break;
        }
        case OFPMP_FLOW:
        case OFPMP_AGGREGATE: {
            ofl_structs_free_match(((struct ofl_msg_multipart_request_flow *)msg)->match, exp);
            break;
        }
        case OFPMP_TABLE:
        case OFPMP_PORT_STATS :
        case OFPMP_QUEUE:
        case OFPMP_GROUP:
        case OFPMP_GROUP_DESC:
        case OFPMP_GROUP_FEATURES:
        case OFPMP_METER:
        case OFPMP_METER_CONFIG:
        case OFPMP_METER_FEATURES:
            break;
        case OFPMP_TABLE_FEATURES:{
            struct ofl_msg_multipart_request_table_features *m = (struct ofl_msg_multipart_request_table_features *)msg;
            OFL_UTILS_FREE_ARR_FUN2(m->table_features, m->tables_num,
                                    ofl_structs_free_table_features, exp);
            break; 
        }
        case OFPMP_PORT_DESC:
            break;
        case OFPMP_EXPERIMENTER: {
            if (exp == NULL || exp->stats == NULL || exp->stats->req_free == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free EXPERIMENTER stats request, but no callback was given.");
                break;
            }
            exp->stats->req_free(msg);
            return 0;
        }
        default:
            return -1;
    }
    free(msg);
    return 0;
}



/* Frees the OFlib stats reply message along with any dynamically allocated
 * structures. */
static int
ofl_msg_free_multipart_reply(struct ofl_msg_multipart_reply_header *msg, struct ofl_exp *exp) {
    switch (msg->type) {
        case OFPMP_DESC: {
            struct ofl_msg_reply_desc *stat = (struct ofl_msg_reply_desc *) msg;
            free(stat->mfr_desc);
            free(stat->hw_desc);
            free(stat->sw_desc);
            free(stat->serial_num);
            free(stat->dp_desc);
            break;
        }
        case OFPMP_FLOW: {
            struct ofl_msg_multipart_reply_flow *stat = (struct ofl_msg_multipart_reply_flow *)msg;
            OFL_UTILS_FREE_ARR_FUN2(stat->stats, stat->stats_num,
                                    ofl_structs_free_flow_stats, exp);
        }
        case OFPMP_AGGREGATE: {
            break;
        }
        case OFPMP_TABLE: {
            struct ofl_msg_multipart_reply_table *stat = (struct ofl_msg_multipart_reply_table *)msg;
            OFL_UTILS_FREE_ARR_FUN(stat->stats, stat->stats_num,
                                   ofl_structs_free_table_stats);
            break;
        }
        case OFPMP_PORT_STATS: {
            struct ofl_msg_multipart_reply_port *stat = (struct ofl_msg_multipart_reply_port *)msg;
            OFL_UTILS_FREE_ARR(stat->stats, stat->stats_num);
            break;
        }
        case OFPMP_QUEUE: {
            struct ofl_msg_multipart_reply_queue *stat = (struct ofl_msg_multipart_reply_queue *)msg;
            OFL_UTILS_FREE_ARR(stat->stats, stat->stats_num);
            break;
        }
        case OFPMP_GROUP: {
            struct ofl_msg_multipart_reply_group *stat = (struct ofl_msg_multipart_reply_group *)msg;
            OFL_UTILS_FREE_ARR_FUN(stat->stats, stat->stats_num,
                                   ofl_structs_free_group_stats);
            break;
        }
        case OFPMP_METER:{
            struct ofl_msg_multipart_reply_meter *stat = (struct ofl_msg_multipart_reply_meter*)msg;
            OFL_UTILS_FREE_ARR_FUN(stat->stats, stat->stats_num,
                                   ofl_structs_free_meter_stats);            
            break;
        }
        case OFPMP_METER_CONFIG:{
            struct ofl_msg_multipart_reply_meter_conf *conf = (struct ofl_msg_multipart_reply_meter_conf *)msg;
            OFL_UTILS_FREE_ARR_FUN(conf->stats, conf->stats_num,
                                   ofl_structs_free_meter_config);             
            break;
        }
        case OFPMP_METER_FEATURES:{
            struct ofl_msg_multipart_reply_meter_features *feat = (struct ofl_msg_multipart_reply_meter_features *)msg;
            free(feat->features);
            break;
        }
        case OFPMP_GROUP_DESC: {
            struct ofl_msg_multipart_reply_group_desc *stat = (struct ofl_msg_multipart_reply_group_desc *)msg;
            OFL_UTILS_FREE_ARR_FUN2(stat->stats, stat->stats_num,
                                    ofl_structs_free_group_desc_stats, exp);
            break;
        }
        case OFPMP_PORT_DESC:{
            struct ofl_msg_multipart_reply_port_desc *stat = (struct ofl_msg_multipart_reply_port_desc *)msg;        
            OFL_UTILS_FREE_ARR_FUN(stat->stats, stat->stats_num,
                                    ofl_structs_free_port);
            break;            
        }
        case OFPMP_TABLE_FEATURES:{
            struct ofl_msg_multipart_reply_table_features *m = (struct ofl_msg_multipart_reply_table_features *)msg;
            OFL_UTILS_FREE_ARR_FUN2(m->table_features, m->tables_num,
                                    ofl_structs_free_table_features, exp);
            break;        
        }
        case OFPMP_EXPERIMENTER: {
            if (exp == NULL || exp->stats || exp->stats->reply_free == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free EXPERIMENTER stats reply, but no callback was given.");
                break;
            }
            exp->stats->reply_free(msg);
            return 0;
        }
        case OFPMP_GROUP_FEATURES:{
            break;
        }
        default: {
            return -1;
        }
    }

    free(msg);
    return 0;
}

int
ofl_msg_free(struct ofl_msg_header *msg, struct ofl_exp *exp) {
     
    switch (msg->type) {
        case OFPT_HELLO: {
            break;
        }
        case OFPT_ERROR: {
            return ofl_msg_free_error((struct ofl_msg_error *)msg);
        }
        case OFPT_ECHO_REQUEST:
        case OFPT_ECHO_REPLY: {
            free(((struct ofl_msg_echo *)msg)->data);
            break;
        }
        case OFPT_EXPERIMENTER: {
            if (exp == NULL || exp->msg == NULL || exp->msg->free == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free EXPERIMENTER message, but no callback was given");
                break;
            }
            exp->msg->free((struct ofl_msg_experimenter *)msg);
            return 0;
        }
        case OFPT_FEATURES_REQUEST: {
            break;
        }
        case OFPT_FEATURES_REPLY: {
            break;
        }
        case OFPT_GET_CONFIG_REQUEST: {
            break;
        }
        case OFPT_GET_CONFIG_REPLY: {
            free(((struct ofl_msg_get_config_reply *)msg)->config);
            break;
        }
        case OFPT_SET_CONFIG: {
            free(((struct ofl_msg_set_config *)msg)->config);
            break;
        }
        case OFPT_PACKET_IN: {
            ofl_structs_free_match(((struct ofl_msg_packet_in *)msg)->match,NULL);
            free(((struct ofl_msg_packet_in *)msg)->data);
            break;
        }
        case OFPT_FLOW_REMOVED: {
            return ofl_msg_free_flow_removed((struct ofl_msg_flow_removed *)msg, true, exp);
            break;
        }
        case OFPT_PORT_STATUS: {
            free(((struct ofl_msg_port_status *)msg)->desc);
            break;
        }
        case OFPT_PACKET_OUT: {
            return ofl_msg_free_packet_out((struct ofl_msg_packet_out *)msg, true, exp);
        }
        case OFPT_FLOW_MOD: {
            return ofl_msg_free_flow_mod((struct ofl_msg_flow_mod *)msg, true, true, exp);
        }
        case OFPT_GROUP_MOD: {
            return ofl_msg_free_group_mod((struct ofl_msg_group_mod *)msg, true, exp);
        }
        case OFPT_PORT_MOD:
        case OFPT_TABLE_MOD: {
            break;
        }
        case OFPT_MULTIPART_REQUEST: {
            return ofl_msg_free_multipart_request((struct ofl_msg_multipart_request_header *)msg, exp);
        }
        case OFPT_MULTIPART_REPLY: {
            return ofl_msg_free_multipart_reply((struct ofl_msg_multipart_reply_header *)msg, exp);
        }
        case OFPT_BARRIER_REQUEST:
        case OFPT_BARRIER_REPLY:
        case OFPT_QUEUE_GET_CONFIG_REQUEST: {
            break;
        }
        case OFPT_ROLE_REPLY:
        case OFPT_ROLE_REQUEST:{
            break;
        }
        case OFPT_GET_ASYNC_REPLY:
        case OFPT_SET_ASYNC:
        case OFPT_GET_ASYNC_REQUEST:{
             break;
        }
        case OFPT_METER_MOD:{
            return ofl_msg_free_meter_mod((struct ofl_msg_meter_mod*)msg, true);
        }
        case OFPT_QUEUE_GET_CONFIG_REPLY: {
            struct ofl_msg_queue_get_config_reply *mod =
                                (struct ofl_msg_queue_get_config_reply *)msg;
            OFL_UTILS_FREE_ARR_FUN(mod->queues, mod->queues_num,
                                   ofl_structs_free_packet_queue);
            break;
        }
    }
    
    free(msg);
    return 0;
}

int 
ofl_msg_free_meter_mod(struct ofl_msg_meter_mod * msg, bool with_bands){
    if (with_bands) {
       OFL_UTILS_FREE_ARR_FUN(msg->bands, msg->meter_bands_num,
                                  ofl_structs_free_meter_bands);
    }
    free(msg);
    return 0;
}

int
ofl_msg_free_packet_out(struct ofl_msg_packet_out *msg, bool with_data, struct ofl_exp *exp) {
    if (with_data) {
        free(msg->data);
    }
    OFL_UTILS_FREE_ARR_FUN2(msg->actions, msg->actions_num,
                            ofl_actions_free, exp);

    free(msg);
    return 0;
}

int
ofl_msg_free_group_mod(struct ofl_msg_group_mod *msg, bool with_buckets, struct ofl_exp *exp) {
    if (with_buckets) {
        OFL_UTILS_FREE_ARR_FUN2(msg->buckets, msg->buckets_num,
                                ofl_structs_free_bucket, exp);
    }

    free(msg);
    return 0;
}

int
ofl_msg_free_flow_mod(struct ofl_msg_flow_mod *msg, bool with_match, bool with_instructions, struct ofl_exp *exp) {
    if (with_match) {
        ofl_structs_free_match(msg->match, exp);
    }
    if (with_instructions) {
        OFL_UTILS_FREE_ARR_FUN2(msg->instructions, msg->instructions_num,
                                ofl_structs_free_instruction, exp);
    }

    free(msg);
    return 0;
}


int
ofl_msg_free_flow_removed(struct ofl_msg_flow_removed *msg, bool with_stats, struct ofl_exp *exp) {
    if (with_stats) {
        ofl_structs_free_flow_stats(msg->stats, exp);
    }
    free(msg);
    return 0;
}



bool
ofl_msg_merge_multipart_request_table_features(struct ofl_msg_multipart_request_table_features *orig, struct ofl_msg_multipart_request_table_features *merge) {
    uint32_t new_tables_num;
    size_t i, j;
    struct ofl_table_feature_prop_header **properties;
    struct ofl_table_feature_prop_header *old_prop;
    struct ofl_table_feature_prop_header *new_prop;
    int properties_num;
    int k;

    /* Keep body potentially empty if nothing to merge. Jean II */
    if(merge->tables_num) {
      new_tables_num = orig->tables_num + merge->tables_num;

      orig->table_features = (struct ofl_table_features ** )realloc(orig->table_features, new_tables_num * sizeof(struct ofl_table_features *));

      for (i=0; i < merge->tables_num; i++) {
        j = orig->tables_num + i;
        orig->table_features[j] = (struct ofl_table_features *)malloc(sizeof(struct ofl_table_features));
        memcpy(orig->table_features[j], merge->table_features[i], sizeof(struct ofl_table_features));
	properties = merge->table_features[i]->properties;
	properties_num = merge->table_features[i]->properties_num;
	for (k = 0; k < properties_num; k++) {
	  old_prop = properties[k];
	  switch (old_prop->type) {
	  case OFPTFPT_INSTRUCTIONS:
	  case OFPTFPT_INSTRUCTIONS_MISS: {
	    struct ofl_table_feature_prop_instructions *old_prop_i = (struct ofl_table_feature_prop_instructions*) old_prop;
	    struct ofl_table_feature_prop_instructions *new_prop_i;
	    new_prop_i = (struct ofl_table_feature_prop_instructions*) malloc(sizeof(struct ofl_table_feature_prop_instructions));
	    new_prop = (struct ofl_table_feature_prop_header *) new_prop_i;
	    memcpy((char *) new_prop, (char *) old_prop, sizeof(struct ofl_table_feature_prop_instructions));
	    new_prop_i->instruction_ids = (struct ofl_instruction_header*) malloc(sizeof(struct ofl_instruction_header) * old_prop_i->ids_num);
	    memcpy((char *) new_prop_i->instruction_ids, (char *) old_prop_i->instruction_ids, sizeof(struct ofl_instruction_header) * old_prop_i->ids_num);
	    break;
	  }
	  case OFPTFPT_NEXT_TABLES:
	  case OFPTFPT_NEXT_TABLES_MISS: {
	    struct ofl_table_feature_prop_next_tables *old_prop_nt = (struct ofl_table_feature_prop_next_tables*) old_prop;
	    struct ofl_table_feature_prop_next_tables *new_prop_nt;
	    new_prop_nt = (struct ofl_table_feature_prop_next_tables*) malloc(sizeof(struct ofl_table_feature_prop_next_tables));
	    new_prop = (struct ofl_table_feature_prop_header *) new_prop_nt;
	    memcpy((char *) new_prop, (char *) old_prop, sizeof(struct ofl_table_feature_prop_next_tables));
	    new_prop_nt->next_table_ids = (uint8_t*) malloc(sizeof(uint8_t) * old_prop_nt->table_num);
	    memcpy((char *) new_prop_nt->next_table_ids, (char *) old_prop_nt->next_table_ids, sizeof(uint8_t) * old_prop_nt->table_num);
	    break;
	  }
	  case OFPTFPT_WRITE_ACTIONS:
	  case OFPTFPT_WRITE_ACTIONS_MISS:
	  case OFPTFPT_APPLY_ACTIONS:
	  case OFPTFPT_APPLY_ACTIONS_MISS: {
	    struct ofl_table_feature_prop_actions *old_prop_a = (struct ofl_table_feature_prop_actions*) old_prop;
	    struct ofl_table_feature_prop_actions *new_prop_a;
	    new_prop_a = (struct ofl_table_feature_prop_actions*) malloc(sizeof(struct ofl_table_feature_prop_actions));
	    new_prop = (struct ofl_table_feature_prop_header *) new_prop_a;
	    memcpy((char *) new_prop, (char *) old_prop, sizeof(struct ofl_table_feature_prop_actions));
	    new_prop_a->action_ids = (struct ofl_action_header*) malloc(sizeof(struct ofl_action_header) * old_prop_a->actions_num);
	    memcpy((char *) new_prop_a->action_ids, (char *) old_prop_a->action_ids, sizeof(struct ofl_action_header) * old_prop_a->actions_num);
	    break;
	  }
	  case OFPTFPT_MATCH:
	  case OFPTFPT_WILDCARDS:
	  case OFPTFPT_WRITE_SETFIELD:
	  case OFPTFPT_WRITE_SETFIELD_MISS:
	  case OFPTFPT_APPLY_SETFIELD:
	  case OFPTFPT_APPLY_SETFIELD_MISS: { 
	    struct ofl_table_feature_prop_oxm *old_prop_o = (struct ofl_table_feature_prop_oxm*) old_prop;
	    struct ofl_table_feature_prop_oxm *new_prop_o;
	    new_prop_o = (struct ofl_table_feature_prop_oxm*) malloc(sizeof(struct ofl_table_feature_prop_oxm));
	    new_prop = (struct ofl_table_feature_prop_header *) new_prop_o;
	    memcpy((char *) new_prop, (char *) old_prop, sizeof(struct ofl_table_feature_prop_oxm));
	    new_prop_o->oxm_ids = (uint32_t*) malloc(sizeof(uint32_t) * old_prop_o->oxm_num);
	    memcpy((char *) new_prop_o->oxm_ids, (char *) old_prop_o->oxm_ids, sizeof(uint32_t) * old_prop_o->oxm_num);
	    break;
	  }
	  default:
	    new_prop = NULL;
	  }
	  orig->table_features[j]->properties[k] = new_prop;
	}
      }

      orig->tables_num = new_tables_num;
    }

    return ((merge->header.flags & OFPMPF_REQ_MORE) == 0);
}

bool
ofl_msg_merge_multipart_reply_flow(struct ofl_msg_multipart_reply_flow *orig, struct ofl_msg_multipart_reply_flow *merge) {
    uint32_t new_stats_num;
    size_t i, j;

    new_stats_num = orig->stats_num + merge->stats_num;

    orig->stats = (struct ofl_flow_stats ** )realloc(orig->stats, new_stats_num * sizeof(struct ofl_flow_stats *));

    for (i=0; i < merge->stats_num; i++) {
        j = orig->stats_num + i;
        orig->stats[j] = (struct ofl_flow_stats *)malloc(sizeof(struct ofl_flow_stats));
        memcpy(orig->stats[j], merge->stats[i], sizeof(struct ofl_flow_stats));
    }

    orig->stats_num = new_stats_num;

    return ((merge->header.flags & OFPMPF_REPLY_MORE) == 0);
}

bool
ofl_msg_merge_multipart_reply_table(struct ofl_msg_multipart_reply_table *orig, struct ofl_msg_multipart_reply_table *merge) {
    uint32_t new_stats_num;
    size_t i, j;

    new_stats_num = orig->stats_num + merge->stats_num;

    orig->stats = (struct ofl_table_stats **)realloc(orig->stats, new_stats_num * sizeof(struct ofl_table_stats *));

    for (i=0; i < merge->stats_num; i++) {
        j = orig->stats_num + i;
        orig->stats[j] = (struct ofl_table_stats *)malloc(sizeof(struct ofl_table_stats));
        memcpy(orig->stats[j], merge->stats[i], sizeof(struct ofl_table_stats));
    }

    orig->stats_num = new_stats_num;

    return ((merge->header.flags & OFPMPF_REPLY_MORE) == 0);
}

bool
ofl_msg_merge_multipart_reply_port(struct ofl_msg_multipart_reply_port *orig, struct ofl_msg_multipart_reply_port *merge) {
    uint32_t new_stats_num;
    size_t i, j;

    new_stats_num = orig->stats_num + merge->stats_num;

    orig->stats = (struct ofl_port_stats **)realloc(orig->stats, new_stats_num * sizeof(struct ofl_port_stats *));

    for (i=0; i < merge->stats_num; i++) {
        j = orig->stats_num + i;
        orig->stats[j] = (struct ofl_port_stats *)malloc(sizeof(struct ofl_port_stats));
        memcpy(orig->stats[j], merge->stats[i], sizeof(struct ofl_port_stats));
    }

    orig->stats_num = new_stats_num;

    return ((merge->header.flags & OFPMPF_REPLY_MORE) == 0);
}

bool
ofl_msg_merge_multipart_reply_queue(struct ofl_msg_multipart_reply_queue *orig, struct ofl_msg_multipart_reply_queue *merge) {
    uint32_t new_stats_num;
    size_t i, j;

    new_stats_num = orig->stats_num + merge->stats_num;

    orig->stats = (struct ofl_queue_stats **)realloc(orig->stats, new_stats_num * sizeof(struct ofl_queue_stats *));

    for (i=0; i < merge->stats_num; i++) {
        j = orig->stats_num + i;
        orig->stats[j] = (struct ofl_queue_stats *)malloc(sizeof(struct ofl_queue_stats));
        memcpy(orig->stats[j], merge->stats[i], sizeof(struct ofl_queue_stats));
    }

    orig->stats_num = new_stats_num;

    return ((merge->header.flags & OFPMPF_REPLY_MORE) == 0);
}

