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

#include <stdbool.h>
#include <string.h>
#include "dynamic-string.h"
#include "datapath.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "oflib/ofl.h"
#include "oflib/oxm-match.h"
#include "time.h"
#include "dp_capabilities.h"
//#include "packet_handle_std.h"

#include "vlog.h"
#define LOG_MODULE VLM_flow_t

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

uint32_t  oxm_ids[]={OXM_OF_IN_PORT,OXM_OF_IN_PHY_PORT,OXM_OF_METADATA,OXM_OF_ETH_DST,
                        OXM_OF_ETH_SRC,OXM_OF_ETH_TYPE, OXM_OF_VLAN_VID, OXM_OF_VLAN_PCP, OXM_OF_IP_DSCP,
                        OXM_OF_IP_ECN, OXM_OF_IP_PROTO, OXM_OF_IPV4_SRC, OXM_OF_IPV4_DST, OXM_OF_TCP_SRC,
                        OXM_OF_TCP_DST, OXM_OF_TCP_FLAGS, OXM_OF_UDP_SRC, OXM_OF_UDP_DST, OXM_OF_SCTP_SRC, OXM_OF_SCTP_DST,
                        OXM_OF_ICMPV4_TYPE, OXM_OF_ICMPV4_CODE, OXM_OF_ARP_OP, OXM_OF_ARP_SPA,OXM_OF_ARP_TPA,
                        OXM_OF_ARP_SHA, OXM_OF_ARP_THA, OXM_OF_IPV6_SRC, OXM_OF_IPV6_DST, OXM_OF_IPV6_FLABEL,
                        OXM_OF_ICMPV6_TYPE, OXM_OF_ICMPV6_CODE, OXM_OF_IPV6_ND_TARGET, OXM_OF_IPV6_ND_SLL,
                        OXM_OF_IPV6_ND_TLL, OXM_OF_MPLS_LABEL, OXM_OF_MPLS_TC, OXM_OF_MPLS_BOS, OXM_OF_PBB_ISID,
                        OXM_OF_TUNNEL_ID, OXM_OF_IPV6_EXTHDR};

#define NUM_OXM_IDS     (sizeof(oxm_ids) / sizeof(uint32_t))
/* Do *NOT* use N_OXM_FIELDS, it's ligically wrong and can run over
 * the oxm_ids array. Jean II */

uint32_t wildcarded[] = {OXM_OF_METADATA, OXM_OF_ETH_DST, OXM_OF_ETH_SRC, OXM_OF_VLAN_VID, OXM_OF_IPV4_SRC,
                               OXM_OF_IPV4_DST, OXM_OF_TCP_FLAGS, OXM_OF_ARP_SPA, OXM_OF_ARP_TPA, OXM_OF_ARP_SHA, OXM_OF_ARP_THA, OXM_OF_IPV6_SRC,
                               OXM_OF_IPV4_DST, OXM_OF_ARP_SPA, OXM_OF_ARP_TPA, OXM_OF_ARP_SHA, OXM_OF_ARP_THA, OXM_OF_IPV6_SRC,
                               OXM_OF_IPV6_DST , OXM_OF_IPV6_FLABEL, OXM_OF_PBB_ISID, OXM_OF_TUNNEL_ID, OXM_OF_IPV6_EXTHDR};                        

#define NUM_WILD_IDS    (sizeof(wildcarded) / sizeof(uint32_t))

struct ofl_instruction_header instructions[] = { {OFPIT_GOTO_TABLE}, 
                  {OFPIT_WRITE_METADATA },{OFPIT_WRITE_ACTIONS},{OFPIT_APPLY_ACTIONS},
                  {OFPIT_CLEAR_ACTIONS},{OFPIT_METER}} ;
struct ofl_instruction_header instructions_nogoto[] = {
                  {OFPIT_WRITE_METADATA },{OFPIT_WRITE_ACTIONS},{OFPIT_APPLY_ACTIONS},
                  {OFPIT_CLEAR_ACTIONS},{OFPIT_METER}} ;

#define N_INSTRUCTIONS  (sizeof(instructions) / sizeof(struct ofl_instruction_header))

struct ofl_action_header actions[] = { {OFPAT_OUTPUT, 4}, 
                  {OFPAT_COPY_TTL_OUT, 4},{OFPAT_COPY_TTL_IN, 4},{OFPAT_SET_MPLS_TTL, 4},
                  {OFPAT_DEC_MPLS_TTL, 4},{OFPAT_PUSH_VLAN, 4},{OFPAT_POP_VLAN, 4}, {OFPAT_PUSH_MPLS, 4},
                  {OFPAT_POP_MPLS, 4},{OFPAT_SET_QUEUE, 4}, {OFPAT_GROUP, 4}, {OFPAT_SET_NW_TTL, 4}, {OFPAT_DEC_NW_TTL, 4}, 
                  {OFPAT_SET_FIELD, 4}, {OFPAT_PUSH_PBB, 4}, {OFPAT_POP_PBB, 4} } ;

#define N_ACTIONS       (sizeof(actions) / sizeof(struct ofl_action_header))

/* When inserting an entry, this function adds the flow entry to the list of
 * hard and idle timeout entries, if appropriate. */
static void
add_to_timeout_lists(struct flow_table *table, struct flow_entry *entry) {
    if (entry->stats->idle_timeout > 0) {
        list_insert(&table->idle_entries, &entry->idle_node);
    }

    if (entry->remove_at > 0) {
        struct flow_entry *e;

        /* hard timeout entries are ordered by the time they should be removed at. */
        LIST_FOR_EACH (e, struct flow_entry, hard_node, &table->hard_entries) {
            if (e->remove_at > entry->remove_at) {
                list_insert(&e->hard_node, &entry->hard_node);
                return;
            }
        }
        list_insert(&e->hard_node, &entry->hard_node);
    }
}

/* Handles flow mod messages with ADD command. */
static ofl_err
flow_table_add(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool check_overlap, bool *match_kept, bool *insts_kept, struct ofl_exp *exp) {
    // Note: new entries will be placed behind those with equal priority
    struct flow_entry *entry, *new_entry;
    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries) {
        if (check_overlap && flow_entry_overlaps(entry, mod, exp)) {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        }
        /* if the entry equals, replace the old one */
        if (flow_entry_matches(entry, mod, true/*strict*/, false/*check_cookie*/, exp)) {
            new_entry = flow_entry_create(table->dp, table, mod);
            *match_kept = true;
            *insts_kept = true;

            /* NOTE: no flow removed message should be generated according to spec. */
            list_replace(&new_entry->match_node, &entry->match_node);
            list_remove(&entry->hard_node);
            list_remove(&entry->idle_node);
            flow_entry_destroy(entry);
            add_to_timeout_lists(table, new_entry);
            return 0;
        }

        if (mod->priority > entry->stats->priority) {
            break;
        }
    }

    if (table->stats->active_count == FLOW_TABLE_MAX_ENTRIES) {
        return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL);
    }
    table->stats->active_count++;

    new_entry = flow_entry_create(table->dp, table, mod);
    *match_kept = true;
    *insts_kept = true;

    list_insert(&entry->match_node, &new_entry->match_node);
    add_to_timeout_lists(table, new_entry);

    return 0;
}

/* Handles flow mod messages with MODIFY command. 
    If the flow doesn't exists don't do nothing*/
static ofl_err
flow_table_modify(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool strict, bool *insts_kept, struct ofl_exp *exp) {
    struct flow_entry *entry;

    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries) {
        if (flow_entry_matches(entry, mod, strict, true/*check_cookie*/, exp)) {
            flow_entry_replace_instructions(entry, mod->instructions_num, mod->instructions);
	    flow_entry_modify_stats(entry, mod);
            *insts_kept = true;
        }
    }

    return 0;
}

/* Handles flow mod messages with DELETE command. */
static ofl_err
flow_table_delete(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool strict, struct ofl_exp *exp) {
    struct flow_entry *entry, *next;

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, match_node, &table->match_entries) {
        if ((mod->out_port == OFPP_ANY || flow_entry_has_out_port(entry, mod->out_port)) &&
            (mod->out_group == OFPG_ANY || flow_entry_has_out_group(entry, mod->out_group)) &&
            flow_entry_matches(entry, mod, strict, true/*check_cookie*/, exp)) {
             flow_entry_remove(entry, OFPRR_DELETE);
        }
    }

    return 0;
}


ofl_err
flow_table_flow_mod(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool *match_kept, bool *insts_kept, struct ofl_exp *exp) {
    switch (mod->command) {
        case (OFPFC_ADD): {
            bool overlap = ((mod->flags & OFPFF_CHECK_OVERLAP) != 0);
            return flow_table_add(table, mod, overlap, match_kept, insts_kept, exp);
        }
        case (OFPFC_MODIFY): {
            return flow_table_modify(table, mod, false, insts_kept, exp);
        }
        case (OFPFC_MODIFY_STRICT): {
            return flow_table_modify(table, mod, true, insts_kept, exp);
        }
        case (OFPFC_DELETE): {
            return flow_table_delete(table, mod, false, exp);
        }
        case (OFPFC_DELETE_STRICT): {
            return flow_table_delete(table, mod, true, exp);
        }
        default: {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
        }
    }
}


struct flow_entry *
flow_table_lookup(struct flow_table *table, struct packet *pkt, struct ofl_exp *exp) {
    struct flow_entry *entry;

    table->stats->lookup_count++;
    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        struct ofl_match_header *m;

        m = entry->match == NULL ? entry->stats->match : entry->match;

        /* select appropriate handler, based on match type of flow entry. */
        switch (m->type) {
            case (OFPMT_OXM): {
               if (packet_handle_std_match(pkt->handle_std, (struct ofl_match *)m, exp)) {
                    if (!entry->no_byt_count)                                            
                        entry->stats->byte_count += pkt->buffer->size;
                    if (!entry->no_pkt_count)
                        entry->stats->packet_count++;
                    entry->last_used = time_msec();

                    table->stats->matched_count++;
                    return entry;
                } 
                break;

                break;
            }
            default: {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to process flow entry with unknown match type (%u).", m->type);
            }
        }
    }

    return NULL;
}



void
flow_table_timeout(struct flow_table *table) {
    struct flow_entry *entry, *next;

    /* NOTE: hard timeout entries are ordered by the time they should be removed at,
     * so if one is not removed, the rest will not be either. */
    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, hard_node, &table->hard_entries) {
        if (!flow_entry_hard_timeout(entry)) {
            break;
        }
    }

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, idle_node, &table->idle_entries) {
        flow_entry_idle_timeout(entry);
    }
}


static void 
flow_table_create_property(struct ofl_table_feature_prop_header **prop, enum ofp_table_feature_prop_type type){

    switch(type){
        case OFPTFPT_INSTRUCTIONS:
        case OFPTFPT_INSTRUCTIONS_MISS:{
            struct ofl_table_feature_prop_instructions *inst_capabilities;
            inst_capabilities = xmalloc(sizeof(struct ofl_table_feature_prop_instructions));
            inst_capabilities->header.type = type;
            inst_capabilities->instruction_ids = xmalloc(sizeof(instructions));
	    if (PIPELINE_TABLES > 1) {
              inst_capabilities->ids_num = N_INSTRUCTIONS;
              memcpy(inst_capabilities->instruction_ids, instructions, sizeof(instructions));
	    } else {
              inst_capabilities->ids_num = N_INSTRUCTIONS - 1;
              memcpy(inst_capabilities->instruction_ids, instructions_nogoto, sizeof(instructions_nogoto));
	    }
            inst_capabilities->header.length = ofl_structs_table_features_properties_ofp_len(&inst_capabilities->header, NULL);            
            (*prop) =  (struct ofl_table_feature_prop_header*) inst_capabilities;
            break;        
        }
        case OFPTFPT_NEXT_TABLES:
        case OFPTFPT_NEXT_TABLES_MISS:{
             struct ofl_table_feature_prop_next_tables *tbl_reachable;
             int i;
             tbl_reachable = xmalloc(sizeof(struct ofl_table_feature_prop_next_tables));
             tbl_reachable->header.type = type;
             tbl_reachable->table_num = PIPELINE_TABLES ;
             tbl_reachable->next_table_ids = xmalloc(sizeof(uint8_t) * tbl_reachable->table_num);
             for(i=0; i < tbl_reachable->table_num; i++)
                tbl_reachable->next_table_ids[i] = i;
             tbl_reachable->header.length = ofl_structs_table_features_properties_ofp_len(&tbl_reachable->header, NULL); 
             *prop = (struct ofl_table_feature_prop_header*) tbl_reachable;
             break;
        }
        case OFPTFPT_APPLY_ACTIONS:
        case OFPTFPT_APPLY_ACTIONS_MISS:
        case OFPTFPT_WRITE_ACTIONS:
        case OFPTFPT_WRITE_ACTIONS_MISS:{
             struct ofl_table_feature_prop_actions *act_capabilities;
             act_capabilities = xmalloc(sizeof(struct ofl_table_feature_prop_actions));
             act_capabilities->header.type =  type;
             act_capabilities->actions_num= N_ACTIONS;
             act_capabilities->action_ids = xmalloc(sizeof(actions));
             memcpy(act_capabilities->action_ids, actions, sizeof(actions));
             act_capabilities->header.length = ofl_structs_table_features_properties_ofp_len(&act_capabilities->header, NULL);                         
             *prop =  (struct ofl_table_feature_prop_header*) act_capabilities; 
             break;
        }
        case OFPTFPT_MATCH:
        case OFPTFPT_APPLY_SETFIELD:
        case OFPTFPT_APPLY_SETFIELD_MISS:
        case OFPTFPT_WRITE_SETFIELD:
        case OFPTFPT_WRITE_SETFIELD_MISS:{
            struct ofl_table_feature_prop_oxm *oxm_capabilities; 
            oxm_capabilities = xmalloc(sizeof(struct ofl_table_feature_prop_oxm));
            oxm_capabilities->header.type = type;
            oxm_capabilities->oxm_num = NUM_OXM_IDS;
            oxm_capabilities->oxm_ids = xmalloc(sizeof(oxm_ids));
            memcpy(oxm_capabilities->oxm_ids, oxm_ids, sizeof(oxm_ids));
            oxm_capabilities->header.length = ofl_structs_table_features_properties_ofp_len(&oxm_capabilities->header, NULL);             
            *prop =  (struct ofl_table_feature_prop_header*) oxm_capabilities;
            break;
        }  
        case OFPTFPT_WILDCARDS:{
            struct ofl_table_feature_prop_oxm *oxm_capabilities;
            oxm_capabilities = xmalloc(sizeof(struct ofl_table_feature_prop_oxm)); 
            oxm_capabilities->header.type = type;
            oxm_capabilities->oxm_num = NUM_WILD_IDS;
            oxm_capabilities->oxm_ids = xmalloc(sizeof(wildcarded));
            memcpy(oxm_capabilities->oxm_ids, wildcarded, sizeof(wildcarded));
            oxm_capabilities->header.length = ofl_structs_table_features_properties_ofp_len(&oxm_capabilities->header, NULL);                         
            *prop =  (struct ofl_table_feature_prop_header*) oxm_capabilities;
            break;
        }        
        case OFPTFPT_EXPERIMENTER:
        case OFPTFPT_EXPERIMENTER_MISS:{
            break;        
        }        
    }
}

static int
flow_table_features(struct ofl_table_features *features){

    int type, j;
    features->properties = (struct ofl_table_feature_prop_header **) xmalloc(sizeof(struct ofl_table_feature_prop_header *) * TABLE_FEATURES_NUM);
    j = 0;
    for(type = OFPTFPT_INSTRUCTIONS; type <= OFPTFPT_APPLY_SETFIELD_MISS; type++){ 
        //features->properties[j] = xmalloc(sizeof(struct ofl_table_feature_prop_header));
        flow_table_create_property(&features->properties[j], type);
        if(type == OFPTFPT_MATCH|| type == OFPTFPT_WILDCARDS){
            type++;
        }
        j++;
    }
    /* Sanity check. Jean II */
    if(j != TABLE_FEATURES_NUM) {
        VLOG_WARN(LOG_MODULE, "Invalid number of table features, %d instead of %d.", j, TABLE_FEATURES_NUM);
        abort();
    }
    return j;
}

struct flow_table *
flow_table_create(struct datapath *dp, uint8_t table_id) {
    struct flow_table *table;
    struct ds string = DS_EMPTY_INITIALIZER;

    ds_put_format(&string, "table_%u", table_id);

    table = xmalloc(sizeof(struct flow_table));
    table->dp = dp;
    table->disabled = 0;
    
    /*Init table stats */
    table->stats = xmalloc(sizeof(struct ofl_table_stats));
    table->stats->table_id      = table_id;
    table->stats->active_count  = 0;
    table->stats->lookup_count  = 0;
    table->stats->matched_count = 0;

    /* Init Table features */
    table->features = xmalloc(sizeof(struct ofl_table_features));
    table->features->table_id = table_id;
    table->features->name          = ds_cstr(&string);
    table->features->metadata_match = 0xffffffffffffffff; 
    table->features->metadata_write = 0xffffffffffffffff;
    table->features->config        = OFPTC_TABLE_MISS_CONTROLLER;
    table->features->max_entries   = FLOW_TABLE_MAX_ENTRIES;
    table->features->properties_num = flow_table_features(table->features);

    list_init(&table->match_entries);
    list_init(&table->hard_entries);
    list_init(&table->idle_entries);

    table->state_table = state_table_create();

    return table;
}

void
flow_table_destroy(struct flow_table *table) {
    struct flow_entry *entry, *next;

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, match_node, &table->match_entries) {
        flow_entry_destroy(entry);
    }
    free(table->features);
    free(table->stats);
    state_table_destroy(table->state_table);
    free(table);
}

void
flow_table_stats(struct flow_table *table, struct ofl_msg_multipart_request_flow *msg,
                 struct ofl_flow_stats ***stats, size_t *stats_size, size_t *stats_num, struct ofl_exp *exp) {
    struct flow_entry *entry;

    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        if ((msg->out_port == OFPP_ANY || flow_entry_has_out_port(entry, msg->out_port)) &&
            (msg->out_group == OFPG_ANY || flow_entry_has_out_group(entry, msg->out_group)) &&
            match_std_nonstrict((struct ofl_match *)msg->match,
                                (struct ofl_match *)entry->stats->match, exp)) {

            flow_entry_update(entry);
            if ((*stats_size) == (*stats_num)) {
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_flow_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
            }
            (*stats)[(*stats_num)] = entry->stats;
            (*stats_num)++;
        }
    }
}

void
flow_table_aggregate_stats(struct flow_table *table, struct ofl_msg_multipart_request_flow *msg,
                           uint64_t *packet_count, uint64_t *byte_count, uint32_t *flow_count) {
    struct flow_entry *entry;

    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        if ((msg->out_port == OFPP_ANY || flow_entry_has_out_port(entry, msg->out_port)) &&
            (msg->out_group == OFPG_ANY || flow_entry_has_out_group(entry, msg->out_group))) {
			
			if (!entry->no_pkt_count)
            	(*packet_count) += entry->stats->packet_count;
			if (!entry->no_byt_count)            
				(*byte_count)   += entry->stats->byte_count;
            (*flow_count)++;
        }
    }

}

