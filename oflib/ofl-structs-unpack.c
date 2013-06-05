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
#include "ofl-print.h"
#include "ofl-actions.h"
#include "ofl-structs.h"
#include "ofl-utils.h"
#include "ofl-packets.h"
#include "ofl-log.h"
#include "oxm-match.h"
#include "openflow/openflow.h"

#define LOG_MODULE ofl_str_u
OFL_LOG_INIT(LOG_MODULE)

ofl_err
ofl_structs_instructions_unpack(struct ofp_instruction *src, size_t *len, struct ofl_instruction_header **dst, struct ofl_exp *exp) {
    size_t ilen;
    struct ofl_instruction_header *inst = NULL;

    if (*len < sizeof(struct ofp_instruction)) {
        OFL_LOG_WARN(LOG_MODULE, "Received instruction is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received instruction has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    ilen = ntohs(src->len);

    switch (ntohs(src->type)) {
        case OFPIT_GOTO_TABLE: {
            struct ofp_instruction_goto_table *si;
            struct ofl_instruction_goto_table *di;

            if (ilen < sizeof(struct ofp_instruction_goto_table)) {
                OFL_LOG_WARN(LOG_MODULE, "Received GOTO_TABLE instruction has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }

            si = (struct ofp_instruction_goto_table *)src;

            if (si->table_id >= PIPELINE_TABLES) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ts = ofl_table_to_string(si->table_id);
                    OFL_LOG_WARN(LOG_MODULE, "Received GOTO_TABLE instruction has invalid table_id (%s).", ts);
                    free(ts);
                }
                return ofl_error(OFPET_BAD_INSTRUCTION, OFPBIC_BAD_TABLE_ID);
            }

            di = (struct ofl_instruction_goto_table *)malloc(sizeof(struct ofl_instruction_goto_table));

            di->table_id = si->table_id;

            inst = (struct ofl_instruction_header *)di;
            ilen -= sizeof(struct ofp_instruction_goto_table);
            break;
        }

        case OFPIT_WRITE_METADATA: {
            struct ofp_instruction_write_metadata *si;
            struct ofl_instruction_write_metadata *di;

            if (ilen < sizeof(struct ofp_instruction_write_metadata)) {
                OFL_LOG_WARN(LOG_MODULE, "Received WRITE_METADATA instruction has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }

            si = (struct ofp_instruction_write_metadata *)src;
            di = (struct ofl_instruction_write_metadata *)malloc(sizeof(struct ofl_instruction_write_metadata));

            di->metadata =      ntoh64(si->metadata);
            di->metadata_mask = ntoh64(si->metadata_mask);

            inst = (struct ofl_instruction_header *)di;
            ilen -= sizeof(struct ofp_instruction_write_metadata);
            break;
        }
        case OFPIT_WRITE_ACTIONS:
        case OFPIT_APPLY_ACTIONS: {
            struct ofp_instruction_actions *si;
            struct ofl_instruction_actions *di;
            struct ofp_action_header *act;
            ofl_err error;
            size_t i;

            if (ilen < sizeof(struct ofp_instruction_actions)) {
                OFL_LOG_WARN(LOG_MODULE, "Received *_ACTIONS instruction has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }
            ilen -= sizeof(struct ofp_instruction_actions);

            si = (struct ofp_instruction_actions *)src;
            di = (struct ofl_instruction_actions *)malloc(sizeof(struct ofl_instruction_actions));

            error = ofl_utils_count_ofp_actions((uint8_t *)si->actions, ilen, &di->actions_num);
            if (error) {
                free(di);
                return error;
            }
            di->actions = (struct ofl_action_header **)malloc(di->actions_num * sizeof(struct ofl_action_header *));

            act = si->actions;
            for (i = 0; i < di->actions_num; i++) {
                error = ofl_actions_unpack(act, &ilen, &(di->actions[i]), exp);
                if (error) {
                    *len = *len - ntohs(src->len) + ilen;
                    OFL_UTILS_FREE_ARR_FUN2(di->actions, i,
                                            ofl_actions_free, exp);
                    free(di);
                    return error;
                }
                act = (struct ofp_action_header *)((uint8_t *)act + ntohs(act->len));
            }

            inst = (struct ofl_instruction_header *)di;
            break;
        }
        case OFPIT_CLEAR_ACTIONS: {
            if (ilen < sizeof(struct ofp_instruction_actions)) {
                OFL_LOG_WARN(LOG_MODULE, "Received CLEAR_ACTIONS instruction has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }

            inst = (struct ofl_instruction_header *)malloc(sizeof(struct ofl_instruction_header));
            inst->type = (enum ofp_instruction_type)ntohs(src->type);

            ilen -= sizeof(struct ofp_instruction_actions);
            break;
        }
        case OFPIT_METER: {
            struct ofp_instruction_meter *si;
            struct ofl_instruction_meter *di;
            
            if (ilen < sizeof(struct ofp_instruction_meter)) {
                OFL_LOG_WARN(LOG_MODULE, "Received METER instruction has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }
            si = (struct ofp_instruction_meter*)src;
            di = (struct ofl_instruction_meter *)malloc(sizeof(struct ofl_instruction_meter));

            di->meter_id = ntohl(si->meter_id);

            inst = (struct ofl_instruction_header *)di;
            ilen -= sizeof(struct ofp_instruction_meter);
            break; 
        }
        case OFPIT_EXPERIMENTER: {
            ofl_err error;

            if (exp == NULL || exp->inst == NULL || exp->inst->unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER instruction, but no callback was given.");
                return ofl_error(OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST);
            }
            error = exp->inst->unpack(src, &ilen, &inst);
            if (error) {
                return error;
            }
            break;
        }
    }

    // must set type before check, so free works correctly
    inst->type = (enum ofp_instruction_type)ntohs(src->type);

    if (ilen != 0) {
        *len = *len - ntohs(src->len) + ilen;
        OFL_LOG_WARN(LOG_MODULE, "The received instruction contained extra bytes (%zu).", ilen);
        ofl_structs_free_instruction(inst, exp);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->len);
    (*dst) = inst;

    return 0;
}

static ofl_err 
ofl_structs_table_properties_unpack(struct ofp_table_feature_prop_header * src, size_t *len, struct ofl_table_feature_prop_header **dst, struct ofl_exp *exp){
    size_t plen;
    ofl_err error;
    struct ofl_table_feature_prop_header * prop = NULL;
        
    if (*len < sizeof(struct ofp_table_feature_prop_header)){
        OFL_LOG_WARN(LOG_MODULE, "Received feature is too short (%zu).", *len);
        return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
    }    
    
    if (*len < ntohs(src->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received table property has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    plen = ntohs(src->length);
    
	switch(ntohs(src->type)){
 		case OFPTFPT_INSTRUCTIONS:
        case OFPTFPT_INSTRUCTIONS_MISS:{
			struct ofp_table_feature_prop_instructions *sp = (struct ofp_table_feature_prop_instructions*) src;
			struct ofl_table_feature_prop_instructions *dp;
            size_t ilen,i;
            uint8_t *ptr;
            
			if (plen < sizeof(struct ofp_table_feature_prop_instructions)) {
                OFL_LOG_WARN(LOG_MODULE, "Received INSTRUCTION feature has invalid length (%zu).", *len);
                return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
            }
			
			dp =  (struct ofl_table_feature_prop_instructions*) malloc(sizeof(struct ofl_table_feature_prop_instructions));		
            ilen = plen - sizeof(struct ofp_table_feature_prop_instructions);
            error = ofl_utils_count_ofp_instructions((uint8_t*) sp->instruction_ids, ilen, &dp->ids_num);			
			if(error){
			    free(dp);
			    return error;
			}
			dp->instruction_ids = (struct ofl_instruction_header*) malloc(sizeof(struct ofl_instruction_header) * dp->ids_num);

            ptr = (uint8_t*) sp->instruction_ids;	
			for(i = 0; i < dp->ids_num; i++){
			    dp->instruction_ids[i].type = ntohs(((struct ofp_instruction*) ptr)->type);
                ptr +=  ntohs(((struct ofp_instruction*) ptr)->len); 
			}
			plen -= ntohs(sp->length);
			prop = (struct ofl_table_feature_prop_header*) dp;
			break;
		}
        case OFPTFPT_NEXT_TABLES:
        case OFPTFPT_NEXT_TABLES_MISS:{
			struct ofp_table_feature_prop_next_tables *sp = (struct ofp_table_feature_prop_next_tables*) src;
			struct ofl_table_feature_prop_next_tables *dp;
			
			if (plen < sizeof(struct ofp_table_feature_prop_next_tables)) {
                OFL_LOG_WARN(LOG_MODULE, "Received NEXT TABLE feature has invalid length (%zu).", *len);
                return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
            }			
			dp = (struct ofl_table_feature_prop_next_tables*) malloc(sizeof(struct ofl_table_feature_prop_next_tables));		
		    
		    dp->table_num = ntohs(sp->length) - sizeof(struct ofp_table_feature_prop_next_tables);
            dp->next_table_ids = (uint8_t*) malloc(sizeof(uint8_t) * dp->table_num);
            memcpy(dp->next_table_ids, sp->next_table_ids, dp->table_num);
            
            plen -= ntohs(sp->length);            		    
		    prop = (struct ofl_table_feature_prop_header*) dp;	
			break;
		}
        case OFPTFPT_WRITE_ACTIONS:
        case OFPTFPT_WRITE_ACTIONS_MISS:
        case OFPTFPT_APPLY_ACTIONS:
        case OFPTFPT_APPLY_ACTIONS_MISS:{
			struct ofp_table_feature_prop_actions *sp = (struct ofp_table_feature_prop_actions*) src;
			struct ofl_table_feature_prop_actions *dp;
			size_t alen, i;
			uint8_t *ptr;
			
			if (plen < sizeof(struct ofp_table_feature_prop_actions)) {
                OFL_LOG_WARN(LOG_MODULE, "Received ACTION feature has invalid length (%zu).", *len);
                return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
            }
            alen = plen - sizeof(struct ofp_table_feature_prop_actions);
			dp = (struct ofl_table_feature_prop_actions*) malloc(sizeof(struct ofl_table_feature_prop_actions));		
		    error = ofl_utils_count_ofp_actions((uint8_t*)sp->action_ids, alen, &dp->actions_num);
            if(error){
			    free(dp);
			    return error;
			}
			
			dp->action_ids = (struct ofl_action_header*) malloc(sizeof(struct ofl_action_header) * dp->actions_num);
			
			ptr = (uint8_t*) sp->action_ids;	
			for(i = 0; i < dp->actions_num; i++){
			    dp->action_ids[i].type = ntohs(((struct ofp_action_header*) ptr)->type);
                dp->action_ids[i].len = ntohs(((struct ofp_action_header*) ptr)->len);
                ptr +=  ntohs(((struct ofp_action_header*) ptr)->len); 
			}
		    plen -= ntohs(sp->length);
		    prop = (struct ofl_table_feature_prop_header*) dp;	
			break;		
		}
        case OFPTFPT_MATCH:
        case OFPTFPT_WILDCARDS:
        case OFPTFPT_WRITE_SETFIELD:
        case OFPTFPT_WRITE_SETFIELD_MISS:
        case OFPTFPT_APPLY_SETFIELD:
        case OFPTFPT_APPLY_SETFIELD_MISS:{
			struct ofp_table_feature_prop_oxm *sp = (struct ofp_table_feature_prop_oxm*) src;
			struct ofl_table_feature_prop_oxm *dp;
			size_t i;
			
			if (plen < sizeof(struct ofp_table_feature_prop_oxm)) {
                OFL_LOG_WARN(LOG_MODULE, "Received MATCH feature has invalid length (%zu).", *len);
                return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
            }			
			
			dp = (struct ofl_table_feature_prop_oxm*) malloc(sizeof(struct ofl_table_feature_prop_oxm));		
		    
		    dp->oxm_num = (ntohs(sp->length) - sizeof(struct ofp_table_feature_prop_oxm))/sizeof(uint32_t);
            dp->oxm_ids = (uint32_t*) malloc(sizeof(uint32_t) * dp->oxm_num);
            for(i = 0; i < dp->oxm_num; i++ ){
                    dp->oxm_ids[i] = ntohl(sp->oxm_ids[i]);
            }
            plen -= ntohs(sp->length);  		    
		    prop = (struct ofl_table_feature_prop_header*) dp;	

			break;
		}				
	}
    // must set type before check, so free works correctly
    prop->type = (enum ofp_table_feature_prop_type) ntohs(src->type);
    /* Make sure it can be reused for packing. Jean II */
    prop->length = ntohs(src->length);

	if (plen != 0){
        *len = *len - ntohs(src->length) + plen;
        OFL_LOG_WARN(LOG_MODULE, "The received property contained extra bytes (%zu).", plen);
        //ofl_structs_free_property(inst, exp);
        return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
    }
	*len -= ntohs(src->length);    
	(*dst) = prop;
    return 0;
}


ofl_err
ofl_structs_table_features_unpack(struct ofp_table_features *src,size_t *len, struct ofl_table_features **dst, struct ofl_exp *exp){
    struct ofl_table_features *feat;
    uint8_t *prop;
    ofl_err error;
    size_t plen, i;
    
    if(*len < sizeof(struct ofp_table_features)){
        OFL_LOG_WARN(LOG_MODULE, "Received table feature is too short (%zu).", *len);  
        return ofl_error(OFPET_TABLE_FEATURES_FAILED, OFPTFFC_BAD_LEN);
    }
    
    if(*len < ntohs(src->length)){
        OFL_LOG_WARN(LOG_MODULE, "Received table_feature has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    
    feat = (struct ofl_table_features*) malloc(sizeof(struct ofl_table_features));

    feat->length = ntohs(src->length);
    feat->table_id = src->table_id;
    feat->name = malloc(OFP_MAX_TABLE_NAME_LEN);
    strncpy(feat->name, src->name, OFP_MAX_TABLE_NAME_LEN);
    feat->metadata_match = ntoh64(src->metadata_match); 
    feat->metadata_write =  ntoh64(src->metadata_write);
    feat->config = ntohl(src->config);
    feat->max_entries = ntohl(src->max_entries);
    
    plen = ntohs(src->length) - sizeof(struct ofp_table_features);
    error = ofl_utils_count_ofp_table_features_properties((uint8_t*) src->properties, plen, &feat->properties_num);
    if (error) {
        free(feat);
        return error;
    }
    feat->properties = (struct ofl_table_feature_prop_header**) malloc(sizeof(struct ofl_table_feature_prop_header *) * feat->properties_num);
    
    prop = (uint8_t*) src->properties;
    for(i = 0; i < feat->properties_num; i++){
        error = ofl_structs_table_properties_unpack((struct ofp_table_feature_prop_header*) prop, &plen, &feat->properties[i], exp);
        if (error) {
            *len = *len - ntohs(src->length) + plen;
            /*OFL_UTILS_FREE_ARR_FUN2(b->actions, i,
                                    ofl_actions_free, exp);*/
            free(feat);
            return error;
        }
        prop += ROUND_UP(ntohs(((struct ofp_table_feature_prop_header*) prop)->length),8);
    }        
    
    *len -= ntohs(src->length);

    *dst = feat;
    return 0;
}

ofl_err
ofl_structs_bucket_unpack(struct ofp_bucket *src, size_t *len, uint8_t gtype, struct ofl_bucket **dst, struct ofl_exp *exp) {
    struct ofl_bucket *b;
    struct ofp_action_header *act;
    size_t blen;
    ofl_err error;
    size_t i;

    if (*len < sizeof(struct ofp_bucket)) {
        OFL_LOG_WARN(LOG_MODULE, "Received bucket is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received bucket has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    blen = ntohs(src->len) - sizeof(struct ofp_bucket);

    if (gtype == OFPGT_SELECT && ntohs(src->weight) == 0) {
        OFL_LOG_WARN(LOG_MODULE, "Received bucket has no weight for SELECT group.");
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    if (gtype != OFPGT_SELECT && ntohs(src->weight) > 0) {
        OFL_LOG_WARN(LOG_MODULE, "Received bucket has weight for non-SELECT group.");
        return ofl_error(OFPET_GROUP_MOD_FAILED, OFPGMFC_INVALID_GROUP);
    }

    b = (struct ofl_bucket *)malloc(sizeof(struct ofl_bucket));

    b->weight =      ntohs(src->weight);
    b->watch_port =  ntohl(src->watch_port);
    b->watch_group = ntohl(src->watch_group);

    error = ofl_utils_count_ofp_actions((uint8_t *)src->actions, blen, &b->actions_num);
    if (error) {
        free(b);
        return error;
    }
    b->actions = (struct ofl_action_header **)malloc(b->actions_num * sizeof(struct ofl_action_header *));

    act = src->actions;
    for (i = 0; i < b->actions_num; i++) {
        error = ofl_actions_unpack(act, &blen, &(b->actions[i]), exp);
        if (error) {
            *len = *len - ntohs(src->len) + blen;
            OFL_UTILS_FREE_ARR_FUN2(b->actions, i,
                                    ofl_actions_free, exp);
            free(b);
            return error;
        }
        act = (struct ofp_action_header *)((uint8_t *)act + ntohs(act->len));
    }

    if (blen >= 8) {
        *len = *len - ntohs(src->len) + blen;
        ofl_structs_free_bucket(b, exp);
        OFL_LOG_WARN(LOG_MODULE, "Received bucket has more than 64 bit padding (%zu).", blen);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= ntohs(src->len);

    *dst = b;
    return 0;
}


ofl_err
ofl_structs_flow_stats_unpack(struct ofp_flow_stats *src, uint8_t *buf, size_t *len, struct ofl_flow_stats **dst, struct ofl_exp *exp) {
    struct ofl_flow_stats *s;
    struct ofp_instruction *inst;
    ofl_err error;
    size_t slen;
    size_t i;
    int match_pos;
    if (*len < ( (sizeof(struct ofp_flow_stats) - sizeof(struct ofp_match)) + ROUND_UP(ntohs(src->match.length),8))) {
        OFL_LOG_WARN(LOG_MODULE, "Received flow stats has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received flow stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (src->table_id >= PIPELINE_TABLES) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(src->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received flow stats has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }

    slen = ntohs(src->length) - (sizeof(struct ofp_flow_stats) - sizeof(struct ofp_match));

    s = (struct ofl_flow_stats *)malloc(sizeof(struct ofl_flow_stats));
    s->table_id =             src->table_id;
    s->duration_sec =  ntohl( src->duration_sec);
    s->duration_nsec = ntohl( src->duration_nsec);
    s->priority =      ntohs( src->priority);
    s->idle_timeout =  ntohs( src->idle_timeout);
    s->hard_timeout =  ntohs( src->hard_timeout);
    s->cookie =        ntoh64(src->cookie);
    s->packet_count =  ntoh64(src->packet_count);
    s->byte_count =    ntoh64(src->byte_count);

    match_pos = sizeof(struct ofp_flow_stats) - 4;

    error = ofl_structs_match_unpack(&(src->match),buf + match_pos , &slen, &(s->match), exp);
    if (error) {
        free(s);
        return error;
    }
    error = ofl_utils_count_ofp_instructions((struct ofp_instruction *) (buf + ROUND_UP(match_pos + s->match->length,8)), 
                                            slen, &s->instructions_num);
    
    if (error) {
        ofl_structs_free_match(s->match, exp);
        free(s);
        return error;
    }
   s->instructions = (struct ofl_instruction_header **)malloc(s->instructions_num * sizeof(struct ofl_instruction_header *));

   inst = (struct ofp_instruction *) (buf + ROUND_UP(match_pos + s->match->length,8));
   for (i = 0; i < s->instructions_num; i++) {
        error = ofl_structs_instructions_unpack(inst, &slen, &(s->instructions[i]), exp);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(s->instructions, i,
                                    ofl_structs_free_instruction, exp);
            free(s);
            return error;
        }
        inst = (struct ofp_instruction *)((uint8_t *)inst + ntohs(inst->len));
    }

    if (slen != 0) {
        *len = *len - ntohs(src->length) + slen;
        OFL_LOG_WARN(LOG_MODULE, "The received flow stats contained extra bytes (%zu).", slen);
        ofl_structs_free_flow_stats(s, exp);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= ntohs(src->length);
    *dst = s;
    return 0;
}


ofl_err
ofl_structs_group_stats_unpack(struct ofp_group_stats *src, size_t *len, struct ofl_group_stats **dst) {
    struct ofl_group_stats *s;
    struct ofp_bucket_counter *c;
    ofl_err error;
    size_t slen;
    size_t i;

    if (*len < sizeof(struct ofp_group_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received group desc stats reply is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received group stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (ntohl(src->group_id) > OFPG_MAX) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *gs = ofl_group_to_string(ntohl(src->group_id));
            OFL_LOG_WARN(LOG_MODULE, "Received group stats has invalid group_id (%s).", gs);
            free(gs);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    slen = ntohs(src->length) - sizeof(struct ofp_group_stats);

    s = (struct ofl_group_stats *)malloc(sizeof(struct ofl_group_stats));
    s->group_id = ntohl(src->group_id);
    s->ref_count = ntohl(src->ref_count);
    s->packet_count = ntoh64(src->packet_count);
    s->byte_count = ntoh64(src->byte_count);
    s->duration_sec =  htonl(src->duration_sec);
    s->duration_nsec =  htonl(src->duration_nsec);

    error = ofl_utils_count_ofp_bucket_counters(src->bucket_stats, slen, &s->counters_num);
    if (error) {
        free(s);
        return error;
    }
    s->counters = (struct ofl_bucket_counter **)malloc(s->counters_num * sizeof(struct ofl_bucket_counter *));

    c = src->bucket_stats;
    for (i = 0; i < s->counters_num; i++) {
        error = ofl_structs_bucket_counter_unpack(c, &slen, &(s->counters[i]));
        if (error) {
            OFL_UTILS_FREE_ARR(s->counters, i);
            free(s);
            return error;
        }
        c = (struct ofp_bucket_counter *)((uint8_t *)c + sizeof(struct ofp_bucket_counter));
    }

    if (slen != 0) {
        *len = *len - ntohs(src->length) + slen;
        OFL_LOG_WARN(LOG_MODULE, "The received group stats contained extra bytes (%zu).", slen);
        ofl_structs_free_group_stats(s);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->length);
    *dst = s;
    return 0;
}

ofl_err
ofl_structs_meter_band_stats_unpack(struct ofp_meter_band_stats *src, size_t *len, struct ofl_meter_band_stats **dst){
    struct ofl_meter_band_stats *p;

    if (*len < sizeof(struct ofp_meter_band_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received meter band stats has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_meter_band_stats);

    p = (struct ofl_meter_band_stats *)malloc(sizeof(struct ofl_meter_band_stats));
    p->packet_band_count = ntoh64(src->packet_band_count);
    p->byte_band_count =   ntoh64(src->byte_band_count);

    *dst = p;
    return 0; 
 
}

ofl_err
ofl_structs_meter_stats_unpack(struct ofp_meter_stats *src, size_t *len, struct ofl_meter_stats **dst) {
    struct ofl_meter_stats *s;
    struct ofp_meter_band_stats *c;
    ofl_err error;
    size_t slen;
    size_t i;

    if (*len < sizeof(struct ofp_meter_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received meter stats reply is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received meter stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    slen = ntohs(src->len) - sizeof(struct ofp_meter_stats);

    s = (struct ofl_meter_stats *) malloc(sizeof(struct ofl_meter_stats));
    s->meter_id = ntohl(src->meter_id);
    s->len = ntohs(src->len);
    
    s->flow_count = ntohl(src->flow_count);
    s->packet_in_count = ntoh64(src->packet_in_count);
    s->byte_in_count = ntoh64(src->byte_in_count);
    s->duration_sec =  htonl(src->duration_sec);
    s->duration_nsec =  htonl(src->duration_nsec);

    error = ofl_utils_count_ofp_meter_band_stats(src->band_stats, slen, &s->meter_bands_num);
    if (error) {
        free(s);
        return error;
    }
    s->band_stats = (struct ofl_meter_band_stats **)malloc(s->meter_bands_num * sizeof(struct ofl_meter_band_stats *));

    c = src->band_stats;
    for (i = 0; i < s->meter_bands_num; i++) {
        error = ofl_structs_meter_band_stats_unpack(c, &slen, &(s->band_stats[i]));
        if (error) {
            OFL_UTILS_FREE_ARR(s->band_stats, i);
            free(s);
            return error;
        }
        c = (struct ofp_meter_band_stats *)((uint8_t *)c + sizeof(struct ofp_meter_band_stats));
    }

    if (slen != 0) {
        *len = *len - ntohs(src->len) + slen;
        OFL_LOG_WARN(LOG_MODULE, "The received meter stats contained extra bytes (%zu).", slen);
        ofl_structs_free_meter_stats(s);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= ntohs(src->len);
    *dst = s;
    return 0;
}

ofl_err
ofl_structs_meter_config_unpack(struct ofp_meter_config *src, size_t *len, struct ofl_meter_config **dst) {
    struct ofl_meter_config *s;
    struct ofp_meter_band_header *b;
    ofl_err error;
    size_t slen;
    size_t i;

    if (*len < sizeof(struct ofp_meter_config)) {
        OFL_LOG_WARN(LOG_MODULE, "Received meter config reply is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received meter config reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    slen = ntohs(src->length) - sizeof(struct ofp_meter_config);

    s = (struct ofl_meter_config *) malloc(sizeof(struct ofl_meter_config));
    s->meter_id = ntohl(src->meter_id);
    s->length = ntohs(src->length);
    
    s->flags = ntohs(src->flags);

    error = ofl_utils_count_ofp_meter_bands(src->bands, slen, &s->meter_bands_num);
    if (error) {
        free(s);
        return error;
    }
    s->bands = (struct ofl_meter_band_header **)malloc(s->meter_bands_num * sizeof(struct ofl_meter_band_header *));

    b= src->bands;
    for (i = 0; i < s->meter_bands_num; i++) {
        error = ofl_structs_meter_band_unpack(b, &slen, &(s->bands[i]));
        if (error) {
            OFL_UTILS_FREE_ARR(s->bands, i);
            free(s);
            return error;
        }
        b = (struct ofp_meter_band_header *)((uint8_t *)b + ntohs(b->len));
    }

    if (slen != 0) {
        *len = *len - ntohs(src->length) + slen;
        OFL_LOG_WARN(LOG_MODULE, "The received meter config contained extra bytes (%zu).", slen);
        //ofl_structs_free_meter_stats(s);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= ntohs(src->length);
    *dst = s;
    return 0;
}

ofl_err
ofl_structs_queue_prop_unpack(struct ofp_queue_prop_header *src, size_t *len, struct ofl_queue_prop_header **dst) {

    if (*len < sizeof(struct ofp_action_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received queue property is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received queue property has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    switch (ntohs(src->property)) {
        case OFPQT_MIN_RATE: {
            struct ofp_queue_prop_min_rate *sp = (struct ofp_queue_prop_min_rate *)src;
            struct ofl_queue_prop_min_rate *dp = (struct ofl_queue_prop_min_rate *)malloc(sizeof(struct ofl_queue_prop_min_rate));

            if (*len < sizeof(struct ofp_queue_prop_min_rate)) {
                OFL_LOG_WARN(LOG_MODULE, "Received MIN_RATE queue property has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }
            *len -= sizeof(struct ofp_queue_prop_min_rate);

            dp->rate = ntohs(sp->rate);

            *dst = (struct ofl_queue_prop_header *)dp;
            break;
        }
        case OFPQT_MAX_RATE:{
            struct ofp_queue_prop_max_rate *sp = (struct ofp_queue_prop_max_rate *)src;
            struct ofl_queue_prop_max_rate *dp = (struct ofl_queue_prop_max_rate *)malloc(sizeof(struct ofl_queue_prop_max_rate));
            
            if (*len < sizeof(struct ofp_queue_prop_max_rate)) {
                OFL_LOG_WARN(LOG_MODULE, "Received MAX_RATE queue property has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }
            *len -= sizeof(struct ofp_queue_prop_max_rate);   
            dp->rate = ntohs(sp->rate);

            *dst = (struct ofl_queue_prop_header *)dp;
            break;    
        
        }
        case OFPQT_EXPERIMENTER:{
            struct ofp_queue_prop_experimenter *sp = (struct ofp_queue_prop_experimenter *)src;
            struct ofl_queue_prop_experimenter *dp = (struct ofl_queue_prop_experimenter *)malloc(sizeof(struct ofl_queue_prop_experimenter));
            
            if (*len < sizeof(struct ofp_queue_prop_experimenter)) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER queue property has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
            }
            *len -= sizeof(struct ofp_queue_prop_experimenter);   
            dp->data = sp->data;

            *dst = (struct ofl_queue_prop_header *)dp;
            break;    
        
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Received unknown queue prop type.");
            return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
        }
    }

    (*dst)->type = (enum ofp_queue_properties)ntohs(src->property);
    return 0;
}


ofl_err
ofl_structs_packet_queue_unpack(struct ofp_packet_queue *src, size_t *len, struct ofl_packet_queue **dst) {
    struct ofl_packet_queue *q;
    struct ofp_queue_prop_header *prop;
    ofl_err error;
    size_t i;

    if (*len < ntohs(src->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received packet queue has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_packet_queue);

    q = (struct ofl_packet_queue *)malloc(sizeof(struct ofl_packet_queue));
    q->queue_id = ntohl(src->queue_id);

    error = ofl_utils_count_ofp_queue_props((uint8_t *)src->properties, *len, &q->properties_num);
    if (error) {
        free(q);
        return error;
    }
    q->properties = (struct ofl_queue_prop_header **)malloc(q->properties_num * sizeof(struct ofl_queue_prop_header *));

    prop = src->properties;
    for (i = 0; i < q->properties_num; i++) {
        ofl_structs_queue_prop_unpack(prop, len, &(q->properties[i]));
        prop = (struct ofp_queue_prop_header *)((uint8_t *)prop + ntohs(prop->len));
    }

    *dst = q;
    return 0;
}


ofl_err
ofl_structs_port_unpack(struct ofp_port *src, size_t *len, struct ofl_port **dst) {
    struct ofl_port *p;

    if (*len < sizeof(struct ofp_port)) {
        OFL_LOG_WARN(LOG_MODULE, "Received port has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    if (ntohl(src->port_no) == 0 ||
        (ntohl(src->port_no) > OFPP_MAX && ntohl(src->port_no) != OFPP_LOCAL)) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ps = ofl_port_to_string(ntohl(src->port_no));
            OFL_LOG_WARN(LOG_MODULE, "Received port has invalid port_id (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_port);
    p = (struct ofl_port *)malloc(sizeof(struct ofl_port));

    p->port_no = ntohl(src->port_no);
    memcpy(p->hw_addr, src->hw_addr, ETH_ADDR_LEN);
    p->name = strcpy((char *)malloc(strlen(src->name) + 1), src->name);
    p->config = ntohl(src->config);
    p->state = ntohl(src->state);
    p->curr = ntohl(src->curr);
    p->advertised = ntohl(src->advertised);
    p->supported = ntohl(src->supported);
    p->peer = ntohl(src->peer);
    p->curr_speed = ntohl(src->curr_speed);
    p->max_speed = ntohl(src->max_speed);

    *dst = p;
    return 0;
}



ofl_err
ofl_structs_table_stats_unpack(struct ofp_table_stats *src, size_t *len, struct ofl_table_stats **dst) {
    struct ofl_table_stats *p;

    if (*len < sizeof(struct ofp_table_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received table stats has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }

    if (src->table_id == 0xff) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(src->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received table stats has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_table_stats);

    p = (struct ofl_table_stats *)malloc(sizeof(struct ofl_table_stats));
    p->table_id =      src->table_id;
    p->active_count =  ntohl(src->active_count);
    p->lookup_count =  ntoh64(src->lookup_count);
    p->matched_count = ntoh64(src->matched_count);

    *dst = p;
    return 0;
}

ofl_err
ofl_structs_port_stats_unpack(struct ofp_port_stats *src, size_t *len, struct ofl_port_stats **dst) {
    struct ofl_port_stats *p;

    if (*len < sizeof(struct ofp_port_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received port stats has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    if (ntohl(src->port_no) == 0 ||
        (ntohl(src->port_no) > OFPP_MAX && ntohl(src->port_no) != OFPP_LOCAL)) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ps = ofl_port_to_string(ntohl(src->port_no));
            OFL_LOG_WARN(LOG_MODULE, "Received port stats has invalid port_id (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_port_stats);

    p = (struct ofl_port_stats *)malloc(sizeof(struct ofl_port_stats));

    p->port_no      = ntohl(src->port_no);
    p->rx_packets   = ntoh64(src->rx_packets);
    p->tx_packets   = ntoh64(src->tx_packets);
    p->rx_bytes     = ntoh64(src->rx_bytes);
    p->tx_bytes     = ntoh64(src->tx_bytes);
    p->rx_dropped   = ntoh64(src->rx_dropped);
    p->tx_dropped   = ntoh64(src->tx_dropped);
    p->rx_errors    = ntoh64(src->rx_errors);
    p->tx_errors    = ntoh64(src->tx_errors);
    p->rx_frame_err = ntoh64(src->rx_frame_err);
    p->rx_over_err  = ntoh64(src->rx_over_err);
    p->rx_crc_err   = ntoh64(src->rx_crc_err);
    p->collisions   = ntoh64(src->collisions);
    p->duration_sec = ntohl(src->duration_sec);
    p->duration_nsec = ntohl(src->duration_nsec);
    *dst = p;
    return 0;
}

ofl_err
ofl_structs_queue_stats_unpack(struct ofp_queue_stats *src, size_t *len, struct ofl_queue_stats **dst) {
    struct ofl_queue_stats *p;

    if (*len < sizeof(struct ofp_queue_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received queue stats has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (ntohl(src->port_no) == 0 || ntohl(src->port_no) > OFPP_MAX) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ps = ofl_port_to_string(ntohl(src->port_no));
            OFL_LOG_WARN(LOG_MODULE, "Received queue stats has invalid port_id (%s).", ps);
            free(ps);
        }
        return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_queue_stats);

    p = (struct ofl_queue_stats *)malloc(sizeof(struct ofl_queue_stats));

    p->port_no =    ntohl(src->port_no);
    p->queue_id =   ntohl(src->queue_id);
    p->tx_bytes =   ntoh64(src->tx_bytes);
    p->tx_packets = ntoh64(src->tx_packets);
    p->tx_errors =  ntoh64(src->tx_errors);
    p->duration_sec = ntohl(src->duration_sec);
    p->duration_nsec = ntohl(src->duration_nsec);
    *dst = p;
    return 0;
}

ofl_err
ofl_structs_group_desc_stats_unpack(struct ofp_group_desc_stats *src, size_t *len, struct ofl_group_desc_stats **dst, struct ofl_exp *exp) {
    struct ofl_group_desc_stats *dm;
    struct ofp_bucket *bucket;
    ofl_err error;
    size_t dlen;
    size_t i;

    if (*len < sizeof(struct ofp_group_desc_stats)) {
        OFL_LOG_WARN(LOG_MODULE, "Received group desc stats reply is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received group desc stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (ntohl(src->group_id) > OFPG_MAX) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *gs = ofl_group_to_string(ntohl(src->group_id));
            OFL_LOG_WARN(LOG_MODULE, "Received group desc stats has invalid group_id (%s).", gs);
            free(gs);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    dlen = ntohs(src->length) - sizeof(struct ofp_group_desc_stats);

    dm = (struct ofl_group_desc_stats *)malloc(sizeof(struct ofl_group_desc_stats));

    dm->type = src->type;
    dm->group_id = ntohl(src->group_id);

    error = ofl_utils_count_ofp_buckets(src->buckets, dlen, &dm->buckets_num);
    if (error) {
        free(dm);
        return error;
    }
    dm->buckets = (struct ofl_bucket **)malloc(dm->buckets_num * sizeof(struct ofl_bucket *));

    bucket = src->buckets;
    for (i = 0; i < dm->buckets_num; i++) {
        error = ofl_structs_bucket_unpack(bucket, &dlen, dm->type, &(dm->buckets[i]), exp);
        if (error) {
            OFL_UTILS_FREE_ARR_FUN2(dm->buckets, i,
                                    ofl_structs_free_bucket, exp);
            free (dm);
            return error;
        }
        bucket = (struct ofp_bucket *)((uint8_t *)bucket + ntohs(bucket->len));
    }

    if (dlen != 0) {
        *len = *len - ntohs(src->length) + dlen;
        OFL_LOG_WARN(LOG_MODULE, "The received group desc stats contained extra bytes (%zu).", dlen);
        ofl_structs_free_group_desc_stats(dm, exp);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->length);
    *dst = dm;
    return 0;
}

ofl_err
ofl_structs_bucket_counter_unpack(struct ofp_bucket_counter *src, size_t *len, struct ofl_bucket_counter **dst) {
    struct ofl_bucket_counter *p;

    if (*len < sizeof(struct ofp_bucket_counter)) {
        OFL_LOG_WARN(LOG_MODULE, "Received bucket counter has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= sizeof(struct ofp_bucket_counter);

    p = (struct ofl_bucket_counter *)malloc(sizeof(struct ofl_bucket_counter));
    p->packet_count = ntoh64(src->packet_count);
    p->byte_count =   ntoh64(src->byte_count);

    *dst = p;
    return 0;
}

ofl_err
ofl_structs_meter_band_unpack(struct ofp_meter_band_header *src, size_t *len, struct ofl_meter_band_header **dst){
	struct ofl_meter_band_header *mb;

	if(*len < sizeof(struct ofp_meter_band_header)){
		OFL_LOG_WARN(LOG_MODULE, "Received meter band is too short (%zu).", *len);
		return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
	}
	switch (ntohs(src->type)){
		case OFPMBT_DROP:{
			struct ofl_meter_band_drop *b = (struct ofl_meter_band_drop *)malloc(sizeof(struct ofl_meter_band_drop));
			b->type = ntohs(src->type);
			b->rate = ntohl(src->rate);
			b->burst_size = ntohl(src->burst_size);
			mb = (struct ofl_meter_band_header *)b;
			*dst = mb;
			break;
		}
		case OFPMBT_DSCP_REMARK:{
			struct ofl_meter_band_dscp_remark *b = (struct ofl_meter_band_dscp_remark *)malloc(sizeof(struct ofl_meter_band_dscp_remark));
			struct ofp_meter_band_dscp_remark *s = (struct ofp_meter_band_dscp_remark*)src;
			b->type = ntohs(s->type);
			b->rate = ntohl(s->rate);
			b->burst_size = ntohl(s->burst_size);
			b->prec_level = s->prec_level;
			mb = (struct ofl_meter_band_header *)b;
			*dst = mb;
			break;
		}
		case OFPMBT_EXPERIMENTER:{
			struct ofl_meter_band_experimenter *b = (struct ofl_meter_band_experimenter *)malloc(sizeof(struct ofl_meter_band_experimenter));
			struct ofp_meter_band_experimenter *s = (struct ofp_meter_band_experimenter*) src;
			b->type = ntohs(s->type);
			b->rate = ntohl(s->rate);
			b->burst_size = ntohl(s->burst_size);
			b->experimenter = ntohl(s->experimenter);
			mb = (struct ofl_meter_band_header *)b;
			*dst = mb;
			break;
		}
	}
	*len -= ntohs(src->len);
	return 0;
}



static ofl_err
ofl_structs_oxm_match_unpack(struct ofp_match* src, uint8_t* buf, size_t *len, struct ofl_match **dst){

     int error = 0;
     struct ofpbuf *b = ofpbuf_new(0);
     struct ofl_match *m = (struct ofl_match *) malloc(sizeof(struct ofl_match));
    *len -= ROUND_UP(ntohs(src->length),8);
     if(ntohs(src->length) > sizeof(struct ofp_match)){
         ofpbuf_put(b, buf, ntohs(src->length) - (sizeof(struct ofp_match) -4)); 
         error = oxm_pull_match(b, m, ntohs(src->length) - (sizeof(struct ofp_match) -4));
         m->header.length = ntohs(src->length) - 4;
     }
    else {
		 m->header.length = 0;
		 m->header.type = ntohs(src->type);	
	}
    ofpbuf_delete(b);    
    *dst = m;
    return error;
}

ofl_err
ofl_structs_match_unpack(struct ofp_match *src,uint8_t * buf, size_t *len, struct ofl_match_header **dst, struct ofl_exp *exp) {

    switch (ntohs(src->type)) {
        case (OFPMT_OXM): {

             return ofl_structs_oxm_match_unpack(src, buf, len, (struct ofl_match**) dst );       
            
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received match is experimental, but no callback was given.");
                return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_TYPE);
            }
            return exp->match->unpack(src, len, dst);
        }
    }
}
