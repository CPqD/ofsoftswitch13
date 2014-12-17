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

#include <netinet/in.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include "oxm-match.h"
#include "ofl.h"
#include "ofl-utils.h"
#include "ofl-actions.h"
#include "ofl-structs.h"
#include "ofl-messages.h"
#include "ofl-log.h"
#include "openflow/openflow.h"

#define LOG_MODULE ofl_act_p
OFL_LOG_INIT(LOG_MODULE)


size_t
ofl_actions_ofp_len(struct ofl_action_header *action, struct ofl_exp *exp) {
    switch (action->type) {
        case OFPAT_OUTPUT:
            return sizeof(struct ofp_action_output);
       
        case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN:
            return sizeof(struct ofp_action_header);
        case OFPAT_SET_MPLS_TTL:
            return sizeof(struct ofp_action_mpls_ttl);
        case OFPAT_DEC_MPLS_TTL:
            return sizeof(struct ofp_action_header);
        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_PBB:
        case OFPAT_PUSH_MPLS:  
            return sizeof(struct ofp_action_push);
        case OFPAT_POP_VLAN:
        case OFPAT_POP_PBB:
            return sizeof(struct ofp_action_header);
        case OFPAT_POP_MPLS:
            return sizeof(struct ofp_action_pop_mpls);
        case OFPAT_SET_QUEUE:
            return sizeof(struct ofp_action_set_queue);
        case OFPAT_GROUP:
            return sizeof(struct ofp_action_group);
        case OFPAT_SET_NW_TTL:
            return sizeof(struct ofp_action_nw_ttl);
        case OFPAT_DEC_NW_TTL:
            return sizeof(struct ofp_action_header);
        case OFPAT_SET_FIELD: {
            struct ofl_action_set_field  *a = (struct ofl_action_set_field  *) action;  
            return sizeof(struct ofp_action_set_field) + ROUND_UP(OXM_LENGTH(a->field->header),8) ;
        }    
        case OFPAT_EXPERIMENTER: {
            if (exp == NULL || exp->act == NULL || exp->act->ofp_len == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "requesting experimenter length, but no callback was given.");
                return -1;
            }
            return exp->act->ofp_len(action);
        }
        default:
            return 0;
    }
}

size_t
ofl_actions_ofp_total_len(struct ofl_action_header **actions,
                          size_t actions_num, struct ofl_exp *exp) {
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN2(sum, actions, actions_num,
                           ofl_actions_ofp_len, exp);
    return sum;
}

size_t
ofl_actions_pack(struct ofl_action_header *src, struct ofp_action_header *dst, uint8_t* data,  struct ofl_exp *exp) {

    dst->type = htons(src->type);
    memset(dst->pad, 0x00, 4);

    switch (src->type) {
        case OFPAT_OUTPUT: {
            struct ofl_action_output *sa = (struct ofl_action_output *)src;
            struct ofp_action_output *da = (struct ofp_action_output *)dst;

            da->len =     htons(sizeof(struct ofp_action_output));
            da->port =    htonl(sa->port);
            da->max_len = htons(sa->max_len);
            memset(da->pad, 0x00, 6);
            return sizeof(struct ofp_action_output);
        }
      
        case OFPAT_COPY_TTL_OUT:
        case OFPAT_COPY_TTL_IN: {
            dst->len = htons(sizeof(struct ofp_action_header));
            return sizeof(struct ofp_action_header);
        }
      
        case OFPAT_SET_MPLS_TTL: {
            struct ofl_action_mpls_ttl *sa = (struct ofl_action_mpls_ttl *)src;
            struct ofp_action_mpls_ttl *da = (struct ofp_action_mpls_ttl *)dst;

            da->len =      htons(sizeof(struct ofp_action_mpls_ttl));
            da->mpls_ttl = sa->mpls_ttl;
            memset(da->pad, 0x00, 3);
            return sizeof(struct ofp_action_mpls_ttl);
        }
        case OFPAT_DEC_MPLS_TTL: {
            dst->len = htons(sizeof(struct ofp_action_header));
            return sizeof(struct ofp_action_header);
        }
        case OFPAT_PUSH_VLAN:
        case OFPAT_PUSH_MPLS: 
        case OFPAT_PUSH_PBB:{
            struct ofl_action_push *sa = (struct ofl_action_push *)src;
            struct ofp_action_push *da = (struct ofp_action_push *)dst;

            da->len =       htons(sizeof(struct ofp_action_push));
            da->ethertype = htons(sa->ethertype);
            memset(da->pad, 0x00, 2);
            return sizeof(struct ofp_action_push);
        }
        case OFPAT_POP_VLAN: 
        case OFPAT_POP_PBB: {
            struct ofp_action_header *da = (struct ofp_action_header *)dst;

            da->len = htons(sizeof(struct ofp_action_header));
            return sizeof (struct ofp_action_header);
        }
        case OFPAT_POP_MPLS: {
            struct ofl_action_pop_mpls *sa = (struct ofl_action_pop_mpls *)src;
            struct ofp_action_pop_mpls *da = (struct ofp_action_pop_mpls *)dst;

            da->len =       htons(sizeof(struct ofp_action_pop_mpls));
            da->ethertype = htons(sa->ethertype);
            memset(da->pad, 0x00, 2);
            return sizeof(struct ofp_action_pop_mpls);
        }
        case OFPAT_SET_QUEUE: {
            struct ofl_action_set_queue *sa = (struct ofl_action_set_queue *)src;
            struct ofp_action_set_queue *da = (struct ofp_action_set_queue *)dst;

            da->len =      htons(sizeof(struct ofp_action_set_queue));
            da->queue_id = htonl(sa->queue_id);
            return sizeof(struct ofp_action_set_queue);
        }
        case OFPAT_GROUP: {
            struct ofl_action_group *sa = (struct ofl_action_group *)src;
            struct ofp_action_group *da = (struct ofp_action_group *)dst;

            da->len =      htons(sizeof(struct ofp_action_group));
            da->group_id = htonl(sa->group_id);
            return sizeof(struct ofp_action_group);
        }
        case OFPAT_SET_NW_TTL: {
            struct ofl_action_set_nw_ttl *sa = (struct ofl_action_set_nw_ttl *)src;
            struct ofp_action_nw_ttl *da = (struct ofp_action_nw_ttl *)dst;

            da->len =    htons(sizeof(struct ofp_action_nw_ttl));
            da->nw_ttl = sa->nw_ttl;
            memset(da->pad, 0x00, 3);
            return sizeof(struct ofp_action_nw_ttl);
        }
        case OFPAT_DEC_NW_TTL: {
            dst->len = htons(sizeof(struct ofp_action_header));
            return sizeof(struct ofp_action_header);
        }
        case OFPAT_SET_FIELD: {
            struct ofl_action_set_field *sa = (struct ofl_action_set_field *) src;
            struct ofp_action_set_field *da = (struct ofp_action_set_field *) dst;
            uint32_t header;
            uint8_t padding_size;
                        
            da->len = htons(sizeof(struct ofp_action_set_field) + ROUND_UP(OXM_LENGTH(sa->field->header),8));
            /*Put OXM header in the field*/
            header = htonl(sa->field->header);
            memcpy(&da->field, &header, 4);
            switch (OXM_LENGTH(sa->field->header)){
                case 1:
                case 6:
                case 3:
                case 16:
                    memcpy(data + (sizeof(struct ofp_action_set_field)), sa->field->value, OXM_LENGTH(sa->field->header));
                    break;
                case 2:{
                   uint16_t value = htons(*((uint16_t*) sa->field->value));
                   memcpy(data + (sizeof(struct ofp_action_set_field)),&value,OXM_LENGTH(sa->field->header));
                    break;
                }
                case 4:{
                    uint32_t value; 
					uint8_t field = OXM_FIELD(sa->field->header);					
					if( field != 11 && field != 12 && field != 22 && field != 23) 
						value = htonl(*((uint32_t*) sa->field->value));
					else  
						value = *((uint32_t*) sa->field->value);                   
					memcpy(data + (sizeof(struct ofp_action_set_field)), &value, OXM_LENGTH(sa->field->header));
                    break;
                }
                case 8:{
                    uint64_t value = hton64(*((uint64_t*) sa->field->value));
                    memcpy(data + (sizeof(struct ofp_action_set_field)),&value,OXM_LENGTH(sa->field->header));
                    break;
                }
            }
            /*padding*/
            padding_size = ROUND_UP(OXM_LENGTH(sa->field->header),8) - OXM_LENGTH(sa->field->header);
            memset(data + (sizeof(struct ofp_action_set_field) + OXM_LENGTH(sa->field->header)), 0, padding_size);            
            return ntohs((da->len));
        
        }
        case OFPAT_EXPERIMENTER: {
            if (exp == NULL || exp->act == NULL || exp->act->pack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Trying to pack experimenter, but no callback was given.");
                return 0;
            }
            return exp->act->pack(src, dst);
        }
        default:
            return 0;
    };
}
