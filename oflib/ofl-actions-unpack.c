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
#include "ofl.h"
#include "ofl-utils.h"
#include "ofl-actions.h"
#include "ofl-structs.h"
#include "ofl-messages.h"
#include "ofl-print.h"
#include "ofl-packets.h"
#include "ofl-log.h"
#include "openflow/openflow.h"
#include "oxm-match.h"

#define LOG_MODULE ofl_act_u
OFL_LOG_INIT(LOG_MODULE)


ofl_err
ofl_actions_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst, struct ofl_exp *exp) {

    if (*len < sizeof(struct ofp_action_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received action is too short (%zu).", *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if (*len < ntohs(src->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received action has invalid length (set to %u, but only %zu received).", ntohs(src->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    if ((ntohs(src->len) % 8) != 0) {
        OFL_LOG_WARN(LOG_MODULE, "Received action length is not a multiple of 64 bits (%u).", ntohs(src->len));
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    switch (ntohs(src->type)) {
        case OFPAT_OUTPUT: {
            struct ofp_action_output *sa;
            struct ofl_action_output *da;

            if (*len < sizeof(struct ofp_action_output)) {
                OFL_LOG_WARN(LOG_MODULE, "Received OUTPUT action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_output *)src;

            if (ntohl(sa->port) == 0 ||
                (ntohl(sa->port) > OFPP_MAX && ntohl(sa->port) < OFPP_IN_PORT) ||
                ntohl(sa->port) == OFPP_ANY) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ps = ofl_port_to_string(ntohl(sa->port));
                    OFL_LOG_WARN(LOG_MODULE, "Received OUTPUT action has invalid port (%s).", ps);
                    free(ps);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }

            da = (struct ofl_action_output *)malloc(sizeof(struct ofl_action_output));
            da->port = ntohl(sa->port);
            da->max_len = ntohs(sa->max_len);

            *len -= sizeof(struct ofp_action_output);
            *dst = (struct ofl_action_header *)da;
            break;
        }
        case OFPAT_COPY_TTL_OUT: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_COPY_TTL_IN: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_SET_MPLS_TTL: {
            struct ofp_action_mpls_ttl *sa;
            struct ofl_action_mpls_ttl *da;

            if (*len < sizeof(struct ofp_action_mpls_ttl)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_MPLS_TTL action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_mpls_ttl *)src;

            da = (struct ofl_action_mpls_ttl *)malloc(sizeof(struct ofl_action_mpls_ttl));
            da->mpls_ttl = sa->mpls_ttl;

            *len -= sizeof(struct ofp_action_mpls_ttl);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_DEC_MPLS_TTL: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_mpls_ttl);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_PUSH_VLAN: 
        case OFPAT_PUSH_PBB:
        case OFPAT_PUSH_MPLS: {
            struct ofp_action_push *sa;
            struct ofl_action_push *da;

            if (*len < sizeof(struct ofp_action_push)) {
                OFL_LOG_WARN(LOG_MODULE, "Received PUSH_VLAN/MPLS/PBB action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_push *)src;

            if (((ntohs(src->type) == OFPAT_PUSH_VLAN) &&
                    (ntohs(sa->ethertype) != ETH_TYPE_VLAN &&
                     ntohs(sa->ethertype) != ETH_TYPE_VLAN_PBB)) ||
                ((ntohs(src->type) == OFPAT_PUSH_MPLS) &&
                    (ntohs(sa->ethertype) != ETH_TYPE_MPLS &&
                     ntohs(sa->ethertype) != ETH_TYPE_MPLS_MCAST)) ||
                ((ntohs(src->type) == OFPAT_PUSH_PBB) &&
                    (ntohs(sa->ethertype) != ETH_TYPE_PBB))) {
                OFL_LOG_WARN(LOG_MODULE, "Received PUSH_VLAN/MPLS/PBB has invalid eth type. (%u)", ntohs(sa->ethertype));
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_ARGUMENT);
            }

            da = (struct ofl_action_push *)malloc(sizeof(struct ofl_action_push));
            da->ethertype = ntohs(sa->ethertype);

            *len -= sizeof(struct ofp_action_push);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_POP_VLAN: 
        case OFPAT_POP_PBB: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }
                
        case OFPAT_POP_MPLS: {
            struct ofp_action_pop_mpls *sa;
            struct ofl_action_pop_mpls *da;

            if (*len < sizeof(struct ofp_action_pop_mpls)) {
                OFL_LOG_WARN(LOG_MODULE, "Received POP_MPLS action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_pop_mpls *)src;

            da = (struct ofl_action_pop_mpls *)malloc(sizeof(struct ofl_action_pop_mpls));
            da->ethertype = ntohs(sa->ethertype);

            *len -= sizeof(struct ofp_action_pop_mpls);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_QUEUE: {
            struct ofp_action_set_queue *sa;
            struct ofl_action_set_queue *da;

            if (*len < sizeof(struct ofp_action_set_queue)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_QUEUE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_set_queue *)src;

            da = (struct ofl_action_set_queue *)malloc(sizeof(struct ofl_action_set_queue));
            da->queue_id = ntohl(sa->queue_id);

            *len -= sizeof(struct ofp_action_set_queue);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_GROUP: {
            struct ofp_action_group *sa;
            struct ofl_action_group *da;

            if (*len < sizeof(struct ofp_action_group)) {
                OFL_LOG_WARN(LOG_MODULE, "Received GROUP action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_group *)src;

            if (ntohl(sa->group_id) > OFPG_MAX) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *gs = ofl_group_to_string(ntohl(sa->group_id));
                    OFL_LOG_WARN(LOG_MODULE, "Received GROUP action has invalid group id (%s).", gs);
                    free(gs);
                }
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
            }

            da = (struct ofl_action_group *)malloc(sizeof(struct ofl_action_group));
            da->group_id = ntohl(sa->group_id);

            *len -= sizeof(struct ofp_action_group);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_SET_NW_TTL: {
            struct ofp_action_nw_ttl *sa;
            struct ofl_action_set_nw_ttl *da;

            if (*len < sizeof(struct ofp_action_nw_ttl)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET_NW_TTL action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            sa = (struct ofp_action_nw_ttl *)src;

            da = (struct ofl_action_set_nw_ttl *)malloc(sizeof(struct ofl_action_set_nw_ttl));
            da->nw_ttl = sa->nw_ttl;

            *len -= sizeof(struct ofp_action_nw_ttl);
            *dst = (struct ofl_action_header *)da;
            break;
        }

        case OFPAT_DEC_NW_TTL: {
            //ofp_action_header length was already checked
            *len -= sizeof(struct ofp_action_header);
            *dst = (struct ofl_action_header *)malloc(sizeof(struct ofl_action_header));
            break;
        }

        case OFPAT_SET_FIELD: {
            struct ofp_action_set_field *sa;
            struct ofl_action_set_field *da;
            uint8_t *value;
            
            sa = (struct ofp_action_set_field*) src;
            da = (struct ofl_action_set_field *)malloc(sizeof(struct ofl_action_set_field));
            da->field = (struct ofl_match_tlv*) malloc(sizeof(struct ofl_match_tlv));
            
            memcpy(&da->field->header,sa->field,4);
            da->field->header = ntohl(da->field->header);
            value = (uint8_t *) src + sizeof (struct ofp_action_set_field);
            da->field->value = malloc(OXM_LENGTH(da->field->header));
            /*TODO: need to check if other fields are valid */
            if(da->field->header == OXM_OF_IN_PORT || da->field->header == OXM_OF_IN_PHY_PORT
                                    || da->field->header == OXM_OF_METADATA
                                    || da->field->header == OXM_OF_IPV6_EXTHDR){

                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_SET_TYPE);
            }
            switch(OXM_LENGTH(da->field->header)){
                case 1:
                case 3:
                case 6:
                case 16:
                    memcpy(da->field->value , value, OXM_LENGTH(da->field->header));
                    break;
                case 2:{
                   uint16_t v = ntohs(*((uint16_t*) value));
                   memcpy(da->field->value , &v, OXM_LENGTH(da->field->header));
                    break;
                }
                case 4:{
                    uint32_t v; 
        		    uint8_t field = OXM_FIELD(da->field->header);					
        		    if( field != 11 && field != 12 && field != 22 && field != 23)  
        		        v = htonl(*((uint32_t*) value));
        		    else v = *((uint32_t*) value);
                    memcpy(da->field->value , &v, OXM_LENGTH(da->field->header));
                    break;
                }
                case 8:{
                    uint64_t v = ntoh64(*((uint64_t*) value));                    
                    memcpy(da->field->value , &v, OXM_LENGTH(da->field->header));
                    break;
                }                
            }
     	    *len -= ROUND_UP(ntohs(src->len),8);
     	    *dst = (struct ofl_action_header *)da;
            break;
	}

        case OFPAT_EXPERIMENTER: {
            ofl_err error;

            if (*len < sizeof(struct ofp_action_experimenter_header)) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
            }

            if (exp == NULL || exp->act == NULL || exp->act->unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action, but no callback is given.");
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_EXPERIMENTER);
            }
            error = exp->act->unpack(src, len, dst);
            if (error) {
                return error;
            }
            break;
        }

        default: {
            OFL_LOG_WARN(LOG_MODULE, "Received unknown action type (%u).", ntohs(src->type));
            return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
        }
    }
    (*dst)->type = (enum ofp_action_type)((int)ntohs(src->type));

    return 0;
}
