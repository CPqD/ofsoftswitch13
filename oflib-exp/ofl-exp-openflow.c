/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
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
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "openflow/openflow.h"
#include "openflow/openflow-ext.h"
#include "ofl-exp-openflow.h"
#include "../oflib/ofl-log.h"
#include "../oflib/ofl-print.h"
 #include "../oflib/ofl-utils.h"

#define LOG_MODULE ofl_exp_of
OFL_LOG_INIT(LOG_MODULE)



/* functions used by OFP_EXP_STATE_MOD*/
static ofl_err
ofl_structs_extraction_unpack(struct ofp_exp_extraction *src, size_t *len, struct ofl_exp_msg_extraction *dst) {
    int error=0;
    int i;
    if(*len == (1+ntohl(src->field_count))*sizeof(uint32_t) && (ntohl(src->field_count)>0))
    {
        dst->field_count=ntohl(src->field_count);
        for (i=0;i<dst->field_count;i++)
        {
            dst->fields[i]=ntohl(src->fields[i]);
        }
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod extraction is too short (%zu).", *len);
       return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    *len -= ((1+ntohl(src->field_count))*sizeof(uint32_t));
 
    return 0;
}

static ofl_err
ofl_structs_key_unpack(struct ofp_exp_state_entry *src, size_t *len, struct ofl_exp_msg_state_entry *dst) {
    int error=0;
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if((*len == (2*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t))) && (ntohl(src->key_len)>0))
    {
        dst->key_len=ntohl(src->key_len);
        dst->state=ntohl(src->state);
        for (i=0;i<dst->key_len;i++)
        {
            key[i]=src->key[i];
        }
        memcpy(dst->key, key, OFPSC_MAX_KEY_LEN);
        OFL_LOG_WARN(LOG_MODULE, "key count is %d\n",dst->key_len);
        OFL_LOG_WARN(LOG_MODULE, "state is %d\n",dst->state);  
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod add flow is too short (%zu).", *len);
       return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
 

    *len -= (2*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t));
 
    return 0;
}



int
ofl_exp_openflow_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len) {
    if (msg->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;
        switch (exp->type) {
            case (OFP_EXT_QUEUE_MODIFY):
            case (OFP_EXT_QUEUE_DELETE): {
                struct ofl_exp_openflow_msg_queue *q = (struct ofl_exp_openflow_msg_queue *)exp;
                struct openflow_queue_command_header *ofp;

                *buf_len = sizeof(struct openflow_queue_command_header) + ofl_structs_packet_queue_ofp_len(q->queue);
                *buf     = (uint8_t *)malloc(*buf_len);

                ofp = (struct openflow_queue_command_header *)(*buf);
                ofp->header.vendor  = htonl(exp->header.experimenter_id);
                ofp->header.subtype = htonl(exp->type);
                ofp->port = htonl(q->port_id);

                ofl_structs_packet_queue_pack(q->queue, (struct ofp_packet_queue *)ofp->body);
                return 0;
            }
            case (OFP_EXT_SET_DESC): {
                struct ofl_exp_openflow_msg_set_dp_desc *s = (struct ofl_exp_openflow_msg_set_dp_desc *)exp;
                struct openflow_ext_set_dp_desc *ofp;

                *buf_len  = sizeof(struct openflow_ext_set_dp_desc);
                *buf     = (uint8_t *)malloc(*buf_len);

                ofp = (struct openflow_ext_set_dp_desc *)(*buf);
                ofp->header.vendor  = htonl(exp->header.experimenter_id);
                ofp->header.subtype = htonl(exp->type);
                strncpy(ofp->dp_desc, s->dp_desc, DESC_STR_LEN);

                return 0;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Openflow Experimenter message.");
                return -1;
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-Openflow Experimenter message.");
        return -1;
    }
}

ofl_err
ofl_exp_openflow_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg) {
    struct ofp_message_extension_header *exp;

    if (*len < sizeof(struct ofp_message_extension_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_message_extension_header *)oh;


    if (ntohl(exp->vendor) == OPENFLOW_VENDOR_ID) {

        switch (ntohl(exp->subtype)) {
            case (OFP_EXT_QUEUE_MODIFY):
            case (OFP_EXT_QUEUE_DELETE): 
            {
                struct openflow_queue_command_header *src;
                struct ofl_exp_openflow_msg_queue *dst;
                ofl_err error;

                if (*len < sizeof(struct openflow_queue_command_header)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received EXT_QUEUE_MODIFY message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }
                *len -= sizeof(struct openflow_queue_command_header);

                src = (struct openflow_queue_command_header *)exp;

                dst = (struct ofl_exp_openflow_msg_queue *)malloc(sizeof(struct ofl_exp_openflow_msg_queue));
                dst->header.header.experimenter_id = ntohl(exp->vendor);
                dst->header.type                   = ntohl(exp->subtype);
                dst->port_id                       = ntohl(src->port);

                error = ofl_structs_packet_queue_unpack((struct ofp_packet_queue *)(src->body), len, &(dst->queue));
                if (error) {
                    free(dst);
                    return error;
                }

                (*msg) = (struct ofl_msg_experimenter *)dst;
                return 0;
            }
            case (OFP_EXT_SET_DESC): 
            {
                struct openflow_ext_set_dp_desc *src;
                struct ofl_exp_openflow_msg_set_dp_desc *dst;


                if (*len < sizeof(struct openflow_ext_set_dp_desc)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received EXT_SET_DESC message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }
                *len -= sizeof(struct openflow_ext_set_dp_desc);

                src = (struct openflow_ext_set_dp_desc *)exp;

                dst = (struct ofl_exp_openflow_msg_set_dp_desc *)malloc(sizeof(struct ofl_exp_openflow_msg_set_dp_desc));
                dst->header.header.experimenter_id = ntohl(exp->vendor);
                dst->header.type                   = ntohl(exp->subtype);

                dst->dp_desc = strcpy((char *)malloc(strlen(src->dp_desc)+1), src->dp_desc);

                (*msg) = (struct ofl_msg_experimenter *)dst;
                return 0;
            }
            case (OFP_EXT_STATE_MOD): 
            {
                struct ofp_exp_state_mod *sm;
                struct ofl_exp_msg_state_mod *dm;
                ofl_err error;
                size_t i;
                int state_entry_pos;

                if (*len < sizeof(struct ofp_exp_state_mod)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }
                sm = (struct ofp_exp_state_mod *)exp;
                dm = (struct ofl_exp_msg_state_mod *)malloc(sizeof(struct ofl_exp_msg_state_mod));
                
                if (sm->table_id >= PIPELINE_TABLES) {
                    OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%zu).", sm->table_id );
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
                } 
                *len -= sizeof(struct ofp_message_extension_header);

                dm->header.header.experimenter_id = ntohl(exp->vendor);
                dm->header.type                   = ntohl(exp->subtype);
                dm->cookie = ntoh64(sm->cookie);
                dm->cookie_mask = ntoh64(sm->cookie_mask);
                dm->table_id = sm->table_id;
                dm->command = (enum ofp_exp_state_mod_command)sm->command;
                
                *len -= sizeof(dm->cookie) + sizeof(dm->cookie_mask) + sizeof(dm->table_id) + 1;

                
                if (dm->command == OFPSC_ADD_FLOW_STATE || dm->command == OFPSC_DEL_FLOW_STATE){
                error = ofl_structs_key_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                } 

                else if(dm->command ==OFPSC_SET_L_EXTRACTOR || dm->command == OFPSC_SET_U_EXTRACTOR){
                error = ofl_structs_extraction_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                }
                (*msg) = (struct ofl_msg_experimenter *)dm;
                return 0;
            }

            case (OFP_EXT_FLAG_MOD): 
            {
                struct ofp_exp_flag_mod *sm;
                struct ofl_exp_msg_flag_mod *dm;
                ofl_err error;
                size_t i;
               
                
                if (*len < sizeof(struct ofp_exp_flag_mod)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received FLAG_MOD message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }
                sm = (struct ofp_exp_flag_mod *)exp;
                dm = (struct ofl_exp_msg_flag_mod *)malloc(sizeof(struct ofl_exp_msg_flag_mod));
                
                *len -= sizeof(struct ofp_exp_flag_mod);

                dm->header.header.experimenter_id = ntohl(exp->vendor);
                dm->header.type                   = ntohl(exp->subtype);
                dm->flag = ntohl(sm->flag);
                dm->flag_mask = ntohl(sm->flag_mask);
                dm->command = (enum ofp_exp_flag_mod_command)sm->command;
            
                (*msg) = (struct ofl_msg_experimenter *)dm;
                return 0;
            }

            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Openflow Experimenter message.");
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to unpack non-Openflow Experimenter message.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
    }
    free(msg);
    return 0;
}

int
ofl_exp_openflow_msg_free(struct ofl_msg_experimenter *msg) {
    if (msg->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;
        switch (exp->type) {
            case (OFP_EXT_QUEUE_MODIFY):
            case (OFP_EXT_QUEUE_DELETE): {
                struct ofl_exp_openflow_msg_queue *q = (struct ofl_exp_openflow_msg_queue *)exp;
                ofl_structs_free_packet_queue(q->queue);
                break;
            }
            case (OFP_EXT_SET_DESC): {
                struct ofl_exp_openflow_msg_set_dp_desc *s = (struct ofl_exp_openflow_msg_set_dp_desc *)exp;
                free(s->dp_desc);
                break;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Openflow Experimenter message.");
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to free non-Openflow Experimenter message.");
    }
    free(msg);
    return 0;
}

char *
ofl_exp_openflow_msg_to_string(struct ofl_msg_experimenter *msg) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    if (msg->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;
        switch (exp->type) {
            case (OFP_EXT_QUEUE_MODIFY):
            case (OFP_EXT_QUEUE_DELETE): {
                struct ofl_exp_openflow_msg_queue *q = (struct ofl_exp_openflow_msg_queue *)exp;
                fprintf(stream, "%squeue{port=\"", exp->type == OFP_EXT_QUEUE_MODIFY ? "mod" : "del");
                ofl_port_print(stream, q->port_id);
                fprintf(stream, "\", queue=");
                ofl_structs_queue_print(stream, q->queue);
                fprintf(stream, "}");
                break;
            }
            case (OFP_EXT_SET_DESC): {
                struct ofl_exp_openflow_msg_set_dp_desc *s = (struct ofl_exp_openflow_msg_set_dp_desc *)exp;
                fprintf(stream, "setdesc{desc=\"%s\"}", s->dp_desc);
                break;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Openflow Experimenter message.");
                fprintf(stream, "ofexp{type=\"%u\"}", exp->type);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-Openflow Experimenter message.");
        fprintf(stream, "exp{exp_id=\"%u\"}", msg->experimenter_id);
    }

    fclose(stream);
    return str;
}

/*experimenter action functions*/

ofl_err
ofl_exp_openflow_act_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst) {

    if (*len < sizeof(struct ofp_action_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    struct ofp_action_experimenter_header *exp;
    exp = (struct ofp_action_experimenter_header *)src;

    if (ntohl(exp->experimenter) == OPENFLOW_VENDOR_ID) {
        struct ofp_action_extension_header *ext;
        ext = (struct ofp_action_extension_header *)exp;

        switch (ntohl(ext->act_type)) {
            case (OFPAT_EXP_SET_STATE): 
            {
                struct ofp_exp_action_set_state *sa;
                struct ofl_exp_action_set_state *da;
                if (*len < sizeof(struct ofp_exp_action_set_state)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received SET STATE action has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
                }
                sa = (struct ofp_exp_action_set_state *)ext;
                da = (struct ofl_exp_action_set_state *)malloc(sizeof(struct ofl_exp_action_set_state));


                if (sa->stage_id >= PIPELINE_TABLES) {
                    if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                        char *ts = ofl_table_to_string(sa->stage_id);
                        OFL_LOG_WARN(LOG_MODULE, "Received SET STATE action has invalid stage_id (%s).", ts);
                        free(ts);
                    }
                    free(da);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
                }

                da->header.header.experimenter_id = ntohl(exp->experimenter);
                da->header.act_type = ntohl(ext->act_type);
                da->state = ntohl(sa->state);
                da->stage_id = sa->stage_id;

                *dst = (struct ofl_action_header *)da;
                *len -= sizeof(struct ofp_exp_action_set_state);
                break; 
            }

            case (OFPAT_EXP_SET_FLAG): 
            {
                struct ofp_exp_action_set_flag *sa;
                struct ofl_exp_action_set_flag *da;
                if (*len < sizeof(struct ofp_exp_action_set_flag)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received SET FLAG action has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
                }
                sa = (struct ofp_exp_action_set_flag*)ext;
                da = (struct ofl_exp_action_set_flag *)malloc(sizeof(struct ofl_exp_action_set_flag));

                da->header.header.experimenter_id = ntohl(exp->experimenter);
                da->header.act_type = ntohl(ext->act_type);
                da->value = ntohl(sa->value);
                da->mask = ntohl(sa->mask);

                *dst = (struct ofl_action_header *)da;
                *len -= sizeof(struct ofp_exp_action_set_flag);
                break; 
            }

            default: 
            {
                OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Openflow Experimenter action.");
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            }
        }
    }
    return 0;
}

int 
ofl_exp_openflow_act_pack(struct ofl_action_header *src, struct ofp_action_header *dst){
    
    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) src;
    
    if (exp->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_act_header *ext = (struct ofl_exp_openflow_act_header *)exp;
        switch (ext->act_type) {
            case (OFPAT_EXP_SET_STATE):
            {
                struct ofl_exp_action_set_state *sa = (struct ofl_exp_action_set_state *) ext;
                struct ofp_exp_action_set_state *da = (struct ofp_exp_action_set_state *) dst;

                da->header.header.experimenter = htonl(exp->experimenter_id);
                da->header.act_type = htonl(ext->act_type);
                memset(da->header.pad, 0x00, 4);
                da->state = htonl(sa->state);
                da->stage_id = sa->stage_id;
                memset(da->pad, 0x00, 3);
                dst->len = htons(sizeof(struct ofp_exp_action_set_state));

                return sizeof(struct ofp_exp_action_set_state);
            }
            case (OFPAT_EXP_SET_FLAG): 
            {
                struct ofl_exp_action_set_flag *sa = (struct ofl_exp_action_set_flag *) ext;
                struct ofp_exp_action_set_flag *da = (struct ofp_exp_action_set_flag *) dst;

                da->header.header.experimenter = htonl(exp->experimenter_id);
                da->header.act_type = htonl(ext->act_type);
                memset(da->header.pad, 0x00, 4);
                da->value = htonl(sa->value);
                da->mask = htonl(sa->mask);
                dst->len = htons(sizeof(struct ofp_exp_action_set_flag));

                return sizeof(struct ofp_exp_action_set_flag);
            }
            default:
                return 0;
        }
    }
}

size_t
ofl_exp_openflow_act_ofp_len(struct ofl_action_header *act)
{
    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) act;
    if (exp->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_act_header *ext = (struct ofl_exp_openflow_act_header *)exp;
        switch (ext->act_type) {

            case (OFPAT_EXP_SET_STATE):
                return sizeof(struct ofp_exp_action_set_state);

            case (OFPAT_EXP_SET_FLAG):
                return sizeof(struct ofp_exp_action_set_flag);

            default:
                return 0;
        }
    }
}

char *
ofl_exp_openflow_act_to_string(struct ofl_action_header *act)
{
    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) act;
    
    if (exp->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_act_header *ext = (struct ofl_exp_openflow_act_header *)exp;
        switch (ext->act_type) {
            case (OFPAT_EXP_SET_STATE):
            {
                struct ofl_exp_action_set_state *a = (struct ofl_exp_action_set_state *)ext;
                char *string = malloc(50);
                sprintf(string, "{set_state=[state=\"%u\",stage_id=\"%u\"]}", a->state, a->stage_id);
                return string;
                break;
            }
            case (OFPAT_EXP_SET_FLAG): 
            {
                struct ofl_exp_action_set_flag *a = (struct ofl_exp_action_set_flag *)ext;
                char *string = malloc(100);
                char string_value[33];
                masked_value_print(string_value,decimal_to_binary(a->value),decimal_to_binary(a->mask));
                sprintf(string, "{set_flag=[flag=%s]}", string_value);
                return string;
                break;
            }
        }
    }
}

int     
ofl_exp_openflow_act_free(struct ofl_action_header *act){

    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) act;
    struct ofl_exp_openflow_act_header *ext = (struct ofl_exp_openflow_act_header *)exp;
    if (exp->experimenter_id == OPENFLOW_VENDOR_ID) {
        switch (ext->act_type) {
            case (OFPAT_EXP_SET_STATE):
            {
                struct ofl_exp_action_set_state *a = (struct ofl_exp_action_set_state *)ext;
                free(a);
                return;
                break;
            }
            case (OFPAT_EXP_SET_FLAG):
            {
                struct ofl_exp_action_set_flag *a = (struct ofl_exp_action_set_flag *)ext;
                free(a);
                return;
                break;
            }
        }
    }
    free(act);
}