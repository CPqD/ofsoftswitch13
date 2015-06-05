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

#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include "ofl-exp.h"
#include "ofl-exp-nicira.h"
#include "ofl-exp-openflow.h"
#include "ofl-exp-openstate.h"
#include "../oflib/ofl-messages.h"
#include "../oflib/ofl-log.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow-ext.h"
#include "openflow/openstate-ext.h"

#define LOG_MODULE ofl_exp
OFL_LOG_INIT(LOG_MODULE)



int
ofl_exp_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len) {
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_pack(msg, buf, buf_len);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_pack(msg, buf, buf_len);
        }
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_msg_pack(msg, buf, buf_len);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown EXPERIMENTER message (%u).", msg->experimenter_id);
            return -1;
        }
    }
}

ofl_err
ofl_exp_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg) {
    struct ofp_experimenter_header *exp;

    if (*len < sizeof(struct ofp_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message is shorter than ofp_experimenter_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_experimenter_header *)oh;

    switch (ntohl(exp->experimenter)) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_unpack(oh, len, msg);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_unpack(oh, len, msg);
        }
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_msg_unpack(oh, len, msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown EXPERIMENTER message (%u).", ntohl(exp->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}

int
ofl_exp_msg_free(struct ofl_msg_experimenter *msg) {
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_free(msg);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_free(msg);
        }
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_msg_free(msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown EXPERIMENTER message (%u).", msg->experimenter_id);
            free(msg);
            return -1;
        }
    }
}

char *
ofl_exp_msg_to_string(struct ofl_msg_experimenter *msg) {
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_to_string(msg);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_to_string(msg);
        }
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_msg_to_string(msg);
        }
        default: {
            char *str;
            size_t str_size;
            FILE *stream = open_memstream(&str, &str_size);
            OFL_LOG_WARN(LOG_MODULE, "Trying to convert to string unknown EXPERIMENTER message (%u).", msg->experimenter_id);
            fprintf(stream, "exp{id=\"0x%"PRIx32"\"}", msg->experimenter_id);
            fclose(stream);
            return str;
        }
    }
}

int 
ofl_exp_act_pack(struct ofl_action_header *src, struct ofp_action_header *dst){

    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) src;
    
    switch (exp->experimenter_id) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_act_pack(src,dst);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}

ofl_err 
ofl_exp_act_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst){
    
    struct ofp_action_experimenter_header *exp;

    if (*len < sizeof(struct ofp_action_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action is shorter than ofp_experimenter_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }


    exp = (struct ofp_action_experimenter_header *)src;

    switch(ntohl(exp->experimenter)){
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_act_unpack(src,len,dst);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}


int     
ofl_exp_act_free(struct ofl_action_header *act){
    
    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) act;
        
    switch (exp->experimenter_id) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_act_free(act);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}

size_t
ofl_exp_act_ofp_len(struct ofl_action_header *act){    

    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) act;
    switch (exp->experimenter_id) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_act_ofp_len(act);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}

char *
ofl_exp_act_to_string(struct ofl_action_header *act){

    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) act;
    
    switch (exp->experimenter_id) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_act_to_string(act);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}

int 
ofl_exp_stats_req_pack (struct ofl_msg_multipart_request_header *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp){

    struct ofl_msg_multipart_request_experimenter *ext = (struct ofl_msg_multipart_request_experimenter *) msg;
    switch (ext->experimenter_id) {

        case (OPENSTATE_VENDOR_ID):
            return ofl_exp_openstate_stats_req_pack(ext, buf, buf_len, exp);
                
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown multipart EXPERIMENTER message (%u).", ext->experimenter_id);
            return -1;
        }
    }
}

int 
ofl_exp_stats_reply_pack (struct ofl_msg_multipart_reply_header *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp){
    struct ofl_msg_multipart_reply_experimenter *ext = (struct ofl_msg_multipart_reply_experimenter *) msg;
    switch (ext->experimenter_id) {

        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_stats_reply_pack(ext, buf, buf_len, exp);
        }
                
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown multipart EXPERIMENTER message (%u).", ext->experimenter_id);
            return -1;
        }
    }
}

ofl_err
ofl_exp_stats_req_unpack (struct ofp_multipart_request *os, uint8_t *buf, size_t *len, struct ofl_msg_multipart_request_header **msg, struct ofl_exp *exp){

    struct ofp_experimenter_stats_header *ext  = (struct ofp_experimenter_stats_header *)os->body;

    if (*len < sizeof(struct ofp_experimenter_stats_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message is shorter than ofp_experimenter_stats_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch (ntohl(ext->experimenter)) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_stats_req_unpack(os, buf, len, msg, exp);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown EXPERIMENTER message %"PRIx32".", ntohl(ext->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}

ofl_err
ofl_exp_stats_reply_unpack (struct ofp_multipart_reply *os, uint8_t *buf, size_t *len, struct ofl_msg_multipart_reply_header **msg, struct ofl_exp *exp){
    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *)os->body;

    if (*len < sizeof(struct ofp_experimenter_stats_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message is shorter than ofp_experimenter_stats_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch (ntohl(ext->experimenter)) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_stats_reply_unpack(os, buf, len, (struct ofl_msg_multipart_reply_header **)msg, exp);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown EXPERIMENTER message (%u).", ntohl(ext->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}

char *
ofl_exp_stats_req_to_string (struct ofl_msg_multipart_request_header *msg, struct ofl_exp *exp){
    struct ofl_msg_multipart_request_experimenter *ext = (struct ofl_msg_multipart_request_experimenter *) msg;
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    switch (ext->experimenter_id) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_stats_request_to_string(ext, exp);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to convert to string unknown EXPERIMENTER message (%u).", ext->experimenter_id);
            fprintf(stream, "exp{id=\"0x%"PRIx32"\"}", ext->experimenter_id);           
        }
    }
    fclose(stream);
    return str;
}
    

char *
ofl_exp_stats_reply_to_string (struct ofl_msg_multipart_reply_header *msg, struct ofl_exp *exp){
    struct ofl_msg_multipart_reply_experimenter *ext = (struct ofl_msg_multipart_reply_experimenter *) msg;
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    switch (ext->experimenter_id) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_stats_reply_to_string(ext, exp);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to convert to string unknown EXPERIMENTER message %"PRIx32".", ext->experimenter_id);
            fprintf(stream, "exp{id=\"0x%"PRIx32"\"}", ext->experimenter_id);
        }
    }
    fclose(stream);
    return str;
}

int
ofl_exp_stats_req_free (struct ofl_msg_multipart_request_header *msg){
    struct ofl_msg_multipart_request_experimenter *exp = (struct ofl_msg_multipart_request_experimenter *) msg;
    switch (exp->experimenter_id) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_stats_req_free(msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown EXPERIMENTER message (%u).", exp->experimenter_id);
            free(msg);
            return -1;
        }
    }
}

int
ofl_exp_stats_reply_free (struct ofl_msg_multipart_reply_header *msg){
    struct ofl_msg_multipart_reply_experimenter *exp = (struct ofl_msg_multipart_reply_experimenter *) msg;
    switch (exp->experimenter_id) {
        case (OPENSTATE_VENDOR_ID): {
            return ofl_exp_openstate_stats_reply_free(msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown EXPERIMENTER message (%u).", exp->experimenter_id);
            free(msg);
            return -1;
        }
    }
}

void
ofl_exp_field_pack (struct ofpbuf *buf, struct ofl_match_tlv *oft){
    /*pollins: probabilmente ci sarà da definire una struttura che determina la posizione dell'experimenter ID (come è fatto adesso presuppone che sia il primo valore in value)*/
    switch(*((uint32_t*) (oft->value)))
    {
        case OPENSTATE_VENDOR_ID:{
            ofl_exp_openstate_field_pack(buf, oft);
            break;
        }
        default:
            break;
    }
}

int
ofl_exp_field_unpack (struct ofl_match *match, struct oxm_field *f, void *experimenter_id, void *value, void *mask){
    switch (ntohl(*((uint32_t*) experimenter_id))) {
        case OPENSTATE_VENDOR_ID:{
            return ofl_exp_openstate_field_unpack(match, f, experimenter_id, value, mask);
            }
        default:
                NOT_REACHED();
        }
    NOT_REACHED();
}

void
ofl_exp_field_match (struct ofl_match_tlv *f, int *packet_header, int *field_len, uint8_t **flow_val, uint8_t **flow_mask){
    switch(*((uint32_t*) (f->value))){
        case OPENSTATE_VENDOR_ID:
            ofl_exp_openstate_field_match(f, packet_header, field_len, flow_val, flow_mask);
            break;
        default:
            break;             
    }
}

void
ofl_exp_field_compare (struct ofl_match_tlv *f, struct ofl_match_tlv *packet_f, uint8_t **packet_val){
    switch(*((uint32_t*) (f->value)))
    {
        case OPENSTATE_VENDOR_ID:
            ofl_exp_openstate_field_compare(packet_f, packet_val);
            break;
        default:
            break;
    }
}

void
ofl_exp_field_match_std (struct ofl_match_tlv *flow_mod_match, struct ofl_match_tlv *flow_entry_match, int *field_len, uint8_t **flow_mod_val, uint8_t **flow_entry_val, uint8_t **flow_mod_mask, uint8_t **flow_entry_mask){
    switch(*((uint32_t*)(flow_mod_match->value)))
    {
        case OPENSTATE_VENDOR_ID:
            ofl_exp_openstate_field_match_std(flow_mod_match, flow_mod_match, field_len, flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask);
            break;
        default:
            break;
    }
}

void
ofl_exp_field_overlap_a (struct ofl_match_tlv *f_a, int *field_len, uint8_t **val_a, uint8_t **mask_a, int *header, int *header_m, uint64_t *all_mask){
    switch(*((uint32_t*) (f_a->value)))
    {
        case OPENSTATE_VENDOR_ID:
            ofl_exp_openstate_field_overlap_a(f_a, field_len, val_a, mask_a, header, header_m, all_mask);
            break;
        default:
            break;
    }
}

void
ofl_exp_field_overlap_b (struct ofl_match_tlv *f_b, int *field_len, uint8_t **val_b, uint8_t **mask_b, uint64_t *all_mask){
    switch(*((uint32_t*) (f_b->value)))
    {
        case OPENSTATE_VENDOR_ID:
            ofl_exp_openstate_field_overlap_b(f_b, field_len, val_b, mask_b, all_mask);
            break;
        default:
            break;
    }
}