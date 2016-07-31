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
#include "ofl-exp-beba.h"
#include "../oflib/ofl-messages.h"
#include "../oflib/ofl-log.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openflow/openflow-ext.h"
#include "openflow/beba-ext.h"

#define LOG_MODULE ofl_exp
OFL_LOG_INIT(LOG_MODULE)



static char *
ofl_exp_unknown_id_to_string(int id)
{
        char *str;
        size_t str_size;
        FILE *stream = open_memstream(&str, &str_size);
        OFL_LOG_WARN(LOG_MODULE, "Trying to convert to string unknown EXPERIMENTER message (%u).", id);
        fprintf(stream, "exp{id=\"0x%"PRIx32"\"}", id);
        fclose(stream);
        return str;
}


int
ofl_exp_msg_pack(struct ofl_msg_experimenter const *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp)
{
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_pack(msg, buf, buf_len);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_pack(msg, buf, buf_len);
        }
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_msg_pack(msg, buf, buf_len, exp);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown EXPERIMENTER message (%u).", msg->experimenter_id);
            return -1;
        }
    }
}

ofl_err
ofl_exp_msg_unpack(struct ofp_header const *oh, size_t *len, struct ofl_msg_experimenter **msg, struct ofl_exp const * ofl_exp)
{
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
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_msg_unpack(oh, len, msg, ofl_exp);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown EXPERIMENTER message (%u).", ntohl(exp->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}

int
ofl_exp_msg_free(struct ofl_msg_experimenter *msg)
{
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_free(msg);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_free(msg);
        }
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_msg_free(msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown EXPERIMENTER message (%u).", msg->experimenter_id);
            free(msg);
            return -1;
        }
    }
}

char *
ofl_exp_msg_to_string(struct ofl_msg_experimenter const *msg)
{
    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            return ofl_exp_openflow_msg_to_string(msg);
        }
        case (NX_VENDOR_ID): {
            return ofl_exp_nicira_msg_to_string(msg);
        }
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_msg_to_string(msg);
        }
        default: {
            return ofl_exp_unknown_id_to_string(msg->experimenter_id);
        }
    }
}

int
ofl_exp_act_pack(struct ofl_action_header const *src, struct ofp_action_header *dst)
{
    struct ofl_action_experimenter const *exp = (struct ofl_action_experimenter const *) src;

    switch (exp->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_act_pack(src,dst);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}

ofl_err
ofl_exp_act_unpack(struct ofp_action_header const *src, size_t *len, struct ofl_action_header **dst)
{
    struct ofp_action_experimenter_header *exp;

    if (*len < sizeof(struct ofp_action_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action is shorter than ofp_experimenter_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }


    exp = (struct ofp_action_experimenter_header *)src;

    switch(ntohl(exp->experimenter)){
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_act_unpack(src,len,dst);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}


int
ofl_exp_act_free(struct ofl_action_header *act)
{
    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) act;

    switch (exp->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_act_free(act);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}

size_t
ofl_exp_act_ofp_len(struct ofl_action_header const *act)
{
    struct ofl_action_experimenter const *exp = (struct ofl_action_experimenter const *) act;

    switch (exp->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_act_ofp_len(act);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}


char *
ofl_exp_act_to_string(struct ofl_action_header const *act)
{
    struct ofl_action_experimenter const * exp = (struct ofl_action_experimenter const *) act;

    switch (exp->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_act_to_string(act);
        }
        default: {
            return ofl_exp_unknown_id_to_string(exp->experimenter_id);
        }
    }
}


int
ofl_exp_stats_req_pack (struct ofl_msg_multipart_request_header const *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp)
{
    struct ofl_msg_multipart_request_experimenter *ext = (struct ofl_msg_multipart_request_experimenter *) msg;

    switch (ext->experimenter_id) {

        case (BEBA_VENDOR_ID):
            return ofl_exp_beba_stats_req_pack(ext, buf, buf_len, exp);

        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown multipart EXPERIMENTER message (%u).", ext->experimenter_id);
            return -1;
        }
    }
}

int
ofl_exp_stats_reply_pack (struct ofl_msg_multipart_reply_header const *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp)
{
    struct ofl_msg_multipart_reply_experimenter const *ext = (struct ofl_msg_multipart_reply_experimenter const *) msg;

    switch (ext->experimenter_id) {

        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_stats_reply_pack(ext, buf, buf_len, exp);
        }

        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown multipart EXPERIMENTER message (%u).", ext->experimenter_id);
            return -1;
        }
    }
}

ofl_err
ofl_exp_stats_req_unpack (struct ofp_multipart_request const *os, uint8_t const *buf, size_t *len,
              struct ofl_msg_multipart_request_header **msg, struct ofl_exp const *exp)
{
    struct ofp_experimenter_stats_header *ext  = (struct ofp_experimenter_stats_header *)os->body;

    if (*len < sizeof(struct ofp_experimenter_stats_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message is shorter than ofp_experimenter_stats_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch (ntohl(ext->experimenter)) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_stats_req_unpack(os, buf, len, msg, exp);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown EXPERIMENTER message %"PRIx32".", ntohl(ext->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}

ofl_err
ofl_exp_stats_reply_unpack (struct ofp_multipart_reply const *os, uint8_t const *buf, size_t *len,
                struct ofl_msg_multipart_reply_header **msg, struct ofl_exp const *exp)
{
    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *)os->body;

    if (*len < sizeof(struct ofp_experimenter_stats_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message is shorter than ofp_experimenter_stats_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    switch (ntohl(ext->experimenter)) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_stats_reply_unpack(os, buf, len, (struct ofl_msg_multipart_reply_header **)msg, exp);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown EXPERIMENTER message (%u).", ntohl(ext->experimenter));
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}

char *
ofl_exp_stats_req_to_string (struct ofl_msg_multipart_request_header const *msg, struct ofl_exp const *exp)
{
    struct ofl_msg_multipart_request_experimenter const *ext = (struct ofl_msg_multipart_request_experimenter const *) msg;
    switch (ext->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_stats_request_to_string(ext, exp);
        }
        default: {
        return ofl_exp_unknown_id_to_string(ext->experimenter_id);
        }
    }
}


char *
ofl_exp_stats_reply_to_string (struct ofl_msg_multipart_reply_header const *msg, struct ofl_exp const *exp)
{
    struct ofl_msg_multipart_reply_experimenter *ext = (struct ofl_msg_multipart_reply_experimenter *) msg;
    switch (ext->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_stats_reply_to_string(ext, exp);
        }
        default: {
            return ofl_exp_unknown_id_to_string(ext->experimenter_id);
        }
    }
}


int
ofl_exp_stats_req_free (struct ofl_msg_multipart_request_header *msg)
{
    struct ofl_msg_multipart_request_experimenter *exp = (struct ofl_msg_multipart_request_experimenter *) msg;

    switch (exp->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_stats_req_free(msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown EXPERIMENTER message (%u).", exp->experimenter_id);
            free(msg);
            return -1;
        }
    }
}

int
ofl_exp_stats_reply_free (struct ofl_msg_multipart_reply_header *msg)
{
    struct ofl_msg_multipart_reply_experimenter *exp = (struct ofl_msg_multipart_reply_experimenter *) msg;
    switch (exp->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_stats_reply_free(msg);
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown EXPERIMENTER message (%u).", exp->experimenter_id);
            free(msg);
            return -1;
        }
    }
}

void
ofl_exp_field_pack (struct ofpbuf *buf, struct ofl_match_tlv const *oft)
{
    /*TODO pollins: probably we have to define a structure that points to the experimenter_ID position (Now the experimenter ID is the first value in "value")*/
    switch(*((uint32_t*) (oft->value)))
    {
        case BEBA_VENDOR_ID:{
            ofl_exp_beba_field_pack(buf, oft);
            break;
        }
        default:
            break;
    }
}

int
ofl_exp_field_unpack (struct ofl_match *match, struct oxm_field const *f, void const *experimenter_id, void const *value, void const *mask)
{
    switch (ntohl(*((uint32_t*) experimenter_id))) {
        case BEBA_VENDOR_ID:{
            return ofl_exp_beba_field_unpack(match, f, experimenter_id, value, mask);
            }
        default:
                NOT_REACHED();
        }
    NOT_REACHED();
}

void
ofl_exp_field_match (struct ofl_match_tlv *f, int *packet_header, int *field_len, uint8_t **flow_val, uint8_t **flow_mask)
{
    switch(*((uint32_t*) (f->value))){
        case BEBA_VENDOR_ID:
            ofl_exp_beba_field_match(f, packet_header, field_len, flow_val, flow_mask);
            break;
        default:
            break;
    }
}

void
ofl_exp_field_compare (struct ofl_match_tlv *f, struct ofl_match_tlv *packet_f, uint8_t **packet_val)
{
    switch(*((uint32_t*) (f->value)))
    {
        case BEBA_VENDOR_ID:
            ofl_exp_beba_field_compare(packet_f, packet_val);
            break;
        default:
            break;
    }
}

void
ofl_exp_field_match_std (struct ofl_match_tlv *flow_mod_match, struct ofl_match_tlv * flow_entry_match UNUSED, int *field_len,
             uint8_t **flow_mod_val, uint8_t **flow_entry_val, uint8_t **flow_mod_mask, uint8_t **flow_entry_mask)
{
    // FIXME!
    switch(*((uint32_t*)(flow_mod_match->value)))
    {
        case BEBA_VENDOR_ID:
            ofl_exp_beba_field_match_std(flow_mod_match, flow_mod_match, field_len, flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask);
            break;
        default:
            break;
    }
}

void
ofl_exp_field_overlap_a (struct ofl_match_tlv *f_a, int *field_len, uint8_t **val_a, uint8_t **mask_a, int *header, int *header_m, uint64_t *all_mask)
{
    switch(*((uint32_t*) (f_a->value)))
    {
        case BEBA_VENDOR_ID:
            ofl_exp_beba_field_overlap_a(f_a, field_len, val_a, mask_a, header, header_m, all_mask);
            break;
        default:
            break;
    }
}

void
ofl_exp_field_overlap_b (struct ofl_match_tlv *f_b, int *field_len, uint8_t **val_b, uint8_t **mask_b, uint64_t *all_mask)
{
    switch(*((uint32_t*) (f_b->value)))
    {
        case BEBA_VENDOR_ID:
            ofl_exp_beba_field_overlap_b(f_b, field_len, val_b, mask_b, all_mask);
            break;
        default:
            break;
    }
}

int
ofl_exp_inst_pack (struct ofl_instruction_header const *src, struct ofp_instruction *dst) {
	struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) src;
	switch (exp->experimenter_id) {
		case (BEBA_VENDOR_ID): {
			return ofl_exp_beba_inst_pack(src,dst);
		}
		default: {
			return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
		}

	}
}

ofl_err
ofl_exp_inst_unpack (struct ofp_instruction const *src, size_t *len, struct ofl_instruction_header **dst) {
    struct ofp_instruction_experimenter_header *exp;

    if (*len < sizeof(struct ofp_instruction_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER instruction is shorter than ofp_experimenter_header.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }


    exp = (struct ofp_instruction_experimenter_header *)src;

    switch(ntohl(exp->experimenter)){
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_inst_unpack(src,len,dst);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}

int
ofl_exp_inst_free (struct ofl_instruction_header *i) {
	struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) i;
	switch (exp->experimenter_id) {
		case (BEBA_VENDOR_ID): {
			return ofl_exp_beba_inst_free(i);
		}
		default: {
			return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
		}

	}
}

size_t
ofl_exp_inst_ofp_len (struct ofl_instruction_header const *i) {
	struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) i;
	switch (exp->experimenter_id) {
		case (BEBA_VENDOR_ID): {
			return ofl_exp_beba_inst_ofp_len(i);
		}
		default: {
			return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
		}

	}
}

char *
ofl_exp_inst_to_string (struct ofl_instruction_header const *i) {
	struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) i;
    switch (exp->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            return ofl_exp_beba_inst_to_string(i);
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }

    }
}

int
ofl_exp_err_pack(struct ofl_msg_exp_error const *msg, uint8_t **buf, size_t *buf_len){
    switch (msg->experimenter){
        case BEBA_VENDOR_ID:{
            ofl_exp_beba_error_pack(msg,buf,buf_len);
            break;}
        default:{
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown ERROR EXPERIMENTER message (%u).", msg->experimenter);
            return -1;}
    }
    return 0;
}

int
ofl_exp_err_free(struct ofl_msg_exp_error *msg){
    switch (msg->experimenter){
        case BEBA_VENDOR_ID:{
            ofl_exp_beba_error_free(msg);
            break;}
        default:{
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown ERROR EXPERIMENTER message (%u).", msg->experimenter);
            return -1;}
    }
    return 0;
}

char *
ofl_exp_err_to_string(struct ofl_msg_exp_error const *msg)
{
    switch (msg->experimenter){
        case BEBA_VENDOR_ID:{
            return ofl_exp_beba_error_to_string(msg);
        }
        default:{
            return ofl_exp_unknown_id_to_string(msg->experimenter);
        }
    }
}
