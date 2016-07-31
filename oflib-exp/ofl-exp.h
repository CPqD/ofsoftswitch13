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

#ifndef OFL_EXP_H
#define OFL_EXP_H 1

#include "../oflib/ofl-messages.h"
#include "openflow/openflow.h"


int
ofl_exp_msg_pack(struct ofl_msg_experimenter const *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp);

ofl_err
ofl_exp_msg_unpack(struct ofp_header const *oh, size_t *len, struct ofl_msg_experimenter **msg, struct ofl_exp const *exp);

int
ofl_exp_msg_free(struct ofl_msg_experimenter *msg);

char *
ofl_exp_msg_to_string(struct ofl_msg_experimenter const *msg);

int
ofl_exp_act_pack(struct ofl_action_header const *src, struct ofp_action_header *dst);

ofl_err
ofl_exp_act_unpack(struct ofp_action_header const *src, size_t *len, struct ofl_action_header **dst);

int
ofl_exp_act_free(struct ofl_action_header *act);

size_t
ofl_exp_act_ofp_len(struct ofl_action_header const *act);

char *
ofl_exp_act_to_string(struct ofl_action_header const *act);

int
ofl_exp_stats_req_pack (struct ofl_msg_multipart_request_header const *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp);

int
ofl_exp_stats_reply_pack (struct ofl_msg_multipart_reply_header const *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp);

ofl_err
ofl_exp_stats_req_unpack (struct ofp_multipart_request const *os, uint8_t const *buf, size_t *len, struct ofl_msg_multipart_request_header **msg, struct ofl_exp const *exp);

ofl_err
ofl_exp_stats_reply_unpack (struct ofp_multipart_reply const *os, uint8_t const *buf, size_t *len, struct ofl_msg_multipart_reply_header **msg, struct ofl_exp const *exp);

char *
ofl_exp_stats_req_to_string (struct ofl_msg_multipart_request_header const *msg, struct ofl_exp const *exp);

char *
ofl_exp_stats_reply_to_string (struct ofl_msg_multipart_reply_header const *msg, struct ofl_exp const *exp);

int
ofl_exp_stats_req_free (struct ofl_msg_multipart_request_header *msg);

int
ofl_exp_stats_reply_free (struct ofl_msg_multipart_reply_header *msg);

void
ofl_exp_field_pack(struct ofpbuf *buf, struct ofl_match_tlv const *oft);

int
ofl_exp_field_unpack(struct ofl_match *match, struct oxm_field const *f, void const *experimenter_id, void const *value, void const *mask);


void
ofl_exp_field_match(struct ofl_match_tlv *f, int *packet_header, int *field_len, uint8_t **flow_val, uint8_t **flow_mask);

void
ofl_exp_field_compare (struct ofl_match_tlv *f, struct ofl_match_tlv *value, uint8_t **packet_val);

void
ofl_exp_field_match_std (struct ofl_match_tlv *flow_mod_match, struct ofl_match_tlv *flow_entry_match, int *field_len, uint8_t **flow_mod_val, uint8_t **flow_entry_val, uint8_t **flow_mod_mask, uint8_t **flow_entry_mask);

void
ofl_exp_field_overlap_a (struct ofl_match_tlv *f_a, int *field_len, uint8_t **val_a, uint8_t **mask_a, int *header, int *header_m, uint64_t *all_mask);

void
ofl_exp_field_overlap_b (struct ofl_match_tlv *f_b, int *field_len, uint8_t **val_b, uint8_t **mask_b, uint64_t *all_mask);

int
ofl_exp_inst_pack (struct ofl_instruction_header const *src, struct ofp_instruction *dst);

ofl_err
ofl_exp_inst_unpack (struct ofp_instruction const *src, size_t *len, struct ofl_instruction_header **dst);

int
ofl_exp_inst_free (struct ofl_instruction_header *i);

size_t
ofl_exp_inst_ofp_len (struct ofl_instruction_header const *i);

char *
ofl_exp_inst_to_string (struct ofl_instruction_header const *i);

int
ofl_exp_err_pack(struct ofl_msg_exp_error const *msg, uint8_t **buf, size_t *buf_len);

int
ofl_exp_err_free(struct ofl_msg_exp_error *msg);

char *
ofl_exp_err_to_string(struct ofl_msg_exp_error const *msg);

#endif /* OFL_EXP_H */
