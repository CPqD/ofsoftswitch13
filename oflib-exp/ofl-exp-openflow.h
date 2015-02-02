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

#ifndef OFL_EXP_OPENFLOW_H
#define OFL_EXP_OPENFLOW_H 1


#include "../oflib/ofl-structs.h"
#include "../oflib/ofl-messages.h"
#include "../include/openflow/openflow-ext.h"
/**************************************************************************/
/*                        experimenter messages ofl_exp                   */
/**************************************************************************/
struct ofl_exp_openflow_msg_header {
    struct ofl_msg_experimenter   header; /* OPENFLOW_VENDOR_ID */

    uint32_t   type;
};

struct ofl_exp_openflow_msg_queue {
    struct ofl_exp_openflow_msg_header   header; /* OFP_EXT_QUEUE_MODIFY|DELETE */

    uint32_t                  port_id;
    struct ofl_packet_queue  *queue;
};


struct ofl_exp_openflow_msg_set_dp_desc {
    struct ofl_exp_openflow_msg_header   header; /* OFP_EXT_SET_DESC */

    char  *dp_desc;
};


/************************
 * state mod messages
 ************************/

struct ofl_exp_msg_state_mod {
    struct ofl_exp_openflow_msg_header header;   /* OFP_EXP_STATE_MOD */
    uint64_t cookie;
    uint64_t cookie_mask;
    uint8_t table_id;
    enum ofp_exp_state_mod_command command;
    uint8_t payload[8+OFPSC_MAX_KEY_LEN]; //ugly! for now it's ok XXX
};

struct ofl_exp_msg_state_entry {
    uint32_t key_len;
    uint32_t state;
    uint8_t key[OFPSC_MAX_KEY_LEN];
};

struct ofl_exp_msg_extraction {
    uint32_t field_count;
    uint32_t fields[OFPSC_MAX_FIELD_COUNT];
};

/************************
 * flag mod messages
 ************************/

struct ofl_exp_msg_flag_mod {
    struct ofl_exp_openflow_msg_header header;   /* OFPT_EXP_FLAG_MOD */
    uint32_t flag;
    uint32_t flag_mask;
    enum ofp_exp_flag_mod_command command;
};

/*************************************************************************/
/*                        experimenter actions ofl_exp                   */
/*************************************************************************/
struct ofl_exp_openflow_act_header {
    struct ofl_action_experimenter   header; /* OPENFLOW_VENDOR_ID */

    uint32_t   act_type;
};


struct ofl_exp_action_set_state {
    struct ofl_exp_openflow_act_header  header; /* OFPAT_EXP_SET_STATE */

    uint32_t state;
    uint8_t stage_id; /*we have 64 flow table in the pipeline*/
};

struct ofl_exp_action_set_flag {
    struct ofl_exp_openflow_act_header   header; /* OFPAT_EXP_SET_FLAG */

    uint32_t value;
    uint32_t mask;
};





int
ofl_exp_openflow_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len);

ofl_err
ofl_exp_openflow_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg);

int
ofl_exp_openflow_msg_free(struct ofl_msg_experimenter *msg);

char *
ofl_exp_openflow_msg_to_string(struct ofl_msg_experimenter *msg);

/*experimenter action functions*/

int 
ofl_exp_openflow_act_pack(struct ofl_action_header *src, struct ofp_action_header *dst);

ofl_err
ofl_exp_openflow_act_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst);

size_t
ofl_exp_openflow_act_ofp_len(struct ofl_action_header *act);

int     
ofl_exp_openflow_act_free(struct ofl_action_header *act);

char *
ofl_exp_openflow_act_to_string(struct ofl_action_header *act);

#endif /* OFL_EXP_OPENFLOW_H */
