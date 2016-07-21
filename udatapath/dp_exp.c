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
#include <string.h>
#include "datapath.h"
#include "dp_exp.h"
#include "packet.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "oflib-exp/ofl-exp-openflow.h"
#include "oflib-exp/ofl-exp-nicira.h"
#include "oflib-exp/ofl-exp-beba.h"
#include "openflow/openflow.h"
#include "openflow/openflow-ext.h"
#include "openflow/nicira-ext.h"
#include "openflow/beba-ext.h"
#include "vlog.h"
#include "pipeline.h"

#define LOG_MODULE VLM_dp_exp

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

void
dp_exp_action(struct packet *pkt, struct ofl_action_experimenter *act) {
    if(act->experimenter_id == BEBA_VENDOR_ID)
    {
        struct ofl_exp_beba_act_header *action;
        struct ofl_exp_msg_notify_state_change ntf_message;
        action = (struct ofl_exp_beba_act_header *) act;
        switch(action->act_type){

            case(OFPAT_EXP_SET_STATE):
            {
                struct ofl_exp_action_set_state *wns = (struct ofl_exp_action_set_state *)action;
                if (state_table_is_stateful(pkt->dp->pipeline->tables[wns->table_id]->state_table) && state_table_is_configured(pkt->dp->pipeline->tables[wns->table_id]->state_table))
                {
                    struct state_table *st = pkt->dp->pipeline->tables[wns->table_id]->state_table;
                    VLOG_DBG_RL(LOG_MODULE, &rl, "executing action NEXT STATE at stage %u", wns->table_id);

                    // State Sync: Get the new state, encoded in ntf_message, and pack a message to be sent via dp_send_message.
                    // This invocation occurs when a state transition happens due to a dynamic event (e.g., a newly received packet).
                    state_table_set_state(st, pkt, NULL, wns, &ntf_message);
                    if (ntf_message.old_state != ntf_message.new_state) {
                        int err = dp_send_message(pkt->dp, (struct ofl_msg_header *)&ntf_message, NULL);
                        if (err) {
                            VLOG_WARN_RL(LOG_MODULE, &rl, "ERROR sending state change notification %s:%i", __FILE__, __LINE__);
                        }
                    }
                }
                else
                {
                    VLOG_WARN_RL(LOG_MODULE, &rl, "ERROR NEXT STATE at stage %u: stage not stateful", wns->table_id);
                }
                break;
            }
            case (OFPAT_EXP_SET_GLOBAL_STATE):
            {
                struct ofl_exp_action_set_global_state *wns = (struct ofl_exp_action_set_global_state *)action;
                uint32_t global_state = pkt->dp->global_state;

                global_state = (global_state & ~(wns->global_state_mask)) | (wns->global_state & wns->global_state_mask);
                pkt->dp->global_state = global_state;
                break;
            }
            default:
                VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown experimenter action (%u).", htonl(act->experimenter_id));
                break;
        }
        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *p = packet_to_string(pkt);
            VLOG_DBG_RL(LOG_MODULE, &rl, "action result: %s", p);
            free(p);
        }
    }
}

void
dp_exp_inst(struct packet *pkt UNUSED, struct ofl_instruction_experimenter *inst) {
	switch (inst->experimenter_id) {
		case (BEBA_VENDOR_ID): {
			struct ofl_exp_beba_instr_header *beba_inst = (struct ofl_exp_beba_instr_header*) inst;
			switch (beba_inst->instr_type) {
				case (OFPIT_IN_SWITCH_PKT_GEN): {
					struct ofl_exp_instruction_in_switch_pkt_gen *beba_insw_i =
							(struct ofl_exp_instruction_in_switch_pkt_gen *) beba_inst;
					struct pkttmp_table *t = pkt->dp->pkttmps;
					struct pkttmp_entry *pkttmp;
					uint8_t found = 0;
					struct ofpbuf *buf;
					struct packet *gen_pkt;

					HMAP_FOR_EACH_WITH_HASH(pkttmp, struct pkttmp_entry, node,
							beba_insw_i->pkttmp_id, &t->entries) {

						uint8_t *data;

						//VLOG_WARN_RL(LOG_MODULE, &rl, "Retrieving: pkttmp id %u!", pkttmp->pkttmp_id);
						//
						found = 1;

						// ** Packet generation **

						/* If there is no packet in the message, send error message */
						if (!pkttmp->data_length){
							VLOG_WARN_RL(LOG_MODULE, &rl,
									"No packet data associated with pkttmp_id %u!",
									beba_insw_i->pkttmp_id);
							return;
						}

						/* NOTE: the created packet will take the ownership of data. */
						buf = ofpbuf_new(0);
						data = (uint8_t *)memcpy(xmalloc(pkttmp->data_length), pkttmp->data, pkttmp->data_length);

						// TODO apply copy_instrs
						ofpbuf_use(buf, data, pkttmp->data_length);
						ofpbuf_put_uninit(buf, pkttmp->data_length);

						// TODO check specification of in_port value, currently set to 0
						gen_pkt = packet_create(pkttmp->dp, 0, buf, true);
						//Required to enable submission to the pipeline when
						//there is an action output with port number TABLE
						gen_pkt->packet_out = true;

						if (gen_pkt == NULL) {
							VLOG_WARN_RL(LOG_MODULE, &rl,
									"No packet data associated with pkttmp_id %u!",
									beba_insw_i->pkttmp_id);
							return;
						}
						// ---

						// The pkt generation never leads to a PACKET_IN message,
						// thus, the cookie value is not required and set to 0
						dp_execute_action_list(gen_pkt, beba_insw_i->actions_num,
								beba_insw_i->actions, 0);
						if(gen_pkt) {
							packet_destroy(gen_pkt);
						}
					}

					if (!found) {
						VLOG_WARN_RL(LOG_MODULE, &rl, "No PKTTMP for pkttmp_id %u!", beba_insw_i->pkttmp_id);
					}
					return;

				}
			}


			// TODO Perform packet generation instruction
			VLOG_WARN_RL(LOG_MODULE, &rl, "Unknown BEBA instruction type!");
			return;
		}
		default: {
			VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown experimenter instruction (%u).", inst->experimenter_id);
		}
	}

}

ofl_err
dp_exp_stats(struct datapath *dp UNUSED, struct ofl_msg_multipart_request_experimenter *msg, const struct sender *sender UNUSED) {
    ofl_err err;
    switch (msg->experimenter_id) {
        case (BEBA_VENDOR_ID): {
            struct ofl_exp_beba_msg_multipart_request *exp = (struct ofl_exp_beba_msg_multipart_request *)msg;

            switch(exp->type) {
                case (OFPMP_EXP_STATE_STATS): {
                    struct ofl_exp_msg_multipart_reply_state reply;
                    err = handle_stats_request_state(dp->pipeline, (struct ofl_exp_msg_multipart_request_state *)msg, sender, &reply);
                    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);
                    free(reply.stats);
                    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
                    return err;
                }
                case (OFPMP_EXP_GLOBAL_STATE_STATS): {
                    struct ofl_exp_msg_multipart_reply_global_state reply;
                    err = handle_stats_request_global_state(dp->pipeline, sender, &reply);
                    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);
                    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
                    return err;
                }
                default: {
                    VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter type (%u).", exp->type);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
                }
            }
        }
        default: {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter stats (%u).", msg->experimenter_id);
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}


ofl_err
dp_exp_message(struct datapath *dp, struct ofl_msg_experimenter *msg, const struct sender *sender) {

    switch (msg->experimenter_id) {
        case (OPENFLOW_VENDOR_ID): {
            struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;

            switch(exp->type) {
                case (OFP_EXT_QUEUE_MODIFY): {
                    return dp_ports_handle_queue_modify(dp, (struct ofl_exp_openflow_msg_queue *)msg, sender);
                }
                case (OFP_EXT_QUEUE_DELETE): {
                    return dp_ports_handle_queue_delete(dp, (struct ofl_exp_openflow_msg_queue *)msg, sender);
                }
                case (OFP_EXT_SET_DESC): {
                    return dp_handle_set_desc(dp, (struct ofl_exp_openflow_msg_set_dp_desc *)msg, sender);
                }
                default: {
                	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter type (%u).", exp->type);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
                }
            }
        }
        case (BEBA_VENDOR_ID): {
            struct ofl_exp_beba_msg_header *exp = (struct ofl_exp_beba_msg_header *)msg;
            struct ofl_exp_msg_notify_state_change ntf_message;
            int res;

            switch(exp->type) {
                case (OFPT_EXP_STATE_MOD): {
                    // State Sync: This invocation occurs when a state transition happens due to a request from the controller.
                    // Since the controller already knows the new state to be set, there is no point to generate a notification.
                    // If you want to notify the controller for this case, use `dp_send_message(dp, (struct ofl_msg_header *)&ntf_message, NULL);`
                    // after the handle_state_mod call.
                    res = handle_state_mod(dp->pipeline, (struct ofl_exp_msg_state_mod *)msg, sender, &ntf_message);

                    return res;
                }
                case (OFPT_EXP_PKTTMP_MOD): {
                    return handle_pkttmp_mod(dp->pipeline, (struct ofl_exp_msg_pkttmp_mod *)msg, sender);
                }
                default: {
                    VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter type (%u).", exp->type);
                    return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_MESSAGE);
                }
            }
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}
