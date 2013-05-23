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

#ifndef DP_ACTIONS_H
#define DP_ACTIONS_H 1

#include <sys/types.h>
#include "datapath.h"
#include "packet.h"
#include "oflib/ofl-actions.h"


/****************************************************************************
 * Datapath action implementations.
 ****************************************************************************/

/* Executes the action on the given packet. */
void
dp_execute_action(struct packet *pkt,
                  struct ofl_action_header *action);


/* Executes the list of action on the given packet. */
void
dp_execute_action_list(struct packet *pkt,
                size_t actions_num, struct ofl_action_header **actions, uint64_t cookie);

/* Outputs the packet on the given port and queue. */
void
dp_actions_output_port(struct packet *pkt, uint32_t out_port, uint32_t out_queue, uint16_t max_len, uint64_t cookie);

/* Returns true if the given list of actions has an output action to the port. */
bool
dp_actions_list_has_out_port(size_t actions_num, struct ofl_action_header **actions, uint32_t port);

/* Returns true if the given list of actions has an group action to the group. */
bool
dp_actions_list_has_out_group(size_t actions_num, struct ofl_action_header **actions, uint32_t group);

/* Validates the set of actions based on the available ports and groups. Returns an OpenFlow
 * error if the actions are invalid. */
ofl_err
dp_actions_validate(struct datapath *dp, size_t actions_num, struct ofl_action_header **actions);

/* Validates the set of set_field actions, checking if the pre requisites are present in the match. Returns and Openlow
 * error if the actions are invalid. */
ofl_err
dp_actions_check_set_field_req(struct ofl_msg_flow_mod *msg, size_t actions_num, struct ofl_action_header **actions);

#endif /* DP_ACTIONS_H */
