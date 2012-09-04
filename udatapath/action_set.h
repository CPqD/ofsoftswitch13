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

#ifndef ACTION_SET_H
#define ACTION_SET_H 1

#include <sys/types.h>
#include <stdio.h>
#include "datapath.h"
#include "packet.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-structs.h"

struct action_set;
struct datapath;
struct packet;


/****************************************************************************
 * Implementation of an action set associated with a datapath packet
 ****************************************************************************/

struct action_set *
action_set_create(struct ofl_exp *exp);

/* Destroys an action set */
void
action_set_destroy(struct action_set *set);

/* Creates a clone of an action set. Used when cloning a datapath packet in
 * groups. */
struct action_set *
action_set_clone(struct action_set *set);

/* Writes the set of given actions to the set, overwriting existing types as
 * defined by the 1.1 spec. */
void
action_set_write_actions(struct action_set *set,
                         size_t actions_num,
                         struct ofl_action_header **actions);


/* Clears the actions from the set. */
void
action_set_clear_actions(struct action_set *set);

/* Executes the actions in the set on the packet. Packet is the owner of the
 * action set right now, but this might be changed in the future. */
void
action_set_execute(struct action_set *set, struct packet *pkt, uint64_t cookie);

/* Converts the action set to a string representation. */
char *
action_set_to_string(struct action_set *set);

/* Converts the action set to a string representation and appends it to the
 * given string. */
void
action_set_print(FILE *stream, struct action_set *set);

#endif /* ACTION_SET */
