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
 */

#ifndef FLOW_entry_H
#define FLOW_entry_H 1


#include <stdbool.h>
#include <sys/types.h>
#include "datapath.h"
#include "list.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "timeval.h"

/****************************************************************************
 * Implementation of a flow table entry.
 ****************************************************************************/

struct flow_entry {
    struct list              match_node;  /* list nodes in flow table lists. */
    struct list              hard_node;
    struct list              idle_node;

    struct datapath         *dp;
    struct flow_table       *table;
    struct ofl_flow_stats   *stats;
    struct ofl_match_header *match; /* Original match structure is stored in stats;
                                       this one is a modified version, which reflects
                                       1.2 matching rules. */
    uint64_t                 created;  /* time the entry was created at. */
    uint64_t                 remove_at; /* time the entry should be removed at
                                           due to its hard timeout. */
    uint64_t                 last_used; /* last time the flow entry matched a packet */
    bool                     send_removed; /* true if a flow removed should be sent
                                              when removing a flow. */

    bool                     no_pkt_count; /* true if doesn't keep track of flow matched packets*/     
    bool                     no_byt_count; /* true if doesn't keep track of flow matched bytes*/
    struct list              group_refs;  /* list of groups referencing the flow. */
    struct list              meter_refs;  /* list of meters referencing the flow. */
};

struct packet;

/* Returns true if the flow entry matches the match in the flow mod message. */
bool
flow_entry_matches(struct flow_entry *entry, struct ofl_msg_flow_mod *mod, bool strict, bool check_cookie);

/* Returns true if the flow entry overlaps with the match in the flow mod message. */
bool
flow_entry_overlaps(struct flow_entry *entry, struct ofl_msg_flow_mod *mod);

/* Replaces the current instructions of the entry with the given ones. */
void
flow_entry_replace_instructions(struct flow_entry *entry,
                                      size_t instructions_num,
                                      struct ofl_instruction_header **instructions);
void
flow_entry_modify_stats(struct flow_entry *entry,
			struct ofl_msg_flow_mod *mod);

/* Checks if the entry should time out because of its idle timeout. If so, the
 * packet is freed, flow removed message is generated, and true is returned. */
bool
flow_entry_idle_timeout(struct flow_entry *entry);

/* Checks if the entry should time out because of its hard timeout. If so, the
 * packet is freed, flow removed message is generated, and true is returned. */
bool
flow_entry_hard_timeout(struct flow_entry *entry);

/* Returns true if the flow entry has an output action to the given port. */
bool
flow_entry_has_out_port(struct flow_entry *entry, uint32_t port);

/* Returns true if the flow entry has a group action to the given group. */
bool
flow_entry_has_out_group(struct flow_entry *entry, uint32_t group);

/* Updates the time fields of the flow entry statistics. Used before generating
 * flow statistics messages. */
void
flow_entry_update(struct flow_entry *entry);

/* Creates a flow entry. */
struct flow_entry *
flow_entry_create(struct datapath *dp, struct flow_table *table, struct ofl_msg_flow_mod *mod);

/* Destroys a flow entry. */
void
flow_entry_destroy(struct flow_entry *entry);

/* Removes a flow entry with the given reason. A flow removed message is sent if needed. */
void
flow_entry_remove(struct flow_entry *entry, uint8_t reason);

#endif /* FLOW_entry_H 1 */
