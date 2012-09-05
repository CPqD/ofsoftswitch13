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

#ifndef GROUP_entry_H
#define GROUP_entry_H 1

#include <stdbool.h>
#include "hmap.h"
#include "packet.h"
#include "group_table.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"


/****************************************************************************
 * Implementation of a group table entry.
 ****************************************************************************/


struct packet;
struct datapath;
struct flow_entry;

struct group_entry {
    struct hmap_node             node;

    struct datapath             *dp;
    struct group_table          *table;
    struct ofl_group_desc_stats *desc;
    struct ofl_group_stats      *stats;
    uint64_t created;
    void                        *data;     /* private data for group implementation. */

    struct list                  flow_refs; /* references to flows referencing the group. */
};

struct sender;
struct group_table;

/* Executes the group entry on the packet. */
void
group_entry_execute(struct group_entry *entry,
                          struct packet *packet);

/* Creates a group entry. */
struct group_entry *
group_entry_create(struct datapath *dp, struct group_table *table, struct ofl_msg_group_mod *mod);

/* Destroys a group entry. */
void
group_entry_destroy(struct group_entry *entry);

/* Returns true if the group entry has an group action to the given group ID. */
bool
group_entry_has_out_group(struct group_entry *entry, uint32_t group_id);

/* Adds a flow reference to the group entry. */
void
group_entry_add_flow_ref(struct group_entry *entry, struct flow_entry *fe);

/* Removes a flow reference from the group entry. */
void
group_entry_del_flow_ref(struct group_entry *entry, struct flow_entry *fe);

/* Updates the time fields of the group entry statistics. Used before generating
 * group statistics messages. */
void
group_entry_update(struct group_entry *entry);

#endif /* GROUP_entry_H */
