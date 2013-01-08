/* Copyright (c) 2012, Applistar, Vietnam
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
 *
 */

#ifndef METER_ENTRY_H
#define METER_ENTRY_H 1

#include <stdbool.h>
#include "hmap.h"
#include "list.h"
#include "packet.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "meter_table.h"



/****************************************************************************
 * Implementation of a meter entry.
 ****************************************************************************/


/* Structures from others */
struct packet;
struct datapath;
struct flow_entry;
struct sender;

/* Meter entry */
struct meter_entry {
	struct hmap_node            node;			/* Refered by the meter table */

	struct datapath				*dp;			/* The datapath */
	struct meter_table			*table;			/* The meter table */

	struct ofl_meter_stats		*stats;			/* Meter statistics */
	struct ofl_meter_config		*config;		/* Meter configuration */

    uint64_t                    created;  /* time the entry was created at. */
    	
	struct list                 flow_refs;		/* references to flows referencing the meter. */

};

/* Creates a meter entry. */
struct meter_entry *
meter_entry_create(struct datapath *dp, struct meter_table *table, struct ofl_msg_meter_mod *mod);

/*Update counters */
void
meter_entry_update(struct meter_entry *entry);

/* Destroys a meter entry. */
void
meter_entry_destroy(struct meter_entry *entry);

/* Apply the meter entry on the packet. */
void
meter_entry_apply(struct meter_entry *entry, struct packet **pkt);


/* Adds a flow reference to the meter entry. */
void
meter_entry_add_flow_ref(struct meter_entry *entry, struct flow_entry *fe);

/* Removes a flow reference from the meter entry. */
void
meter_entry_del_flow_ref(struct meter_entry *entry, struct flow_entry *fe);

void
refill_bucket(struct meter_entry *entry);

#endif /* METER_ENTRY_H */
