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

#ifndef METER_TABLE_H
#define METER_TABLE_H 1

#include <stdbool.h>
#include "hmap.h"
#include "list.h"
#include "packet.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "meter_entry.h"

#define DEFAULT_MAX_METER 256
#define DEFAULT_MAX_BAND_PER_METER 16
#define DEFAULT_MAX_METER_COLOR 8
#define METER_TABLE_MAX_BANDS 1024


/****************************************************************************
 * Implementation of meter table.
 ****************************************************************************/

/* Meter table */
struct meter_table {
  struct datapath		*dp;				/* The datapath */
	struct ofl_meter_features *features;	
	size_t				 entries_num;		/* The number of meters */
  struct hmap			meter_entries;	    /* Meter entries */
	size_t              bands_num;

};


/* Creates a meter table. */
struct meter_table *
meter_table_create(struct datapath *dp);

/* Destroys a meter table. */
void
meter_table_destroy(struct meter_table *table);

/* Returns the meter with the given ID. */
struct meter_entry *
meter_table_find(struct meter_table *table, uint32_t meter_id);

/* Apply the given meter on the packet. */
void
meter_table_apply(struct meter_table *table, struct packet **packet, uint32_t meter_id);

/* Handles a meter_mod message. */
ofl_err
meter_table_handle_meter_mod(struct meter_table *table, struct ofl_msg_meter_mod  *mod, const struct sender *sender);


/* Handles a meter stats request message. */
ofl_err
meter_table_handle_stats_request_meter(struct meter_table *table,
                                  struct ofl_msg_multipart_meter_request *msg,
                                  const struct sender *sender UNUSED);

/* Handles a meter config request message. */
ofl_err
meter_table_handle_stats_request_meter_conf(struct meter_table *table,
                                  struct ofl_msg_multipart_meter_request *msg UNUSED,
                                  const struct sender *sender);

ofl_err
meter_table_handle_features_request(struct meter_table *table,
                                   struct ofl_msg_multipart_request_header *msg UNUSED,
                                  const struct sender *sender); 

void 
meter_table_add_tokens(struct meter_table *table);


#endif /* METER_TABLE_H */
