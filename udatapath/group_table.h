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

#ifndef GROUP_TABLE_H
#define GROUP_TABLE_H 1

#include "datapath.h"
#include "group_entry.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "packet.h"


/****************************************************************************
 * Implementation of group tables.
 ****************************************************************************/


#define GROUP_TABLE_MAX_ENTRIES 4096
#define GROUP_TABLE_MAX_BUCKETS 8192

struct datapath;
struct packet;
struct sender;

struct group_table {
    struct datapath  *dp;
	struct ofl_msg_multipart_reply_group_features *features;   
	size_t            entries_num;
    struct hmap       entries;
    size_t            buckets_num;
};


/* Handles a group_mod message. */
ofl_err
group_table_handle_group_mod(struct group_table *table, struct ofl_msg_group_mod *mod, const struct sender *sender);

/* Handles a group stats request message. */
ofl_err
group_table_handle_stats_request_group(struct group_table *table,
                                  struct ofl_msg_multipart_request_group *msg,
                                  const struct sender *sender);

/* Handles a group desc stats request message */
ofl_err
group_table_handle_stats_request_group_desc(struct group_table *table,
        struct ofl_msg_multipart_request_header *msg,
        const struct sender *sender);

/* Handles a group features stats request message */
ofl_err
group_table_handle_stats_request_group_features(struct group_table *table,
                                  struct ofl_msg_multipart_request_header *msg UNUSED,
                                  const struct sender *sender);

/* Returns the group entry with the given ID. */
struct group_entry *
group_table_find(struct group_table *table, uint32_t group_id);

/* Executes the given group entry on the packet. */
void
group_table_execute(struct group_table *table, struct packet *packet, uint32_t group_id);

/* Creates a group table. */
struct group_table *
group_table_create(struct datapath *dp);

/* Destroys a group table. */
void
group_table_destroy(struct group_table *table);


#endif /* GROUP_TABLE_H */

