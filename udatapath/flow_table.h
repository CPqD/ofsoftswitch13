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

#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H 1
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "pipeline.h"
#include "timeval.h"


#define FLOW_TABLE_MAX_ENTRIES 1024
#define TABLE_FEATURES_NUM 14
// EEDJAS: N_OXM_FIELDS is an enum value exported by oxm-match.h via ofl-structs.h
// #define N_OXM_FIELDS 40
#define N_INSTRUCTIONS 6
#define N_ACTIONS 16
#define N_WILDCARDED 16
/****************************************************************************
 * Implementation of a flow table. The current implementation stores flow
 * entries in priority and then insertion order.
 ****************************************************************************/


struct flow_table {
    struct datapath           *dp;
    struct ofl_table_features *features;      /*store table features*/
    struct ofl_table_stats    *stats;         /* structure storing table statistics. */
    
    struct list               match_entries;  /* list of entries in order. */
    struct list               hard_entries;   /* list of entries with hard timeout;
                                                ordered by their timeout times. */
    struct list               idle_entries;   /* unordered list of entries with
                                                idle timeout. */
};

extern uint32_t oxm_ids[];

extern uint32_t wildcarded[]; 

extern struct ofl_instruction_header instructions[];

extern struct ofl_action_header actions[];
/* Handles a flow mod message. */
ofl_err
flow_table_flow_mod(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool *match_kept, bool *insts_kept);

/* Finds the flow entry with the highest priority, which matches the packet. */
struct flow_entry *
flow_table_lookup(struct flow_table *table, struct packet *pkt);

/* Orders the flow table to check the timeout its flows. */
void
flow_table_timeout(struct flow_table *table);

/* Creates a flow table. */
struct flow_table *
flow_table_create(struct datapath *dp, uint8_t table_id);

/* Destroys a flow table. */
void
flow_table_destroy(struct flow_table *table);

/* Collects statistics of the flow entries of the table. */
void
flow_table_stats(struct flow_table *table, struct ofl_msg_multipart_request_flow *msg,
                 struct ofl_flow_stats ***stats, size_t *stats_size, size_t *stats_num);

/* Collects aggregate statistics of the flow entries of the table. */
void
flow_table_aggregate_stats(struct flow_table *table, struct ofl_msg_multipart_request_flow *msg,
                           uint64_t *packet_count, uint64_t *byte_count, uint32_t *flow_count);

#endif /* FLOW_TABLE_H */
