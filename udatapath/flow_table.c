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

#include <stdbool.h>
#include <string.h>
#include "dynamic-string.h"
#include "datapath.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "oflib/ofl.h"
#include "time.h"
//#include "packet_handle_std.h"

#include "vlog.h"
#define LOG_MODULE VLM_flow_t

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

/* When inserting an entry, this function adds the flow entry to the list of
 * hard and idle timeout entries, if appropriate. */
static void
add_to_timeout_lists(struct flow_table *table, struct flow_entry *entry) {
    if (entry->stats->idle_timeout > 0) {
        list_insert(&table->idle_entries, &entry->idle_node);
    }

    if (entry->remove_at > 0) {
        struct flow_entry *e;

        /* hard timeout entries are ordered by the time they should be removed at. */
        LIST_FOR_EACH (e, struct flow_entry, hard_node, &table->hard_entries) {
            if (e->remove_at > entry->remove_at) {
                list_insert(&e->hard_node, &entry->hard_node);
                return;
            }
        }
        list_insert(&e->hard_node, &entry->hard_node);
    }
}

/* Handles flow mod messages with ADD command. */
static ofl_err
flow_table_add(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool check_overlap, bool *match_kept, bool *insts_kept) {
    // Note: new entries will be placed behind those with equal priority
    struct flow_entry *entry, *new_entry;

    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries) {
        if (check_overlap && flow_entry_overlaps(entry, mod)) {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_OVERLAP);
        }

        /* if the entry equals, replace the old one */
        if (flow_entry_matches(entry, mod, true/*strict*/, false/*check_cookie*/)) {
            new_entry = flow_entry_create(table->dp, table, mod);
            *match_kept = true;
            *insts_kept = true;

            /* NOTE: no flow removed message should be generated according to spec. */
            list_replace(&new_entry->match_node, &entry->match_node);
            list_remove(&entry->hard_node);
            list_remove(&entry->idle_node);
            flow_entry_destroy(entry);
            add_to_timeout_lists(table, new_entry);
            return 0;
        }

        if (mod->priority > entry->stats->priority) {
            break;
        }
    }

    if (table->stats->active_count == FLOW_TABLE_MAX_ENTRIES) {
        return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_TABLE_FULL);
    }
    table->stats->active_count++;

    new_entry = flow_entry_create(table->dp, table, mod);
    *match_kept = true;
    *insts_kept = true;

    list_insert(&entry->match_node, &new_entry->match_node);
    add_to_timeout_lists(table, new_entry);

    return 0;
}

/* Handles flow mod messages with MODIFY command. 
    If the flow doesn't exists don't do nothing*/
static ofl_err
flow_table_modify(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool strict, bool *insts_kept) {
    struct flow_entry *entry;

    LIST_FOR_EACH (entry, struct flow_entry, match_node, &table->match_entries) {
        if (flow_entry_matches(entry, mod, strict, true/*check_cookie*/)) {
            flow_entry_replace_instructions(entry, mod->instructions_num, mod->instructions);
            *insts_kept = true;
        }
    }

    return 0;
}

/* Handles flow mod messages with DELETE command. */
static ofl_err
flow_table_delete(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool strict) {
    struct flow_entry *entry, *next;

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, match_node, &table->match_entries) {
        if (flow_entry_matches(entry, mod, strict, true/*check_cookie*/)) {
             flow_entry_remove(entry, OFPRR_DELETE);
        }
    }

    return 0;
}


ofl_err
flow_table_flow_mod(struct flow_table *table, struct ofl_msg_flow_mod *mod, bool *match_kept, bool *insts_kept) {
    switch (mod->command) {
        case (OFPFC_ADD): {
            bool overlap = ((mod->flags & OFPFF_CHECK_OVERLAP) != 0);
            return flow_table_add(table, mod, overlap, match_kept, insts_kept);
        }
        case (OFPFC_MODIFY): {
            return flow_table_modify(table, mod, false, insts_kept);
        }
        case (OFPFC_MODIFY_STRICT): {
            return flow_table_modify(table, mod, true, insts_kept);
        }
        case (OFPFC_DELETE): {
            return flow_table_delete(table, mod, false);
        }
        case (OFPFC_DELETE_STRICT): {
            return flow_table_delete(table, mod, true);
        }
        default: {
            return ofl_error(OFPET_FLOW_MOD_FAILED, OFPFMFC_BAD_COMMAND);
        }
    }
}


struct flow_entry *
flow_table_lookup(struct flow_table *table, struct packet *pkt) {
    struct flow_entry *entry;

    table->stats->lookup_count++;

    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        struct ofl_match_header *m;

        m = entry->match == NULL ? entry->stats->match : entry->match;

        /* select appropriate handler, based on match type of flow entry. */
        switch (m->type) {
            case (OFPMT_OXM): {
               if (packet_handle_std_match(pkt->handle_std,
                                            (struct ofl_match *)m)) {
                    if (!entry->no_byt_count)                                            
                        entry->stats->byte_count += pkt->buffer->size;
                    if (!entry->no_pkt_count)
                        entry->stats->packet_count++;
                    entry->last_used = time_msec();

                    table->stats->matched_count++;

                    return entry;
                }
                break;

                break;
            }
            default: {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to process flow entry with unknown match type (%u).", m->type);
            }
        }
    }

    return NULL;
}



void
flow_table_timeout(struct flow_table *table) {
    struct flow_entry *entry, *next;

    /* NOTE: hard timeout entries are ordered by the time they should be removed at,
     * so if one is not removed, the rest will not be either. */
    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, hard_node, &table->hard_entries) {
        if (!flow_entry_hard_timeout(entry)) {
            break;
        }
    }

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, idle_node, &table->idle_entries) {
        flow_entry_idle_timeout(entry);
    }
}

struct flow_table *
flow_table_create(struct datapath *dp, uint8_t table_id) {
    struct flow_table *table;
    struct ds string = DS_EMPTY_INITIALIZER;

    ds_put_format(&string, "table_%u", table_id);

    table = xmalloc(sizeof(struct flow_table));
    table->dp = dp;

    table->stats = xmalloc(sizeof(struct ofl_table_stats));
    table->stats->table_id      = table_id;
    /*table->stats->name          = ds_cstr(&string);
    table->stats->match         = DP_SUPPORTED_MATCH_FIELDS;
    table->stats->instructions  = DP_SUPPORTED_INSTRUCTIONS;
    table->stats->write_actions = DP_SUPPORTED_ACTIONS;
    table->stats->apply_actions = DP_SUPPORTED_ACTIONS;
    table->stats->config        = OFPTC_TABLE_MISS_CONTROLLER;
    table->stats->max_entries   = FLOW_TABLE_MAX_ENTRIES;*/
    table->stats->active_count  = 0;
    table->stats->lookup_count  = 0;
    table->stats->matched_count = 0;

    list_init(&table->match_entries);
    list_init(&table->hard_entries);
    list_init(&table->idle_entries);

    return table;
}

void
flow_table_destroy(struct flow_table *table) {
    struct flow_entry *entry, *next;

    LIST_FOR_EACH_SAFE (entry, next, struct flow_entry, match_node, &table->match_entries) {
        flow_entry_destroy(entry);
    }
    free(table->features);
    free(table->stats);
    free(table);
}

void
flow_table_stats(struct flow_table *table, struct ofl_msg_multipart_request_flow *msg,
                 struct ofl_flow_stats ***stats, size_t *stats_size, size_t *stats_num) {
    struct flow_entry *entry;

    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        if ((msg->out_port == OFPP_ANY || flow_entry_has_out_port(entry, msg->out_port)) &&
            (msg->out_group == OFPG_ANY || flow_entry_has_out_group(entry, msg->out_group)) &&
            match_std_nonstrict((struct ofl_match *)msg->match,
                                (struct ofl_match *)entry->stats->match)) {

            flow_entry_update(entry);
            if ((*stats_size) == (*stats_num)) {
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_flow_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
            }
            (*stats)[(*stats_num)] = entry->stats;
            (*stats_num)++;
        }
    }
}

void
flow_table_aggregate_stats(struct flow_table *table, struct ofl_msg_multipart_request_flow *msg,
                           uint64_t *packet_count, uint64_t *byte_count, uint32_t *flow_count) {
    struct flow_entry *entry;

    LIST_FOR_EACH(entry, struct flow_entry, match_node, &table->match_entries) {
        if ((msg->out_port == OFPP_ANY || flow_entry_has_out_port(entry, msg->out_port)) &&
            (msg->out_group == OFPG_ANY || flow_entry_has_out_group(entry, msg->out_group))) {

            (*packet_count) += entry->stats->packet_count;
            (*byte_count)   += entry->stats->byte_count;
            (*flow_count)++;
        }
    }

}
