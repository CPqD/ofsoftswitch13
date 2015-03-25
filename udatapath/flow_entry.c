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
#include <stdlib.h>
#include "datapath.h"
#include "dp_actions.h"
#include "flow_table.h"
#include "flow_entry.h"
#include "group_table.h"
#include "group_entry.h"
#include "meter_table.h"
#include "meter_entry.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-utils.h"
#include "packets.h"
#include "timeval.h"
#include "util.h"

#include "vlog.h"
#define LOG_MODULE VLM_flow_e

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

struct group_ref_entry {
    struct list   node;
    uint32_t      group_id;
};

struct meter_ref_entry {
    struct list   node;
    uint32_t      meter_id;
};

static void
init_group_refs(struct flow_entry *entry);

static void
del_group_refs(struct flow_entry *entry);

static void
init_meter_refs(struct flow_entry *entry);

static void
del_meter_refs(struct flow_entry *entry);

bool
flow_entry_has_out_port(struct flow_entry *entry, uint32_t port) {
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];
            if (dp_actions_list_has_out_port(ia->actions_num, ia->actions, port)) {
                return true;
            }
        }
    }
    return false;
}


bool
flow_entry_has_out_group(struct flow_entry *entry, uint32_t group) {
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];
            if (dp_actions_list_has_out_group(ia->actions_num, ia->actions, group)) {
                return true;
            }
        }
    }
    return false;
}


bool
flow_entry_matches(struct flow_entry *entry, struct ofl_msg_flow_mod *mod, bool strict, bool check_cookie) {
	if (check_cookie && ((entry->stats->cookie & mod->cookie_mask) != (mod->cookie & mod->cookie_mask))) {
		return false;
	}
    
    if (strict) {
        return ( (entry->stats->priority == mod->priority) &&
                 match_std_strict((struct ofl_match *)mod->match,
                                (struct ofl_match *)entry->stats->match));
    } else {
        return match_std_nonstrict((struct ofl_match *)mod->match,
                                   (struct ofl_match *)entry->stats->match);
    }
}

bool
flow_entry_overlaps(struct flow_entry *entry, struct ofl_msg_flow_mod *mod) {
        return (entry->stats->priority == mod->priority &&
            (mod->out_port == OFPP_ANY || flow_entry_has_out_port(entry, mod->out_port)) &&
            (mod->out_group == OFPG_ANY || flow_entry_has_out_group(entry, mod->out_group)) &&
            match_std_overlap((struct ofl_match *)entry->stats->match,
                                            (struct ofl_match *)mod->match));
}


void
flow_entry_replace_instructions(struct flow_entry *entry,
                                      size_t instructions_num,
                                      struct ofl_instruction_header **instructions) {

    /* TODO Zoltan: could be done more efficiently, but... */
    del_group_refs(entry);

    OFL_UTILS_FREE_ARR_FUN2(entry->stats->instructions, entry->stats->instructions_num,
                            ofl_structs_free_instruction, entry->dp->exp);

    entry->stats->instructions_num = instructions_num;
    entry->stats->instructions     = instructions;

    init_group_refs(entry);
}

void
flow_entry_modify_stats(struct flow_entry *entry,
                              struct ofl_msg_flow_mod *mod) {

    /* Reset flow counters as needed. Jean II */
    if ((mod->flags & OFPFF_RESET_COUNTS) != 0) {
        if (!(entry->no_pkt_count))
            entry->stats->packet_count     = 0;
        if (!(entry->no_byt_count))
            entry->stats->byte_count       = 0;
    }
}

bool
flow_entry_idle_timeout(struct flow_entry *entry) {
    bool timeout;

    timeout = (entry->stats->idle_timeout != 0) &&
              (time_msec() > entry->last_used + entry->stats->idle_timeout * 1000);

    if (timeout) {
        flow_entry_remove(entry, OFPRR_IDLE_TIMEOUT);
    }
    return timeout;
}

bool
flow_entry_hard_timeout(struct flow_entry *entry) {
    bool timeout;

    timeout = (entry->remove_at != 0) && (time_msec() > entry->remove_at);

    if (timeout) {
        flow_entry_remove(entry, OFPRR_HARD_TIMEOUT);
    }
    return timeout;
}

void
flow_entry_update(struct flow_entry *entry) {
    entry->stats->duration_sec  =  (time_msec() - entry->created) / 1000;
    entry->stats->duration_nsec = ((time_msec() - entry->created) % 1000) * 1000000;
}

/* Returns true if the flow entry has a reference to the given group. */
static bool
has_group_ref(struct flow_entry *entry, uint32_t group_id) {
    struct group_ref_entry *g;

    LIST_FOR_EACH(g, struct group_ref_entry, node, &entry->group_refs) {
        if (g->group_id == group_id) {
            return true;
        }
    }
    return false;
}

/* Initializes the group references of the flow entry. */
static void
init_group_refs(struct flow_entry *entry) {
    struct group_ref_entry *e;
    size_t i,j;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_APPLY_ACTIONS ||
            entry->stats->instructions[i]->type == OFPIT_WRITE_ACTIONS) {
            struct ofl_instruction_actions *ia = (struct ofl_instruction_actions *)entry->stats->instructions[i];

            for (j=0; j < ia->actions_num; j++) {
                if (ia->actions[j]->type == OFPAT_GROUP) {
                    struct ofl_action_group *ag = (struct ofl_action_group *)(ia->actions[j]);
                    if (!has_group_ref(entry, ag->group_id)) {
                        struct group_ref_entry *gre = xmalloc(sizeof(struct group_ref_entry));
                        gre->group_id = ag->group_id;
                        list_insert(&entry->group_refs, &gre->node);
                    }
                }
            }
        }
    }

    /* notify groups of the new referencing flow entry */
    LIST_FOR_EACH(e, struct group_ref_entry, node, &entry->group_refs) {
    	struct group_entry *group = group_table_find(entry->dp->groups, e->group_id);
    	if (group != NULL) {
    	    group_entry_add_flow_ref(group, entry);
    	} else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to access non-existing group(%u).", e->group_id);
    	}
    }
}

/* Deletes group references from the flow, and also deletes the flow references
 * from the referecenced groups. */
static void
del_group_refs(struct flow_entry *entry) {
    struct group_ref_entry *gre, *next;

    LIST_FOR_EACH_SAFE(gre, next, struct group_ref_entry, node, &entry->group_refs) {

    	struct group_entry *group = group_table_find(entry->dp->groups, gre->group_id);
    	if (group != NULL) {
    	    group_entry_del_flow_ref(group, entry);
    	} else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to access non-existing group(%u).", gre->group_id);
    	}
    	list_remove(&gre->node);
        free(gre);
    }
}


/* Returns true if the flow entry has a reference to the given meter. */
static bool
has_meter_ref(struct flow_entry *entry, uint32_t meter_id) {
    struct meter_ref_entry *m;

    LIST_FOR_EACH(m, struct meter_ref_entry, node, &entry->meter_refs) {
        if (m->meter_id == meter_id) {
            return true;
        }
    }
    return false;
}

/* Initializes the meter references of the flow entry. */
static void
init_meter_refs(struct flow_entry *entry) {
    struct meter_ref_entry *e;
    size_t i;

    for (i=0; i<entry->stats->instructions_num; i++) {
        if (entry->stats->instructions[i]->type == OFPIT_METER ) {
            struct ofl_instruction_meter *ia = (struct ofl_instruction_meter *)entry->stats->instructions[i];

			if (!has_meter_ref(entry, ia->meter_id)) {
				struct meter_ref_entry *mre = xmalloc(sizeof(struct meter_ref_entry));
				mre->meter_id = ia->meter_id;
				list_insert(&entry->meter_refs, &mre->node);
			}

        }
    }

    /* notify meter of the new referencing flow entry */
    LIST_FOR_EACH(e, struct meter_ref_entry, node, &entry->meter_refs) {
    	struct meter_entry *meter = meter_table_find(entry->dp->meters, e->meter_id);
    	if (meter != NULL) {
    		meter_entry_add_flow_ref(meter, entry);
    	} else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to access non-existing meter(%u).", e->meter_id);
    	}
    }
}

/* Deletes meter references from the flow, and also deletes the flow references
 * from the referecenced groups. */
static void
del_meter_refs(struct flow_entry *entry) {
    struct meter_ref_entry *mre, *next;

    LIST_FOR_EACH_SAFE(mre, next, struct meter_ref_entry, node, &entry->meter_refs) {

    	struct meter_entry *meter = meter_table_find(entry->dp->meters, mre->meter_id);
    	if (meter != NULL) {
    		meter_entry_del_flow_ref(meter, entry);
    	} else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to access non-existing meter(%u).", mre->meter_id);
    	}
    	list_remove(&mre->node);
        free(mre);
    }
}


struct flow_entry *
flow_entry_create(struct datapath *dp, struct flow_table *table, struct ofl_msg_flow_mod *mod) {
    struct flow_entry *entry;
    uint64_t now;

    now = time_msec();

    entry = xmalloc(sizeof(struct flow_entry));
    entry->dp    = dp;
    entry->table = table;

    entry->stats = xmalloc(sizeof(struct ofl_flow_stats));

    entry->stats->table_id         = mod->table_id;
    entry->stats->duration_sec     = 0;
    entry->stats->duration_nsec    = 0;
    entry->stats->priority         = mod->priority;
    entry->stats->idle_timeout     = mod->idle_timeout;
    entry->stats->hard_timeout     = mod->hard_timeout;
    entry->stats->flags            = mod->flags;
    entry->stats->cookie           = mod->cookie;
    entry->no_pkt_count = ((mod->flags & OFPFF_NO_PKT_COUNTS) != 0 );
    entry->no_byt_count = ((mod->flags & OFPFF_NO_BYT_COUNTS) != 0 ); 
    if (entry->no_pkt_count)
        entry->stats->packet_count     = 0xffffffffffffffff;
    else 
        entry->stats->packet_count     = 0;
    if (entry->no_byt_count)
        entry->stats->byte_count       = 0xffffffffffffffff;
    else 
        entry->stats->byte_count       = 0;

    entry->stats->match            = mod->match;
    entry->stats->instructions_num = mod->instructions_num;
    entry->stats->instructions     = mod->instructions;

    entry->match = mod->match; /* TODO: MOD MATCH? */

    entry->created      = now;
    entry->remove_at    = mod->hard_timeout == 0 ? 0
                                  : now + mod->hard_timeout * 1000;
    entry->last_used    = now;
    entry->send_removed = ((mod->flags & OFPFF_SEND_FLOW_REM) != 0);
    list_init(&entry->match_node);
    list_init(&entry->idle_node);
    list_init(&entry->hard_node);

    list_init(&entry->group_refs);
    init_group_refs(entry);

    list_init(&entry->meter_refs);
    init_meter_refs(entry);

    return entry;
}

void
flow_entry_destroy(struct flow_entry *entry) {
    // NOTE: This will be called when the group entry itself destroys the
    //       flow; but it won't be a problem.
    del_group_refs(entry);
    del_meter_refs(entry);
    ofl_structs_free_flow_stats(entry->stats, entry->dp->exp);
    // assumes it is a standard match
    //free(entry->match);
    free(entry);
}

void
flow_entry_remove(struct flow_entry *entry, uint8_t reason) {
    if (entry->send_removed) {
        flow_entry_update(entry);
        {
            struct ofl_msg_flow_removed msg =
                    {{.type = OFPT_FLOW_REMOVED},
                     .reason = reason,
                     .stats  = entry->stats};

            dp_send_message(entry->dp, (struct ofl_msg_header *)&msg, NULL);
        }
    }

    list_remove(&entry->match_node);
    list_remove(&entry->hard_node);
    list_remove(&entry->idle_node);
    entry->table->stats->active_count--;
    flow_entry_destroy(entry);
}
