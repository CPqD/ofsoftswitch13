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

#include <stdlib.h>
#include "action_set.h"
#include "dp_actions.h"
#include "datapath.h"
#include "packet.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-print.h"
#include "packet.h"
#include "list.h"
#include "util.h"
#include "vlog.h"

#define LOG_MODULE VLM_action_set

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

struct action_set_entry;

struct action_set {
    struct list     actions;   /* the list of actions in the action set,
+                                   stored in the order of precedence as defined
+                                   by the specification. */
    struct ofl_exp *exp;       /* experimenter callbacks */
};

struct action_set_entry {
    struct list                node;

    struct ofl_action_header  *action;  /* these actions point to actions in
+                                        * flow table entry instructions */
    int                        order;   /* order of the entry as defined */
};




/* Returns the priority of the action it should be executed in
 * according to the spec. Note, that the actions are already
 * stored in this order.
 */
static int
action_set_order(struct ofl_action_header *act) {
    switch (act->type) {
        case (OFPAT_COPY_TTL_OUT):   return 40;
        case (OFPAT_COPY_TTL_IN):    return 10;
        case (OFPAT_SET_FIELD):      return 60;
        case (OFPAT_SET_MPLS_TTL):   return 60;
        case (OFPAT_DEC_MPLS_TTL):   return 50;
        case (OFPAT_PUSH_PBB):       return 30;
        case (OFPAT_POP_PBB):        return 20;
        case (OFPAT_PUSH_VLAN):      return 30;
        case (OFPAT_POP_VLAN):       return 20;
        case (OFPAT_PUSH_MPLS):      return 30;
        case (OFPAT_POP_MPLS):       return 20;
        case (OFPAT_SET_QUEUE):      return 70;
        case (OFPAT_GROUP):          return 80;
        case (OFPAT_SET_NW_TTL):     return 60;
        case (OFPAT_DEC_NW_TTL):     return 50;
        case (OFPAT_OUTPUT):         return 90;
        case (OFPAT_EXPERIMENTER):   return 75;
        default:                     return 79;
    }
}


/* Creates a new set entry */
struct action_set *
action_set_create(struct ofl_exp *exp) {
    struct action_set *set = xmalloc(sizeof(struct action_set));
    list_init(&set->actions);
    set->exp = exp;

    return set;
}

void action_set_destroy(struct action_set *set) {
    action_set_clear_actions(set);
    free(set);
}

static struct action_set_entry *
action_set_create_entry(struct ofl_action_header *act) {
    struct action_set_entry *entry;

    entry = xmalloc(sizeof(struct action_set_entry));
    entry->action = act;
    entry->order = action_set_order(act);

    return entry;
}

struct action_set *
action_set_clone(struct action_set *set) {
    struct action_set *s = xmalloc(sizeof(struct action_set));
    struct action_set_entry *entry, *new_entry;

    list_init(&s->actions);
    s->exp = set->exp;

    LIST_FOR_EACH(entry, struct action_set_entry, node, &set->actions) {
        new_entry = action_set_create_entry(entry->action);
        list_push_back(&s->actions, &new_entry->node);
    }

    return s;
}


/* Writes a single action to the action set. Overwrites existing actions with
 * the same type in the set. The list order is based on the precedence defined
 * in the specification. */
static void
action_set_write_action(struct action_set *set,
                        struct ofl_action_header *act) {
    struct action_set_entry *entry, *new_entry;

    new_entry = action_set_create_entry(act);

    LIST_FOR_EACH(entry, struct action_set_entry, node, &set->actions) {
        if (entry->action->type == new_entry->action->type) {
            if(entry->action->type == OFPAT_SET_FIELD){
                struct ofl_action_set_field *new_act = 
                        (struct ofl_action_set_field*) new_entry->action;
                struct ofl_action_set_field *act = 
                            (struct ofl_action_set_field *) entry->action;
                if(act->field->header != new_act->field->header){
                    continue;
                }     
            } 
            /* replace same type of action */
            list_replace(&new_entry->node, &entry->node);
            /* NOTE: action in entry must not be freed, as it is owned by the
             *       write instruction which added the action to the set */
            free(entry);

            return;
        }
        if (new_entry->order < entry->order) {
            /* insert higher order action before */
            list_insert(&entry->node, &new_entry->node);

            return;
        }
    }

    /* add action to the end of set */
    list_insert(&entry->node, &new_entry->node);
}


void
action_set_write_actions(struct action_set *set,
                         size_t actions_num,
                         struct ofl_action_header **actions) {
    size_t i;
    VLOG_DBG_RL(LOG_MODULE, &rl, "Writing to action set.");
    for (i=0; i<actions_num; i++) {
        action_set_write_action(set, actions[i]);
    }
    VLOG_DBG_RL(LOG_MODULE, &rl, "%s", action_set_to_string(set));
}

void
action_set_clear_actions(struct action_set *set) {
    struct action_set_entry *entry, *next;

    LIST_FOR_EACH_SAFE(entry, next, struct action_set_entry, node, &set->actions) {
        list_remove(&entry->node);
        // NOTE: action in entry must not be freed, as it is owned by the write instruction
        //       which added the action to the set
        free(entry);
    }
}

void
action_set_execute(struct action_set *set, struct packet *pkt, uint64_t cookie) {
    struct action_set_entry *entry, *next;

    LIST_FOR_EACH_SAFE(entry, next, struct action_set_entry, node, &set->actions) {
        dp_execute_action(pkt, entry->action);
        list_remove(&entry->node);
        free(entry);
    }

    /* Clear the action set in any case. Group processing depend on
     * a clean action-set. Jean II */
    action_set_clear_actions(pkt->action_set);

        /* According to the spec. if there was a group action, the output
         * port action should be ignored */
        if (pkt->out_group != OFPG_ANY) {
            uint32_t group_id = pkt->out_group;
            pkt->out_group = OFPG_ANY;

            /* Transfer packet to the group. It will be destroyed. Jean II */
            group_table_execute(pkt->dp->groups, pkt, group_id);

            return;
        } else if (pkt->out_port != OFPP_ANY) {
            uint32_t port_id = pkt->out_port;
            uint32_t queue_id = pkt->out_queue;
            uint16_t max_len = pkt->out_port_max_len;
            pkt->out_port = OFPP_ANY;
            pkt->out_port_max_len = 0;
            pkt->out_queue = 0;

            dp_actions_output_port(pkt, port_id, queue_id, max_len, cookie);
            packet_destroy(pkt);
            return;
        }

    /* No output or group action. Just drop the packet. Jean II */
    packet_destroy(pkt);
}

char *
action_set_to_string(struct action_set *set) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    action_set_print(stream, set);

    fclose(stream);
    return str;
}

void
action_set_print(FILE *stream, struct action_set *set) {
    struct action_set_entry *entry;

    fprintf(stream, "[");

    LIST_FOR_EACH(entry, struct action_set_entry, node, &set->actions) {
        ofl_action_print(stream, entry->action, set->exp);
        if (entry->node.next != &set->actions) { fprintf(stream, ", "); }
    }

    fprintf(stream, "]");
}

