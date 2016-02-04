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
#include "flow_entry.h"
#include "group_entry.h"
#include "group_table.h"
#include "dp_actions.h"
#include "datapath.h"
#include "util.h"
#include "oflib/ofl.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-utils.h"

#include "vlog.h"
#define LOG_MODULE VLM_group_e

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);



struct group_table;
struct datapath;

/* Node in the list of references to flows, which reference the group entry. */
struct flow_ref_entry {
    struct list node;
    struct flow_entry *entry;
};

/* Private data for select groups; for implementing weighted round-robin. */
struct group_entry_wrr_data {
    uint16_t max_weight;  /* maximum weight of the buckets. */
    uint16_t gcd_weight;  /* g.c.d. of bucket weights. */
    uint16_t curr_weight; /* current weight in w.r.r. algorithm. */
    size_t   curr_bucket; /* bucket executed last time. */
};

static uint16_t
gcd(uint16_t a, uint16_t b);

static bool
bucket_is_alive(struct ofl_bucket *bucket, struct datapath *dp);

static void
init_select_group(struct group_entry *entry, struct ofl_msg_group_mod *mod);

static size_t
select_from_select_group(struct group_entry *entry);

static size_t
select_from_ff_group(struct group_entry *entry);


struct group_entry *
group_entry_create(struct datapath *dp, struct group_table *table, struct ofl_msg_group_mod *mod) {
    struct group_entry *entry;
    size_t i;
    
    entry = xmalloc(sizeof(struct group_entry));
    entry->dp          = dp;
    entry->table       = table;
    entry->desc = xmalloc(sizeof(struct ofl_group_desc_stats));
    entry->desc->type =        mod->type;
    entry->desc->group_id =    mod->group_id;
    entry->desc->buckets_num = mod->buckets_num;
    entry->desc->buckets     = mod->buckets;
    entry->stats = xmalloc(sizeof(struct ofl_group_stats));
    entry->stats->group_id      = mod->group_id;
    entry->stats->ref_count     = 0;
    entry->stats->packet_count  = 0;
    entry->stats->byte_count    = 0;
    entry->stats->counters_num  = mod->buckets_num;
    entry->stats->counters      = (struct ofl_bucket_counter **) xmalloc(sizeof(struct ofl_bucket_counter *) * entry->stats->counters_num);
    entry->stats->duration_sec  = 0;
    entry->stats->duration_nsec = 0;

    for (i=0; i<entry->stats->counters_num; i++) {
        entry->stats->counters[i] = (struct ofl_bucket_counter *) xmalloc(sizeof(struct ofl_bucket_counter));
        entry->stats->counters[i]->packet_count = 0;
        entry->stats->counters[i]->byte_count = 0;
    }
    switch (mod->type) {
        case (OFPGT_SELECT): {
            init_select_group(entry, mod);
            break;
        }
        default: {
            entry->data = NULL;
        }
    }
    list_init(&entry->flow_refs);
    return entry;
}


void
group_entry_destroy(struct group_entry *entry) {
    struct flow_ref_entry *ref, *next;

    // remove all referencing flows
    LIST_FOR_EACH_SAFE(ref, next, struct flow_ref_entry, node, &entry->flow_refs) {
        flow_entry_remove(ref->entry, OFPRR_GROUP_DELETE);
        // Note: the flow_ref_entryf will be destroyed after a chain of calls in flow_entry_remove
        // no point in decreasing stats counter, as the group is destroyed anyway

    }

    ofl_structs_free_group_desc_stats(entry->desc, entry->dp->exp);
    ofl_structs_free_group_stats(entry->stats);
    free(entry->data);
    free(entry);
}

/* Executes a group entry of type ALL. */
static void
execute_all(struct group_entry *entry, struct packet *pkt) {
    size_t i;

    /* TODO Zoltan: Currently packets are always cloned. However it should
     * be possible to see if cloning is necessary, or not, based on bucket actions. */
    for (i=0; i<entry->desc->buckets_num; i++) {
        struct ofl_bucket *bucket = entry->desc->buckets[i];
        struct packet *p = packet_clone(pkt);

        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *b = ofl_structs_bucket_to_string(bucket, entry->dp->exp);
            VLOG_DBG_RL(LOG_MODULE, &rl, "Writing bucket: %s.", b);
            free(b);
        }

        action_set_write_actions(p->action_set, bucket->actions_num, bucket->actions);

        entry->stats->byte_count += p->buffer->size;
        entry->stats->packet_count++;
        entry->stats->counters[i]->byte_count += p->buffer->size;
        entry->stats->counters[i]->packet_count++;

        /* Cookie field is set 0xffffffffffffffff
           because we cannot associate to any
           particular flow */
        action_set_execute(p->action_set, p, 0xffffffffffffffff);
        /* Clone will be destroyed above. Jean II */
    }
    packet_destroy(pkt);
}

/* Executes a group entry of type SELECT. */
static void
execute_select(struct group_entry *entry, struct packet *pkt) {
    size_t b  = select_from_select_group(entry);

    if (b != -1) {
        struct ofl_bucket *bucket = entry->desc->buckets[b];

        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *b = ofl_structs_bucket_to_string(bucket, entry->dp->exp);
            VLOG_DBG_RL(LOG_MODULE, &rl, "Writing bucket: %s.", b);
            free(b);
        }

        action_set_write_actions(pkt->action_set, bucket->actions_num, bucket->actions);

        entry->stats->byte_count += pkt->buffer->size;
        entry->stats->packet_count++;
        entry->stats->counters[b]->byte_count += pkt->buffer->size;
        entry->stats->counters[b]->packet_count++;
        /* Cookie field is set 0xffffffffffffffff
           because we cannot associate to any
           particular flow */
        action_set_execute(pkt->action_set, pkt, 0xffffffffffffffff);
    } else {
        VLOG_DBG_RL(LOG_MODULE, &rl, "No bucket in group.");
        packet_destroy(pkt);
    }
}

/* Execute a group entry of type INDIRECT. */
static void
execute_indirect(struct group_entry *entry, struct packet *pkt) {

    if (entry->desc->buckets_num > 0) {
        struct ofl_bucket *bucket = entry->desc->buckets[0];

        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *b = ofl_structs_bucket_to_string(bucket, entry->dp->exp);
            VLOG_DBG_RL(LOG_MODULE, &rl, "Writing bucket: %s.", b);
            free(b);
        }

        action_set_write_actions(pkt->action_set, bucket->actions_num, bucket->actions);

        entry->stats->byte_count += pkt->buffer->size;
        entry->stats->packet_count++;
        entry->stats->counters[0]->byte_count += pkt->buffer->size;
        entry->stats->counters[0]->packet_count++;
        /* Cookie field is set 0xffffffffffffffff
           because we cannot associate to any
           particular flow */
        action_set_execute(pkt->action_set, pkt, 0xffffffffffffffff);
    } else {
        VLOG_DBG_RL(LOG_MODULE, &rl, "No bucket in group.");
        packet_destroy(pkt);
    }
}

/* Execute a group entry of type FAILFAST. */
static void
execute_ff(struct group_entry *entry, struct packet *pkt) {
    size_t b  = select_from_ff_group(entry);

    if (b != -1) {
        struct ofl_bucket *bucket = entry->desc->buckets[b];

        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
            char *b = ofl_structs_bucket_to_string(bucket, entry->dp->exp);
            VLOG_DBG_RL(LOG_MODULE, &rl, "Writing bucket: %s.", b);
            free(b);
        }

        action_set_write_actions(pkt->action_set, bucket->actions_num, bucket->actions);

        entry->stats->byte_count += pkt->buffer->size;
        entry->stats->packet_count++;
        entry->stats->counters[b]->byte_count += pkt->buffer->size;
        entry->stats->counters[b]->packet_count++;
        /* Cookie field is set 0xffffffffffffffff
           because we cannot associate to any
           particular flow */
        action_set_execute(pkt->action_set, pkt, 0xffffffffffffffff);
    } else {
        VLOG_DBG_RL(LOG_MODULE, &rl, "No bucket in group.");
        packet_destroy(pkt);
    }
}



void
group_entry_execute(struct group_entry *entry,
                          struct packet *packet) {

    VLOG_DBG_RL(LOG_MODULE, &rl, "Executing group %u.", entry->stats->group_id);

    /* Group action are often used in the action-set. Action-set
     * processing is terminal, so the original packet is passed to us
     * for processing. In that case, the caller must clear the
     * action-set of the packet. See action_set_execute().
     * Spec v1.1 and later also say that a group action can occur in
     * action-list, in that case it must process a clone/copy of the
     * packet and execution continue on the original packet. In that
     * case, the caller must do the appropriate cloning of the packet.
     * See dp_execute_action_list().
     * In any case, we won't return the packet to the caller, we will
     * destroy it or pass it to someone.
     * Jean II */

    switch (entry->desc->type) {
        case (OFPGT_ALL): {
            execute_all(entry, packet);
            break;
        }
        case (OFPGT_SELECT): {
            execute_select(entry, packet);
            break;
        }
        case (OFPGT_INDIRECT): {
            execute_indirect(entry, packet);
            break;
        }
        case (OFPGT_FF): {
            execute_ff(entry, packet);
            break;
        }
        default: {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown group type (%u) in group (%u).", entry->desc->type, entry->stats->group_id);
            packet_destroy(packet);
        }
    }
}

void
group_entry_update(struct group_entry *entry){
    entry->stats->duration_sec  =  (time_msec() - entry->created) / 1000;
    entry->stats->duration_nsec = ((time_msec() - entry->created) % 1000) * 1000000;
}

/* Returns true if the group entry has  reference to the flow entry. */
static bool
has_flow_ref(struct group_entry *entry, struct flow_entry *fe) {
    struct flow_ref_entry *f;

    LIST_FOR_EACH(f, struct flow_ref_entry, node, &entry->flow_refs) {
        if (f->entry == fe) {
            return true;
        }
    }
    return false;
}

bool
group_entry_has_out_group(struct group_entry *entry, uint32_t group_id) {
    size_t i;

    for (i=0; i<entry->desc->buckets_num; i++) {
        struct ofl_bucket *b = (struct ofl_bucket *)entry->desc->buckets[i];
        if (dp_actions_list_has_out_group(b->actions_num, b->actions, group_id)) {
            return true;
        }
    }
    return false;
}

void
group_entry_add_flow_ref(struct group_entry *entry, struct flow_entry *fe) {
    if (!(has_flow_ref(entry, fe))) {
        struct flow_ref_entry *f = xmalloc(sizeof(struct flow_ref_entry));
        f->entry = fe;
        list_insert(&entry->flow_refs, &f->node);
        entry->stats->ref_count++;
    }
}

void
group_entry_del_flow_ref(struct group_entry *entry, struct flow_entry *fe) {
    struct flow_ref_entry *f, *next;

    LIST_FOR_EACH_SAFE(f, next, struct flow_ref_entry, node, &entry->flow_refs) {
        if (f->entry == fe) {
            list_remove(&f->node);
            free(f);
            entry->stats->ref_count--;
        }
    }
}


/* Returns true if the bucket is alive. */
static bool
bucket_is_alive(struct ofl_bucket *bucket, struct datapath *dp) {
    struct sw_port *p =  dp_ports_lookup(dp, bucket->watch_port);

    if(bucket->watch_port == OFPP_ANY || (p->conf->config & OFPPC_PORT_DOWN) ||
        (p->conf->state & OFPPS_LINK_DOWN)){
        return false;
    }
    // TODO Zoltan: Implement link up/down detection
    return true;
}


/* Initializes the private w.r.r. data for a select group entry. */
static void
init_select_group(struct group_entry *entry, struct ofl_msg_group_mod *mod) {
    struct group_entry_wrr_data *data;
    size_t i;

    entry->data = xmalloc(sizeof(struct group_entry_wrr_data));
    data = (struct group_entry_wrr_data *)entry->data;

    data->curr_weight = 0;
    data->curr_bucket = -1;

    if (mod->buckets_num == 0) {
        data->gcd_weight = 0;
        data->max_weight = 0;
    } else {
        data->gcd_weight = entry->desc->buckets[0]->weight;
        data->max_weight = entry->desc->buckets[0]->weight;

        for (i=1; i< entry->desc->buckets_num; i++) {
            data->gcd_weight = gcd(data->gcd_weight, entry->desc->buckets[i]->weight);
            data->max_weight = MAX(data->max_weight, entry->desc->buckets[i]->weight);
        }

    }
}

/* Selects a bucket from a select group, based on the w.r.r. algorithm. */
static size_t
select_from_select_group(struct group_entry *entry) {
    struct group_entry_wrr_data *data;
    size_t guard;

    if (entry->desc->buckets_num == 0) {
        return -1;
    }

    data = (struct group_entry_wrr_data *)entry->data;
    guard = 0;

    while (guard < entry->desc->buckets_num) {
        data->curr_bucket = (data->curr_bucket + 1) % entry->desc->buckets_num;

        if (data->curr_bucket == 0) {
            if (data->curr_weight <= data->gcd_weight) {
                data->curr_weight = data->max_weight;
            } else {
                data->curr_weight = data->curr_weight - data->gcd_weight;
            }
        }

        if (entry->desc->buckets[data->curr_bucket]->weight >= data->curr_weight) {
            return data->curr_bucket;
        }
        guard++;
    }
    VLOG_WARN_RL(LOG_MODULE, &rl, "Could not select from select group.");
    return -1;
}

/* Selects the first live bucket from the failfast group. */
static size_t
select_from_ff_group(struct group_entry *entry) {
    size_t i;

    for (i=0; i<entry->desc->buckets_num; i++) {
        if (bucket_is_alive(entry->desc->buckets[i], entry->dp)) {
            return i;
        }
    }
    return -1;
}

/* Returns the g.c.d. of the two numbers. */
static uint16_t
gcd(uint16_t a, uint16_t b) {
    uint16_t c;

    while (a != 0) {
        c = a;
        a = b % a;
        b = c;
    }

    return b;
}
