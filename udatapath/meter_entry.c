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

#include <stdbool.h>
#include "csum.h"
#include "flow_entry.h"
#include "meter_entry.h"
#include "meter_table.h"
#include "dp_actions.h"
#include "datapath.h"
#include "util.h"
#include "oflib/ofl.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-utils.h"
#include "oflib/ofl-messages.h"
#include "timeval.h"
#include <math.h>
#include "vlog.h"
#define LOG_MODULE VLM_meter_e

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);



struct meter_table;
struct datapath;

/* Node in the list of references to flows, which reference the meter entry. */
struct flow_ref_entry {
    struct list node;
    struct flow_entry *entry;
};



struct meter_entry *
meter_entry_create(struct datapath *dp, struct meter_table *table, struct ofl_msg_meter_mod *mod) {
    struct meter_entry *entry;
    size_t i;
    uint64_t now;

    now = time_msec();
    entry = xmalloc(sizeof(struct meter_entry));

    entry->dp          = dp;
    entry->table       = table;


    entry->config = xmalloc(sizeof(struct ofl_meter_config));
    entry->config->meter_id =  mod->meter_id;
    entry->config->flags =    mod->flags;
    entry->config->meter_bands_num = mod->meter_bands_num;

    //entry->config->bands = mod->bands; //allocate and copy from mod
    entry->config->bands = (struct ofl_meter_band_header **) xmalloc(sizeof(struct ofl_meter_band_header *) * entry->config->meter_bands_num);
    for(i = 0; i < entry->config->meter_bands_num; i++){
        switch(mod->bands[i]->type){
            case (OFPMBT_DROP):{
                struct ofl_meter_band_drop *band = xmalloc(sizeof(struct ofl_meter_band_drop));
                band->type = OFPMBT_DROP;
                band->rate = mod->bands[i]->rate;
                band->burst_size = mod->bands[i]->burst_size;
                entry->config->bands[i] = (struct ofl_meter_band_header *) band;
                break;
            }
            case (OFPMBT_DSCP_REMARK):{
                struct ofl_meter_band_dscp_remark *band = xmalloc(sizeof(struct ofl_meter_band_dscp_remark));
                struct ofl_meter_band_dscp_remark *old = (struct ofl_meter_band_dscp_remark *) mod->bands[i];
                band->type = OFPMBT_DSCP_REMARK;
                band->rate = old->rate;
                band->burst_size = old->burst_size;
                band->prec_level = old->prec_level;
                entry->config->bands[i] = (struct ofl_meter_band_header *) band;
                break;
            }
            case (OFPMBT_EXPERIMENTER):{
                struct ofl_meter_band_experimenter *band = xmalloc(sizeof(struct ofl_meter_band_experimenter));
                struct ofl_meter_band_experimenter *old = (struct ofl_meter_band_experimenter *) mod->bands[i];
                band->type = OFPMBT_EXPERIMENTER;
                band->rate = old->rate;
                band->burst_size = old->burst_size;
                band->experimenter = old->experimenter;
                entry->config->bands[i] = (struct ofl_meter_band_header *) band;
                break;
            }
        }
    }

    entry->stats = xmalloc(sizeof(struct ofl_meter_stats));
    entry->stats->meter_id      = mod->meter_id;
    entry->stats->byte_in_count = 0;
    entry->stats->flow_count  = 0;
    entry->stats->packet_in_count  = 0;
    entry->stats->meter_bands_num    = mod->meter_bands_num;
    entry->stats->duration_nsec  = 0;
    entry->stats->duration_sec = 0;
    entry->created      = now;
    entry->stats->band_stats      = (struct ofl_meter_band_stats **) xmalloc(sizeof(struct ofl_meter_band_stats *) * entry->stats->meter_bands_num);


    for (i=0; i<entry->stats->meter_bands_num; i++) {
        entry->stats->band_stats[i] = (struct ofl_meter_band_stats *) xmalloc(sizeof(struct ofl_meter_band_stats));
        entry->stats->band_stats[i]->byte_band_count = 0;
        entry->stats->band_stats[i]->packet_band_count = 0;
        entry->stats->band_stats[i]->last_fill = time_msec();
        entry->stats->band_stats[i]->tokens = 0;
    }

    list_init(&entry->flow_refs);

    return entry;
}

void
meter_entry_update(struct meter_entry *entry) {
    entry->stats->duration_sec  =  (time_msec() - entry->created) / 1000;
    entry->stats->duration_nsec = ((time_msec() - entry->created) % 1000) * 1000000;
}

void
meter_entry_destroy(struct meter_entry *entry) {
    struct flow_ref_entry *ref, *next;

    // remove all referencing flows
    LIST_FOR_EACH_SAFE(ref, next, struct flow_ref_entry, node, &entry->flow_refs) {
        flow_entry_remove(ref->entry, OFPRR_METER_DELETE);// METER_DELETE ???????
        // Note: the flow_ref_entryf will be destroyed after a chain of calls in flow_entry_remove
    }

    OFL_UTILS_FREE_ARR_FUN(entry->config->bands, entry->config->meter_bands_num, ofl_structs_free_meter_bands);
    free(entry->config);

    OFL_UTILS_FREE_ARR(entry->stats->band_stats, entry->stats->meter_bands_num);
    free(entry->stats);
    free(entry);
}

static bool
consume_tokens(struct ofl_meter_band_stats *band, uint16_t meter_flag, struct packet *pkt){

    if(meter_flag & OFPMF_KBPS){
        uint32_t pkt_size = pkt->buffer->size * 8;
        if (band->tokens >= pkt_size) {
            band->tokens -= pkt_size;
            return true;
        } else {
            return false;
        }

    }
    else if(meter_flag & OFPMF_PKTPS) {
        if (band->tokens >= 1000) {
            band->tokens -= 1000;
            return true;
        } else {
            return false;
        }
    }
    return false;
}

static size_t
choose_band(struct meter_entry *entry, struct packet *pkt)
{
	size_t i;
	size_t band_index = -1;
	uint32_t tmp_rate = 0;
	for(i = 0; i < entry->stats->meter_bands_num; i++)
	{
		struct ofl_meter_band_header *band_header = entry->config->bands[i];
		if(!consume_tokens(entry->stats->band_stats[i], entry->config->flags, pkt) && band_header->rate > tmp_rate)
		{
			tmp_rate = band_header->rate;
			band_index = i;
		}
	}
	return band_index;
}


void
meter_entry_apply(struct meter_entry *entry, struct packet **pkt){

    size_t b;
    bool drop = false;

    entry->stats->packet_in_count++;
    entry->stats->byte_in_count += (*pkt)->buffer->size;

    b = choose_band(entry, *pkt);
    if(b != -1){
        struct ofl_meter_band_header *band_header = (struct ofl_meter_band_header*)  entry->config->bands[b];
        switch(band_header->type){
            case OFPMBT_DROP:{
                drop = true;
                break;
            }
            case OFPMBT_DSCP_REMARK:{
                packet_handle_std_validate(&(*pkt)->handle_std);
            if ((*pkt)->handle_std.valid)
            {
                struct ofl_meter_band_dscp_remark *band_header = (struct ofl_meter_band_dscp_remark *)  entry->config->bands[b];
                /* Nothing prevent this band to be used for non-IP packets, so filter them out. Jean II */
                if ((*pkt)->handle_std.proto.ipv4 != NULL) {

                    // Fetch dscp in ipv4 header
                    struct ip_header *ipv4 = (*pkt)->handle_std.proto.ipv4;
                    uint8_t old_drop = ipv4->ip_tos & 0x1C;
                    /* The spec says that we need to increase
                                       the drop precedence of the packet.
                                       We need a valid DSCP out of the process,
                                       so we can only modify dscp if the
                                       drop precedence is low (tos 0x***010**)
                                       or medium (tos 0x***100**). Jean II */
                    if (((old_drop == 0x8) && (band_header->prec_level <= 2)) || ((old_drop == 0x10) && (band_header->prec_level <= 1))) {
                        uint8_t new_drop = old_drop + (band_header->prec_level << 3);
                        uint8_t new_tos = new_drop | (ipv4->ip_tos & 0xE3);
                        uint16_t old_val = htons((ipv4->ip_ihl_ver << 8) + ipv4->ip_tos);
                        uint16_t new_val = htons((ipv4->ip_ihl_ver << 8) + new_tos);
                        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
                        ipv4->ip_tos = new_tos;
                    }
                }
                else if ((*pkt)->handle_std.proto.ipv6 != NULL){
                    struct ipv6_header *ipv6 = (*pkt)->handle_std.proto.ipv6;
                    uint32_t ipv6_ver_tc_fl = ntohl(ipv6->ipv6_ver_tc_fl);
                    uint32_t old_drop = ipv6_ver_tc_fl & 0x1C00000;
                    if (((old_drop == 0x800000) && (band_header->prec_level <= 2)) || ((old_drop == 0x1000000) && (band_header->prec_level <= 1))){
                        uint32_t prec_level = band_header->prec_level << 23;
                        uint32_t new_drop = old_drop + prec_level;
                        ipv6->ipv6_ver_tc_fl = htonl(new_drop | (ipv6_ver_tc_fl & 0xFE3FFFFF));
                    }
                }
                (*pkt)->handle_std.valid = false;
        }
                break;
            }
            case OFPMBT_EXPERIMENTER:{
                break;
            }
        }
        entry->stats->band_stats[b]->byte_band_count += (*pkt)->buffer->size;
        entry->stats->band_stats[b]->packet_band_count++;
        if (drop){
            VLOG_DBG_RL(LOG_MODULE, &rl, "Dropping packet: rate %d", band_header->rate);
            packet_destroy(*pkt);
            *pkt = NULL;
        }
    }

}

/* Returns true if the meter entry has  reference to the flow entry. */
static bool
has_flow_ref(struct meter_entry *entry, struct flow_entry *fe) {
    struct flow_ref_entry *f;

    LIST_FOR_EACH(f, struct flow_ref_entry, node, &entry->flow_refs) {
        if (f->entry == fe) {
            return true;
        }
    }
    return false;
}


void
meter_entry_add_flow_ref(struct meter_entry *entry, struct flow_entry *fe) {
    if (!(has_flow_ref(entry, fe))) {
        struct flow_ref_entry *f = xmalloc(sizeof(struct flow_ref_entry));
        f->entry = fe;
        list_insert(&entry->flow_refs, &f->node);
        entry->stats->flow_count++;
    }
}

void
meter_entry_del_flow_ref(struct meter_entry *entry, struct flow_entry *fe) {
    struct flow_ref_entry *f, *next;

    LIST_FOR_EACH_SAFE(f, next, struct flow_ref_entry, node, &entry->flow_refs) {
        if (f->entry == fe) {
            list_remove(&f->node);
            free(f);
            entry->stats->flow_count--;
        }
    }
}

/* Add tokens to the bucket based on elapsed time. */
void
refill_bucket(struct meter_entry *entry)
{
    size_t i;

    for(i = 0; i < entry->config->meter_bands_num; i++) {
    	long long int now = time_msec();
        uint32_t rate;
        uint32_t burst_size;
        uint64_t tokens;
        rate = entry->config->bands[i]->rate * 1000;
        burst_size = entry->config->bands[i]->burst_size * 1000;
        tokens =  (now - entry->stats->band_stats[i]->last_fill) *
                rate  + entry->stats->band_stats[i]->tokens;
        entry->stats->band_stats[i]->last_fill = now;
        if (!(entry->config->flags & OFPMF_BURST)){
            if(entry->config->flags & OFPMF_KBPS && tokens >= 1){
		        entry->stats->band_stats[i]->tokens = MIN(tokens, rate);
            }
            else{
                if(tokens >= 1000) {
                    entry->stats->band_stats[i]->tokens = MIN(tokens, rate);
                }
            }
        }
        else {
            if(entry->config->flags & OFPMF_KBPS && tokens >= 1 ){
                    entry->stats->band_stats[i]->tokens = MIN(tokens,burst_size);
            }
            else {
                if(tokens >= 1000) {
                    entry->stats->band_stats[i]->tokens = MIN(tokens,burst_size);
                }
            }
        }
    }
}
