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
#include <stdbool.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "packet_handle_std.h"
#include "packet.h"
#include "packets.h"
#include "oflib/ofl-structs.h"
#include "openflow/openflow.h"
#include "compiler.h"

#include "lib/hash.h"
#include "oflib/oxm-match.h"

#include "nbee_link/nbee_link.h"

/* Resets all protocol fields to NULL */

void
packet_handle_std_validate(struct packet_handle_std *handle) {

    if(handle->valid)
        return;
    struct ofl_match_tlv * iter, *next;
    HMAP_FOR_EACH_SAFE(iter, next, struct ofl_match_tlv, hmap_node, &handle->match.match_fields){
        free(iter->value);
        free(iter);
    }
    ofl_structs_match_init(&handle->match);

    if (nblink_packet_parse(handle->pkt->buffer,&handle->match,
                            handle->proto) < 0)
        return;

    handle->valid = true;

    /* Add in_port value to the hash_map */
    ofl_structs_match_put32(&handle->match, OXM_OF_IN_PORT, handle->pkt->in_port);
    /*Add metadata value to the hash_map */
    ofl_structs_match_put64(&handle->match,  OXM_OF_METADATA, 0xffffffffffffffff);
    return;
}


struct packet_handle_std *
packet_handle_std_create(struct packet *pkt) {
	struct packet_handle_std *handle = xmalloc(sizeof(struct packet_handle_std));
	handle->proto = xmalloc(sizeof(struct protocols_std));
	handle->pkt = pkt;

	hmap_init(&handle->match.match_fields);

	handle->valid = false;
	packet_handle_std_validate(handle);

	return handle;
}

struct packet_handle_std *
packet_handle_std_clone(struct packet *pkt, struct packet_handle_std *handle UNUSED) {
    struct packet_handle_std *clone = xmalloc(sizeof(struct packet_handle_std));

    clone->pkt = pkt;
    clone->proto = xmalloc(sizeof(struct protocols_std));
    hmap_init(&clone->match.match_fields);
    clone->valid = false;
    // TODO Zoltan: if handle->valid, then match could be memcpy'd, and protocol
    //              could be offset
    packet_handle_std_validate(clone);

    return clone;
}

void
packet_handle_std_destroy(struct packet_handle_std *handle) {

    struct ofl_match_tlv * iter, *next;
    HMAP_FOR_EACH_SAFE(iter, next, struct ofl_match_tlv, hmap_node, &handle->match.match_fields){
        free(iter->value);
        free(iter);
    }
    free(handle->proto);
    hmap_destroy(&handle->match.match_fields);
    free(handle);
}

bool
packet_handle_std_is_ttl_valid(struct packet_handle_std *handle) {
    packet_handle_std_validate(handle);

    if (handle->proto->mpls != NULL) {
        uint32_t ttl = ntohl(handle->proto->mpls->fields) & MPLS_TTL_MASK;
        if (ttl <= 1) {
            return false;
        }
    }
    if (handle->proto->ipv4 != NULL) {
        if (handle->proto->ipv4->ip_ttl < 1) {
            return false;
        }
    }
    return true;
}

bool
packet_handle_std_is_fragment(struct packet_handle_std *handle) {
    packet_handle_std_validate(handle);

    return false;
    /*return ((handle->proto->ipv4 != NULL) &&
            IP_IS_FRAGMENT(handle->proto->ipv4->ip_frag_off));*/
}


bool
packet_handle_std_match(struct packet_handle_std *handle, struct ofl_match *match){

    if (!handle->valid){
        packet_handle_std_validate(handle);
        if (!handle->valid){
            return false;
        }
    }

    return packet_match(match ,&handle->match );
}



/* If pointer is not null, returns str; otherwise returns an empty string. */
static inline const char *
pstr(void *ptr, const char *str) {
    return (ptr == NULL) ? "" : str;
}

/* Prints the names of protocols that are available in the given protocol stack. */

static void
proto_print(FILE *stream, struct protocols_std *p) {
    fprintf(stream, "{%s%s%s%s%s%s%s%s%s}",
            pstr(p->eth, "eth"), pstr(p->vlan, ",vlan"), pstr(p->mpls, ",mpls"), pstr(p->ipv4, ",ipv4"),
            pstr(p->arp, ",arp"), pstr(p->tcp, ",tcp"), pstr(p->udp, ",udp"), pstr(p->sctp, ",sctp"),
            pstr(p->icmp, ",icmp"));
}

char *
packet_handle_std_to_string(struct packet_handle_std *handle) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    packet_handle_std_print(stream, handle);

    fclose(stream);
    return str;
}

void
packet_handle_std_print(FILE *stream, struct packet_handle_std *handle) {
    packet_handle_std_validate(handle);

    fprintf(stream, "{proto=");
    proto_print(stream, handle->proto);

    fprintf(stream, ", match=");
    ofl_structs_match_print(stream, (struct ofl_match_header *)(&handle->match), handle->pkt->dp->exp);
    fprintf(stream, "\"}");
}

