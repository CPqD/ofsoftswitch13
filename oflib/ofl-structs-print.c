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
 *
 */

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <math.h>
#include "oxm-match.h"
#include "openflow/openflow.h"
#include "openflow/beba-ext.h"

#include "ofl.h"
#include "ofl-actions.h"
#include "ofl-structs.h"
#include "ofl-print.h"
#include "ofl-packets.h"


#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

#define IP_FMT "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8

char *
ofl_structs_port_to_string(struct ofl_port const *port)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_port_print(stream, port);
    fclose(stream);
    return str;
}

void
ofl_structs_port_print(FILE *stream, struct ofl_port const *port)
{
    fprintf(stream, "{no=\"");
    ofl_port_print(stream, port->port_no);
    fprintf(stream, "\", hw_addr=\""ETH_ADDR_FMT"\", name=\"%s\", "
                          "config=\"0x%"PRIx32"\", state=\"0x%"PRIx32"\", curr=\"0x%"PRIx32"\", "
                          "adv=\"0x%"PRIx32"\", supp=\"0x%"PRIx32"\", peer=\"0x%"PRIx32"\", "
                          "curr_spd=\"%ukbps\", max_spd=\"%ukbps\"}",
                  ETH_ADDR_ARGS(port->hw_addr), port->name,
                  port->config, port->state, port->curr,
                  port->advertised, port->supported, port->peer,
                  port->curr_speed, port->max_speed);
}

char *
ofl_structs_instruction_to_string(struct ofl_instruction_header const *inst, struct ofl_exp const *exp)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_instruction_print(stream, inst, exp);
    fclose(stream);
    return str;
}


void
ofl_structs_instruction_print(FILE *stream, struct ofl_instruction_header const *inst, struct ofl_exp const *exp)
{
    ofl_instruction_type_print(stream, inst->type);

    switch(inst->type) {
        case (OFPIT_GOTO_TABLE): {
            struct ofl_instruction_goto_table *i = (struct ofl_instruction_goto_table*)inst;
            
            fprintf(stream, "{table=\"%u\"}", i->table_id);

            break;
        }
        case (OFPIT_WRITE_METADATA): {
            struct ofl_instruction_write_metadata *i = (struct ofl_instruction_write_metadata *)inst;

            fprintf(stream, "{meta=\"0x%"PRIx64"\", mask=\"0x%"PRIx64"\"}",
                          i->metadata, i->metadata_mask);

            break;
        }
        case (OFPIT_WRITE_ACTIONS):
        case (OFPIT_APPLY_ACTIONS): {
            struct ofl_instruction_actions *i = (struct ofl_instruction_actions *)inst;
            size_t j;

            fprintf(stream, "{acts=[");
            for(j=0; j<i->actions_num; j++) {
                ofl_action_print(stream, i->actions[j], exp);
                if (j < i->actions_num - 1) { fprintf(stream, ", "); }
            }
            fprintf(stream, "]}");

            break;
        }
        case (OFPIT_CLEAR_ACTIONS): {
            break;
        }
        case (OFPIT_METER):{
            struct ofl_instruction_meter *i = (struct ofl_instruction_meter *)inst;
            fprintf(stream, "{meter=\"%u\"}", i->meter_id);          
            break;
        }
        case (OFPIT_EXPERIMENTER): {
            if (exp == NULL || exp->inst == NULL || exp->inst->to_string == NULL) {
                struct ofl_instruction_experimenter *i = (struct ofl_instruction_experimenter *)inst;

                fprintf(stream, "{id=\"0x%"PRIx32"\"}", i->experimenter_id);
            } else {
                char *c = exp->inst->to_string(inst);
                fprintf(stream, "%s", c);
                free (c);
            }
            break;
        }
    }

}

char *
ofl_structs_match_to_string(struct ofl_match_header *match, struct ofl_exp const *exp)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_match_print(stream, match, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_match_print(FILE *stream, struct ofl_match_header *match, struct ofl_exp const *exp)
{

    switch (match->type) {
        case (OFPMT_OXM): {
            struct ofl_match *m = (struct ofl_match*) match;
            ofl_structs_oxm_match_print(stream, m);
            break;
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->to_string == NULL) {
                fprintf(stream, "?(%u)", match->type);
            } else {
                char *c = exp->match->to_string(match);
                fprintf(stream, "%s", c);
                free(c);
            }
        }
    }
}


char *
ofl_structs_oxm_match_to_string(struct ofl_match *m)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_structs_oxm_match_print(stream, m);
    fclose(stream);
    return str;
}


void
ofl_structs_oxm_match_print(FILE *stream, const struct ofl_match *omt)
{
	struct ofl_match_tlv   *f;
	int 					i;
	size_t 					size;
	
	if(omt->header.length > 4)
	    size = hmap_count(&omt->match_fields);
	else size = 0;
	
	fprintf(stream, "oxm{");
	if (size) {
		/* Iterate over all possible OXM fields in their natural order */
		for (i = 0; i<NUM_OXM_FIELDS; i++) {
			f = oxm_match_lookup(all_fields[i].header, omt);
			if (f != NULL) {
				/* Field present: print it */
				ofl_structs_oxm_tlv_print(stream, f);
				if (--size > 0) fprintf(stream, ", ");
			}
		}
	}
	else {
		fprintf(stream, "all match");
	}
	fprintf(stream, "}");
}


char *
ofl_structs_oxm_tlv_to_string(struct ofl_match_tlv *f)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_structs_oxm_tlv_print(stream, f);
    fclose(stream);
    return str;
}


void
ofl_structs_oxm_tlv_print(FILE *stream, struct ofl_match_tlv *f)
{
	uint16_t class = OXM_VENDOR(f->header);
	uint8_t field = OXM_FIELD(f->header);

	switch (class) {
		case(OFPXMC_OPENFLOW_BASIC):
			switch (field) {

				case OFPXMT_OFB_IN_PORT:
					fprintf(stream, "in_port=\"%d\"", *((uint32_t*) f->value));
					break;
				case OFPXMT_OFB_IN_PHY_PORT:
					fprintf(stream, "in_phy_port=\"%d\"", *((uint32_t*) f->value));
					break;
				case OFPXMT_OFB_VLAN_VID: {
					uint16_t v = *((uint16_t *) f->value);
					if (v == OFPVID_NONE)
						fprintf(stream, "vlan_vid= none");
					else if (v == OFPVID_PRESENT && OXM_HASMASK(f->header))
						fprintf(stream, "vlan_vid= any");
					else
						fprintf(stream, "vlan_vid=\"%d\"",v & VLAN_VID_MASK);
					break;
				}
				case OFPXMT_OFB_VLAN_PCP:
					fprintf(stream, "vlan_pcp=\"%d\"", *f->value & 0x7);
					break;
				case OFPXMT_OFB_ETH_TYPE:
					fprintf(stream, "eth_type=\"0x%x\"",  *((uint16_t *) f->value));
					break;
				case OFPXMT_OFB_TCP_SRC:
					fprintf(stream, "tcp_src=\"%d\"", *((uint16_t*) f->value));
					break;
				case OFPXMT_OFB_TCP_DST:
					fprintf(stream, "tcp_dst=\"%d\"", *((uint16_t*) f->value));
					break;
				case OFPXMT_OFB_UDP_SRC:
					fprintf(stream, "udp_src=\"%d\"", *((uint16_t*) f->value));
					break;
				case OFPXMT_OFB_UDP_DST:
					fprintf(stream, "udp_dst=\"%d\"", *((uint16_t*) f->value));
					break;
				case OFPXMT_OFB_SCTP_SRC:
					fprintf(stream, "sctp_src=\"%d\"", *((uint16_t*) f->value));
					break;
				case OFPXMT_OFB_SCTP_DST:
					fprintf(stream, "sctp_dst=\"%d\"", *((uint16_t*) f->value));
					break;
				case OFPXMT_OFB_ETH_SRC:
					fprintf(stream, "eth_src=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", eth_src_mask=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value + 6));
					}
					break;
				case OFPXMT_OFB_ETH_DST:
					fprintf(stream, "eth_dst=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", eth_dst_mask=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value + 6));
					}
					break;

				case  OFPXMT_OFB_TCP_FLAGS:
					fprintf(stream, "tcp_flags=\"0x%"PRIx16"\"", *((uint16_t*)(f->value)));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", tcp_flags_mask=\"0x%"PRIx16"\"", *((uint16_t*)(f->value + 2)));
					}
					break;

				case OFPXMT_OFB_IPV4_DST:
					fprintf(stream, "ipv4_dst=\""IP_FMT"\"", IP_ARGS(f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", ipv4_dst_mask=\""IP_FMT"\"", IP_ARGS(f->value + 4));
					}
					break;
				case OFPXMT_OFB_IPV4_SRC:
					fprintf(stream, "ipv4_src=\""IP_FMT"\"", IP_ARGS(f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", ipv4_src_mask=\""IP_FMT"\"", IP_ARGS(f->value + 4));
					}
					break;
				case OFPXMT_OFB_IP_PROTO:
					fprintf(stream, "ip_proto=\"%d\"", *f->value);
					break;
				case OFPXMT_OFB_IP_DSCP:
					fprintf(stream, "ip_dscp=\"%d\"", *f->value & 0x3f);
					break;
				case OFPXMT_OFB_IP_ECN:
					fprintf(stream, "ip_ecn=\"%d\"", *f->value & 0x3);
					break;
				case OFPXMT_OFB_ICMPV4_TYPE:
					fprintf(stream, "icmpv4_type= \"%d\"", *f->value);
					break;
				case OFPXMT_OFB_ICMPV4_CODE:
					fprintf(stream, "icmpv4_code=\"%d\"", *f->value);
					break;
				case OFPXMT_OFB_ARP_SHA:
					fprintf(stream, "arp_sha=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", arp_sha_mask=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value + 6));
					}
					break;
				case OFPXMT_OFB_ARP_THA:
					fprintf(stream, "arp_tha=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", arp_tha_mask=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value + 6));
					}
					break;
				case OFPXMT_OFB_ARP_SPA:
					fprintf(stream, "arp_spa=\""IP_FMT"\"", IP_ARGS(f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", arp_sha_mask=\""IP_FMT"\"", IP_ARGS(f->value + 4));
					}
					break;
				case OFPXMT_OFB_ARP_TPA:
					fprintf(stream, "arp_tpa=\""IP_FMT"\"", IP_ARGS(f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", arp_tpa_mask=\""IP_FMT"\"", IP_ARGS(f->value + 4));
					}
					break;
				case OFPXMT_OFB_ARP_OP:
					fprintf(stream, "arp_op=\"0x%x\"", *((uint16_t*) f->value));
					break;
				case OFPXMT_OFB_IPV6_SRC: {
					char addr_str[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, f->value, addr_str, INET6_ADDRSTRLEN);
					fprintf(stream, "nw_src_ipv6=\"%s\"", addr_str);
					if (OXM_HASMASK(f->header)) {
						inet_ntop(AF_INET6, f->value + 16, addr_str, INET6_ADDRSTRLEN);
						fprintf(stream, ", nw_src_ipv6_mask=\"%s\"", addr_str);
					}
					break;
				}
				case OFPXMT_OFB_IPV6_DST: {
					char addr_str[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, f->value, addr_str, INET6_ADDRSTRLEN);
					fprintf(stream, "nw_dst_ipv6=\"%s\"", addr_str);
					if (OXM_HASMASK(f->header)) {
						inet_ntop(AF_INET6, f->value + 16, addr_str, INET6_ADDRSTRLEN);
						fprintf(stream, ", nw_dst_ipv6_mask=\"%s\"", addr_str);
					}
					break;
				}
				case OFPXMT_OFB_IPV6_ND_TARGET: {
					char addr_str[INET6_ADDRSTRLEN];
					inet_ntop(AF_INET6, f->value, addr_str, INET6_ADDRSTRLEN);
					fprintf(stream, "ipv6_nd_target=\"%s\"", addr_str);
					break;
				}
				case OFPXMT_OFB_IPV6_ND_SLL:
					fprintf(stream, "ipv6_nd_sll=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value));
					break;
				case OFPXMT_OFB_IPV6_ND_TLL:
					fprintf(stream, "ipv6_nd_tll=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(f->value));
					break;
				case OFPXMT_OFB_IPV6_FLABEL:
					fprintf(stream, "ipv6_flow_label=\"%d\"", *((uint32_t*) f->value) & 0x000fffff);
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", ipv6_flow_label_mask=\"%d\"", *((uint32_t*) (f->value+4)));
					}
					break;
				case OFPXMT_OFB_ICMPV6_TYPE:
					fprintf(stream, "icmpv6_type=\"%d\"", *f->value);
					break;
				case OFPXMT_OFB_ICMPV6_CODE:
					fprintf(stream, "icmpv6_code=\"%d\"", *f->value);
					break;
				case OFPXMT_OFB_MPLS_LABEL:
					fprintf(stream, "mpls_label=\"%d\"",((uint32_t) *f->value) & 0x000fffff);
					break;
				case OFPXMT_OFB_MPLS_TC:
					fprintf(stream, "mpls_tc=\"%d\"", *f->value & 0x3);
					break;
				case OFPXMT_OFB_MPLS_BOS:
					fprintf(stream, "mpls_bos=\"%d\"", *f->value & 0x1);
					break;
				case OFPXMT_OFB_METADATA:
					fprintf(stream, "metadata=\"0x%"PRIx64"\"", *((uint64_t*) f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", metadata_mask=\"0x%"PRIx64"\"", *((uint64_t*)(f->value+8)));
					}
					break;
				case OFPXMT_OFB_PBB_ISID   :
					fprintf(stream, "pbb_isid=\"%x%x%x\"", f->value[0],f->value[1], f->value[2]);
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", pbb_isid_mask=\"%x%x%x\"", (f->value+4)[0], (f->value+4)[1], (f->value+4)[2]);
					}
					break;
				case OFPXMT_OFB_TUNNEL_ID:
					fprintf(stream, "tunnel_id=\"%"PRIu64"\"", *((uint64_t*) f->value));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", tunnel_id_mask=\"%"PRIu64"\"", *((uint64_t*)(f->value+8)));
					}
					break;
				case OFPXMT_OFB_IPV6_EXTHDR:
					fprintf(stream, "ext_hdr=\"");
					ofl_ipv6_ext_hdr_print(stream, *((uint16_t*) f->value));
					fprintf(stream, "\"");
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ", ext_hdr_mask=\"0x%x\"", *((uint16_t*)(f->value+4)));
					}
					break;
		                        
		        default:
					fprintf(stream, "unknown type %d", field);					
				
				}
				break;


        case(OFPXMC_EXPERIMENTER):
        	switch (field) {
	        	case OFPXMT_EXP_STATE:
		        	fprintf(stream, "state=\"%"PRIu32"\"", *((uint32_t*)(f->value + EXP_ID_LEN)));
					if (OXM_HASMASK(f->header)) {
						fprintf(stream, ",state_mask=\"%"PRIu32"\"", *((uint32_t*)(f->value + EXP_ID_LEN + 4)));
					}
		 			break;

				case OFPXMT_EXP_GLOBAL_STATE:
					fprintf(stream, "global_state=");
					if (!OXM_HASMASK(f->header)) {
						char string_value[33];
			            masked_value_print(string_value,decimal_to_binary(*((uint32_t*) (f->value + EXP_ID_LEN))),decimal_to_binary((uint32_t)(pow(2,32)-1)));
			            fprintf(stream,"%s",string_value);
					} else {
						char string_value[33];
			            masked_value_print(string_value,decimal_to_binary(*((uint32_t*) (f->value + EXP_ID_LEN))),decimal_to_binary(*((uint32_t*)(f->value + EXP_ID_LEN + 4))));
			            fprintf(stream,"%s",string_value);
			        }
					break;
	
				default:
					fprintf(stream, "unknown type %d", field);
			}
			break;
		default:
			fprintf(stream, "unknown vendor %"PRIu16"", class);	
	}
}


char *
ofl_structs_config_to_string(struct ofl_config *c)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_config_print(stream, c);
    fclose(stream);
    return str;
}

void
ofl_structs_config_print(FILE *stream, struct ofl_config *c)
{
    fprintf(stream, "{flags=\"0x%"PRIx16"\", mlen=\"%u\"}",
                  c->flags, c->miss_send_len);
}

char *
ofl_structs_bucket_to_string(struct ofl_bucket *b, struct ofl_exp const *exp)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_bucket_print(stream, b, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_bucket_print(FILE *stream, struct ofl_bucket *b, struct ofl_exp const *exp)
{
    size_t i;

    fprintf(stream, "{w=\"%u\", wprt=\"", b->weight);
    ofl_port_print(stream, b->watch_port);
    fprintf(stream, "\", wgrp=\"");
    ofl_group_print(stream, b->watch_group);
    fprintf(stream, "\", acts=[");

    for (i=0; i<b->actions_num; i++) {
        ofl_action_print(stream, b->actions[i], exp);
        if (i < b->actions_num - 1) { fprintf(stream, ", "); }
    }

    fprintf(stream, "]}");
}

char *
ofl_structs_queue_to_string(struct ofl_packet_queue *q)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_queue_print(stream, q);
    fclose(stream);
    return str;
}

void
ofl_structs_queue_print(FILE *stream, struct ofl_packet_queue *q)
{
    size_t i;

    fprintf(stream, "{q=\"");
    ofl_queue_print(stream, q->queue_id);
    fprintf(stream, "\", props=[");

    for (i=0; i<q->properties_num; i++) {
        ofl_structs_queue_prop_print(stream, q->properties[i]);
        if (i < q->properties_num - 1) { fprintf(stream, ", "); }
    }

    fprintf(stream, "]}");
}

char *
ofl_structs_queue_prop_to_string(struct ofl_queue_prop_header *p)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_queue_prop_print(stream, p);
    fclose(stream);
    return str;
}

void
ofl_structs_queue_prop_print(FILE *stream, struct ofl_queue_prop_header *p)
{
    ofl_queue_prop_type_print(stream, p->type);

    switch(p->type) {
        case (OFPQT_MIN_RATE): {
            struct ofl_queue_prop_min_rate *pm = (struct ofl_queue_prop_min_rate *)p;

            fprintf(stream, "{rate=\"%u\"}", pm->rate);
            break;
        }
        case (OFPQT_MAX_RATE): {
        	break;
        }
        case (OFPQT_EXPERIMENTER): {
        	break;
        }
    }
}

char *
ofl_structs_flow_stats_to_string(struct ofl_flow_stats *s, struct ofl_exp const *exp)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_flow_stats_print(stream, s, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_flow_stats_print(FILE *stream, struct ofl_flow_stats *s, struct ofl_exp const *exp)
{
    size_t i;
    if(ofl_colored_output())
    {
	    fprintf(stream, "{\x1B[31mtable\x1B[0m=\"");
	    ofl_table_print(stream, s->table_id);
	    fprintf(stream, "\", \x1B[31mmatch\x1B[0m=\"");
	    ofl_structs_match_print(stream, s->match, exp);
	    fprintf(stream, "\", dur_s=\"%u\", dur_ns=\"%u\", prio=\"%u\", "
	                          "idle_to=\"%u\", hard_to=\"%u\", cookie=\"0x%"PRIx64"\", "
	                          "pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\", \x1B[31minsts\x1B[0m=[",
	                  s->duration_sec, s->duration_nsec, s->priority,
	                  s->idle_timeout, s->hard_timeout, s->cookie,
	                  s->packet_count, s->byte_count);
	}

	else 
	{
		fprintf(stream, "{table=\"");
	    ofl_table_print(stream, s->table_id);
	    fprintf(stream, "\", match=\"");
	    ofl_structs_match_print(stream, s->match, exp);
	    fprintf(stream, "\", dur_s=\"%u\", dur_ns=\"%u\", prio=\"%u\", "
	                          "idle_to=\"%u\", hard_to=\"%u\", cookie=\"0x%"PRIx64"\", "
	                          "pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\", insts=[",
	                  s->duration_sec, s->duration_nsec, s->priority,
	                  s->idle_timeout, s->hard_timeout, s->cookie,
	                  s->packet_count, s->byte_count);
	}

    for (i=0; i<s->instructions_num; i++) {
        ofl_structs_instruction_print(stream, s->instructions[i], exp);
        if (i < s->instructions_num - 1) { fprintf(stream, ", "); };
    }
    if (ofl_colored_output())
    	fprintf(stream, "]}");
}

char *
ofl_structs_bucket_counter_to_string(struct ofl_bucket_counter *s)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_bucket_counter_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_bucket_counter_print(FILE *stream, struct ofl_bucket_counter *c)
{
    if (ofl_colored_output()){
		fprintf(stream, "{\x1B[32mpkt_cnt\x1B[0m=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\"}",
                  c->packet_count, c->byte_count);
    }
    else
    {
		fprintf(stream, "{pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\"}",
                  c->packet_count, c->byte_count);
    }
}


char *
ofl_structs_group_stats_to_string(struct ofl_group_stats *s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_group_stats_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_group_stats_print(FILE *stream, struct ofl_group_stats *s)
{
    size_t i;
    if (ofl_colored_output())
    {
    	fprintf(stream, "{\x1B[31mgroup\x1B[0m=\"");
		ofl_group_print(stream, s->group_id);
		fprintf(stream, "\", ref_cnt=\"%u\", \x1B[36mpkt_cnt\x1B[0m=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\", cntrs=[",
		              s->ref_count, s->packet_count, s->byte_count);

    }
    else
    {
		fprintf(stream, "{group=\"");
		ofl_group_print(stream, s->group_id);
		fprintf(stream, "\", ref_cnt=\"%u\", pkt_cnt=\"%"PRIu64"\", byte_cnt=\"%"PRIu64"\", cntrs=[",
		              s->ref_count, s->packet_count, s->byte_count);
	}

    for (i=0; i<s->counters_num; i++) {
        ofl_structs_bucket_counter_print(stream, s->counters[i]);
        if (i < s->counters_num - 1) { fprintf(stream, ", "); };
    }

    if(ofl_colored_output())
    	fprintf(stream, "]}\n\n");
    else
    	fprintf(stream, "]}");
}


char*
ofl_structs_meter_band_to_string(struct ofl_meter_band_header* s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_meter_band_print(stream, s);
    fclose(stream);
    return str;

}


void
ofl_structs_meter_band_print(FILE *stream, struct ofl_meter_band_header* s)
{
    fprintf(stream, "{type = ");
    ofl_meter_band_type_print(stream, s->type);
    switch(s->type){
        case(OFPMBT_DROP):{
            struct ofl_meter_band_drop *d = (struct ofl_meter_band_drop*)s;
            fprintf(stream, ", rate=\"%"PRIu32"\", burst_size=\"%"PRIu32"\"}",
                  d->rate, d->burst_size);                    
            break;
        }
        case(OFPMBT_DSCP_REMARK):{
            struct ofl_meter_band_dscp_remark *d = (struct ofl_meter_band_dscp_remark*)s;
            fprintf(stream, ", rate=\"%"PRIu32"\", burst_size=\"%"PRIu32"\", prec_level=\"%u\"}",
                  d->rate, d->burst_size, d->prec_level);         
            break;
        }
        case(OFPMBT_EXPERIMENTER):{
            struct ofl_meter_band_experimenter *d = (struct ofl_meter_band_experimenter*)s;
            fprintf(stream, ", rate=\"%"PRIu32"\", burst_size=\"%"PRIu32"\", exp_id=\"%"PRIu32"\"}",
                  d->rate, d->burst_size, d->experimenter);           
            break;
        }
    }
}


char* 
ofl_structs_meter_band_stats_to_string(struct ofl_meter_band_stats* s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_meter_band_stats_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_meter_band_stats_print(FILE *stream, struct ofl_meter_band_stats* s)
{
    fprintf(stream, "{pkt_band_cnt=\"%"PRIu64"\", byte_band_cnt=\"%"PRIu64"\"}",
                  s->packet_band_count, s->byte_band_count);
}

char* 
ofl_structs_meter_stats_to_string(struct ofl_meter_stats* s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_meter_stats_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_meter_stats_print(FILE *stream, struct ofl_meter_stats* s)
{
    size_t i;

    fprintf(stream, "{meter= %x\"", s->meter_id);
    fprintf(stream, "\", flow_cnt=\"%u\", pkt_in_cnt=\"%"PRIu64"\", byte_in_cnt=\"%"PRIu64"\"" 
                    ", duration_sec=\"%"PRIu32"\", duration_nsec=\"%"PRIu32"\", bands=[",
                  s->flow_count, s->packet_in_count, s->byte_in_count, 
                  s->duration_sec, s->duration_nsec);
  
    for (i=0; i<s->meter_bands_num; i++) {
        ofl_structs_meter_band_stats_print(stream, s->band_stats[i]);
        if (i < s->meter_bands_num - 1) { fprintf(stream, ", "); };
    }

    fprintf(stream, "]}");                
}

char* 
ofl_structs_meter_config_to_string(struct ofl_meter_config* s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_meter_config_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_meter_config_print(FILE *stream, struct ofl_meter_config* s)
{
    size_t i;
    
    fprintf(stream, "{meter= %x\"", s->meter_id);
    fprintf(stream, "\", flags=\"%"PRIx16"\", bands=[",
                  s->flags);    

    for (i=0; i<s->meter_bands_num; i++) {
        ofl_structs_meter_band_print(stream, s->bands[i]);
        if (i < s->meter_bands_num - 1) { fprintf(stream, ", "); };
    }

    fprintf(stream, "]}"); 
}


char* 
ofl_structs_meter_features_to_string(struct ofl_meter_features* s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_meter_features_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_meter_features_print(FILE *stream, struct ofl_meter_features* s)
{
    
    fprintf(stream, "{max_meter=\"%"PRIu32"\", band_types=\"%"PRIx32"\","
            "capabilities =\"%"PRIx32"\", max_bands = %u , max_color = %u",  
                s->max_meter, s->band_types, s->capabilities, s->max_bands, s->max_color);
    fprintf(stream, "}"); 

}

char *
ofl_structs_table_stats_to_string(struct ofl_table_stats *s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_structs_table_stats_print(stream, s);

    fclose(stream);
    return str;
}

void
ofl_structs_table_stats_print(FILE *stream, struct ofl_table_stats *s)
{
    fprintf(stream, "{table=\"");
    ofl_table_print(stream, s->table_id);
    fprintf(stream, "\", active=\"%u\", "
                          "lookup=\"%"PRIu64"\", match=\"%"PRIu64"\"",
                  s->active_count,
                  s->lookup_count, s->matched_count);
}

char *
ofl_structs_table_properties_to_string(struct ofl_table_feature_prop_header *s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_table_properties_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_table_properties_print(FILE * stream, struct ofl_table_feature_prop_header* s)
{
    int i;    
    fprintf(stream, "{property=\"");
    ofl_properties_type_print(stream, s->type);
    switch(s->type){
        case OFPTFPT_INSTRUCTIONS:
        case OFPTFPT_INSTRUCTIONS_MISS:{
            struct ofl_table_feature_prop_instructions *insts = (struct ofl_table_feature_prop_instructions*) s; 
            fprintf(stream, "[");        
	    if(insts->ids_num) {
                for(i = 0; i < insts->ids_num -1; i++){
                    ofl_instruction_type_print(stream, insts->instruction_ids[i].type);
                    fprintf(stream, ", ");        
                }
                ofl_instruction_type_print(stream, insts->instruction_ids[insts->ids_num-1].type);
	    }
            fprintf(stream, "]");        
            break;
        }
        case OFPTFPT_NEXT_TABLES:
        case OFPTFPT_NEXT_TABLES_MISS:{
            struct ofl_table_feature_prop_next_tables *tbls = (struct ofl_table_feature_prop_next_tables*) s;
            fprintf(stream, "[");
	    if(tbls->table_num) {
                for(i = 0; i < tbls->table_num -1; i++){
                    fprintf(stream, "%d, ", tbls->next_table_ids[i]);
                }
                fprintf(stream, "%d]", tbls->next_table_ids[tbls->table_num -1]);
	    }
            break;
        }
        case OFPTFPT_APPLY_ACTIONS:
        case OFPTFPT_APPLY_ACTIONS_MISS:
        case OFPTFPT_WRITE_ACTIONS:
        case OFPTFPT_WRITE_ACTIONS_MISS:{
            struct ofl_table_feature_prop_actions *acts = (struct ofl_table_feature_prop_actions*) s;
            fprintf(stream, "[");
	    if(acts->actions_num) {
                for(i = 0; i < acts->actions_num -1; i++){
                    ofl_action_type_print(stream, acts->action_ids[i].type);
                    fprintf(stream, ", ");
                }
                ofl_action_type_print(stream, acts->action_ids[acts->actions_num-1].type);
	    }
            fprintf(stream, "]");                                    
            break;
        }
        case OFPTFPT_MATCH:
        case OFPTFPT_WILDCARDS:
        case OFPTFPT_APPLY_SETFIELD:
        case OFPTFPT_APPLY_SETFIELD_MISS:
        case OFPTFPT_WRITE_SETFIELD:
        case OFPTFPT_WRITE_SETFIELD_MISS:{
            struct ofl_table_feature_prop_oxm *oxms = (struct ofl_table_feature_prop_oxm*) s;
            fprintf(stream, "[");
	    if(oxms->oxm_num) {
                for(i = 0; i < oxms->oxm_num -1; i++){
                    ofl_oxm_type_print(stream, oxms->oxm_ids[i]);
                    fprintf(stream, ", " );
                }
                ofl_oxm_type_print(stream, oxms->oxm_ids[oxms->oxm_num -1]);
	    }
            fprintf(stream, "]");                                    
            break;
        }
        
        
    }
    fprintf(stream, "\"} ");
}

char *
ofl_structs_table_features_to_string(struct ofl_table_features *s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_table_features_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_table_features_print(FILE *stream, struct ofl_table_features *s)
{
    int i;
    fprintf(stream, "{table=\"");
    ofl_table_print(stream, s->table_id);  
    fprintf(stream, "\", name=\"%s\", "
                          "metadata_match=\"%"PRIx64"\", metadata_write=\"%"PRIx64"\", config=\"%"PRIu32"\"," 
                          "max_entries=\"%"PRIu32"\"",
                  s->name, s->metadata_match, s->metadata_write, s->config, s->max_entries);      
    for(i =0; i < s->properties_num; i++){
        ofl_structs_table_properties_print(stream, s->properties[i]);    
    }    
}

char *
ofl_structs_port_stats_to_string(struct ofl_port_stats *s)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_port_stats_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_port_stats_print(FILE *stream, struct ofl_port_stats *s)
{

    fprintf(stream, "{port=\"");
    ofl_port_print(stream, s->port_no);
    fprintf(stream, "\", rx_pkt=\"%"PRIu64"\", tx_pkt=\"%"PRIu64"\", "
                          "rx_bytes=\"%"PRIu64"\", tx_bytes=\"%"PRIu64"\", "
                          "rx_drops=\"%"PRIu64"\", tx_drops=\"%"PRIu64"\", "
                          "rx_errs=\"%"PRIu64"\", tx_errs=\"%"PRIu64"\", "
                          "rx_frm=\"%"PRIu64"\", rx_over=\"%"PRIu64"\", "
                          "rx_crc=\"%"PRIu64"\", coll=\"%"PRIu64"\"}",
                  s->rx_packets, s->tx_packets,
                  s->rx_bytes, s->tx_bytes,
                  s->rx_dropped, s->tx_dropped,
                  s->rx_errors, s->tx_errors,
                  s->rx_frame_err, s->rx_over_err,
                  s->rx_crc_err, s->collisions);
};

char *
ofl_structs_queue_stats_to_string(struct ofl_queue_stats *s)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_queue_stats_print(stream, s);
    fclose(stream);
    return str;
}

void
ofl_structs_queue_stats_print(FILE *stream, struct ofl_queue_stats *s)
{

    fprintf(stream, "{port=\"");
    ofl_port_print(stream, s->port_no);
    fprintf(stream, "\", q=\"");
    ofl_queue_print(stream, s->queue_id);
    fprintf(stream, "\", tx_bytes=\"%"PRIu64"\", "
                          "tx_pkt=\"%"PRIu64"\", tx_err=\"%"PRIu64"\"}",
                  s->tx_bytes, s->tx_packets, s->tx_errors);
};

char *
ofl_structs_group_desc_stats_to_string(struct ofl_group_desc_stats *s, struct ofl_exp const *exp)
{
        char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_group_desc_stats_print(stream, s, exp);
    fclose(stream);
    return str;
}

void
ofl_structs_group_desc_stats_print(FILE *stream, struct ofl_group_desc_stats *s, struct ofl_exp const *exp)
{
    size_t i;

    fprintf(stream, "{type=\"");
    ofl_group_type_print(stream, s->type);
    if(ofl_colored_output())
    {
    	fprintf(stream, "\", \x1B[31mgroup\x1B[0m=\"");
    	ofl_group_print(stream, s->group_id);
    	fprintf(stream, "\", buckets=[\n\n");
    }
    else
    {
    	fprintf(stream, "\", group=\"");
    	ofl_group_print(stream, s->group_id);
    	fprintf(stream, "\", buckets=[");
    }

    for (i=0; i<s->buckets_num; i++) {
        ofl_structs_bucket_print(stream, s->buckets[i], exp);
        if (i < s->buckets_num - 1) {
        	if(ofl_colored_output())
                fprintf(stream, ",\n\n");
            else
                fprintf(stream, ", "); };
    }

    if(ofl_colored_output())
    	fprintf(stream, "]}\n\n");
    else
    	fprintf(stream, "]}");
}


char *
ofl_structs_async_config_to_string(struct ofl_async_config *s)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_structs_async_config_print(stream, s);
    fclose(stream);
    return str;
}


void
ofl_structs_async_config_print(FILE * stream, struct ofl_async_config *s)
{
    fprintf(stream, "{equal=[");
    ofl_async_packet_in(stream, s->packet_in_mask[0]);
    ofl_async_port_status(stream, s->port_status_mask[0]);
    ofl_async_flow_removed(stream, s->flow_removed_mask[0]);
    fprintf(stream, "], ");    
    fprintf(stream, "slave=[");
    ofl_async_packet_in(stream, s->packet_in_mask[1]);
    ofl_async_port_status(stream, s->port_status_mask[1]);
    ofl_async_flow_removed(stream, s->flow_removed_mask[1]);
    fprintf(stream, "]}");        
}

