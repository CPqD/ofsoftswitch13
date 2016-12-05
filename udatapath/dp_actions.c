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
 * The code to recalculate the ip checksum when the ip tos is changed was taken from
 * ofss switch https://github.com/TrafficLab/ofss.
 * Credits: Zoltán Lajos Kis
 */

#include <netinet/in.h>
#include "csum.h"
#include "dp_exp.h"
#include "dp_actions.h"
#include "dp_buffers.h"
#include "datapath.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-log.h"
#include "packet.h"
#include "packets.h"
#include "pipeline.h"
#include "crc32.h"
#include "util.h"
#include "oflib/oxm-match.h"
#include "hash.h"

#define LOG_MODULE VLM_dp_acts

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

/* Note: if the packet has multiple match handlers, they must all be updated
 * or invalidated by the actions. Also if the buffer might be reallocated,
 * e.g. because of a push action, the action implementations must make sure
 * that any internal pointers of the handler structures are also updated, or
 * invalidated.
 */

/* Executes an output action. */
static void
output(struct packet *pkt, struct ofl_action_output *action) {
    pkt->out_port = action->port;

    if (action->port == OFPP_CONTROLLER) {
        pkt->out_port_max_len = action->max_len;
    }
}

/* Executes a set field action.
TODO: if we use the the index structure to the packet fields
revalidation is not needed  */

static void
set_field(struct packet *pkt, struct ofl_action_set_field *act )
{
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.valid)
    {
        /*Field existence is guaranteed by the
        field pre-requisite on matching */
        fprintf(stderr, "Header %d\n", OXM_FIELD(act->field->header));
        switch(act->field->header){
            case OXM_OF_ETH_DST:{
                memcpy(pkt->handle_std.proto.eth->eth_dst,
                    act->field->value, OXM_LENGTH(act->field->header));
                break;
            }
            case OXM_OF_ETH_SRC:{
                memcpy(pkt->handle_std.proto.eth->eth_src,
                    act->field->value, OXM_LENGTH(act->field->header));
                break;
            }
            case OXM_OF_ETH_TYPE:{
                uint16_t v = *((uint16_t*) act->field->value);
                pkt->handle_std.proto.eth->eth_type = htons(v);
                break;
            }
            case OXM_OF_VLAN_VID:{
                struct vlan_header *vlan =  pkt->handle_std.proto.vlan;
                /* VLAN existence is no guaranteed by match prerquisite*/
                if(vlan != NULL){
                    uint16_t v = (*(uint16_t*)act->field->value);
                    vlan->vlan_tci = htons((ntohs(vlan->vlan_tci) & ~VLAN_VID_MASK) | (v & VLAN_VID_MASK));
                }
                break;
            }
            case OXM_OF_VLAN_PCP:{
                struct vlan_header *vlan = pkt->handle_std.proto.vlan;
                /* VLAN existence is no guaranteed by match prerquisite*/
                if(vlan != NULL){
                    vlan->vlan_tci = (vlan->vlan_tci & ~htons(VLAN_PCP_MASK))
                                    | htons(*act->field->value << VLAN_PCP_SHIFT);
                    break;
                }
            }
            case OXM_OF_IP_DSCP:{
                if (pkt->handle_std.proto.ipv4){
                    struct ip_header *ipv4 =  pkt->handle_std.proto.ipv4;
                    uint8_t tos = (ipv4->ip_tos & ~IP_DSCP_MASK) |
                                   (*act->field->value << 2);
                    uint16_t old_val = htons((ipv4->ip_ihl_ver << 8) + ipv4->ip_tos);
                    uint16_t new_val = htons((ipv4->ip_ihl_ver << 8) + tos);
                    ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
                    ipv4->ip_tos = tos;
                }
                else if (pkt->handle_std.proto.ipv6){
                    struct ipv6_header *ipv6 =  pkt->handle_std.proto.ipv6;
                    uint32_t ipv6_ver_tc_fl = (ipv6->ipv6_ver_tc_fl & ~htonl(IPV6_DSCP_MASK)) |
                                   htonl((((uint32_t) *act->field->value) << IPV6_DSCP_SHIFT));
                    ipv6->ipv6_ver_tc_fl = ipv6_ver_tc_fl;
                }
                break;
            }
            case OXM_OF_IP_ECN:{
                if (pkt->handle_std.proto.ipv4){
                    struct ip_header *ipv4 =  pkt->handle_std.proto.ipv4;
                    uint8_t tos = (ipv4->ip_tos & ~IP_ECN_MASK) |
                               (*act->field->value & IP_ECN_MASK);
                    uint16_t old_val = htons((ipv4->ip_ihl_ver << 8) + ipv4->ip_tos);
                    uint16_t new_val = htons((ipv4->ip_ihl_ver << 8) + tos);
                    ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
                    ipv4->ip_tos = tos;
                }
                else if (pkt->handle_std.proto.ipv6){
                     struct ipv6_header *ipv6 =  pkt->handle_std.proto.ipv6;
                     uint32_t ipv6_ver_tc_fl = (ipv6->ipv6_ver_tc_fl & ~htonl(IPV6_ECN_MASK)) |
                                   htonl((((uint32_t) *act->field->value) << IPV6_ECN_SHIFT));
                    ipv6->ipv6_ver_tc_fl = ipv6_ver_tc_fl;
                }
                break;
            }
            case OXM_OF_IP_PROTO:{
                struct ip_header *ipv4 =  pkt->handle_std.proto.ipv4;
                uint16_t new_val, old_val;
                uint8_t proto = *act->field->value;
                old_val = htons((ipv4->ip_ttl << 8) + ipv4->ip_proto);
                new_val =  htons((ipv4->ip_ttl << 8) + proto);
                ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
                ipv4->ip_proto = proto;
                break;
            }
            case OXM_OF_IPV4_SRC:{
                struct ip_header *ipv4 = pkt->handle_std.proto.ipv4;

                /*Reconstruct TCP or UDP checksum*/
                if (pkt->handle_std.proto.tcp != NULL) {
                    struct tcp_header *tcp = pkt->handle_std.proto.tcp;
                    tcp->tcp_csum = recalc_csum32(tcp->tcp_csum,
                        ipv4->ip_src, *((uint32_t*) act->field->value));
                } else if (pkt->handle_std.proto.udp != NULL) {
                    struct udp_header *udp = pkt->handle_std.proto.udp;
                    udp->udp_csum = recalc_csum32(udp->udp_csum,
                        ipv4->ip_src, *((uint32_t*) act->field->value));
                }

                ipv4->ip_csum = recalc_csum32(ipv4->ip_csum, ipv4->ip_src,
                                     *((uint32_t*) act->field->value));

                ipv4->ip_src = *((uint32_t*) act->field->value);
                break;
            }
            case OXM_OF_IPV4_DST:{
                struct ip_header *ipv4 = pkt->handle_std.proto.ipv4;

                /*Reconstruct TCP or UDP checksum*/
                if (pkt->handle_std.proto.tcp != NULL) {
                    struct tcp_header *tcp = pkt->handle_std.proto.tcp;
                    tcp->tcp_csum = recalc_csum32(tcp->tcp_csum,
                        ipv4->ip_dst, *((uint32_t*) act->field->value));
                } else if (pkt->handle_std.proto.udp != NULL) {
                    struct udp_header *udp = pkt->handle_std.proto.udp;
                    udp->udp_csum = recalc_csum32(udp->udp_csum,
                        ipv4->ip_dst, *((uint32_t*) act->field->value));
                }

                ipv4->ip_csum = recalc_csum32(ipv4->ip_csum, ipv4->ip_dst,
                                    *((uint32_t*) act->field->value));

                ipv4->ip_dst = *((uint32_t*) act->field->value);
                break;
            }
            case OXM_OF_TCP_SRC:{
                struct tcp_header *tcp = pkt->handle_std.proto.tcp;
                uint16_t v = htons(*(uint16_t*) act->field->value);
                tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, tcp->tcp_src, v);
                tcp->tcp_src = v;
                break;
            }
            case OXM_OF_TCP_DST:{
                struct tcp_header *tcp = pkt->handle_std.proto.tcp;
                uint16_t v = htons(*(uint16_t*) act->field->value);
                tcp->tcp_csum = recalc_csum16(tcp->tcp_csum, tcp->tcp_dst, v);
                tcp->tcp_dst = v;
                break;
            }
            case OXM_OF_UDP_SRC:{
                struct udp_header *udp = pkt->handle_std.proto.udp;
                uint16_t v = htons(*(uint16_t*) act->field->value);
                udp->udp_csum = recalc_csum16(udp->udp_csum, udp->udp_src, v);
                udp->udp_src = v;
                break;
            }
            case OXM_OF_UDP_DST:{
                struct udp_header *udp = pkt->handle_std.proto.udp;
                uint16_t v = htons(*(uint16_t*) act->field->value);
                udp->udp_csum = recalc_csum16(udp->udp_csum, udp->udp_dst, v);
                udp->udp_dst = v;
                break;
            }
            /*TODO recalculate SCTP checksum*/
            case OXM_OF_SCTP_SRC:{
                crc_t crc;
                struct sctp_header *sctp = pkt->handle_std.proto.sctp;
                size_t len = ((uint8_t*) ofpbuf_tail(pkt->handle_std.pkt->buffer)) - (uint8_t *) sctp;
                uint16_t v = htons(*(uint16_t*) act->field->value);
                sctp->sctp_csum = 0;
                sctp->sctp_src = v;
                crc = crc_init();
                crc = crc_update(crc, (unsigned char*)sctp, len);
                crc = crc_finalize(crc);
                sctp->sctp_csum = crc;
                break;
            }
            case OXM_OF_SCTP_DST:{
                crc_t crc;
                struct sctp_header *sctp = pkt->handle_std.proto.sctp;
                size_t len = ((uint8_t*) ofpbuf_tail(pkt->handle_std.pkt->buffer)) - (uint8_t *) sctp;
                uint16_t v = htons(*(uint16_t*) act->field->value);
                sctp->sctp_csum = 0;
                sctp->sctp_dst = v;
                crc = crc_init();
                crc = crc_update(crc, (unsigned char*)sctp, len);
                crc = crc_finalize(crc);
                sctp->sctp_csum = crc;
                break;
            }
            case OXM_OF_ICMPV4_TYPE:
            case OXM_OF_ICMPV6_TYPE:{
                    struct icmp_header *icmp_header =  pkt->handle_std.proto.icmp;
                    uint16_t new_val, old_val;
                    uint8_t icmp_type = *act->field->value;
                    old_val = htons((icmp_header->icmp_type << 8) + icmp_header->icmp_code);
                    new_val =  htons((icmp_type << 8) + icmp_header->icmp_code);
                    icmp_header->icmp_csum = recalc_csum16(icmp_header->icmp_csum , old_val, new_val);
                    icmp_header->icmp_type = *act->field->value;
                break;
            }
            case OXM_OF_ICMPV4_CODE:
            case OXM_OF_ICMPV6_CODE:{
                    struct icmp_header *icmp_header =  pkt->handle_std.proto.icmp;
                    uint16_t new_val, old_val;
                    uint8_t icmp_code = *act->field->value;
                    old_val = htons((icmp_header->icmp_type << 8) + icmp_header->icmp_code);
                    new_val =  htons((icmp_header->icmp_type << 8) + icmp_code);
                    icmp_header->icmp_csum = recalc_csum16(icmp_header->icmp_csum , old_val, new_val);
                    icmp_header->icmp_code = *act->field->value;
                break;
            }
            case OXM_OF_ARP_OP: {
                pkt->handle_std.proto.arp->ar_op = htons(*((uint16_t*) act->field->value));
                break;
            }
            case OXM_OF_ARP_SPA:{
                pkt->handle_std.proto.arp->ar_spa = *((uint32_t*)
                                                            act->field->value);
                break;
            }
            case OXM_OF_ARP_TPA:{
                 pkt->handle_std.proto.arp->ar_tpa = *((uint32_t*)
                                                            act->field->value);
                 break;
            }
            case OXM_OF_ARP_SHA:{
                memcpy(pkt->handle_std.proto.arp->ar_sha,
                        act->field->value, OXM_LENGTH(act->field->header));
                break;
            }
            case OXM_OF_ARP_THA:{
                memcpy(pkt->handle_std.proto.arp->ar_tha,
                        act->field->value, OXM_LENGTH(act->field->header));
                break;
            }
            case OXM_OF_IPV6_SRC:{
                struct ipv6_header *ipv6 = pkt->handle_std.proto.ipv6;
                 /*Reconstruct TCP or UDP checksum*/
                if (pkt->handle_std.proto.tcp != NULL) {
                    struct tcp_header *tcp = pkt->handle_std.proto.tcp;
                    tcp->tcp_csum = recalc_csum128(tcp->tcp_csum,
                        ipv6->ipv6_src.s6_addr,  act->field->value);
                } else if (pkt->handle_std.proto.udp != NULL) {
                    struct udp_header *udp = pkt->handle_std.proto.udp;
                    udp->udp_csum = recalc_csum128(udp->udp_csum,
                        ipv6->ipv6_src.s6_addr, act->field->value);
                }
                memcpy(&pkt->handle_std.proto.ipv6->ipv6_src,
                        act->field->value, OXM_LENGTH(act->field->header));
                break;
            }
            case OXM_OF_IPV6_DST:{
                struct ipv6_header *ipv6 = pkt->handle_std.proto.ipv6;
                 /*Reconstruct TCP or UDP checksum*/
                if (pkt->handle_std.proto.tcp != NULL) {
                    struct tcp_header *tcp = pkt->handle_std.proto.tcp;
                    tcp->tcp_csum = recalc_csum128(tcp->tcp_csum,
                        ipv6->ipv6_dst.s6_addr,  act->field->value);
                } else if (pkt->handle_std.proto.udp != NULL) {
                    struct udp_header *udp = pkt->handle_std.proto.udp;
                    udp->udp_csum = recalc_csum128(udp->udp_csum,
                        ipv6->ipv6_dst.s6_addr, act->field->value);
                }
                memcpy(&pkt->handle_std.proto.ipv6->ipv6_dst,
                        act->field->value, OXM_LENGTH(act->field->header));

                break;
            }
            case OXM_OF_IPV6_FLABEL:{
                struct ipv6_header *ipv6 = (struct ipv6_header*)
                                            pkt->handle_std.proto.ipv6;
                uint32_t v = *((uint32_t*) act->field->value);
                ipv6->ipv6_ver_tc_fl  = (ipv6->ipv6_ver_tc_fl  &
                    ~ntohl(IPV6_FLABEL_MASK)) | ntohl(v & IPV6_FLABEL_MASK);
                break;
            }
            /*IPV6 Neighbor Discovery */
            case OXM_OF_IPV6_ND_TARGET:{
                struct icmp_header *icmp = pkt->handle_std.proto.icmp;
                uint8_t offset;
                uint8_t old_value[16];
                uint8_t *data = (uint8_t*)icmp;
                /*ICMP header + neighbor discovery header reserved bytes*/
                offset = sizeof(struct icmp_header) + 4;
                memcpy(old_value, data + offset, OXM_LENGTH(act->field->header));
                memcpy(data + offset, act->field->value,
                                            OXM_LENGTH(act->field->header));
                icmp->icmp_csum = recalc_csum128(icmp->icmp_csum,
                           old_value, act->field->value);
                break;
            }
            case OXM_OF_IPV6_ND_SLL:
            case OXM_OF_IPV6_ND_TLL:{
                struct icmp_header *icmp = pkt->handle_std.proto.icmp;
                uint8_t offset;
                uint32_t old_val32;
                uint32_t new_val32;
                uint16_t old_val16;
                uint16_t new_val16;
                struct ipv6_nd_options_hd *opt = (struct ipv6_nd_options_hd*)
                                        ((uint8_t*) icmp + sizeof(struct icmp_header) +
                                        sizeof(struct ipv6_nd_header));
                uint8_t *data = (uint8_t*) opt;
                /*ICMP header + neighbor discovery header reserved bytes*/
                offset = sizeof(struct ipv6_nd_options_hd);
                if(opt->type == ND_OPT_SLL || opt->type == ND_OPT_TLL){
                    old_val16 = *((uint16_t*) (data + offset));
                    old_val32 = *((uint32_t*) (data + offset + sizeof(uint16_t)));

                    memcpy(data + offset, act->field->value,
                                    OXM_LENGTH(act->field->header));
                    new_val16 = *((uint16_t*) (act->field->value));
                    new_val32 = *((uint32_t*) (act->field->value + sizeof(uint16_t)));
                    icmp->icmp_csum = recalc_csum16(icmp->icmp_csum, old_val16, new_val16);
                    icmp->icmp_csum = recalc_csum32(icmp->icmp_csum, old_val32, new_val32);
                }
                break;
            }
            case OXM_OF_MPLS_LABEL:{
                struct mpls_header *mpls = pkt->handle_std.proto.mpls;
                uint32_t v = *((uint32_t*) act->field->value);
                mpls->fields = (mpls->fields & ~ntohl(MPLS_LABEL_MASK)) |
                ntohl((v << MPLS_LABEL_SHIFT) & MPLS_LABEL_MASK);
                break;
            }
            case OXM_OF_MPLS_TC:{
                struct mpls_header *mpls = pkt->handle_std.proto.mpls;
                mpls->fields = (mpls->fields & ~ntohl(MPLS_TC_MASK))
                | ntohl((*act->field->value << MPLS_TC_SHIFT) & MPLS_TC_MASK);
                break;
            }
            case OXM_OF_MPLS_BOS:{
                struct mpls_header *mpls = pkt->handle_std.proto.mpls;
                mpls->fields = (mpls->fields & ~ntohl(MPLS_S_MASK))
                | ntohl((*act->field->value << MPLS_S_SHIFT) & MPLS_S_MASK);
                break;
            }
            case OXM_OF_PBB_ISID :{
                struct pbb_header *pbb = pkt->handle_std.proto.pbb;
                uint8_t* pbb_isid;
                pbb_isid = act->field->value;
                pbb->id = (pbb->id & 0xFF) | ((pbb_isid[2] << 24) | (pbb_isid[1] << 16) | (pbb_isid[1] << 8));
                break;
            }
            case OXM_OF_TUNNEL_ID :{
                struct  ofl_match_tlv *f;
                HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
                    hmap_node, hash_int(OXM_OF_TUNNEL_ID, 0), &(pkt)->handle_std.match.match_fields){
                    uint64_t *tunnel_id = (uint64_t*) f->value;
                    *tunnel_id = *((uint64_t*) act->field->value);
                }
                break;
            }
            default:
                VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to set unknow field.");
                break;
        }
        pkt->handle_std.valid = false;
        return;
    }

}

/* Executes copy ttl out action.*/
static void
copy_ttl_out(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std.proto.mpls;
        if ((ntohl(mpls->fields) & MPLS_S_MASK) == 0) {
            // There is an inner MPLS header
            struct mpls_header *in_mpls = (struct mpls_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);
            mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | (in_mpls->fields & htonl(MPLS_TTL_MASK));

        } else if (pkt->buffer->size >= ETH_HEADER_LEN + MPLS_HEADER_LEN +
            IP_HEADER_LEN || pkt->buffer->size >= ETH_HEADER_LEN +
            MPLS_HEADER_LEN + IPV6_HEADER_LEN) {
            // Assumes an IPv4 or Ipv6 header follows, if there is place for it
            uint8_t version = *((uint8_t *)mpls + MPLS_HEADER_LEN) >> 4;
            if (version == IPV4_VERSION){
                struct ip_header *ipv4 = (struct ip_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);
                mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | htonl((uint32_t)ipv4->ip_ttl & MPLS_TTL_MASK);
            }
            else if (version == IPV6_VERSION){
               struct ipv6_header *ipv6 = (struct ipv6_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);
               mpls->fields = (mpls->fields & ~htonl(MPLS_TTL_MASK)) | htonl((uint32_t)ipv6->ipv6_hop_limit & MPLS_TTL_MASK);
            }
        }
        else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute copy ttl in action on packet with only one mpls.");
        }
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute COPY_TTL_OUT action on packet with no mpls.");
    }
}

/* Executes copy ttl in action. */
static void
copy_ttl_in(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std.proto.mpls;

        if ((ntohl(mpls->fields) & MPLS_S_MASK) == 0) {
            // There is an inner MPLS header
            struct mpls_header *in_mpls = (struct mpls_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);

            in_mpls->fields = (in_mpls->fields & ~htonl(MPLS_TTL_MASK)) | (mpls->fields & htonl(MPLS_TTL_MASK));

        } else if (pkt->buffer->size >= ETH_HEADER_LEN + MPLS_HEADER_LEN +
            IP_HEADER_LEN || pkt->buffer->size >= ETH_HEADER_LEN +
            MPLS_HEADER_LEN + IPV6_HEADER_LEN) {
            // Assumes an IPv4 or Ipv6 header follows, if there is place for it
            uint8_t version = *((uint8_t *)mpls + MPLS_HEADER_LEN) >> 4;
            if (version == IPV4_VERSION){
                struct ip_header *ipv4 = (struct ip_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);
                uint8_t new_ttl = (ntohl(mpls->fields) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
                uint16_t old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
                uint16_t new_val = htons((ipv4->ip_proto) + (new_ttl<<8));
                ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
                ipv4->ip_ttl = new_ttl;
            }
            else if (version == IPV6_VERSION){
               struct ipv6_header *ipv6 = (struct ipv6_header *)((uint8_t *)mpls + MPLS_HEADER_LEN);
               uint8_t new_ttl = (ntohl(mpls->fields) & MPLS_TTL_MASK) >> MPLS_TTL_SHIFT;
                ipv6->ipv6_hop_limit = new_ttl;
            }
        }
        else {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute copy ttl in action on packet with only one mpls.");
        }
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute COPY_TTL_IN action on packet with no mpls.");
    }
}

/*Executes push vlan action. */
static void
push_vlan(struct packet *pkt, struct ofl_action_push *act) {
    // TODO Zoltan: if 802.3, check if new length is still valid
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.eth != NULL) {
        struct eth_header  *eth,  *new_eth;
        struct snap_header *snap, *new_snap;
        struct vlan_header *vlan, *new_vlan, *push_vlan;
        size_t eth_size;

        eth = pkt->handle_std.proto.eth;
        snap = pkt->handle_std.proto.eth_snap;
        vlan = pkt->handle_std.proto.vlan;

        eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

        if (ofpbuf_headroom(pkt->buffer) >= VLAN_HEADER_LEN) {
            // there is available space in headroom, move eth backwards
            pkt->buffer->data = (uint8_t *)(pkt->buffer->data) - VLAN_HEADER_LEN;
            pkt->buffer->size += VLAN_HEADER_LEN;

            memmove(pkt->buffer->data, eth, eth_size);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((uint8_t *)new_eth
                                        + ETH_HEADER_LEN + LLC_HEADER_LEN);
            push_vlan = (struct vlan_header *)((uint8_t *)new_eth + eth_size);
            new_vlan = vlan;
        } else {
            // not enough headroom, use tailroom of the packet

            // Note: ofpbuf_put_uninit might relocate the whole packet
            ofpbuf_put_uninit(pkt->buffer, VLAN_HEADER_LEN);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((uint8_t *)new_eth
                                        + ETH_HEADER_LEN + LLC_HEADER_LEN);
            push_vlan = (struct vlan_header *)((uint8_t *)new_eth + eth_size);

            // push data to create space for new vlan tag
            memmove((uint8_t *)push_vlan + VLAN_HEADER_LEN, push_vlan,
                    pkt->buffer->size - eth_size);

            new_vlan = vlan == NULL ? NULL
              : (struct vlan_header *)((uint8_t *)push_vlan + VLAN_HEADER_LEN);
        }

        push_vlan->vlan_tci = new_vlan == NULL ? 0x0000 : new_vlan->vlan_tci;

        if (new_snap != NULL) {
            push_vlan->vlan_next_type = new_snap->snap_type;
            new_snap->snap_type = ntohs(act->ethertype);
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + VLAN_HEADER_LEN);
        } else {
            push_vlan->vlan_next_type = new_eth->eth_type;
            new_eth->eth_type = ntohs(act->ethertype);
        }

        // TODO Zoltan: This could be faster if VLAN match is updated
        //              and proto pointers are shifted in case of realloc, ...
        pkt->handle_std.valid = false;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute push vlan action on packet with no eth.");
    }
}

/*Executes pop vlan action. */
static void
pop_vlan(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.eth != NULL && pkt->handle_std.proto.vlan != NULL) {
        struct eth_header *eth = pkt->handle_std.proto.eth;
        struct snap_header *eth_snap = pkt->handle_std.proto.eth_snap;
        struct vlan_header *vlan = pkt->handle_std.proto.vlan;
        size_t move_size;

        if (eth_snap != NULL) {
            eth_snap->snap_type = vlan->vlan_next_type;
            eth->eth_type = htons(ntohs(eth->eth_type) - VLAN_HEADER_LEN);
        } else {
            eth->eth_type = vlan->vlan_next_type;
        }

        move_size = (uint8_t *)vlan - (uint8_t *)eth;

        pkt->buffer->data = (uint8_t *)pkt->buffer->data + VLAN_HEADER_LEN;
        pkt->buffer->size -= VLAN_HEADER_LEN;

        memmove(pkt->buffer->data, eth, move_size);

        //TODO Zoltan: revalidating might not be necessary in all cases
        pkt->handle_std.valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_VLAN action on packet with no eth/vlan.");
    }
}


/*Executes set mpls ttl action.*/
static void
set_mpls_ttl(struct packet *pkt, struct ofl_action_mpls_ttl *act) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std.proto.mpls;

        mpls->fields = (mpls->fields & ~ntohl(MPLS_TTL_MASK)) | ntohl((act->mpls_ttl << MPLS_TTL_SHIFT) & MPLS_TTL_MASK);

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_MPLS_TTL action on packet with no mpls.");
    }
}

/*Executes dec mpls ttl action.*/
static void
dec_mpls_ttl(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.mpls != NULL) {
        struct mpls_header *mpls = pkt->handle_std.proto.mpls;

        uint32_t ttl = ntohl(mpls->fields) & MPLS_TTL_MASK;

        if (ttl > 0) { ttl--; }
        mpls->fields = (mpls->fields & ~ntohl(MPLS_TTL_MASK)) | htonl(ttl);

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute DEC_MPLS_TTL action on packet with no mpls.");
    }
}

/*Executes push mpls action. */
static void
push_mpls(struct packet *pkt, struct ofl_action_push *act) {
    // TODO Zoltan: if 802.3, check if new length is still valid
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.eth != NULL) {
        struct eth_header  *eth,  *new_eth;
        struct snap_header *snap, *new_snap;
        struct vlan_header *vlan, *new_vlan;
        struct mpls_header *mpls, *new_mpls, *push_mpls;
        struct ip_header *ipv4, *new_ipv4;
        struct ipv6_header *ipv6, *new_ipv6;
        size_t eth_size;
        size_t head_offset;

        eth = pkt->handle_std.proto.eth;
        snap = pkt->handle_std.proto.eth_snap;
        vlan = pkt->handle_std.proto.vlan_last;
        mpls = pkt->handle_std.proto.mpls;
        ipv4 = pkt->handle_std.proto.ipv4;
        ipv6 = pkt->handle_std.proto.ipv6;

        eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

        head_offset = vlan == NULL ? eth_size
              : (uint8_t *)vlan - (uint8_t *)eth + VLAN_HEADER_LEN;

        if (ofpbuf_headroom(pkt->buffer) >= MPLS_HEADER_LEN) {
            // there is available space in headroom, move eth backwards
            pkt->buffer->data = (uint8_t *)(pkt->buffer->data) - MPLS_HEADER_LEN;
            pkt->buffer->size += MPLS_HEADER_LEN;

            memmove(pkt->buffer->data, eth, head_offset);
            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                    : (struct snap_header *)((uint8_t *)snap - MPLS_HEADER_LEN);
            new_vlan = vlan == NULL ? NULL
                    : (struct vlan_header *)((uint8_t *)vlan - MPLS_HEADER_LEN);
            push_mpls = (struct mpls_header *)((uint8_t *)new_eth + head_offset);
            new_mpls = mpls;
            new_ipv4 = ipv4;
            new_ipv6 = ipv6;

        } else {
            // not enough headroom, use tailroom of the packet

            // Note: ofpbuf_put_uninit might relocate the whole packet
            ofpbuf_put_uninit(pkt->buffer, MPLS_HEADER_LEN);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                    : (struct snap_header *)((uint8_t *)snap - (uint8_t *)eth + (uint8_t *)new_eth);
            new_vlan = vlan == NULL ? NULL
                    : (struct vlan_header *)((uint8_t *)vlan - (uint8_t *)eth + (uint8_t *)new_eth);
            push_mpls = (struct mpls_header *)((uint8_t *)new_eth + head_offset);

            // push data to create space for new MPLS
            memmove((uint8_t *)push_mpls + MPLS_HEADER_LEN, push_mpls,
                    pkt->buffer->size - head_offset);

            new_mpls = mpls == NULL ? NULL
                    : (struct mpls_header *)((uint8_t *)push_mpls + MPLS_HEADER_LEN);
            // Note: if ipv4 was not null, then there was no MPLS header in 1.1
            new_ipv4 = ipv4 == NULL ? NULL
                    : (struct ip_header *)((uint8_t *)push_mpls + MPLS_HEADER_LEN);
            new_ipv6 = ipv6 == NULL ? NULL
                    : (struct ipv6_header *)((uint8_t *)push_mpls + MPLS_HEADER_LEN);
        }

        if (new_mpls != NULL) {
            push_mpls->fields = new_mpls->fields & ~htonl(MPLS_S_MASK);
        } else if (new_ipv4 != NULL) {
            // copy IP TTL to MPLS TTL (rest is zero), and set S bit
            push_mpls->fields = htonl((uint32_t)new_ipv4->ip_ttl & MPLS_TTL_MASK) | htonl(MPLS_S_MASK);
        } else if (new_ipv6 != NULL) {
            // copy IP HOP LIMIT to MPLS TTL (rest is zero), and set S bit
            push_mpls->fields = htonl((uint32_t)new_ipv6->ipv6_hop_limit & MPLS_TTL_MASK) | htonl(MPLS_S_MASK);
        } else {
            push_mpls->fields = htonl(MPLS_S_MASK);
        }

        if (new_vlan != NULL) {
            new_vlan->vlan_next_type = htons(act->ethertype);
        } else if (new_snap != NULL) {
            new_snap->snap_type = htons(act->ethertype);
        } else {
            new_eth->eth_type = htons(act->ethertype);
        }

        if (new_snap != NULL) {
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + MPLS_HEADER_LEN);
        }

        // in 1.1 all proto but eth and mpls will be hidden,
        // so revalidating won't be a tedious work (probably)
        pkt->handle_std.valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute PUSH_MPLS action on packet with no eth.");
    }
}

/* Executes pop mpls action. */
static void
pop_mpls(struct packet *pkt, struct ofl_action_pop_mpls *act) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.eth != NULL && pkt->handle_std.proto.mpls != NULL) {
        struct eth_header *eth = pkt->handle_std.proto.eth;
        struct snap_header *snap = pkt->handle_std.proto.eth_snap;
        struct vlan_header *vlan_last = pkt->handle_std.proto.vlan_last;
        struct mpls_header *mpls = pkt->handle_std.proto.mpls;
        size_t move_size;

        if (vlan_last != NULL) {
            vlan_last->vlan_next_type = htons(act->ethertype);
        } else if (snap != NULL) {
            snap->snap_type = htons(act->ethertype);
        } else {
            eth->eth_type = htons(act->ethertype);
        }

        move_size = (uint8_t *)mpls - (uint8_t *)eth;

        pkt->buffer->data = (uint8_t *)pkt->buffer->data + MPLS_HEADER_LEN;
        pkt->buffer->size -= MPLS_HEADER_LEN;

        memmove(pkt->buffer->data, eth, move_size);

        if (snap != NULL) {
            struct eth_header *new_eth = (struct eth_header *)(pkt->buffer->data);
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + MPLS_HEADER_LEN);
        }

        //TODO Zoltan: revalidating might not be necessary at all cases
        pkt->handle_std.valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_MPLS action on packet with no eth/mpls.");
    }
}

/*Executes push pbb action. */
static void
push_pbb(struct packet *pkt, struct ofl_action_push *act) {
    // TODO Zoltan: if 802.3, check if new length is still valid
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.eth != NULL) {
        struct eth_header  *eth,  *new_eth;
        struct snap_header *snap, *new_snap;
        struct pbb_header *pbb, *new_pbb, *push_pbb;
        struct vlan_header * vlan;
        size_t eth_size;

        eth = pkt->handle_std.proto.eth;
        snap = pkt->handle_std.proto.eth_snap;
        pbb = pkt->handle_std.proto.pbb;
        vlan = pkt->handle_std.proto.vlan;

        eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

        if (ofpbuf_headroom(pkt->buffer) >= PBB_HEADER_LEN) {
            // there is available space in headroom, move eth backwards
            pkt->buffer->data = (uint8_t *)(pkt->buffer->data) - PBB_HEADER_LEN;
            pkt->buffer->size += PBB_HEADER_LEN;

            memmove(pkt->buffer->data, eth, eth_size);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((uint8_t *)new_eth
                                        + ETH_HEADER_LEN + PBB_HEADER_LEN + LLC_HEADER_LEN);
            push_pbb = (struct pbb_header *)((uint8_t *)new_eth + eth_size);
            new_pbb = pbb;

        } else {
            // not enough headroom, use tailroom of the packet

            // Note: ofpbuf_put_uninit might relocate the whole packet
            ofpbuf_put_uninit(pkt->buffer, PBB_HEADER_LEN);

            new_eth = (struct eth_header *)(pkt->buffer->data);
            new_snap = snap == NULL ? NULL
                                   : (struct snap_header *)((uint8_t *)new_eth
                                        + ETH_HEADER_LEN + PBB_HEADER_LEN + LLC_HEADER_LEN);
            push_pbb = (struct pbb_header *)((uint8_t *)new_eth + ETH_HEADER_LEN);

            // push data to create space for new PBB
            memmove((uint8_t *)push_pbb + PBB_HEADER_LEN, push_pbb,
                    pkt->buffer->size - ETH_HEADER_LEN);

           new_pbb = pbb == NULL ? NULL
              : (struct pbb_header *)((uint8_t *)push_pbb + PBB_HEADER_LEN);
        }

        push_pbb->id = new_pbb == NULL ? 0x0000 : new_pbb->id;
        push_pbb->id = vlan == NULL
                       ? push_pbb->id
                       : push_pbb->id & (((uint32_t) (vlan->vlan_tci & ~htonl(VLAN_PCP_MASK)) )<< 16);
        memcpy(push_pbb->c_eth_dst,eth,ETH_HEADER_LEN);

        if (new_snap != NULL) {

            push_pbb->pbb_next_type = new_snap->snap_type;
            new_snap->snap_type = ntohs(act->ethertype);
            new_eth->eth_type = htons(ntohs(new_eth->eth_type) + PBB_HEADER_LEN);
        } else {
            push_pbb->pbb_next_type = new_eth->eth_type;
            new_eth->eth_type = ntohs(act->ethertype);
        }

        pkt->handle_std.valid = false;

    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute push pbb action on packet with no eth.");
    }
}


/*Executes pop pbb action. */
static void
pop_pbb(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.eth != NULL && pkt->handle_std.proto.pbb != NULL) {
        struct eth_header *eth = pkt->handle_std.proto.eth;
        struct pbb_header *pbb = pkt->handle_std.proto.pbb;
        size_t move_size;

        move_size = (uint8_t *) pbb->c_eth_dst - (uint8_t *)eth;

//        pkt->buffer->data = (uint8_t *)pkt->buffer->data + move_size;
//        eth = (uint8_t *)eth + move_size;
        memmove(pkt->buffer->data, pbb->c_eth_dst, (pkt->buffer->size - move_size));
        pkt->buffer->size -= move_size;

        pkt->handle_std.valid = false;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_PBB action on packet with no PBB header.");
    }
}


/* Executes set queue action. */
static void
set_queue(struct packet *pkt UNUSED, struct ofl_action_set_queue *act) {
    pkt->out_queue = act->queue_id;
}

/* Executes group action. */
static void
group(struct packet *pkt, struct ofl_action_group *act) {
    pkt->out_group = act->group_id;
}

/* Executes set nw ttl action.
TODO Set IPv6 hop limit*/
static void
set_nw_ttl(struct packet *pkt, struct ofl_action_set_nw_ttl *act) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.ipv4 != NULL) {
        struct ip_header *ipv4 = pkt->handle_std.proto.ipv4;

        uint16_t old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
        uint16_t new_val = htons((ipv4->ip_proto) + (act->nw_ttl<<8));
        ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
        ipv4->ip_ttl = act->nw_ttl;
    } else if (pkt->handle_std.proto.ipv6 != NULL){
       struct ipv6_header *ipv6 = pkt->handle_std.proto.ipv6;
       ipv6->ipv6_hop_limit = act->nw_ttl;
    }
    else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute SET_NW_TTL action on packet with no ipv4 or ipv6.");
    }
}

/* Executes dec nw ttl action.
TODO Dec IPv6 hop limit*/
static void
dec_nw_ttl(struct packet *pkt, struct ofl_action_header *act UNUSED) {
    packet_handle_std_validate(&pkt->handle_std);
    if (pkt->handle_std.proto.ipv4 != NULL) {

        struct ip_header *ipv4 = pkt->handle_std.proto.ipv4;

        if (ipv4->ip_ttl > 0) {
            uint8_t new_ttl = ipv4->ip_ttl - 1;
            uint16_t old_val = htons((ipv4->ip_proto) + (ipv4->ip_ttl<<8));
            uint16_t new_val = htons((ipv4->ip_proto) + (new_ttl<<8));
            ipv4->ip_csum = recalc_csum16(ipv4->ip_csum, old_val, new_val);
            ipv4->ip_ttl = new_ttl;
        }
    } else if (pkt->handle_std.proto.ipv6 != NULL){
        struct ipv6_header *ipv6 = pkt->handle_std.proto.ipv6;
        if (ipv6->ipv6_hop_limit > 0){
            --ipv6->ipv6_hop_limit;
       }
    }
    else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute DEC_NW_TTL action on packet with no ipv4.");
    }
}


void
dp_execute_action(struct packet *pkt,
               struct ofl_action_header *action) {

    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *a = ofl_action_to_string(action, pkt->dp->exp);
        VLOG_DBG_RL(LOG_MODULE, &rl, "executing action %s.", a);
        free(a);
    }

    switch (action->type) {
        case (OFPAT_SET_FIELD): {
            set_field(pkt,(struct ofl_action_set_field*) action);
            break;
        }
         case (OFPAT_OUTPUT): {
            output(pkt, (struct ofl_action_output *)action);
            break;
        }
        case (OFPAT_COPY_TTL_OUT): {
            copy_ttl_out(pkt, action);
            break;
        }
        case (OFPAT_COPY_TTL_IN): {
            copy_ttl_in(pkt, action);
            break;
        }
        case (OFPAT_SET_MPLS_TTL): {
            set_mpls_ttl(pkt, (struct ofl_action_mpls_ttl *)action);
            break;
        }
        case (OFPAT_DEC_MPLS_TTL): {
            dec_mpls_ttl(pkt, action);
            break;
        }
        case (OFPAT_PUSH_VLAN): {
            push_vlan(pkt, (struct ofl_action_push *)action);
            break;
        }
        case (OFPAT_POP_VLAN): {
            pop_vlan(pkt, action);
            break;
        }
        case (OFPAT_PUSH_MPLS): {
            push_mpls(pkt, (struct ofl_action_push *)action);
            break;
        }
        case (OFPAT_POP_MPLS): {
            pop_mpls(pkt, (struct ofl_action_pop_mpls *)action);
            break;
        }
        case (OFPAT_SET_QUEUE): {
            set_queue(pkt, (struct ofl_action_set_queue *)action);
            break;
        }
        case (OFPAT_GROUP): {
            group(pkt, (struct ofl_action_group *)action);
            break;
        }
        case (OFPAT_SET_NW_TTL): {
            set_nw_ttl(pkt, (struct ofl_action_set_nw_ttl *)action);
            break;
        }
        case (OFPAT_DEC_NW_TTL): {
            dec_nw_ttl(pkt, action);
            break;
        }
        case (OFPAT_PUSH_PBB):{
            push_pbb(pkt, (struct ofl_action_push*)action);
            break;
        }
        case (OFPAT_POP_PBB):{
            pop_pbb(pkt, action);
            break;
        }
        case (OFPAT_EXPERIMENTER): {
            dp_exp_action(pkt, (struct ofl_action_experimenter *)action);
            break;
        }

        default: {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown action type (%u).", action->type);
        }
    }
    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *p = packet_to_string(pkt);
        VLOG_DBG_RL(LOG_MODULE, &rl, "action result: %s", p);
        free(p);
    }

}



void
dp_execute_action_list(struct packet *pkt,
                size_t actions_num, struct ofl_action_header **actions, uint64_t cookie) {
    size_t i;

    VLOG_DBG_RL(LOG_MODULE, &rl, "Executing action list.");

    for (i=0; i < actions_num; i++) {
        dp_execute_action(pkt, actions[i]);

        if (pkt->out_group != OFPG_ANY) {
            struct packet *pkt_clone;
            uint32_t group = pkt->out_group;
            pkt->out_group = OFPG_ANY;
            VLOG_DBG_RL(LOG_MODULE, &rl, "Group action; executing group (%u).", group);
            /* The group must process a copy of the packet in the current state,
             * so that when we return we continue processing an unmodified
             * version of the packet. The group must also ignore the current
	     * action-set. We need to clone the packet with an empty
             * action-set. Jean II */
            pkt_clone = packet_clone(pkt);
            group_table_execute(pkt_clone->dp->groups, pkt_clone, group);

        } else if (pkt->out_port != OFPP_ANY) {
            uint32_t port = pkt->out_port;
            uint32_t queue = pkt->out_queue;
            uint16_t max_len = pkt->out_port_max_len;
            pkt->out_port = OFPP_ANY;
            pkt->out_port_max_len = 0;
            pkt->out_queue = 0;
            VLOG_DBG_RL(LOG_MODULE, &rl, "Port action; sending to port (%u).", port);
            dp_actions_output_port(pkt, port, queue, max_len, cookie);
        }

    }
}


void
dp_actions_output_port(struct packet *pkt, uint32_t out_port, uint32_t out_queue, uint16_t max_len, uint64_t cookie) {

    switch (out_port) {
        case (OFPP_TABLE): {
            if (pkt->packet_out) {
                // NOTE: hackish; makes sure packet cannot be resubmit to pipeline again.
                //       pipeline_process_packet takes overship of the packet, we need a copy.
                struct packet *pkt_copy = packet_clone(pkt);

                pkt_copy->packet_out = false;
                pipeline_process_packet(pkt->dp->pipeline, pkt_copy);
            } else {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to resubmit packet to pipeline.");
            }
            break;
        }
        case (OFPP_IN_PORT): {
            dp_ports_output(pkt->dp, pkt->buffer, pkt->in_port, 0);
            break;
        }
        case (OFPP_CONTROLLER): {
            struct ofl_msg_packet_in msg;
            msg.header.type = OFPT_PACKET_IN;
            msg.total_len   = pkt->buffer->size;
            msg.reason = pkt->handle_std.table_miss? OFPR_NO_MATCH:OFPR_ACTION;
            msg.table_id = pkt->table_id;
            msg.data        = pkt->buffer->data;
            msg.cookie = cookie;

            if (pkt->dp->config.miss_send_len != OFPCML_NO_BUFFER){
                dp_buffers_save(pkt->dp->buffers, pkt);
                msg.buffer_id = pkt->buffer_id;
                msg.data_length = MIN(max_len, pkt->buffer->size);
            }
            else {
                msg.buffer_id = OFP_NO_BUFFER;
                msg.data_length =  pkt->buffer->size;
            }

            if (!pkt->handle_std.valid){
                packet_handle_std_validate(&pkt->handle_std);
            }
            /* In this implementation the fields in_port and in_phy_port
                always will be the same, because we are not considering logical
                ports*/
            msg.match = (struct ofl_match_header*) &pkt->handle_std.match;
            dp_send_message(pkt->dp, (struct ofl_msg_header *)&msg, NULL);
            break;
        }
        case (OFPP_FLOOD):
        case (OFPP_ALL): {
            dp_ports_output_all(pkt->dp, pkt->buffer, pkt->in_port, out_port == OFPP_FLOOD);
            break;
        }
        case (OFPP_NORMAL):
            // TODO Zoltan: Implement
        case (OFPP_LOCAL):
        default: {
            if (pkt->in_port == out_port) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "can't directly forward to input port.");
            } else {
                VLOG_DBG_RL(LOG_MODULE, &rl, "Outputting packet on port %u.", out_port);
                dp_ports_output(pkt->dp, pkt->buffer, out_port, out_queue);
            }
        }
    }
}

bool
dp_actions_list_has_out_port(size_t actions_num, struct ofl_action_header **actions, uint32_t port) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_OUTPUT) {
            struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];
            if (ao->port == port) {
                return true;
            }
        }
    }
    return false;
}

bool
dp_actions_list_has_out_group(size_t actions_num, struct ofl_action_header **actions, uint32_t group) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_GROUP) {
            struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];
            if (ag->group_id == group) {
                return true;
            }
        }
    }
    return false;
}

ofl_err
dp_actions_validate(struct datapath *dp, size_t actions_num, struct ofl_action_header **actions) {
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_OUTPUT) {
            struct ofl_action_output *ao = (struct ofl_action_output *)actions[i];

            if (ao->port <= OFPP_MAX && dp_ports_lookup(dp, ao->port) == NULL) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Output action for invalid port (%u).", ao->port);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
            }
        }
        if (actions[i]->type == OFPAT_GROUP) {
            struct ofl_action_group *ag = (struct ofl_action_group *)actions[i];

            if (ag->group_id <= OFPG_MAX && group_table_find(dp->groups, ag->group_id) == NULL) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Group action for invalid group (%u).", ag->group_id);
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_GROUP);
            }
        }
    }

    return 0;
}

ofl_err
dp_actions_check_set_field_req(struct ofl_msg_flow_mod *msg, size_t actions_num, struct ofl_action_header **actions){
    size_t i;

    for (i=0; i < actions_num; i++) {
        if (actions[i]->type == OFPAT_SET_FIELD) {
            struct ofl_action_set_field *as = (struct ofl_action_set_field*)actions[i];
            struct oxm_field  *f;

            f = oxm_field_lookup(as->field->header);

            /*There is no match field, so the prerequisites are not present*/
            if (msg->match->length == 0 && f->dl_type[0] != 0)
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_MATCH_INCONSISTENT);

            if(!oxm_prereqs_ok(f, (struct ofl_match*) msg->match)) {
                return ofl_error(OFPET_BAD_ACTION, OFPBAC_MATCH_INCONSISTENT);
            }

        }
    }
    return 0;
}

