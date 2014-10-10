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
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>

#include "ofl.h"
#include "ofl-print.h"
#include "oxm-match.h"
#include "openflow/openflow.h"


char *
ofl_port_to_string(uint32_t port) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_port_print(stream, port);
    fclose(stream);
    return str;
}

void
ofl_port_print(FILE *stream, uint32_t port) {
    switch (port) {
        case (OFPP_IN_PORT): {    fprintf(stream, "in_port"); return; }
        case (OFPP_TABLE): {      fprintf(stream, "table"); return; }
        case (OFPP_NORMAL): {     fprintf(stream, "normal"); return; }
        case (OFPP_FLOOD): {      fprintf(stream, "flood"); return; }
        case (OFPP_ALL): {        fprintf(stream, "all"); return; }
        case (OFPP_CONTROLLER): { fprintf(stream, "ctrl"); return; }
        case (OFPP_LOCAL): {      fprintf(stream, "local"); return; }
        case (OFPP_ANY): {        fprintf(stream, "any"); return; }
        default: {                fprintf(stream, "%u", port); return; }
    }
}

char *
ofl_ipv6_ext_hdr_to_string(uint16_t ext_hdr){
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_ipv6_ext_hdr_print(stream, ext_hdr);
    fclose(stream);
    return str;
}

void
ofl_ipv6_ext_hdr_print(FILE *stream, uint16_t ext_hdr) {

	if (ext_hdr != 0) fprintf(stream, "|");
    if (ext_hdr & OFPIEH_NONEXT) {   fprintf(stream, "no_next|"); }
    if (ext_hdr & OFPIEH_ESP) {      fprintf(stream, "esp|"); }
    if (ext_hdr & OFPIEH_AUTH) {     fprintf(stream, "auth|"); }
    if (ext_hdr & OFPIEH_DEST) {     fprintf(stream, "dest|"); }
    if (ext_hdr & OFPIEH_FRAG) {     fprintf(stream, "frag|"); }
    if (ext_hdr & OFPIEH_ROUTER){    fprintf(stream, "router|"); }
    if (ext_hdr & OFPIEH_HOP) {      fprintf(stream, "hop|"); }
    if (ext_hdr & OFPIEH_UNREP) {    fprintf(stream, "unreq|"); }
    if (ext_hdr & OFPIEH_UNSEQ) {    fprintf(stream, "unseq|"); }
}

char *
ofl_queue_to_string(uint32_t queue) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_queue_print(stream, queue);
    fclose(stream);
    return str;
}

void
ofl_queue_print(FILE *stream, uint32_t queue) {
    switch (queue) {
        case (OFPQ_ALL): {        fprintf(stream, "all"); return; }
        default: {                fprintf(stream, "%u", queue); return; }
    }
}


char *
ofl_group_to_string(uint32_t group) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_group_print(stream, group);
    fclose(stream);
    return str;
}

void
ofl_group_print(FILE *stream, uint32_t group) {
    switch (group) {
        case (OFPG_ALL): { fprintf(stream, "all"); return; }
        case (OFPG_ANY): { fprintf(stream, "any"); return; }
        default: {         fprintf(stream, "%u", group); return; }
    }
}



char *
ofl_table_to_string(uint8_t table) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_table_print(stream, table);
    fclose(stream);
    return str;
}

void
ofl_table_print(FILE *stream, uint8_t table) {
    switch (table) {
        case (0xff): { fprintf(stream, "all"); return; }
        default: {     fprintf(stream, "%u", table); return; }
    }
}



char *
ofl_vlan_vid_to_string(uint32_t vid) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_vlan_vid_print(stream, vid);
    fclose(stream);
    return str;
}

void
ofl_vlan_vid_print(FILE *stream, uint32_t vid) {
    switch (vid) {
        case (OFPVID_PRESENT): {  fprintf(stream, "any"); return; }
        case (OFPVID_NONE): { fprintf(stream, "none"); return; }
        default: {            fprintf(stream, "%u", vid); return; }
    }
}



char *
ofl_action_type_to_string(uint16_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_action_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_action_type_print(FILE *stream, uint16_t type) {
    switch (type) {
        case OFPAT_OUTPUT: {   fprintf(stream, "out"); return; }
        case OFPAT_SET_FIELD: {   fprintf(stream, "set_field"); return; }
        case OFPAT_COPY_TTL_OUT: {   fprintf(stream, "ttl_out"); return; }
        case OFPAT_COPY_TTL_IN: {    fprintf(stream, "ttl_in"); return; }
        case OFPAT_SET_MPLS_TTL: {   fprintf(stream, "mpls_ttl"); return; }
        case OFPAT_DEC_MPLS_TTL: {   fprintf(stream, "mpls_dec"); return; }
        case OFPAT_PUSH_VLAN: {      fprintf(stream, "vlan_psh"); return; }
        case OFPAT_POP_VLAN: {       fprintf(stream, "vlan_pop"); return; }
        case OFPAT_PUSH_MPLS: {      fprintf(stream, "mpls_psh"); return; }
        case OFPAT_POP_MPLS: {       fprintf(stream, "mpls_pop"); return; }
        case OFPAT_SET_QUEUE: {      fprintf(stream, "queue"); return; }
        case OFPAT_GROUP: {          fprintf(stream, "group"); return; }
        case OFPAT_PUSH_PBB:  {      fprintf(stream, "pbb_psh"); return; }
        case OFPAT_POP_PBB:   {      fprintf(stream, "pbb_pop"); return; }
        case OFPAT_SET_NW_TTL: {     fprintf(stream, "nw_ttl"); return; }
        case OFPAT_DEC_NW_TTL: {     fprintf(stream, "nw_dec"); return; }
        case OFPAT_EXPERIMENTER: {   fprintf(stream, "exp"); return; }
        default: {                   fprintf(stream, "?(%u)", type); return; }
    }
}

char *
ofl_oxm_type_to_string(uint16_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_oxm_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_oxm_type_print(FILE *stream, uint32_t type){
    switch(type){
    case OXM_OF_IN_PORT:            {fprintf(stream, "in_port"); return; }
    case OXM_OF_IN_PHY_PORT:        {fprintf(stream, "in_phy_port"); return; }
    case OXM_OF_METADATA:           {fprintf(stream, "metadata"); return; }
    case OXM_OF_ETH_DST:            {fprintf(stream, "eth_dst"); return; }
    case OXM_OF_ETH_SRC:            {fprintf(stream, "eth_src"); return; }
    case OXM_OF_ETH_TYPE:           {fprintf(stream, "eth_type"); return; }
    case OXM_OF_VLAN_VID:           {fprintf(stream, "vlan_vid"); return; }
    case OXM_OF_VLAN_PCP:           {fprintf(stream, "vlan_pcp"); return; }
    case OXM_OF_IP_DSCP:            {fprintf(stream, "ip_dscp"); return; }
    case OXM_OF_IP_ECN:             {fprintf(stream, "ip_ecn"); return; }
    case OXM_OF_IP_PROTO:           {fprintf(stream, "ip_proto"); return; }
    case OXM_OF_IPV4_SRC:           {fprintf(stream, "ipv4_src"); return; }
    case OXM_OF_IPV4_DST:           {fprintf(stream, "ipv4_dst"); return; }
    case OXM_OF_TCP_SRC:            {fprintf(stream, "tcp_src"); return; }
    case OXM_OF_TCP_DST:            {fprintf(stream, "tcp_dst"); return; }
    case OXM_OF_UDP_SRC:            {fprintf(stream, "udp_src"); return; }
    case OXM_OF_UDP_DST:            {fprintf(stream, "udp_dst"); return; }
    case OXM_OF_SCTP_SRC:           {fprintf(stream, "sctp_src"); return; }
    case OXM_OF_SCTP_DST:           {fprintf(stream, "sctp_dst"); return; }
    case OXM_OF_ICMPV4_CODE:        {fprintf(stream, "icmpv4_code"); return; }
    case OXM_OF_ICMPV4_TYPE:        {fprintf(stream, "icmpv4_type"); return; }
    case OXM_OF_ARP_OP:             {fprintf(stream, "arp_op"); return; }
    case OXM_OF_ARP_SPA:            {fprintf(stream, "arp_spa"); return; }
    case OXM_OF_ARP_TPA:            {fprintf(stream, "arp_tpa"); return; }
    case OXM_OF_ARP_SHA:            {fprintf(stream, "arp_sha"); return; }
    case OXM_OF_ARP_THA:            {fprintf(stream, "arp_tha"); return; }
    case OXM_OF_IPV6_SRC:           {fprintf(stream, "ipv6_src"); return; }
    case OXM_OF_IPV6_DST:           {fprintf(stream, "ipv6_dst"); return; }
    case OXM_OF_IPV6_FLABEL:        {fprintf(stream, "ipv6_flabel"); return; }
    case OXM_OF_ICMPV6_TYPE:        {fprintf(stream, "icmpv6_type"); return; }
    case OXM_OF_ICMPV6_CODE:        {fprintf(stream, "icmpv6_code"); return; }
    case OXM_OF_IPV6_ND_TARGET:     {fprintf(stream, "ipv6_nd_target"); return; }
    case OXM_OF_IPV6_ND_SLL:        {fprintf(stream, "ipv6_nd_sll"); return; }
    case OXM_OF_IPV6_ND_TLL:        {fprintf(stream, "ipv6_nd_tll"); return; }
    case OXM_OF_MPLS_LABEL:         {fprintf(stream, "mpls_label"); return; }
    case OXM_OF_MPLS_TC:            {fprintf(stream, "mpls_tc"); return; }
    case OXM_OF_MPLS_BOS:           {fprintf(stream, "mpls_bos"); return; }
    case OXM_OF_PBB_ISID:           {fprintf(stream, "pbb_isid"); return; }
    case OXM_OF_TUNNEL_ID:          {fprintf(stream, "tunnel_id"); return; }
    case OXM_OF_IPV6_EXTHDR:        {fprintf(stream, "ipv6_exthdr"); return; }
    default: {                       fprintf(stream, "?(%d)", type); return; }    
    }


}


char *
ofl_instruction_type_to_string(uint16_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_instruction_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_instruction_type_print(FILE *stream, uint16_t type) {
    switch (type) {
        case OFPIT_GOTO_TABLE: {    fprintf(stream, "goto"); return; }
        case OFPIT_WRITE_METADATA: { fprintf(stream, "meta"); return; }
        case OFPIT_WRITE_ACTIONS: {  fprintf(stream, "write"); return; }
        case OFPIT_APPLY_ACTIONS: {  fprintf(stream, "apply"); return; }
        case OFPIT_CLEAR_ACTIONS: {  fprintf(stream, "clear"); return; }
        case OFPIT_METER:         {  fprintf(stream, "meter"); return; }
        case OFPIT_EXPERIMENTER: {   fprintf(stream, "exp"); return; }
        default: {                   fprintf(stream, "?(%u)", type); return; }
    }
}


char *
ofl_queue_prop_type_to_string(uint16_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_queue_prop_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_queue_prop_type_print(FILE *stream, uint16_t type) {
    switch (type) {
        case (OFPQT_MIN_RATE): { fprintf(stream, "minrate"); return; }
        default: {               fprintf(stream, "?(%u)", type); return; }
    }
}



char *
ofl_error_type_to_string(uint16_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_error_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_error_type_print(FILE *stream, uint16_t type) {
    switch (type) {
        case (OFPET_HELLO_FAILED): {         fprintf(stream, "HELLO_FAILED"); return; }
        case (OFPET_BAD_REQUEST): {          fprintf(stream, "BAD_REQUEST"); return; }
        case (OFPET_BAD_ACTION): {           fprintf(stream, "BAD_ACTION"); return; }
        case (OFPET_BAD_INSTRUCTION): {      fprintf(stream, "BAD_INSTRUCTION"); return; }
        case (OFPET_BAD_MATCH): {            fprintf(stream, "BAD_MATCH"); return; }
        case (OFPET_FLOW_MOD_FAILED): {      fprintf(stream, "FLOW_MOD_FAILED"); return; }
        case (OFPET_GROUP_MOD_FAILED): {     fprintf(stream, "GROUP_MOD_FAILED"); return; }
        case (OFPET_PORT_MOD_FAILED): {      fprintf(stream, "PORT_MOD_FAILED"); return; }
        case (OFPET_TABLE_MOD_FAILED): {     fprintf(stream, "TABLE_MOD_FAILED"); return; }
        case (OFPET_METER_MOD_FAILED): {     fprintf(stream, "METER_MOD_FAILED"); return; }
        case (OFPET_QUEUE_OP_FAILED): {      fprintf(stream, "QUEUE_OP_FAILED"); return; }
        case (OFPET_SWITCH_CONFIG_FAILED): { fprintf(stream, "SWITCH_CONFIG_FAILED"); return; }
        case (OFPET_TABLE_FEATURES_FAILED): { fprintf(stream, "TABLE_FEATURES_FAILED"); return; }
        default: {                           fprintf(stream, "?(%u)", type); return; }
    }
}



char *
ofl_error_code_to_string(uint16_t type, uint16_t code) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_error_code_print(stream, type, code);
    fclose(stream);
    return str;
}

void
ofl_error_code_print(FILE *stream, uint16_t type, uint16_t code) {
    switch (type) {
        case (OFPET_HELLO_FAILED): {
            switch (code) {
                case (OFPHFC_INCOMPATIBLE) : { fprintf(stream, "INCOMPATIBLE"); return; }
                case (OFPHFC_EPERM) :        { fprintf(stream, "EPERM"); return; }
            }
            break;
        }
        case (OFPET_BAD_REQUEST): {
            switch (code) {
                case (OFPBRC_BAD_VERSION) :      { fprintf(stream, "BAD_VERSION"); return; }
                case (OFPBRC_BAD_TYPE) :         { fprintf(stream, "BAD_TYPE"); return; }
                case (OFPBRC_BAD_MULTIPART) :    { fprintf(stream, "OFPBRC_BAD_MULTIPART"); return; }
                case (OFPBRC_BAD_EXPERIMENTER) : { fprintf(stream, "BAD_EXPERIMENTER"); return; }
                case (OFPBRC_EPERM) :            { fprintf(stream, "EPERM"); return; }
                case (OFPBRC_BAD_LEN) :          { fprintf(stream, "BAD_LEN"); return; }
                case (OFPBRC_BUFFER_EMPTY) :     { fprintf(stream, "BUFFER_EMPTY"); return; }
                case (OFPBRC_BUFFER_UNKNOWN) :   { fprintf(stream, "BUFFER_UNKNOWN"); return; }
                case (OFPBRC_BAD_TABLE_ID) :     { fprintf(stream, "BAD_TABLE_ID"); return; }
            }
            break;
        }
        case (OFPET_BAD_ACTION): {
            switch (code) {
                case (OFPBAC_BAD_TYPE) :              { fprintf(stream, "BAD_TYPE"); return; }
                case (OFPBAC_BAD_LEN) :               { fprintf(stream, "BAD_LEN"); return; }
                case (OFPBAC_BAD_EXPERIMENTER) :      { fprintf(stream, "BAD_EXPERIMENTER"); return; }
                case (OFPBAC_BAD_OUT_PORT) :          { fprintf(stream, "BAD_OUT_PORT"); return; }
                case (OFPBAC_BAD_ARGUMENT) :          { fprintf(stream, "BAD_ARGUMENT"); return; }
                case (OFPBAC_EPERM) :                 { fprintf(stream, "EPERM"); return; }
                case (OFPBAC_TOO_MANY) :              { fprintf(stream, "TOO_MANY"); return; }
                case (OFPBAC_BAD_QUEUE) :             { fprintf(stream, "BAD_QUEUE"); return; }
                case (OFPBAC_BAD_OUT_GROUP) :         { fprintf(stream, "BAD_OUT_GROUP"); return; }
                case (OFPBAC_UNSUPPORTED_ORDER) :     { fprintf(stream, "UNSUPPORTED_ORDER"); return; }
                case (OFPBAC_BAD_TAG) :               { fprintf(stream, "BAD_TAG"); return; }
                case (OFPBAC_MATCH_INCONSISTENT):     { fprintf(stream, "MATCH_INCONSISTENT"); return;}
                case (OFPBAC_BAD_SET_TYPE):           { fprintf(stream, "BAD_SET_TYPE"); return;}
                case (OFPBAC_BAD_SET_LEN):            { fprintf(stream, "BAD_SET_LEN"); return;}
                case (OFPBAC_BAD_SET_ARGUMENT):       { fprintf(stream, "BAD_SET_ARGUMENT"); return;}
            }
            break;
        }
        case (OFPET_BAD_INSTRUCTION): {
            switch (code) {
                case (OFPBIC_UNKNOWN_INST) :        { fprintf(stream, "UNKNOWN_INST"); return; }
                case (OFPBIC_BAD_TABLE_ID) :        { fprintf(stream, "BAD_TABLE_ID"); return; }
                case (OFPBIC_UNSUP_METADATA) :      { fprintf(stream, "UNSUP_METADATA"); return; }
                case (OFPBIC_UNSUP_METADATA_MASK) : { fprintf(stream, "UNSUP_METADATA_MASK"); return; }
            }
            break;
        }
        case (OFPET_BAD_MATCH): {
            switch (code) {
                case (OFPBMC_BAD_TYPE) :         { fprintf(stream, "BAD_TYPE"); return; }
                case (OFPBMC_BAD_LEN) :          { fprintf(stream, "BAD_LEN"); return; }
                case (OFPBMC_BAD_TAG) :          { fprintf(stream, "BAD_TAG"); return; }
                case (OFPBMC_BAD_DL_ADDR_MASK) : { fprintf(stream, "BAD_DL_ADDR_MASK"); return; }
                case (OFPBMC_BAD_NW_ADDR_MASK) : { fprintf(stream, "BAD_NW_ADDR_MASK"); return; }
                case (OFPBMC_BAD_WILDCARDS) :    { fprintf(stream, "BAD_WILDCARDS"); return; }
                case (OFPBMC_BAD_FIELD) :        { fprintf(stream, "BAD_FIELD"); return; }
                case (OFPBMC_BAD_VALUE) :        { fprintf(stream, "BAD_VALUE"); return; }
                case (OFPBMC_BAD_MASK) :         { fprintf(stream, "BAD_MASK"); return; }
                case (OFPBMC_BAD_PREREQ) :       { fprintf(stream, "BAD_PREREQ"); return; }
                case (OFPBMC_DUP_FIELD) :        { fprintf(stream, "DUP_FIELD"); return; }
                case (OFPBMC_EPERM) :            { fprintf(stream, "PERMISSION ERROR"); return; }
            }
            break;
        }
        case (OFPET_FLOW_MOD_FAILED): {
            switch (code) {
                case (OFPFMFC_UNKNOWN) :      { fprintf(stream, "UNKNOWN"); return; }
                case (OFPFMFC_TABLE_FULL) :   { fprintf(stream, "TABLE_FULL"); return; }
                case (OFPFMFC_BAD_TABLE_ID) : { fprintf(stream, "BAD_TABLE_ID"); return; }
                case (OFPFMFC_OVERLAP) :      { fprintf(stream, "OVERLAP"); return; }
                case (OFPFMFC_EPERM) :        { fprintf(stream, "EPERM"); return; }
                case (OFPFMFC_BAD_TIMEOUT) :  { fprintf(stream, "BAD_TIMEOUT"); return; }
                case (OFPFMFC_BAD_COMMAND) :  { fprintf(stream, "BAD_COMMAND"); return; }
            }
            break;
        }
        case (OFPET_GROUP_MOD_FAILED): {
            switch (code) {
                case (OFPGMFC_GROUP_EXISTS) :         { fprintf(stream, "GROUP_EXISTS"); return; }
                case (OFPGMFC_INVALID_GROUP) :        { fprintf(stream, "INVALID_GROUP"); return; }
                case (OFPGMFC_OUT_OF_BUCKETS) :       { fprintf(stream, "OUT_OF_BUCKETS"); return; }
                case (OFPGMFC_CHAINING_UNSUPPORTED) : { fprintf(stream, "CHAINING_UNSUPPORTED"); return; }
                case (OFPGMFC_WATCH_UNSUPPORTED) :    { fprintf(stream, "UNSUPPORTED"); return; }
                case (OFPGMFC_LOOP) :                 { fprintf(stream, "LOOP"); return; }
                case (OFPGMFC_UNKNOWN_GROUP) :        { fprintf(stream, "UNKNOWN_GROUP"); return; }
            }
            break;
        }
        case (OFPET_PORT_MOD_FAILED): {
            switch (code) {
                case (OFPPMFC_BAD_PORT) :      { fprintf(stream, "BAD_PORT"); return; }
                case (OFPPMFC_BAD_HW_ADDR) :   { fprintf(stream, "BAD_HW_ADDR"); return; }
                case (OFPPMFC_BAD_CONFIG) :    { fprintf(stream, "BAD_CONFIG"); return; }
                case (OFPPMFC_BAD_ADVERTISE) : { fprintf(stream, "BAD_ADVERTISE"); return; }
            }
            break;
        }
        case (OFPET_TABLE_MOD_FAILED): {
            switch (code) {
                case (OFPTMFC_BAD_TABLE) :     { fprintf(stream, "BAD_TABLE"); return; }
                case (OFPTMFC_BAD_CONFIG) :    { fprintf(stream, "BAD_CONFIG"); return; }
            }
            break;
        }
        case (OFPET_METER_MOD_FAILED): {
            switch (code) {
                case (OFPMMFC_METER_EXISTS) :   { fprintf(stream, "METER_EXISTS"); return; }
                case (OFPMMFC_INVALID_METER) :  { fprintf(stream, "INVALID_METER"); return; }
                case (OFPMMFC_UNKNOWN_METER) :  { fprintf(stream, "UNKNOWN_METER"); return; }
                case (OFPMMFC_BAD_COMMAND) :    { fprintf(stream, "BAD_COMMAND"); return; }
                case (OFPMMFC_BAD_FLAGS) :      { fprintf(stream, "BAD_FLAGS"); return; }
                case (OFPMMFC_BAD_RATE) :       { fprintf(stream, "BAD_RATE"); return; }
                case (OFPMMFC_BAD_BURST) :      { fprintf(stream, "BAD_BURST"); return; }
                case (OFPMMFC_BAD_BAND) :       { fprintf(stream, "BAD_BAND"); return; }
                case (OFPMMFC_BAD_BAND_VALUE) : { fprintf(stream, "BAD_BAND_VALUE"); return; }
                case (OFPMMFC_OUT_OF_METERS) :  { fprintf(stream, "OUT_OF_METERS"); return; }
                case (OFPMMFC_OUT_OF_BANDS) :   { fprintf(stream, "OUT_OF_BANDS"); return; }
            }
            break;
        }
        case (OFPET_QUEUE_OP_FAILED): {
            switch (code) {
                case (OFPQOFC_BAD_PORT) :  { fprintf(stream, "BAD_PORT"); return; }
                case (OFPQOFC_BAD_QUEUE) : { fprintf(stream, "BAD_QUEUE"); return; }
                case (OFPQOFC_EPERM) :     { fprintf(stream, "EPERM"); return; }
            }
            break;
        }
        case (OFPET_SWITCH_CONFIG_FAILED): {
            switch (code) {
                case (OFPSCFC_BAD_FLAGS) : { fprintf(stream, "BAD_FLAGS"); return; }
                case (OFPSCFC_BAD_LEN) :   { fprintf(stream, "BAD_LEN"); return; }
            }
            break;
        }
        case (OFPET_TABLE_FEATURES_FAILED): {
            switch (code) {
                case (OFPTFFC_BAD_TABLE) : { fprintf(stream, "BAD_TABLE"); return; }
                case (OFPTFFC_BAD_METADATA) :   { fprintf(stream, "BAD_METADATA"); return; }
                case (OFPTFFC_BAD_TYPE) :   { fprintf(stream, "BAD_TYPE"); return; }
                case (OFPTFFC_BAD_LEN) :   { fprintf(stream, "BAD_LEN"); return; }
                case (OFPTFFC_BAD_ARGUMENT) :   { fprintf(stream, "BAD_ARGUMENT"); return; }
                case (OFPTFFC_EPERM) :   { fprintf(stream, "EPERM"); return; }
            }
            break;
        }
    }
    fprintf(stream, "?(%u)", code);
}



char *
ofl_message_type_to_string(uint16_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_message_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_message_type_print(FILE *stream, uint16_t type) {
    switch (type) {
        case OFPT_HELLO: {                    fprintf(stream, "hello"); return; }
        case OFPT_ERROR: {                    fprintf(stream, "error"); return; }
        case OFPT_ECHO_REQUEST: {             fprintf(stream, "echo_req"); return; }
        case OFPT_ECHO_REPLY: {               fprintf(stream, "echo_repl"); return; }
        case OFPT_EXPERIMENTER: {             fprintf(stream, "exp"); return; }
        case OFPT_FEATURES_REQUEST: {         fprintf(stream, "feat_req"); return; }
        case OFPT_FEATURES_REPLY: {           fprintf(stream, "feat_repl"); return; }
        case OFPT_GET_CONFIG_REQUEST: {       fprintf(stream, "conf_req"); return; }
        case OFPT_GET_CONFIG_REPLY: {         fprintf(stream, "conf_repl"); return; }
        case OFPT_SET_CONFIG: {               fprintf(stream, "set_conf"); return; }
        case OFPT_PACKET_IN: {                fprintf(stream, "pkt_in"); return; }
        case OFPT_FLOW_REMOVED: {             fprintf(stream, "flow_rem"); return; }
        case OFPT_PORT_STATUS: {              fprintf(stream, "port_stat"); return; }
        case OFPT_PACKET_OUT: {               fprintf(stream, "pkt_out"); return; }
        case OFPT_FLOW_MOD: {                 fprintf(stream, "flow_mod"); return; }
        case OFPT_GROUP_MOD: {                fprintf(stream, "grp_mod"); return; }
        case OFPT_PORT_MOD: {                 fprintf(stream, "port_mod"); return; }
        case OFPT_TABLE_MOD: {                fprintf(stream, "tab_mod"); return; }
        case OFPT_MULTIPART_REQUEST: {            fprintf(stream, "stat_req"); return; }
        case OFPT_MULTIPART_REPLY: {              fprintf(stream, "stat_repl"); return; }
        case OFPT_BARRIER_REQUEST: {          fprintf(stream, "barr_req"); return; }
        case OFPT_BARRIER_REPLY: {            fprintf(stream, "barr_repl"); return; }
        case OFPT_QUEUE_GET_CONFIG_REQUEST: { fprintf(stream, "q_cnf_req"); return; }
        case OFPT_QUEUE_GET_CONFIG_REPLY:   { fprintf(stream, "q_cnf_repl"); return; }
		case OFPT_GET_ASYNC_REQUEST:        { fprintf(stream, "get_async_req"); return;}
		case OFPT_GET_ASYNC_REPLY:          { fprintf(stream, "get_async_rep"); return;}
		case OFPT_SET_ASYNC:                { fprintf(stream, "set_async"); return;}
		case OFPT_METER_MOD:				{ fprintf(stream, "meter_mod"); return;}  
		case OFPT_ROLE_REQUEST:             { fprintf(stream, "role_request"); return;}
		case OFPT_ROLE_REPLY:               { fprintf(stream, "role_reply"); return;}
		default: {                            fprintf(stream, "?(%u)", type); return; }
    }
}



char *
ofl_buffer_to_string(uint32_t buffer) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_buffer_print(stream, buffer);
    fclose(stream);
    return str;
}

void
ofl_buffer_print(FILE *stream, uint32_t buffer) {
    switch (buffer) {
        case (0xffffffff): { fprintf(stream, "none"); return; }
        default: {           fprintf(stream, "%u", buffer); return; }
    }
}



char *
ofl_packet_in_reason_to_string(uint8_t reason) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_packet_in_reason_print(stream, reason);
    fclose(stream);
    return str;
}

void
ofl_packet_in_reason_print(FILE *stream, uint8_t reason) {
    switch (reason) {
        case (OFPR_NO_MATCH): { fprintf(stream, "no_match"); return; }
        case (OFPR_ACTION): {   fprintf(stream, "action"); return; }
        default: {              fprintf(stream, "?(%u)", reason); return; }
    }
}



char *
ofl_flow_removed_reason_to_string(uint8_t reason) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_flow_removed_reason_print(stream, reason);
    fclose(stream);
    return str;
}

void
ofl_flow_removed_reason_print(FILE *stream, uint8_t reason) {
    switch(reason) {
        case (OFPRR_IDLE_TIMEOUT): { fprintf(stream, "idle"); return; }
        case (OFPRR_HARD_TIMEOUT): { fprintf(stream, "hard"); return; }
        case (OFPRR_DELETE):       { fprintf(stream, "del"); return; }
        case (OFPRR_GROUP_DELETE): { fprintf(stream, "group"); return; }
        case (OFPRR_METER_DELETE): { fprintf(stream, "meter"); return; }        
        default:                   { fprintf(stream, "?(%u)", reason); return; }
    }
}



char *
ofl_port_status_reason_to_string(uint8_t reason) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_port_status_reason_print(stream, reason);
    fclose(stream);
    return str;
}

void
ofl_port_status_reason_print(FILE *stream, uint8_t reason) {
    switch (reason) {
        case (OFPPR_ADD):  {   fprintf(stream, "add"); return; }
        case (OFPPR_DELETE): { fprintf(stream, "del"); return; }
        case (OFPPR_MODIFY): { fprintf(stream, "mod"); return; }
        default: {             fprintf(stream, "?(%u)", reason); return; }
    }
}



char *
ofl_flow_mod_command_to_string(uint8_t command) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_flow_mod_command_print(stream, command);
    fclose(stream);
    return str;
}

void
ofl_flow_mod_command_print(FILE *stream, uint8_t command) {
    switch (command) {
        case (OFPFC_ADD):  {           fprintf(stream, "add"); return; }
        case (OFPFC_MODIFY):  {        fprintf(stream, "mod"); return; }
        case (OFPFC_MODIFY_STRICT):  { fprintf(stream, "mods"); return; }
        case (OFPFC_DELETE):       {   fprintf(stream, "del"); return; }
        case (OFPFC_DELETE_STRICT):  { fprintf(stream, "dels"); return; }
        default:  {                    fprintf(stream, "?(%u)", command); return; }
    }
}



char *
ofl_group_mod_command_to_string(uint16_t command) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_group_mod_command_print(stream, command);
    fclose(stream);
    return str;
}

void
ofl_group_mod_command_print(FILE *stream, uint16_t command) {
    switch(command) {
        case (OFPGC_ADD): {    fprintf(stream, "add"); return; }
        case (OFPGC_MODIFY): { fprintf(stream, "mod"); return; }
        case (OFPGC_DELETE): { fprintf(stream, "del"); return; }
        default: {             fprintf(stream, "?(%u)", command); return; }
    }
}

char *
ofl_meter_mod_command_to_string(uint16_t command) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_meter_mod_command_print(stream, command);
    fclose(stream);
    return str;
}

void
ofl_meter_mod_command_print(FILE *stream, uint16_t command){
	switch(command){
		case (OFPMC_ADD): {    fprintf(stream, "add"); return; }
		case (OFPMC_MODIFY): { fprintf(stream, "mod"); return; }
		case (OFPMC_DELETE): { fprintf(stream, "del"); return; } 
		default: { fprintf(stream, "?(%u)", command); return;}			
	}
}

char *
ofl_meter_band_type_to_string(uint16_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_meter_band_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_meter_band_type_print(FILE *stream, uint16_t type) {
    switch (type) {
        case OFPMBT_DROP:        {    fprintf(stream, "drop"); return; }
        case OFPMBT_DSCP_REMARK: {    fprintf(stream, "dscp_remark"); return; }
        case OFPMBT_EXPERIMENTER: {    fprintf(stream, "exp"); return; }  
        default: {                   fprintf(stream, "?(%u)", type); return; }
    }              
}        


char *
ofl_group_type_to_string(uint8_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    ofl_group_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_group_type_print(FILE *stream, uint8_t type) {
    switch(type) {
        case (OFPGT_ALL):      { fprintf(stream, "all"); return; }
        case (OFPGT_SELECT):   { fprintf(stream, "sel"); return; }
        case (OFPGT_INDIRECT): { fprintf(stream, "ind"); return; }
        case (OFPGT_FF):       { fprintf(stream, "ff"); return; }
        default: {               fprintf(stream, "?(%u)", type); return; }
    }
}

char *
ofl_stats_type_to_string(uint16_t type) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_stats_type_print(stream, type);
    fclose(stream);
    return str;
}

void
ofl_stats_type_print(FILE *stream, uint16_t type) {
    switch (type) {
        case (OFPMP_DESC):          { fprintf(stream, "desc"); return; }
        case (OFPMP_FLOW):          { fprintf(stream, "flow"); return; }
        case (OFPMP_AGGREGATE):     { fprintf(stream, "aggr"); return; }
        case (OFPMP_TABLE):         { fprintf(stream, "table"); return; }
        case (OFPMP_TABLE_FEATURES):{ fprintf(stream, "table-features"); return; }
        case (OFPMP_PORT_STATS):    { fprintf(stream, "port"); return; }
        case (OFPMP_QUEUE):         { fprintf(stream, "queue"); return; }
        case (OFPMP_GROUP):         { fprintf(stream, "grp"); return; }
        case (OFPMP_GROUP_FEATURES):{ fprintf(stream, "grp_features"); return; }
        case (OFPMP_GROUP_DESC):    { fprintf(stream, "gdesc"); return; }
        case (OFPMP_METER):         { fprintf(stream, "mstats"); return; }
        case (OFPMP_METER_CONFIG):  { fprintf(stream, "mconf"); return; }
        case (OFPMP_METER_FEATURES):{ fprintf(stream, "mfeat"); return; }
        case (OFPMP_PORT_DESC):     { fprintf(stream, "port-desc"); return; }   
        case (OFPMP_EXPERIMENTER):  { fprintf(stream, "exp"); return; }
        default: {                    fprintf(stream, "?(%u)", type); return; }
    }
}

void 
ofl_properties_type_print(FILE *stream, uint16_t type){
    switch(type){
        case (OFPTFPT_INSTRUCTIONS):        { fprintf(stream, "instructions"); return; }
        case (OFPTFPT_INSTRUCTIONS_MISS):   { fprintf(stream, "instructions_miss"); return; }
        case (OFPTFPT_NEXT_TABLES):         { fprintf(stream, "next_tables"); return; }
        case (OFPTFPT_NEXT_TABLES_MISS):    { fprintf(stream, "next_tables_miss"); return; }
        case (OFPTFPT_WRITE_ACTIONS):       { fprintf(stream, "write_actions"); return; }
        case (OFPTFPT_WRITE_ACTIONS_MISS):  { fprintf(stream, "write_actions_miss"); return; }
        case (OFPTFPT_APPLY_ACTIONS):       { fprintf(stream, "apply_actions"); return; }
        case (OFPTFPT_APPLY_ACTIONS_MISS):  { fprintf(stream, "apply_actions_miss"); return; }
        case (OFPTFPT_MATCH):               { fprintf(stream, "oxms"); return; }
        case (OFPTFPT_WILDCARDS):           { fprintf(stream, "wildcards"); return; }
        case (OFPTFPT_WRITE_SETFIELD):     { fprintf(stream, "write_setfield"); return; }
        case (OFPTFPT_WRITE_SETFIELD_MISS):{ fprintf(stream, "write_setfield_miss"); return; }
        case (OFPTFPT_APPLY_SETFIELD):     { fprintf(stream, "apply_setfield"); return; }
        case (OFPTFPT_APPLY_SETFIELD_MISS):{ fprintf(stream, "apply_setfield_miss"); return; }
        case (OFPTFPT_EXPERIMENTER):        { fprintf(stream, "experimenter"); return; }
        case (OFPTFPT_EXPERIMENTER_MISS):   { fprintf(stream, "experimenter_miss"); return; }
        default: {                            fprintf(stream, "?(%u)", type); return; }            
    }
}


void
ofl_async_packet_in(FILE *stream, uint32_t packet_in_mask){
    bool e = false;

    fprintf(stream, "packet_in(" );
    if(packet_in_mask &  (1 << 0)){
       fprintf(stream, "no_match");
       e = true; 
    }
    if(packet_in_mask & ((1 << 1))){
        if(e)
            fprintf(stream,", ");
        fprintf(stream, "action");
        e = true;  
    }
    if(packet_in_mask & ((1 << 2))){
        if(e)
            fprintf(stream,", ");    
        fprintf(stream, "invalid_ttl");
        e = true;
    }
    if (!e)
        fprintf(stream, "none"); 
    fprintf(stream, ")" );
}

void
ofl_async_port_status(FILE *stream, uint32_t port_status_mask){
    bool e = false;
    
    fprintf(stream, "port_status(" );
    if(port_status_mask&  (1 << 0)){
        fprintf(stream, "add");
        e = true;   
    }    
    if(port_status_mask & ((1 << 1))){
        if(e)
            fprintf(stream,", ");        
        fprintf(stream, "delete"); 
        e = true;
    }               
    if(port_status_mask & ((1 << 2))){
        if(e)
            fprintf(stream,", ");     
        fprintf(stream, "modify");
        e = true;
    }
    if (!e)
        fprintf(stream, "none");
     fprintf(stream, ")" );            
}

void
ofl_async_flow_removed(FILE *stream, uint32_t flow_rem_mask){
    bool e = false;
    
    fprintf(stream, "flow_removed(" );    
    if(flow_rem_mask &  (1 << 0)){
        fprintf(stream, "idle_timeout");
        e = true;   
    }        
    if(flow_rem_mask & ((1 << 1))){
        if(e)
            fprintf(stream,", ");      
        fprintf(stream, "hard_timeout"); 
        e = true;           
    }
    if(flow_rem_mask & ((1 << 2))){
        if(e)
            fprintf(stream,", ");      
        fprintf(stream, "delete");
        e = true;
    }        
    if(flow_rem_mask & ((1 << 3))){
        if(e)
            fprintf(stream,", ");        
        fprintf(stream, "group delete");
        e = true;
     }   
    if(flow_rem_mask & ((1 << 4))){
        if(e)
            fprintf(stream,", ");       
        fprintf(stream, "meter delete");        
        e = true;
    }
    if (!e)
        fprintf(stream, "none"); 

    fprintf(stream, ")" );          
}

char *
ofl_hex_to_string(uint8_t *buf, size_t buf_size) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    ofl_hex_print(stream, buf, buf_size);
    fclose(stream);
    return str;
}

void
ofl_hex_print(FILE *stream, uint8_t *buf, size_t buf_size) {
    size_t i;
    size_t lines = 0;

    for (i=0; i < buf_size; i++) {
        if (i % 16 == 0) {
            if (lines > 0) {
                fprintf(stream, "\n");
            }
            lines++;
            fprintf(stream, "%04zu   %02"PRIx8"", i, buf[i]);
        } else if ( i % 8 == 0) {
            fprintf(stream, "  %02"PRIx8"", buf[i]);
        } else {
            fprintf(stream, " %02"PRIx8"", buf[i]);
        }
    }
}
