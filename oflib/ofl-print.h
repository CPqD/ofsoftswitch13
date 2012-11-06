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

#ifndef OFL_PRINT_H
#define OFL_PRINT_H 1

#include <sys/types.h>
#include <inttypes.h>
#include <stdio.h>

#include "ofl.h"
#include "ofl-print.h"


/****************************************************************************
 * Functions for printing enum values
 ****************************************************************************/

char *
ofl_port_to_string(uint32_t port);

void
ofl_port_print(FILE *stream, uint32_t port);

char *
ofl_ipv6_ext_hdr_to_string(uint16_t ext_hdr);

void
ofl_ipv6_ext_hdr_print(FILE *stream, uint16_t ext_hdr);

char *
ofl_queue_to_string(uint32_t queue);

void
ofl_queue_print(FILE *stream, uint32_t queue);

char *
ofl_group_to_string(uint32_t group);

void
ofl_group_print(FILE *stream, uint32_t group);

char *
ofl_table_to_string(uint8_t table);

void
ofl_table_print(FILE *stream, uint8_t table);

char *
ofl_vlan_vid_to_string(uint32_t vid);

void
ofl_vlan_vid_print(FILE *stream, uint32_t vid);

char *
ofl_action_type_to_string(uint16_t type);

void
ofl_action_type_print(FILE *stream, uint16_t type);

char *
ofl_oxm_type_to_string(uint16_t type);

void
ofl_oxm_type_print(FILE *stream, uint32_t type);

char *
ofl_instruction_type_to_string(uint16_t type);

void
ofl_instruction_type_print(FILE *stream, uint16_t type);

char *
ofl_queue_prop_type_to_string(uint16_t type);

void
ofl_queue_prop_type_print(FILE *stream, uint16_t type);

char *
ofl_error_type_to_string(uint16_t type);

void
ofl_error_type_print(FILE *stream, uint16_t type);

char *
ofl_error_code_to_string(uint16_t type, uint16_t code);

void
ofl_error_code_print(FILE *stream, uint16_t type, uint16_t code);

char *
ofl_message_type_to_string(uint16_t type);

void
ofl_message_type_print(FILE *stream, uint16_t type);

char *
ofl_buffer_to_string(uint32_t buffer);

void
ofl_buffer_print(FILE *stream, uint32_t buffer);

char *
ofl_packet_in_reason_to_string(uint8_t reason);

void
ofl_packet_in_reason_print(FILE *stream, uint8_t reason);

char *
ofl_flow_removed_reason_to_string(uint8_t reason);

void
ofl_flow_removed_reason_print(FILE *stream, uint8_t reason);

char *
ofl_port_status_reason_to_string(uint8_t reason);

void
ofl_port_status_reason_print(FILE *stream, uint8_t reason);

char *
ofl_flow_mod_command_to_string(uint8_t command);

void
ofl_flow_mod_command_print(FILE *stream, uint8_t command);

char *
ofl_group_mod_command_to_string(uint16_t command);

void
ofl_group_mod_command_print(FILE *stream, uint16_t command);

char *
ofl_meter_mod_command_to_string(uint16_t command);

void
ofl_meter_mod_command_print(FILE *stream, uint16_t command);

char *
ofl_meter_band_type_to_string(uint16_t type); 

void
ofl_meter_band_type_print(FILE *stream, uint16_t type);

char *
ofl_group_type_to_string(uint8_t type);

void
ofl_group_type_print(FILE *stream, uint8_t type);

char *
ofl_stats_type_to_string(uint16_t type);

void
ofl_stats_type_print(FILE *stream, uint16_t type);

void 
ofl_properties_type_print(FILE *stream, uint16_t type);

void
ofl_async_packet_in(FILE *stream, uint32_t packet_in_mask);

void
ofl_async_port_status(FILE *stream, uint32_t port_status_mask);

void
ofl_async_flow_removed(FILE *stream, uint32_t flow_rem_mask);

char *
ofl_hex_to_string(uint8_t *buf, size_t buf_size);

void
ofl_hex_print(FILE *stream, uint8_t *buf, size_t buf_size);

#endif /* OFL_PRINT_H */
