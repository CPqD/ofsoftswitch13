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

#ifndef OFL_PACKETS_H
#define OFL_PACKETS_H

#define ETH_TYPE_II_START      0x0600
#define ETH_TYPE_IP            0x0800
#define ETH_TYPE_ARP           0x0806
#define ETH_TYPE_VLAN          0x8100
#define ETH_TYPE_VLAN_PBB      0x88a8
#define ETH_TYPE_PBB           0x88e7
#define ETH_TYPE_MPLS          0x8847
#define ETH_TYPE_MPLS_MCAST    0x8848

#define PBB_ISID_LEN		   3
#define ETH_ADDR_LEN           6
#define IPv6_ADDR_LEN	       16


#define VLAN_VID_MASK 0x0fff
#define VLAN_VID_SHIFT 0
#define VLAN_PCP_MASK 0xe000
#define VLAN_PCP_SHIFT 13
#define VLAN_PCP_BITMASK 0x0007 /* the least 3-bit is valid */

#define VLAN_VID_MAX 4095
#define VLAN_PCP_MAX 7



#define MPLS_TTL_MASK 0x000000ff
#define MPLS_TTL_SHIFT 0
#define MPLS_S_MASK 0x00000100
#define MPLS_S_SHIFT 8
#define MPLS_TC_MASK 0x00000e00
#define MPLS_TC_SHIFT 9
#define MPLS_LABEL_MASK 0xfffff000
#define MPLS_LABEL_SHIFT 12

#define MPLS_LABEL_MAX   1048575
#define MPLS_TC_MAX            7



#define IP_ECN_MASK 0x03
#define IP_DSCP_MASK 0xfc





#endif /* OFL_PACKETS_H */
