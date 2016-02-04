/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil
 * Coprright (c) 2013, Ericsson AB, Ericsson Eurolab, Germany
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
 *   * Neither the name of the CPqD nor the names of its
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
#include <string.h>
#include "lib/hash.h"
#include "oflib/oxm-match.h"
#include "match_std.h"


#include "vlog.h"
#define LOG_MODULE VLM_flow_e

/* Returns true if two 8 bit values match */
static inline bool
match_8(uint8_t *a, uint8_t *b) {
    return (*a == *b);
}

/* Returns true if two masked 8 bit values match */
static inline bool
match_mask8(uint8_t *a, uint8_t *am, uint8_t *b) {
    return (((am[0]) & (a[0] ^ b[0])) == 0);
}

/* Returns true if two 16 bit values match */
static inline bool
match_16(uint8_t *a, uint8_t *b) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    return (*a1 == *b1);
}

/* Returns true if two masked 16 bit values match */
static inline bool
match_mask16(uint8_t *a, uint8_t *am, uint8_t *b) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    uint16_t *mask = (uint16_t *) am;
    return (((*mask) & (*a1 ^ *b1)) == 0);
}

/* Returns true if two 24 bit values match */
static inline bool
match_24(uint8_t *a, uint8_t *b) {     
     return (match_16(a, b) &&
             match_8(a+2, b+2));
}

/* Returns true if two masked 24 bit values match */
static inline bool
match_mask24(uint8_t *a, uint8_t *am, uint8_t *b) {
     return (match_mask16(a, am, b) &&
             match_mask8(a+2, am+2, b+2));
}

/* Returns true if two 32 bit values match */
static inline bool
match_32(uint8_t *a, uint8_t *b) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    return (*a1 == *b1);
}

/* Returns true if two masked 32 bit values match */
static inline bool
match_mask32(uint8_t *a, uint8_t *am, uint8_t *b) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask = (uint32_t *) am;
    return (((*mask) & (*a1 ^ *b1)) == 0);
}

/* Returns true if two 48 bit values match */
static inline bool
match_48(uint8_t *a, uint8_t *b) {
     return (match_32(a, b) &&
             match_16(a+4, b+4));
}

/* Returns true if two masked 48 bit values match */
static inline bool
match_mask48(uint8_t *a, uint8_t *am, uint8_t *b) {
     return (match_mask32(a, am, b) &&
             match_mask16(a+4, am+4, b+4));
}

/* Returns true if two 64 bit values match */
static inline bool
match_64(uint8_t *a, uint8_t *b) {
    uint64_t *a1 = (uint64_t *) a;
    uint64_t *b1 = (uint64_t *) b;
    return (*a1 == *b1);
}

/* Returns true if two masked 64 bit values match */
static inline bool
match_mask64(uint8_t *a, uint8_t *am, uint8_t *b) {
    uint64_t *a1 = (uint64_t *) a;
    uint64_t *b1 = (uint64_t *) b;
    uint64_t *mask = (uint64_t *) am;
    return (((*mask) & (*a1 ^ *b1)) == 0);
}

/* Returns true if two 128 bit values match */
static inline bool
match_128(uint8_t *a, uint8_t *b) {
    return (match_64(a, b) &&
            match_64(a+8, b+8));
}

/* Returns true if two masked 128 bit values match */
static inline bool
match_mask128(uint8_t *a, uint8_t *am, uint8_t *b) {
    return (match_mask64(a, am, b) &&
            match_mask64(a+8, am+8, b+8));
}


/* Returns true if the fields in *packet matches the flow entry in *flow_match */
bool
packet_match(struct ofl_match *flow_match, struct ofl_match *packet){

    struct ofl_match_tlv *f;
    struct ofl_match_tlv *packet_f;
    bool has_mask;
    int field_len;
    int packet_header;
    uint8_t *flow_val, *flow_mask= NULL;
    uint8_t *packet_val;

    if (flow_match->header.length == 0){
        return true;
    }

    /* Loop over the flow entry's match fields */
    HMAP_FOR_EACH(f, struct ofl_match_tlv, hmap_node, &flow_match->match_fields)
    {
        /* Check presence of match field in packet */
        has_mask = OXM_HASMASK(f->header);
        field_len =  OXM_LENGTH(f->header);
        packet_header = f->header;
        flow_val = f->value;
        if (has_mask) {
            /* Clear the has_mask bit and divide the field_len by two in the packet field header */
            field_len /= 2;
            packet_header &= 0xfffffe00;
            packet_header |= field_len;
            flow_mask = f->value + field_len;
        }
        /* Lookup the packet header */
        packet_f = oxm_match_lookup(packet_header, packet);
        if (!packet_f) {
        	if (f->header==OXM_OF_VLAN_VID &&
        			*((uint16_t *) f->value)==OFPVID_NONE) {
        		/* There is no VLAN tag, as required */
        		continue;
        	}
        	return false;
        }

        /* Compare the flow and packet field values, considering the mask, if any */
        packet_val = packet_f->value;
        switch (field_len) {
            case 1:
                if (has_mask) {
                    if (!match_mask8(flow_val, flow_mask, packet_val))
                        return false;
                }
                else {
                    if (!match_8(flow_val, packet_val))
                        return false;
                }
                break;
            case 2:
                switch (packet_header) {
                    case OXM_OF_VLAN_VID: {
                        /* Special handling for VLAN ID */
                        uint16_t flow_vlan_id = *((uint16_t*) flow_val);
                        if (flow_vlan_id == OFPVID_NONE) {
                            /* Packet has a VLAN tag when none should be there */
                            return false;
                        } else if (flow_vlan_id == OFPVID_PRESENT) {
                            /* Any VLAN ID is acceptable. No further checks */
                        } else {
                            /* Check the VLAN ID */
                            flow_vlan_id &= VLAN_VID_MASK;
                            if (has_mask){
                                if (!match_mask16((uint8_t*) &flow_vlan_id, flow_mask, packet_val)){
                                    return false;
                                }
                            }
                            else {
                                if (!match_16((uint8_t*) &flow_vlan_id, packet_val)){
                                    return false;
                                }
                            }
                        }
                        break;
                    }
                    case OXM_OF_IPV6_EXTHDR: {
                        /* Special handling for IPv6 Extension header */
                        uint16_t flow_eh = *((uint16_t *) flow_val);
                        uint16_t packet_eh = *((uint16_t *) packet_val);
                        if ((flow_eh & packet_eh) != flow_eh) {
                            /* The packet doesn't have all extension headers specified in the flow */
                            return false;
                        }
                        break;
                    }
                    default:
                        if (has_mask) {
                            if (!match_mask16(flow_val, flow_mask, packet_val))
                                return false;
                        }
                        else {
                            if (!match_16(flow_val, packet_val))
                                return false;
                        }
                        break;
                }
                break;
            case 3:
                if (has_mask) {
                    if (!match_mask24(flow_val, flow_mask, packet_val))
                        return false;
                }
                else {
                    if (!match_24(flow_val, packet_val))
                        return false;
                }
                break;
            case 4:
                if (has_mask) {
                    if (!match_mask32(flow_val, flow_mask, packet_val))
                        return false;
                }
                else {
                    if (!match_32(flow_val, packet_val))
                        return false;
                }
                break;
            case 6:
                if (has_mask) {
                    if (!match_mask48(flow_val, flow_mask, packet_val))
                        return false;
                }
                else {
                    if (!match_48(flow_val, packet_val))
                        return false;
                }
                break;
            case 8:
                if (has_mask) {
                    if (!match_mask64(flow_val, flow_mask, packet_val))
                        return false;
                }
                else {
                    if (!match_64(flow_val, packet_val))
                        return false;
                }
                break;
            case 16:
                if (has_mask) {
                    if (!match_mask128(flow_val, flow_mask, packet_val))
                        return false;
                }
                else {
                    if (!match_128(flow_val, packet_val))
                        return false;
                }
                break;
            default:
                /* Should never happen */
                break;
        }
    }
    /* If we get here, all match fields in the flow entry matched the packet */
    return true;
}


static inline bool
strict_mask8(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return ((am[0] == bm[0]) && ((a[0] ^ b[0]) & am[0])) == 0;
}

static inline bool
strict_mask16(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    uint16_t *mask_a = (uint16_t *) am;
    uint16_t *mask_b = (uint16_t *) bm;
    return ((*mask_a == *mask_b) && ((*a1 ^ *b1) & (*mask_a))) == 0;
}

static inline bool
strict_mask24(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return strict_mask16(a, b, am, bm) &&
           strict_mask8(a+2, b+2, am+2, bm+2);
}

static inline bool
strict_mask32(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask_a = (uint32_t *) am;
    uint32_t *mask_b = (uint32_t *) bm;
    return ((*mask_a == *mask_b) && ((*a1 ^ *b1) & (*mask_a))) == 0;
}

static inline bool
strict_mask_ip(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask_a = (uint32_t *) am;
    uint32_t *mask_b = (uint32_t *) bm;
    return ((*mask_a == *mask_b) && ((*a1 ^ *b1) & (*mask_a))) == 0;
}

static inline bool
strict_mask48(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return strict_mask32(a, b, am, bm) &&
           strict_mask16(a+4, b+4, am+4, bm+4);
}

static inline bool
strict_mask64(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint64_t *a1 = (uint64_t *) a;
    uint64_t *b1 = (uint64_t *) b;
    uint64_t *mask_a = (uint64_t *) am;
    uint64_t *mask_b = (uint64_t *) bm;
    return ((*mask_a == *mask_b) && ((*a1 ^ *b1) & (*mask_a))) == 0;
}

static inline bool
strict_mask128(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return strict_mask64(a, b, am, bm) &&
           strict_mask64(a+8, b+8, am+8, bm+8);

}


/* Two matches strictly match if their wildcard fields are the same, and all the
 * non-wildcarded fields match on the same exact values.
 * NOTE: Handling of bitmasked fields is not specified. In this implementation
 * masked fields are checked for equality, and only unmasked bits are compared
 * in the field.
 */
bool
match_std_strict(struct ofl_match *a, struct ofl_match *b) {

    struct ofl_match_tlv *flow_mod_match;
    struct ofl_match_tlv *flow_entry_match;
    int field_len;
    uint8_t *flow_mod_val, *flow_mod_mask=0;
    uint8_t *flow_entry_val, *flow_entry_mask=0;
    uint8_t oxm_field;
    bool has_mask;

    /* Both matches all wildcarded */
    if(!a->header.length && !b->header.length )
        return true;

    /* If the matches differ in length, there is no reason to compare */
    if (a->header.length != b->header.length)
        return false;

    /* Loop through the flow_mod match fields */
    HMAP_FOR_EACH(flow_mod_match, struct ofl_match_tlv, hmap_node, &a->match_fields)
    {
        /* Check presence of match field in flow entry */
        flow_entry_match = oxm_match_lookup(flow_mod_match->header, b);
        if (!flow_entry_match) {
            return false;
        }

        /* At this point match length and has_mask are equal */
        oxm_field = OXM_FIELD(flow_mod_match->header);
        has_mask = OXM_HASMASK(flow_mod_match->header);
        field_len =  OXM_LENGTH(flow_mod_match->header);
        flow_mod_val = flow_mod_match->value;
        flow_entry_val = flow_entry_match->value;
        if (has_mask)
        {
            field_len /= 2;
            flow_mod_mask = flow_mod_match->value + field_len;
            flow_entry_mask = flow_entry_match->value + field_len;
        }
        switch (field_len) {
            case 1:
                if (has_mask) {
                    if (!strict_mask8(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask)){
                        return false;
                    }
                }
                else {
                    if (!match_8(flow_mod_val, flow_entry_val)){
                        return false;
                    }
                }
                break;
            case 2:
                if (has_mask) {
                    if (!strict_mask16(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask)){
                        return false;
                    }
                }
                else {
                    if (!match_16(flow_mod_val, flow_entry_val)){
                        return false;
                    }
                }
                break;
            case 3:
                if (has_mask) {
                    if (!strict_mask24(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask))
                        return false;
                }
                else {                    
                    if (!match_24(flow_mod_val, flow_entry_val)){
                        return false;
                    }
                }
                break;
            case 4:
                if (has_mask) {
                    /* Quick and dirty fix for IP addresses matching 
                       TODO: Matching needs a huge refactoring  */
                    if (oxm_field == OFPXMT_OFB_IPV4_SRC ||
                        oxm_field == OFPXMT_OFB_IPV4_DST ||
                        oxm_field == OFPXMT_OFB_ARP_SPA ||
                        oxm_field == OFPXMT_OFB_ARP_TPA) {
                        if (!strict_mask_ip(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask)){
                            return false;
                        }
                    }
                    if (!strict_mask32(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask)){
                        return false;
                    }
                }
                else {

                    if (!match_32(flow_mod_val, flow_entry_val)){
                        return false;
                    }
                }
                break;
            case 6:
                if (has_mask) {
                    if (!strict_mask48(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask)){
                        return false;
                    }
                }
                else {
                    if (!match_48(flow_mod_val, flow_entry_val)){
                        return false;
                    }
                }
                break;
            case 8:
                if (has_mask) {
                    if (!strict_mask64(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask)){
                        return false;
                    }
                }
                else {
                    if (!match_64(flow_mod_val, flow_entry_val)){
                        return false;
                    }
                }
                break;
            case 16:
                if (has_mask) {
                    if (!strict_mask128(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask)){
                        return false;
                    }
                }
                else {
                    if (!match_128(flow_mod_val, flow_entry_val)){
                        return false;
                    }
                }
                break;
            default:
                /* Should never happen */
                break;
        } /* switch (field_len) */

    } /* HMAP_FOR_EACH */

    /* If we get here, all match fields in flow_mod were equal to the ones in flow entry */
    /* There can't be more fields in the flow entry as the lengths are the same */
    return true;
}


static inline bool
nonstrict_mask8(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {

    return (~am[0] & (~a[0] | ~b[0] | bm[0]) & (a[0] | b[0] | bm[0])) == 0;
}

static inline bool
nonstrict_mask16(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    uint16_t *mask_a = (uint16_t *) am;
    uint16_t *mask_b = (uint16_t *) bm;
    return (~(*mask_a) & (~(*a1) | ~(*b1) | *mask_b) & (*a1| *b1 | *mask_b)) == 0;
}

static inline bool
nonstrict_mask24(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return nonstrict_mask16(a,  b, am, bm) &&
           nonstrict_mask8(a+2, b+2, am+2, bm+2);
}

static inline bool
nonstrict_mask32(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask_a = (uint32_t *) am;
    uint32_t *mask_b = (uint32_t *) bm;
    return (~(*mask_a) & (~(*a1) | ~(*b1) | *mask_b) & (*a1| *b1 | *mask_b)) == 0;
}

static inline bool
nonstrict_mask48(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return nonstrict_mask32(a,  b, am, bm) &&
           nonstrict_mask16(a+4, b+4, am+4, bm+4);
}

static inline bool
nonstrict_mask64(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint64_t *a1 = (uint64_t *) a;
    uint64_t *b1 = (uint64_t *) b;
    uint64_t *mask_a = (uint64_t *) am;
    uint64_t *mask_b = (uint64_t *) bm;
    return (~(*mask_a) & (~(*a1) | ~(*b1) | *mask_b) & (*a1| *b1 | *mask_b)) == 0;
}

static inline bool
nonstrict_mask128(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return nonstrict_mask64(a, b, am, bm) &&
           nonstrict_mask64(a+8, b+8, am+8, bm+8);
}

/* Flow entry (a) matches flow entry (b) non-strictly if (a) matches whenever (b) matches.
 * Thus, flow (a) must not have more match fields than (b) and all match fields in (a) must
 * be equal or narrower in (b).
 * NOTE: Handling of bitmasked fields is not specified. In this implementation
 * a masked field of (a) matches the field of (b) if all masked bits of (b) are
 * also masked in (a), and for each unmasked bits of (b) , the bit is either
 * masked in (a), or is set to the same value in both matches.
 *
 */
bool
match_std_nonstrict(struct ofl_match *a, struct ofl_match *b)
{
    struct ofl_match_tlv *flow_mod_match;
    struct ofl_match_tlv *flow_entry_match;
    int field_len;
    uint8_t *flow_mod_val, *flow_mod_mask=0;
    uint8_t *flow_entry_val, *flow_entry_mask=0;
    bool has_mask;

    /* Flow a is fully wildcarded */
    if (!a->header.length)
        return true;

    /* Loop through the match fields in flow entry a */
    HMAP_FOR_EACH(flow_mod_match, struct ofl_match_tlv, hmap_node, &a->match_fields)
    {
        /* Check presence of match field in flow entry */
        flow_entry_match = oxm_match_lookup(flow_mod_match->header, b);
        if (!flow_entry_match) {
            return false;
        }

        /* At this point match length and has_mask are equal */
        has_mask = OXM_HASMASK(flow_mod_match->header);
        field_len =  OXM_LENGTH(flow_mod_match->header);
        flow_mod_val = flow_mod_match->value;
        flow_entry_val = flow_entry_match->value;
        if (has_mask)
        {
            field_len /= 2;
            flow_mod_mask = flow_mod_match->value + field_len;
            flow_entry_mask = flow_entry_match->value + field_len;
        }
        switch (field_len) {
            case 1:
                if (has_mask) {
                    if (!nonstrict_mask8(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask))
                        return false;
                }
                else {
                    if (!match_8(flow_mod_val, flow_entry_val))
                        return false;
                }
                break;
            case 2:
                if (has_mask) {
                    if (!nonstrict_mask16(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask))
                        return false;
                }
                else {
                    if (!match_16(flow_mod_val, flow_entry_val))
                        return false;
                }
                break;
             case 3:
                if (has_mask) {
                    if (!nonstrict_mask24(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask))
                        return false;
                }
                else {
                    if (!match_24(flow_mod_val, flow_entry_val))
                        return false;
                }
                break;
            case 4:
                if (has_mask) {
                    if (!nonstrict_mask32(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask))
                        return false;
                }
                else {
                    if (!match_32(flow_mod_val, flow_entry_val))
                        return false;
                }
                break;
            case 6:
                if (has_mask) {
                    if (!nonstrict_mask48(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask))
                        return false;
                }
                else {
                    if (!match_48(flow_mod_val, flow_entry_val))
                        return false;
                }
                break;
            case 8:
                if (has_mask) {
                    if (!nonstrict_mask64(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask))
                        return false;
                }
                else {
                    if (!match_64(flow_mod_val, flow_entry_val))
                        return false;
                }
                break;
            case 16:
                if (has_mask) {
                    if (!nonstrict_mask128(flow_mod_val, flow_entry_val, flow_mod_mask, flow_entry_mask))
                        return false;
                }
                else {
                    if (!match_128(flow_mod_val, flow_entry_val))
                        return false;
                }
                break;
            default:
                /* Should never happen */
                break;
        } /* switch (field_len) */

    } /* HMAP_FOR_EACH */

    /* If we get here, all match fields in flow a were equal or wider than the ones in b */
    /* It doesn't matter if there are further fields in b */
    return true;
}

/* Two masked values are incompatible if their bits differ in positions
 * that are marked as valid in both masks
 */

static inline bool
incompatible_8(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {

    return (( (*am&*a) ^ (*bm&*b) ) != 0);
}

static inline bool
incompatible_16(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    uint16_t *mask_a = (uint16_t *) am;
    uint16_t *mask_b = (uint16_t *) bm;

    return (( (*mask_a&*a1) ^ (*mask_b&*b1) ) != 0);
}

static inline bool
incompatible_32(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask_a = (uint32_t *) am;
    uint32_t *mask_b = (uint32_t *) bm;

    return (( (*mask_a&*a1)^(*mask_b&*b1) ) != 0);
}

static inline bool
incompatible_48(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return (incompatible_32(a, b, am, bm) ||
		    incompatible_16(a+4, b+4, am+4, bm+4));
}

static inline bool
incompatible_64(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint64_t *a1 = (uint64_t *) a;
    uint64_t *b1 = (uint64_t *) b;
    uint64_t *mask_a = (uint64_t *) am;
    uint64_t *mask_b = (uint64_t *) bm;

    return (( (*mask_a&*a1) ^ (*mask_b&*b1) ) != 0);
}

static inline bool
incompatible_128(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return (incompatible_64(a, b, am, bm) ||
			incompatible_64(a+8, b+8, am+8, bm+8));
}


/* Two flow matches overlap if there exists a packet which both match structures match on.
 * Conversely, two flow matches do not overlap if they share at least one match field with
 * incompatible value/mask fields that can't match any packet.
 */

bool
match_std_overlap(struct ofl_match *a, struct ofl_match *b)
{
	uint64_t all_mask[2] = {~0L, ~0L};

    struct ofl_match_tlv *f_a;
    struct ofl_match_tlv *f_b;
    int	header, header_m;
    int field_len;
    uint8_t *val_a, *mask_a;
    uint8_t *val_b, *mask_b;

    /* Loop through the match fields in flow entry a */
    HMAP_FOR_EACH(f_a, struct ofl_match_tlv, hmap_node, &a->match_fields)
    {
        field_len = OXM_LENGTH(f_a->header);
        val_a = f_a->value;
    	if (OXM_HASMASK(f_a->header)) {
    		field_len /= 2;
        	header = (f_a->header & 0xfffffe00) | field_len;
        	header_m = f_a->header;
        	mask_a = f_a->value + field_len;
    	} else {
    		header = f_a->header;
    		header_m = (f_a->header & 0xfffffe00) | 0x100 | (field_len << 1);
    		/* Set a dummy mask with all bits set to 0 (valid) */
        	mask_a = (uint8_t *) all_mask;
    	}

        /* Check presence of corresponding match field in flow entry b
         * Need to check for both masked and non-masked field */
    	f_b = oxm_match_lookup(header, b);
    	if (!f_b) f_b = oxm_match_lookup(header_m, b);

        if (f_b) {
        	val_b = f_b->value;
        	if (OXM_HASMASK(f_b->header)) {
            	mask_b = f_b->value + field_len;
        	} else {
        		/* Set a dummy mask with all bits set to 0 (valid) */
            	mask_b = (uint8_t *) all_mask;
        	}
            switch (field_len) {
                case 1:
                	if (incompatible_8(val_a, val_b, mask_a, mask_b)) {
                		return false;
                    }
                    break;
                case 2:
                	if (incompatible_16(val_a, val_b, mask_a, mask_b)) {
                		return false;
                    }
                    break;
                case 4:
                	if (incompatible_32(val_a, val_b, mask_a, mask_b)) {
                		return false;
                    }
                    break;
                case 6:
                	if (incompatible_48(val_a, val_b, mask_a, mask_b)) {
                		return false;
                    }
                    break;
                case 8:
                	if (incompatible_64(val_a, val_b, mask_a, mask_b)) {
                		return false;
                    }
                    break;
                case 16:
                	if (incompatible_128(val_a, val_b, mask_a, mask_b)) {
                		return false;
                    }
                    break;
                default:
                    /* Should never happen */
                    break;
            } /* switch (field_len) */

        } /* if (f_b) */

    } /* HMAP_FOR_EACH */

    /* If we get here, none of the common match fields in a and b were found incompatible.
     * The flow entries overlap */
    return true;
}

