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
#include "nbee_link/nbee_link.h"


/* Two matches overlap, if there exists a packet,
   which both match structures match on. */
bool
match_std_overlap(struct ofl_match *a, struct ofl_match *b) {
    return (match_std_nonstrict(a, b) || match_std_nonstrict(b, a));
}

static int
matches_8(uint8_t *a, uint8_t *b) {
     return ((a[0] ^ b[0]) == 0x00);
}     

/* Returns true if two values of 8 bit size match, considering their masks. */
static int
pkt_mask8(uint8_t *a, uint8_t *am, uint8_t *b) {
     return ((~(am[0]) & (a[0] ^ b[0])) == 0x00);
}     

/* Returns true if two values of 16 bit size match */
static int
pkt_match_16(uint8_t *a, uint8_t *b) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    return ((*a1 ^ ntohs(*b1)) == 0);
}


/* Returns true if two values of 16 bit size match */
static int
matches_16(uint8_t *a, uint8_t *b) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    return (((*a1 ^ *b1)) == 0);
}


/* Returns true if two values of 16 bit size match, considering their masks. */
static int
pkt_mask16(uint8_t *a, uint8_t *am, uint8_t *b) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    uint16_t *mask = (uint16_t *) am;
    
    return (((~*mask) & (*a1 ^ ntohs(*b1))) == 0);
}

/* Returns true if two values of 16 bit size match, considering their masks. */
static int
matches_mask16(uint8_t *a, uint8_t *am, uint8_t *b) {
    uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    uint16_t *mask = (uint16_t *) am;

    return (((~*mask) & (*a1 ^ *b1)) == 0);
}


/*Returns true if two values of 32 bit size match . */
static int
pkt_match_32(uint8_t *a, uint8_t *b) {  
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    return ((*a1 ^ ntohl(*b1)) == 0);
}

/*Returns true if two values of 32 bit size match . */
static int
matches_32(uint8_t *a, uint8_t *b) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    return ((*a1 ^ *b1) == 0);
}

/*Returns true if two values of 32 bit size match, considering their masks. */
static int
pkt_mask32(uint8_t *a, uint8_t *am, uint8_t *b) { 
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask = (uint32_t *) am;
    
    return (((~*mask) & (*a1 ^ ntohl(*b1))) == 0);
}

/*Returns true if two values of 32 bit size match, considering their masks. */
static int
matches_mask32(uint8_t *a, uint8_t *am, uint8_t *b) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask = (uint32_t *) am;

    return (((~*mask) & (*a1 ^ *b1)) == 0);
}

/* Returns true if two values of 64 bits size match*/
static int
pkt_64(uint8_t *a, uint8_t *b) {
    uint64_t *a1 = (uint64_t *) a;
    uint64_t *b1 = (uint64_t *) b;

    return ((*a1 ^ ntohll(*b1)) == 0);
}

/* Returns true if two values of 64 bits size match*/ 
static int
matches_64(uint8_t *a, uint8_t *b) {    
    uint64_t *a1 = (uint64_t *) a; 
    uint64_t *b1 = (uint64_t *) b;
    
    return ((*a1 ^ *b1) == 0);
} 

/* Returns true if two values of 64 bits size match, considering their masks.*/ 
static int
pkt_mask64(uint8_t *a,uint8_t *am, uint8_t *b) {   
    uint64_t *a1 = (uint64_t *) a; 
    uint64_t *b1 = (uint64_t *) b;
    uint64_t *mask = (uint64_t *) am;
    
    return (((~*mask) & (*a1 ^ ntohll(*b1))) == 0);
} 

/* Returns true if two values of 64 bits size match, considering their masks.*/
static int
matches_mask64(uint8_t *a,uint8_t *am, uint8_t *b) { 
    uint64_t *a1 = (uint64_t *) a;
    uint64_t *b1 = (uint64_t *) b;
    uint64_t *mask = (uint64_t *) am;

    return (((~*mask) & (*a1 ^ *b1)) == 0);
} 

/* Returns true if the two ethernet addresses match */
static int
eth_match(uint8_t *a, uint8_t *b) {
     return (matches_32(a,b) && matches_16(a+4,b+4) );
}

/* Returns true if the two ethernet addresses match, considering their masks. */
static int
eth_mask(uint8_t *a, uint8_t *am, uint8_t *b) {
     return (matches_mask32(a,am,b) && matches_mask16(a+4,am+4,b+4) );
}

static int
ipv6_match(uint8_t *a, uint8_t *b) {
    return (matches_64(a,b) && matches_64(a+8,b+8));
}

static int
ipv6_mask(uint8_t *a, uint8_t *am, uint8_t *b) {    
    return (matches_mask64(a,am,b) && matches_mask64(a+8,am+8,b+8));
}

bool 
packet_match(struct ofl_match *flow_match, struct ofl_match *packet){

    struct ofl_match_tlv *f; 
    struct packet_fields *packet_f;
    bool ret = false;

    if (flow_match->header.length == 0){
        return true;
    }
    /*TODO: Possible combinations of VLAN_ID and masks */
    HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv, hmap_node,hash_int(OXM_OF_VLAN_VID, 0), &flow_match->match_fields){
        uint16_t *matchv = (uint16_t*) f->value;
        /* Check if the field is present in the packet */
        HMAP_FOR_EACH_WITH_HASH(packet_f, struct packet_fields, hmap_node, hash_int(OXM_OF_VLAN_VID, 0), &packet->match_fields){     
            /* Do not match packets with a VLAN Tag */
            if (*matchv == OFPVID_NONE && !OXM_HASMASK(f->header))
                return false;
            ret = true;
        }

        if ((*matchv == OFPVID_PRESENT)  & (OXM_HASMASK(f->header))){
            uint16_t *maskv = (uint16_t*) f->value + 2;
                if (*maskv == OFPVID_PRESENT && !ret )
                    return false;     
        }
          
    }      

    /* Loop through the match fields */
    HMAP_FOR_EACH(f, struct ofl_match_tlv, hmap_node, &flow_match->match_fields){
        /* Check if the field is present in the packet */
        HMAP_FOR_EACH_WITH_HASH(packet_f, struct packet_fields, hmap_node, hash_int(f->header, 0), &packet->match_fields){ 
                int field_len =  OXM_LENGTH(f->header);
                bool has_mask = OXM_HASMASK(f->header);
                ret = true;
                switch (field_len){
                    case (sizeof(uint8_t)):{
                        if (has_mask){
                            if (pkt_mask8(f->value,f->value + field_len, packet_f->value) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_8(f->value, packet_f->value) == 0){
                              return false;
                        }
                        break;   
                    }
                    case (sizeof(uint16_t)):{
                        if (has_mask){
                            if (pkt_mask16(f->value,f->value+ field_len, packet_f->value) == 0){
                              return false;
                            }
                        }
                        else {
                            if (pkt_match_16(f->value, packet_f->value) == 0){
                              return false;
                            }
                        }
                        break;
                    } 
                    case (sizeof(uint32_t)):{ 
                        if (has_mask){
                            if (f->header == OXM_OF_IPV4_DST || f->header == OXM_OF_IPV4_SRC
							    ||f->header == OXM_OF_ARP_SPA || f->header == OXM_OF_ARP_TPA){
							    if (matches_mask32(f->value,f->value + field_len, packet_f->value) == 0){
                                     return false;
                                }
                            }     
                            else 
                                if (pkt_mask32(f->value,f->value + field_len, packet_f->value) == 0){
                                    return false;
                            }
                        }
                        else
                            if (f->header == OXM_OF_IPV4_DST || f->header == OXM_OF_IPV4_SRC
							    ||f->header == OXM_OF_ARP_SPA || f->header == OXM_OF_ARP_TPA){
							    if (matches_32(f->value, packet_f->value) == 0){
                                     return false;
                                }
                            }
                            
                            else 
                                if (pkt_match_32(f->value, packet_f->value) == 0){
                                    return false;
                            }
                        break;
                    }
                    case (ETH_ADDR_LEN):{ 
                         if (has_mask){
                            if (eth_mask(f->value,f->value + field_len, packet_f->value) == 0){
                              return false;
                            }
                         }
                        else 
                            if (eth_match(f->value, packet_f->value) == 0){
                              return false;
                            }
                        break;
                    }
                    case (sizeof(uint64_t)):{ 
                        if (has_mask) {
                            if (pkt_mask64(f->value,f->value + field_len, packet_f->value) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_64(f->value, packet_f->value) == 0){
                              return false;
                            }
                        break;
                    }
   		            case (16):{
                        if (has_mask){
                            if (ipv6_mask(f->value,f->value + field_len, packet_f->value) == 0){
                              return false;
                            }
                        }
                        else 
                            if (ipv6_match(f->value, packet_f->value) == 0){
                              return false;
                            }
                        break;
                    }
               
            }
        }
         if (!ret)
            return ret;
         else ret = false;      
    }

    return true;

}


static inline bool
strict_mask8(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return (am[0] == bm[0]) && ((a[0] ^ b[0]) & ~am[0]) == 0;
}

static inline bool
strict_mask16(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	uint16_t *a1 = (uint16_t *) a;
    uint16_t *b1 = (uint16_t *) b;
    uint16_t *mask_a = (uint16_t *) am;
	uint16_t *mask_b = (uint16_t *) bm;
	return (*mask_a == *mask_b) && ((*a1 ^ *b1) & ~(*mask_a)) == 0;
}

static inline bool
strict_mask32(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask_a = (uint32_t *) am;
	uint32_t *mask_b = (uint32_t *) bm;
	return (*mask_a == *mask_b) && ((*a1 ^ *b1) & ~(*mask_a)) == 0;
}

static inline bool
strict_mask64(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	uint64_t *a1 = (uint64_t *) a;
    uint64_t *b1 = (uint64_t *) b;
    uint64_t *mask_a = (uint64_t *) am;
	uint64_t *mask_b = (uint64_t *) bm;
	return (*mask_a == *mask_b) && ((*a1 ^ *b1) & ~(*mask_a)) == 0;
}

static inline bool
strict_ethaddr(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return strict_mask32(a,b,am,bm) &&
		   strict_mask16(a+4, b+4, am+4, bm+4);
}
		   
		   
static inline bool
strict_ipv6(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    return strict_mask64(a,b,am,bm) &&
		   strict_mask64(a+8, b+8, am+8, bm+8);

}

/* Two matches strictly match, if their wildcard fields are the same, and all the
 * non-wildcarded fields match on the same exact values.
 * NOTE: Handling of bitmasked fields is not specified. In this implementation
 * masked fields are checked for equality, and only unmasked bits are compared
 * in the field.
 */
bool
match_std_strict(struct ofl_match *a, struct ofl_match *b) {
  
    struct ofl_match_tlv *flow_mod_match; 
    struct ofl_match_tlv *flow_entry_match;
    bool ret = false;

    /*Both matches all wildcarded */
    if(!a->header.length && !b->header.length )
        return true;
    /* If the matches differ in length, there is no reason to compare
        once they will differ in the number of fields */
    if (a->header.length != b->header.length)
        return false;

   
    /* Loop through the match fields */
    HMAP_FOR_EACH(flow_mod_match, struct ofl_match_tlv, hmap_node, &a->match_fields){
       /* Check if the field is present in the flow entry */
        HMAP_FOR_EACH_WITH_HASH(flow_entry_match, struct ofl_match_tlv, hmap_node, hash_int(flow_mod_match->header, 0), &b->match_fields){                  
                int field_len =  OXM_LENGTH(flow_mod_match->header);
                bool has_mask;
                /* Check if both fields have or not a mask */
                if ( (OXM_HASMASK(flow_mod_match->header) && !OXM_HASMASK(flow_entry_match->header))
                    || (!OXM_HASMASK(flow_mod_match->header) && OXM_HASMASK(flow_entry_match->header))){
                    return false;
                }
                ret = true;
                has_mask = OXM_HASMASK(flow_mod_match->header);
                switch (field_len){
                    case (sizeof(uint8_t)):{
                        if (has_mask){
                            if (strict_mask8(flow_mod_match->value, flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_8(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                        }
                        break;   
                    }
                    case (sizeof(uint16_t)):{ 
                        if (has_mask){
                            if (strict_mask16(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_16(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                        }
                        break;
                    } 
                    case (sizeof(uint32_t)):{ 

                        if (has_mask){
                            if (strict_mask32(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) ){
                              return false;
                            }
                        }
                        else 
                            if (matches_32(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
                    case (ETH_ADDR_LEN):{ 
                         if (has_mask){
                            if (strict_ethaddr(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                         }
                        else 
                            if (eth_match(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
                    case (sizeof(uint64_t)):{ 
                        if (has_mask) {
                            if (strict_mask64(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_64(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
   		            case (16):{
                        if (has_mask){
                            if (strict_ipv6(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len)== 0){
                              return false;
                            }
                        }
                        else 
                            if (ipv6_match(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
 
            }
           
        }
         if (!ret)
            return ret;
        else ret = false;
    } 

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
nonstrict_mask32(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
    uint32_t *a1 = (uint32_t *) a;
    uint32_t *b1 = (uint32_t *) b;
    uint32_t *mask_a = (uint32_t *) am;
	uint32_t *mask_b = (uint32_t *) bm;
    return (~(*mask_a) & (~(*a1) | ~(*b1) | *mask_b) & (*a1| *b1 | *mask_b)) == 0;
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
nonstrict_ethaddr(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return nonstrict_mask32(a,  b, am, bm) &&
		   nonstrict_mask16(a, b, am, bm);
}

static inline bool
nonstrict_ipv6(uint8_t *a, uint8_t *b, uint8_t *am, uint8_t *bm) {
	return nonstrict_mask64(a, b, am, bm) &&
		   nonstrict_mask64(a, b, am, bm);
}

bool
match_std_nonstrict(struct ofl_match *a, struct ofl_match *b) {
  
struct ofl_match_tlv *flow_mod_match; 
    struct ofl_match_tlv *flow_entry_match;
    bool ret = false;

    /*Matches all flows */
    if(!a->header.length )
        return true;
    
    /* Loop through the match fields */
    HMAP_FOR_EACH(flow_mod_match, struct ofl_match_tlv, hmap_node, &a->match_fields){
       /* Check if the field is present in the flow entry */
        HMAP_FOR_EACH_WITH_HASH(flow_entry_match, struct ofl_match_tlv, hmap_node, hash_int(flow_mod_match->header, 0), &b->match_fields){                  
                int field_len =  OXM_LENGTH(flow_mod_match->header);
                bool has_mask;
                /* Check if both fields have or not a mask */
                if ( (OXM_HASMASK(flow_mod_match->header) && !OXM_HASMASK(flow_entry_match->header))
                    || (!OXM_HASMASK(flow_mod_match->header) && OXM_HASMASK(flow_entry_match->header))){
                    return false;
                }
                ret = true;
                has_mask = OXM_HASMASK(flow_mod_match->header);
                switch (field_len){
                    case (sizeof(uint8_t)):{
                        if (has_mask){
                            if (nonstrict_mask8(flow_mod_match->value, flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_8(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                        }
                        break;   
                    }
                    case (sizeof(uint16_t)):{ 
                        if (has_mask){
                            if (nonstrict_mask16(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_16(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                        }
                        break;
                    } 
                    case (sizeof(uint32_t)):{ 
                        
                        if (has_mask){
                            if (nonstrict_mask32(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) ){
                              return false;
                            }
                        }
                        else 
                            if (matches_32(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
                    case (ETH_ADDR_LEN):{ 
                         if (has_mask){
                            if (nonstrict_ethaddr(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                         }
                        else 
                            if (eth_match(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
                    case (sizeof(uint64_t)):{ 
                        if (has_mask) {
                            if (nonstrict_mask64(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len) == 0){
                              return false;
                            }
                        }
                        else 
                            if (matches_64(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
   		            case (16):{
                        if (has_mask){
                            if (nonstrict_ipv6(flow_mod_match->value,flow_entry_match->value + field_len, flow_entry_match->value,flow_entry_match->value + field_len)== 0){
                              return false;
                            }
                        }
                        else 
                            if (ipv6_match(flow_mod_match->value, flow_entry_match->value) == 0){
                              return false;
                            }
                        break;
                    }
 
            }
           
        }
         if (!ret)
            return ret;
        else ret = false;
    } 
    return true;

}

