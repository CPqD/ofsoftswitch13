/* Copyright (c) 2012, CPqD, Brazil
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
/*
 * Copyright (c) 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OXM_MATCH_H
#define OXM_MATCH_H 1

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include "ofpbuf.h"
#include "hmap.h"
#include "packets.h"
#include "openflow/openflow.h" 
#include "../oflib/ofl-structs.h"


#define OXM_VENDOR(HEADER) ((HEADER) >> 16)
#define OXM_FIELD(HEADER) (((HEADER) >> 9) & 0x7f)
#define OXM_TYPE(HEADER) (((HEADER) >> 9) & 0x7fffff)
#define OXM_HASMASK(HEADER) (((HEADER) >> 8) & 1)
#define OXM_LENGTH(HEADER) ((HEADER) & 0xff)
#define VENDOR_FROM_TYPE(TYPE) ((TYPE) >> 7)
#define FIELD_FROM_TYPE(TYPE)  ((TYPE) & 0x7f)

enum oxm_field_index {
#define DEFINE_FIELD(HEADER,DL_TYPES, NW_PROTO, MASKABLE) \
        OFI_OXM_##HEADER,
#include "oxm-match.def"
    NUM_OXM_FIELDS = 56
};

struct oxm_field {
    struct hmap_node hmap_node;
    enum oxm_field_index index;       /* OFI_* value. */
    uint32_t header;                  /* OXM_* value. */
    uint16_t dl_type[N_OXM_DL_TYPES]; /* dl_type prerequisites. */
    uint8_t nw_proto;                 /* nw_proto prerequisite, if nonzero. */
    bool maskable;                    /* Writable with OXAST_REG_{MOVE,LOAD}? */
};

/* All the known fields. */
extern struct oxm_field all_fields[NUM_OXM_FIELDS];

bool 
check_bad_wildcard(uint8_t value, uint8_t mask);

bool 
check_bad_wildcard16(uint16_t value, uint16_t mask);

bool 
check_bad_wildcard32(uint32_t value, uint32_t mask);

bool 
check_bad_wildcard48(uint8_t *value, uint8_t *mask);

bool 
check_bad_wildcard64(uint64_t value, uint64_t mask);

bool 
check_bad_wildcard128(uint8_t *value, uint8_t *mask);

struct oxm_field *
oxm_field_lookup(uint32_t header);

bool
oxm_prereqs_ok(const struct oxm_field *field, const struct ofl_match *rule);

int
oxm_pull_match(struct ofpbuf * buf, struct ofl_match *match_dst, int match_len);

int oxm_put_match(struct ofpbuf *buf, struct ofl_match *omt);

struct ofl_match_tlv *
oxm_match_lookup(uint32_t header, const struct ofl_match *omt);

uint32_t oxm_entry_ok(const void *, unsigned int );

int
oxm_field_bytes(uint32_t header);

int
oxm_field_bits(uint32_t header);



#endif /* oxm-match.h */
