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

#ifndef OFL_ACTIONS_H
#define OFL_ACTIONS_H 1

#include <sys/types.h>
#include <stdio.h>

#include "ofl.h"
#include "ofl-structs.h"
#include "../include/openflow/openflow.h"

struct ofl_exp;

/****************************************************************************
 * Action structure definitions
 ****************************************************************************/

/* Common header for actions. All action structures - including experimenter
 * ones - must start with this header. */
struct ofl_action_header {
    enum ofp_action_type   type;   /* One of OFPAT_*. */
    uint16_t len; /* Total length */
};


struct ofl_action_output {
    struct ofl_action_header   header; /* OFPAT_OUTPUT. */

    uint32_t   port;    /* Output port. */
    uint16_t   max_len; /* Max length to send to controller. */
};

struct ofl_action_mpls_ttl {
    struct ofl_action_header   header; /* OFPAT_SET_MPLS_TTL. */

    uint8_t   mpls_ttl; /* MPLS TTL */
};

struct ofl_action_push {
    struct ofl_action_header   header; /* OFPAT_PUSH_VLAN/MPLS/PBB. */

    uint16_t   ethertype; /* Ethertype */
};

struct ofl_action_pop_mpls {
    struct ofl_action_header   header; /* OFPAT_POP_MPLS. */

    uint16_t   ethertype; /* Ethertype */
};

struct ofl_action_set_queue {
    struct ofl_action_header   header; /* OFPAT_SET_QUEUE. */

    uint32_t   queue_id;
};

struct ofl_action_group {
    struct ofl_action_header   header; /* OFPAT_GROUP. */

    uint32_t   group_id;  /* Group identifier. */
};

struct ofl_action_set_nw_ttl {
    struct ofl_action_header   header; /* OFPAT_SET_NW_TTL. */

    uint8_t   nw_ttl;
};

struct ofl_action_set_field {
    struct ofl_action_header   header; /* OFPAT_SET_FIELD. */
    struct ofl_match_tlv *field;
};

struct ofl_action_experimenter {
    struct ofl_action_header   header; /* OFPAT_EXPERIMENTER. */

    uint32_t  experimenter_id; /* Experimenter ID */
};


/****************************************************************************
 * Functions for (un)packing action structures
 ****************************************************************************/

/* Packs the action in src to the memory location beginning at the address
 * pointed at by dst. The return value is the length of the resulted structure.
 * In case of an experimenter action, it uses the passed in experimenter
 * callback. */
size_t
ofl_actions_pack(struct ofl_action_header *src, struct ofp_action_header *dst, uint8_t* data, struct ofl_exp *exp);


/* Given a list of action in OpenFlow wire format, these function returns
 * the count of those actions in the passed in byte array. The functions
 * return an ofl_err in case of an error, or 0 on succes. */
ofl_err
ofl_utils_count_ofp_actions(void *data, size_t data_len, size_t *count);


/* Unpacks the wire format action in src to a new memory location and returns a
 * pointer to the location in dst. Returns 0 on success. In case of an
 * experimenter action, it uses the passed in experimenter callback. */
ofl_err
ofl_actions_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst, struct ofl_exp *exp);



/****************************************************************************
 * Functions for freeing action structures
 ****************************************************************************/

/* Calling this function frees the passed in action structure. In case of an
 * experimenter action, it uses the passed in experimenter callback. */
void
ofl_actions_free(struct ofl_action_header *act, struct ofl_exp *exp);



/****************************************************************************
 * Functions for freeing structures
 ****************************************************************************/

/* Returns the length of the resulting OpenFlow action structure from
 * converting the passed in action. In case of an experimenter action, it uses
 * the passed in experimenter callback. */
size_t
ofl_actions_ofp_total_len(struct ofl_action_header **actions, size_t actions_num, struct ofl_exp *exp);

/* Returns the length of the resulting OpenFlow action structures from
 * converting the passed in list of actions. In case of an experimenter action,
 * it uses the passed in experimenter callback. */
size_t
ofl_actions_ofp_len(struct ofl_action_header *action, struct ofl_exp *exp);



/****************************************************************************
 * Functions for printing actions
 ****************************************************************************/

/* Converts the passed in action to a string format. In case of an experimenter
 * action, it uses the passed in experimenter callback. */
char *
ofl_action_to_string(struct ofl_action_header *act, struct ofl_exp *exp);

/* Converts the passed in action to a string format and adds it to the dynamic
 * string. In case of an experimenter action, it uses the passed in
 * experimenter callback. */
void
ofl_action_print(FILE *stream, struct ofl_action_header *act, struct ofl_exp *exp);



#endif /* OFL_ACTIONS */
