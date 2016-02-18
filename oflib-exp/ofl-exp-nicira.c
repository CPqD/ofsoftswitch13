/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
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
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdlib.h>
#include <stdio.h>
#include <netinet/in.h>

#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "ofl-exp-nicira.h"
#include "../oflib/ofl-print.h"
#include "../oflib/ofl-log.h"

#define LOG_MODULE ofl_exp_nx
OFL_LOG_INIT(LOG_MODULE)


int
ofl_exp_nicira_msg_pack(struct ofl_msg_experimenter const *msg, uint8_t **buf, size_t *buf_len)
{
    if (msg->experimenter_id == NX_VENDOR_ID) {
        struct ofl_exp_nicira_msg_header *exp = (struct ofl_exp_nicira_msg_header *)msg;
        switch (exp->type) {
            case (NXT_ROLE_REQUEST):
            case (NXT_ROLE_REPLY): {
                struct ofl_exp_nicira_msg_role *role = (struct ofl_exp_nicira_msg_role *)exp;
                struct nx_role_request *ofp;

                *buf_len = sizeof(struct nx_role_request);
                *buf     = (uint8_t *)malloc(*buf_len);

                ofp = (struct nx_role_request *)(*buf);
                ofp->nxh.vendor =  htonl(exp->header.experimenter_id);
                ofp->nxh.subtype = htonl(exp->type);
                ofp->role = htonl(role->role);

                return 0;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Nicira Experimenter message.");
                return -1;
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-Nicira Experimenter message.");
        return -1;
    }
}

ofl_err
ofl_exp_nicira_msg_unpack(struct ofp_header const *oh, size_t *len, struct ofl_msg_experimenter **msg)
{
    struct nicira_header *exp;

    if (*len < sizeof(struct nicira_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct nicira_header *)oh;

    if (ntohl(exp->vendor) == NX_VENDOR_ID) {

        switch (ntohl(exp->subtype)) {
            case (NXT_ROLE_REQUEST):
            case (NXT_ROLE_REPLY): {
                struct nx_role_request *src;
                struct ofl_exp_nicira_msg_role *dst;

                if (*len < sizeof(struct nx_role_request)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received NXT_ROLE_REPLY message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }
                *len -= sizeof(struct nx_role_request);

                src = (struct nx_role_request *)exp;

                dst = (struct ofl_exp_nicira_msg_role *)malloc(sizeof(struct ofl_exp_nicira_msg_role));
                dst->header.header.experimenter_id = ntohl(exp->vendor);
                dst->header.type                   = ntohl(exp->subtype);
                dst->role                          = ntohl(src->role);

                (*msg) = (struct ofl_msg_experimenter *)dst;
                return 0;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Nicira Experimenter message.");
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to unpack non-Nicira Experimenter message.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
    }
    free(msg);
    return 0;
}

int
ofl_exp_nicira_msg_free(struct ofl_msg_experimenter *msg)
{
    if (msg->experimenter_id == NX_VENDOR_ID) {
        struct ofl_exp_nicira_msg_header *exp = (struct ofl_exp_nicira_msg_header *)msg;
        switch (exp->type) {
            case (NXT_ROLE_REQUEST):
            case (NXT_ROLE_REPLY): {
                break;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Nicira Experimenter message.");
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to free non-Nicira Experimenter message.");
    }
    free(msg);
    return 0;
}

char *
ofl_exp_nicira_msg_to_string(struct ofl_msg_experimenter const *msg)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    if (msg->experimenter_id == NX_VENDOR_ID) {
        struct ofl_exp_nicira_msg_header *exp = (struct ofl_exp_nicira_msg_header *)msg;
        switch (exp->type) {
            case (NXT_ROLE_REQUEST):
            case (NXT_ROLE_REPLY): {
                struct ofl_exp_nicira_msg_role *r = (struct ofl_exp_nicira_msg_role *)exp;
                fprintf(stream, "%s{role=\"%s\"}",
                              exp->type == NXT_ROLE_REQUEST ? "rolereq" : "rolerep",
                              r->role == NX_ROLE_MASTER ? "master" :
                              r->role == NX_ROLE_SLAVE ? "slave"
                                                       : "other");
                break;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Nicira Experimenter message.");
                fprintf(stream, "ofexp{type=\"%u\"}", exp->type);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-Nicira Experimenter message.");
        fprintf(stream, "exp{exp_id=\"%u\"}", msg->experimenter_id);
    }

    fclose(stream);
    return str;
}
