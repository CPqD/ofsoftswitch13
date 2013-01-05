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
#include <string.h>
#include <netinet/in.h>
#include "openflow/openflow.h"
#include "openflow/openflow-ext.h"
#include "ofl-exp-openflow.h"
#include "../oflib/ofl-log.h"
#include "../oflib/ofl-print.h"

#define LOG_MODULE ofl_exp_of
OFL_LOG_INIT(LOG_MODULE)


int
ofl_exp_openflow_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len) {
    if (msg->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;
        switch (exp->type) {
            case (OFP_EXT_QUEUE_MODIFY):
            case (OFP_EXT_QUEUE_DELETE): {
                struct ofl_exp_openflow_msg_queue *q = (struct ofl_exp_openflow_msg_queue *)exp;
                struct openflow_queue_command_header *ofp;

                *buf_len = sizeof(struct openflow_queue_command_header) + ofl_structs_packet_queue_ofp_len(q->queue);
                *buf     = (uint8_t *)malloc(*buf_len);

                ofp = (struct openflow_queue_command_header *)(*buf);
                ofp->header.vendor  = htonl(exp->header.experimenter_id);
                ofp->header.subtype = htonl(exp->type);
                ofp->port = htonl(q->port_id);

                ofl_structs_packet_queue_pack(q->queue, (struct ofp_packet_queue *)ofp->body);
                return 0;
            }
            case (OFP_EXT_SET_DESC): {
                struct ofl_exp_openflow_msg_set_dp_desc *s = (struct ofl_exp_openflow_msg_set_dp_desc *)exp;
                struct openflow_ext_set_dp_desc *ofp;

                *buf_len  = sizeof(struct openflow_ext_set_dp_desc);
                *buf     = (uint8_t *)malloc(*buf_len);

                ofp = (struct openflow_ext_set_dp_desc *)(*buf);
                ofp->header.vendor  = htonl(exp->header.experimenter_id);
                ofp->header.subtype = htonl(exp->type);
                strncpy(ofp->dp_desc, s->dp_desc, DESC_STR_LEN);

                return 0;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Openflow Experimenter message.");
                return -1;
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-Openflow Experimenter message.");
        return -1;
    }
}

ofl_err
ofl_exp_openflow_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg) {
    struct ofp_extension_header *exp;

    if (*len < sizeof(struct ofp_extension_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_extension_header *)oh;

    if (ntohl(exp->vendor) == OPENFLOW_VENDOR_ID) {

        switch (ntohl(exp->subtype)) {
            case (OFP_EXT_QUEUE_MODIFY):
            case (OFP_EXT_QUEUE_DELETE): {
                struct openflow_queue_command_header *src;
                struct ofl_exp_openflow_msg_queue *dst;
                ofl_err error;

                if (*len < sizeof(struct openflow_queue_command_header)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received EXT_QUEUE_MODIFY message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }
                *len -= sizeof(struct openflow_queue_command_header);

                src = (struct openflow_queue_command_header *)exp;

                dst = (struct ofl_exp_openflow_msg_queue *)malloc(sizeof(struct ofl_exp_openflow_msg_queue));
                dst->header.header.experimenter_id = ntohl(exp->vendor);
                dst->header.type                   = ntohl(exp->subtype);
                dst->port_id                       = ntohl(src->port);

                error = ofl_structs_packet_queue_unpack((struct ofp_packet_queue *)(src->body), len, &(dst->queue));
                if (error) {
                    free(dst);
                    return error;
                }

                (*msg) = (struct ofl_msg_experimenter *)dst;
                return 0;
            }
            case (OFP_EXT_SET_DESC): {
                struct openflow_ext_set_dp_desc *src;
                struct ofl_exp_openflow_msg_set_dp_desc *dst;

                if (*len < sizeof(struct openflow_ext_set_dp_desc)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received EXT_SET_DESC message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }
                *len -= sizeof(struct openflow_ext_set_dp_desc);

                src = (struct openflow_ext_set_dp_desc *)exp;

                dst = (struct ofl_exp_openflow_msg_set_dp_desc *)malloc(sizeof(struct ofl_exp_openflow_msg_set_dp_desc));
                dst->header.header.experimenter_id = ntohl(exp->vendor);
                dst->header.type                   = ntohl(exp->subtype);

                dst->dp_desc = strcpy((char *)malloc(strlen(src->dp_desc)+1), src->dp_desc);

                (*msg) = (struct ofl_msg_experimenter *)dst;
                return 0;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Openflow Experimenter message.");
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to unpack non-Openflow Experimenter message.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
    }
    free(msg);
    return 0;
}

int
ofl_exp_openflow_msg_free(struct ofl_msg_experimenter *msg) {
    if (msg->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;
        switch (exp->type) {
            case (OFP_EXT_QUEUE_MODIFY):
            case (OFP_EXT_QUEUE_DELETE): {
                struct ofl_exp_openflow_msg_queue *q = (struct ofl_exp_openflow_msg_queue *)exp;
                ofl_structs_free_packet_queue(q->queue);
                break;
            }
            case (OFP_EXT_SET_DESC): {
                struct ofl_exp_openflow_msg_set_dp_desc *s = (struct ofl_exp_openflow_msg_set_dp_desc *)exp;
                free(s->dp_desc);
                break;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Openflow Experimenter message.");
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to free non-Openflow Experimenter message.");
    }
    free(msg);
    return 0;
}

char *
ofl_exp_openflow_msg_to_string(struct ofl_msg_experimenter *msg) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    if (msg->experimenter_id == OPENFLOW_VENDOR_ID) {
        struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;
        switch (exp->type) {
            case (OFP_EXT_QUEUE_MODIFY):
            case (OFP_EXT_QUEUE_DELETE): {
                struct ofl_exp_openflow_msg_queue *q = (struct ofl_exp_openflow_msg_queue *)exp;
                fprintf(stream, "%squeue{port=\"", exp->type == OFP_EXT_QUEUE_MODIFY ? "mod" : "del");
                ofl_port_print(stream, q->port_id);
                fprintf(stream, "\", queue=");
                ofl_structs_queue_print(stream, q->queue);
                fprintf(stream, "}");
                break;
            }
            case (OFP_EXT_SET_DESC): {
                struct ofl_exp_openflow_msg_set_dp_desc *s = (struct ofl_exp_openflow_msg_set_dp_desc *)exp;
                fprintf(stream, "setdesc{desc=\"%s\"}", s->dp_desc);
                break;
            }
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Openflow Experimenter message.");
                fprintf(stream, "ofexp{type=\"%u\"}", exp->type);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-Openflow Experimenter message.");
        fprintf(stream, "exp{exp_id=\"%u\"}", msg->experimenter_id);
    }

    fclose(stream);
    return str;
}
