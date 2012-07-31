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

#ifndef OFL_H
#define OFL_H 1

#include <sys/types.h>

#include "../include/openflow/openflow.h"

struct ofl_msg_experimenter;
struct ofl_msg_multipart_request_header;
struct ofl_msg_multipart_reply_header;
struct ofl_action_header;
struct ofl_instruction_header;
struct ofl_match_header;
struct ofp_action_header;
struct ofp_instruction;
struct ofp_multipart_reply;
struct ofp_match;


/* ofl_err is used to return OpenFlow error type/code's from functions.
 * See ofl_error function for details.
 */
typedef uint32_t ofl_err;

/* In order to allow OFLib to process experimenter features, callback functions
 * must be defined, and passed to the OFLib functions. Each experimenter
 * feature has its own group of callbacks, and these groups are collected in a
 * single ofl_exp structure.
 * If an experimenter feature is not to be used, the callback can be NULLed.
 *
 * The internal representation of the experimenter structures can be freely
 * defined, but they must use the relevant OFLib headers.
 *
 * For each feature the following functions must be provided:
 *
 * pack: given an experimenter structure, the function should return its
 *       OpenFlow wire format representation.
 * unpack: given the OpenFlow wire format representation of an experimenter
 *         structure, it should return the experimenter structure. The passed
 *         in len tells the available length of bytes in the wire format. The
 *         function should subtract the amount of bytes used up during the
 *         conversion.
 * free: passing an experimenter structure, this function must make sure the
 *       structure is freed.
 * ofp_len: passing an experimenter structure, the function must return the
 *          length of the OpenFlow wire format representation of the structure.
 * to_string: passing an experimenter structure, the function must return a
 *            string representation of the structure.
 *
 */

/* Callback functions for handling experimenter actions. */
struct ofl_exp_act {
    int     (*pack)             (struct ofl_action_header *src, struct ofp_action_header *dst);
    ofl_err (*unpack)           (struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst);
    int     (*free)             (struct ofl_action_header *act);
    size_t  (*ofp_len)          (struct ofl_action_header *act);
    char   *(*to_string)        (struct ofl_action_header *act);
};

/* Callback functions for handling experimenter instructions. */
struct ofl_exp_inst {
    int     (*pack)            (struct ofl_instruction_header *src, struct ofp_instruction *dst);
    ofl_err (*unpack)          (struct ofp_instruction *src, size_t *len, struct ofl_instruction_header **dst);
    int     (*free)            (struct ofl_instruction_header *i);
    size_t  (*ofp_len)         (struct ofl_instruction_header *i);
    char   *(*to_string)       (struct ofl_instruction_header *i);
};

/* Callback functions for handling experimenter match structures. */
struct ofl_exp_match {
    int     (*pack)           (struct ofl_match_header *src, struct ofp_match *dst);
    ofl_err (*unpack)         (struct ofp_match *src, size_t *len, struct ofl_match_header **dst);
    int     (*free)           (struct ofl_match_header *m);
    size_t  (*ofp_len)        (struct ofl_match_header *m);
    char   *(*to_string)      (struct ofl_match_header *m);
};

/* Callback functions for handling experimenter statistics. */
struct ofl_exp_stats {
    int     (*req_pack)        (struct ofl_msg_multipart_request_header *msg, uint8_t **buf, size_t *buf_len);
    ofl_err (*req_unpack)      (struct ofp_multipart_request *os, size_t *len, struct ofl_msg_multipart_request_header **msg);
    int     (*req_free)        (struct ofl_msg_multipart_request_header *msg);
    char   *(*req_to_string)   (struct ofl_msg_multipart_request_header *msg);
    int     (*reply_pack)      (struct ofl_msg_multipart_reply_header *msg, uint8_t **buf, size_t *buf_len);
    ofl_err (*reply_unpack)    (struct ofp_multipart_reply *os, size_t *len, struct ofl_msg_multipart_reply_header **msg);
    int     (*reply_free)      (struct ofl_msg_multipart_reply_header *msg);
    char   *(*reply_to_string) (struct ofl_msg_multipart_reply_header *msg);
};

/* Callback functions for handling experimenter messages. */
struct ofl_exp_msg {
    int     (*pack)             (struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len);
    ofl_err (*unpack)           (struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg);
    int     (*free)             (struct ofl_msg_experimenter *msg);
    char   *(*to_string)        (struct ofl_msg_experimenter *msg);
};

/* Convenience structure for passing all callback groups at once. */
struct ofl_exp {
    struct ofl_exp_act    *act;
    struct ofl_exp_inst   *inst;
    struct ofl_exp_match  *match;
    struct ofl_exp_stats  *stats;
    struct ofl_exp_msg    *msg;
};



/* OFL_ERROR should be returned as ofl_err, when there was an error, but
 * there is no appropriate OpenFlow error type defined, or when no error
 * message should be generated because of the error. */
#define OFL_ERROR 0xffffffff

/* Creates an ofl_err from an OpenFlow error type and code */
static inline ofl_err
ofl_error(uint16_t type, uint16_t code) {
    /* NOTE: highest bit is always set to one, so no error value is zero */
    uint32_t ret = type;
    return 0x80000000 | ret << 16 | code;
}

/* Returns the error type of an ofl_err */
static inline uint16_t
ofl_error_type(ofl_err error) {
    return (0x7fff0000 & error) >> 16;
}

/* Returns the error code of an ofl_err */
static inline uint16_t
ofl_error_code(ofl_err error) {
    return error & 0x0000ffff;
}



#endif /* OFL_H 1 */
