/* Copyright (c) 2008, 2009 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

/* Zoltan:
 * During the move to OpenFlow 1.1 parts of the code was taken from
 * the following repository, with the license below:
 * git://openflow.org/of1.1-spec-test.git (lib/ofp-util.h)
 */
/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
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


#ifndef OFP_H
#define OFP_H 1

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "ofpbuf.h"
#include "flow.h"
#include "../include/openflow/openflow.h"

/* OpenFlow protocol utility functions. */
void *make_openflow(size_t openflow_len, uint8_t type, struct ofpbuf **);
void *make_openflow_xid(size_t openflow_len, uint8_t type,
                        uint32_t xid, struct ofpbuf **);
void *put_openflow(size_t openflow_len, uint8_t type, struct ofpbuf *);
void *put_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                       struct ofpbuf *);
void update_openflow_length(struct ofpbuf *);
void update_instruction_length(struct ofpbuf *, size_t oia_offset);
struct ofpbuf *make_flow_mod(uint8_t command,  uint8_t table_id,
                             const struct flow *, size_t actions_len);
struct ofpbuf *make_add_flow(const struct flow *, uint32_t buffer_id,
			     uint8_t table_id,
                             uint16_t max_idle, size_t actions_len);
struct ofpbuf *make_del_flow(const struct flow *, uint8_t table_id);
struct ofpbuf *make_add_simple_flow(const struct flow *,
                                    uint32_t buffer_id, uint32_t out_port,
                                    uint16_t max_idle);

struct ofpbuf * make_port_desc_request(void);

struct ofpbuf *make_packet_out(const struct ofpbuf *packet, uint32_t buffer_id,
                               uint32_t in_port,
                               const struct ofp_action_header *,
                               size_t n_actions);
struct ofpbuf *make_buffered_packet_out(uint32_t buffer_id,
                                        uint32_t in_port, uint32_t out_port);
struct ofpbuf *make_unbuffered_packet_out(const struct ofpbuf *packet,
                                          uint32_t in_port, uint32_t out_port);
struct ofpbuf *make_echo_request(void);
struct ofpbuf *make_echo_reply(const struct ofp_header *rq);
int check_ofp_message(const struct ofp_header *, uint8_t type, size_t size);
int check_ofp_instruction_array(const struct ofp_instruction *, uint8_t type,
				size_t size, size_t array_elt_size,
				size_t *n_array_elts);
int check_ofp_message_array(const struct ofp_header *, uint8_t type,
                            size_t size, size_t array_elt_size,
                            size_t *n_array_elts);
int check_ofp_packet_out(const struct ofp_header *, struct ofpbuf *data,
                         int *n_actions, int max_ports);

struct flow_stats_iterator {
    const uint8_t *pos, *end;
};
const struct ofp_flow_stats *flow_stats_first(struct flow_stats_iterator *,
                                              const struct ofp_multipart_reply *);
const struct ofp_flow_stats *flow_stats_next(struct flow_stats_iterator *);

struct actions_iterator {
    const union ofp_action *pos, *end;
};
const union ofp_action *actions_first(struct actions_iterator *,
                                      const union ofp_action *,
                                      size_t n_actions);
const union ofp_action *actions_next(struct actions_iterator *);
int validate_actions(const union ofp_action *, size_t n_actions,
                     int max_ports, bool is_packet_out);
bool action_outputs_to_port(const union ofp_action *, uint32_t port);


static inline int
ofp_mkerr(uint16_t type, uint16_t code)
{
    assert(type > 0 && type <= 0x7fff);
    return (type << 16) | code;
}

/* Hack to get the action parser to do sort of the right stuff. */
union ofp_action {
    uint16_t type;
    struct ofp_action_header header;
    struct ofp_action_experimenter_header experimenter;
};
OFP_ASSERT(sizeof(union ofp_action) == 8);

#endif /* ofp.h */
