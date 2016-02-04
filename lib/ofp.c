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

#include <config.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdlib.h>
#include "ofp.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "packets.h"
#include "random.h"
#include "util.h"

#define LOG_MODULE VLM_ofp
#include "vlog.h"

/* XXX we should really use consecutive xids to avoid probabilistic
 * failures. */
static inline uint32_t
alloc_xid(void)
{
    return random_uint32();
}

/* Allocates and stores in '*bufferp' a new ofpbuf with a size of
 * 'openflow_len', starting with an OpenFlow header with the given 'type' and
 * an arbitrary transaction id.  Allocated bytes beyond the header, if any, are
 * zeroed.
 *
 * The caller is responsible for freeing '*bufferp' when it is no longer
 * needed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
make_openflow(size_t openflow_len, uint8_t type, struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_openflow_xid(openflow_len, type, alloc_xid(), *bufferp);
}



/* Allocates and stores in '*bufferp' a new ofpbuf with a size of
 * 'openflow_len', starting with an OpenFlow header with the given 'type' and
 * transaction id 'xid'.  Allocated bytes beyond the header, if any, are
 * zeroed.
 *
 * The caller is responsible for freeing '*bufferp' when it is no longer
 * needed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
make_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                  struct ofpbuf **bufferp)
{
    *bufferp = ofpbuf_new(openflow_len);
    return put_openflow_xid(openflow_len, type, xid, *bufferp);
}

/* Appends 'openflow_len' bytes to 'buffer', starting with an OpenFlow header
 * with the given 'type' and an arbitrary transaction id.  Allocated bytes
 * beyond the header, if any, are zeroed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
put_openflow(size_t openflow_len, uint8_t type, struct ofpbuf *buffer)
{
    return put_openflow_xid(openflow_len, type, alloc_xid(), buffer);
}

/* Appends 'openflow_len' bytes to 'buffer', starting with an OpenFlow header
 * with the given 'type' and an transaction id 'xid'.  Allocated bytes beyond
 * the header, if any, are zeroed.
 *
 * The OpenFlow header length is initially set to 'openflow_len'; if the
 * message is later extended, the length should be updated with
 * update_openflow_length() before sending.
 *
 * Returns the header. */
void *
put_openflow_xid(size_t openflow_len, uint8_t type, uint32_t xid,
                 struct ofpbuf *buffer)
{
    struct ofp_header *oh;

    assert(openflow_len >= sizeof *oh);
    assert(openflow_len <= UINT16_MAX);

    oh = ofpbuf_put_uninit(buffer, openflow_len);
    oh->version = OFP_VERSION;
    oh->type = type;
    oh->length = htons(openflow_len);
    oh->xid = xid;
    memset(oh + 1, 0, openflow_len - sizeof *oh);
    return oh;
}

/* Updates the 'length' field of the OpenFlow message in 'buffer' to
 * 'buffer->size'. */
void
update_openflow_length(struct ofpbuf *buffer)
{
    struct ofp_header *oh = ofpbuf_at_assert(buffer, 0, sizeof *oh);
    oh->length = htons(buffer->size);
}

/* Updates the 'len' field of the instruction header in 'buffer' to
 * "what it should be"(tm). */
void
update_instruction_length(struct ofpbuf *buffer, size_t oia_offset)
{
    struct ofp_header *oh = ofpbuf_at_assert(buffer, 0, sizeof *oh);
    struct ofp_instruction *ih = ofpbuf_at_assert(buffer, oia_offset,
						  sizeof *ih);
    ih->len = htons(buffer->size - oia_offset);
}

struct ofpbuf *
make_flow_mod(uint8_t command, uint8_t table_id,
	      const struct flow *flow UNUSED, size_t actions_len)
{
    struct ofp_flow_mod *ofm;
    size_t size = sizeof *ofm + actions_len;
    struct ofpbuf *out = ofpbuf_new(size);
    ofm = ofpbuf_put_zeros(out, sizeof *ofm);
    ofm->header.version = OFP_VERSION;
    ofm->header.type = OFPT_FLOW_MOD;
    ofm->header.length = htons(size);
    ofm->cookie = 0;
    /*TODO fill match
    ofm->match.in_port = flow->in_port;
    memcpy(ofm->match.dl_src, flow->dl_src, sizeof ofm->match.dl_src);
    memcpy(ofm->match.dl_dst, flow->dl_dst, sizeof ofm->match.dl_dst);
    ofm->match.dl_vlan = flow->dl_vlan;
    ofm->match.dl_vlan_pcp = flow->dl_vlan_pcp;
    ofm->match.dl_type = flow->dl_type;
    ofm->match.nw_src = flow->nw_src;
    ofm->match.nw_dst = flow->nw_dst;
    ofm->match.nw_proto = flow->nw_proto;
    ofm->match.nw_tos = flow->nw_tos;
    ofm->match.tp_src = flow->tp_src;
    ofm->match.tp_dst = flow->tp_dst; */
    ofm->command = command;
    ofm->table_id = table_id;

    return out;
}

struct ofpbuf *
make_add_flow(const struct flow *flow, uint32_t buffer_id, uint8_t table_id,
              uint16_t idle_timeout, size_t actions_len)
{
    struct ofp_instruction_actions *oia;
    size_t instruction_len = sizeof *oia + actions_len;
    struct ofpbuf *out = make_flow_mod(OFPFC_ADD, table_id,
				       flow, instruction_len);
    struct ofp_flow_mod *ofm = out->data;
    ofm->idle_timeout = htons(idle_timeout);
    ofm->hard_timeout = htons(OFP_FLOW_PERMANENT);
    ofm->buffer_id = htonl(buffer_id);
    /* Use a single apply-actions for now - Jean II */
    oia = ofpbuf_put_zeros(out, sizeof *oia);
    oia->type = htons(OFPIT_APPLY_ACTIONS);
    oia->len = htons(instruction_len);
    return out;
}



struct ofpbuf *
make_del_flow(const struct flow *flow, uint8_t table_id)
{
    struct ofpbuf *out = make_flow_mod(OFPFC_DELETE_STRICT, table_id, flow, 0);
    struct ofp_flow_mod *ofm = out->data;
    ofm->out_port = htonl(OFPP_ANY);
    return out;
}


struct ofpbuf *
make_add_simple_flow(const struct flow *flow,
                     uint32_t buffer_id, uint32_t out_port,
                     uint16_t idle_timeout)
{
    if (out_port != OFPP_ANY) {
        struct ofp_action_output *oao;
        struct ofpbuf *buffer;

        buffer = make_add_flow(flow, buffer_id, 0x00, idle_timeout, sizeof *oao);
        oao = ofpbuf_put_zeros(buffer, sizeof *oao);
        oao->type = htons(OFPAT_OUTPUT);
        oao->len = htons(sizeof *oao);
        oao->port = htonl(out_port);
        return buffer;
    } else {
        return make_add_flow(flow, buffer_id, 0, idle_timeout, 0);
    }
}

struct ofpbuf *
make_port_desc_request(void){

    struct ofp_multipart_request *desc;
    struct ofpbuf *out = ofpbuf_new(sizeof *desc);
    desc = ofpbuf_put_uninit(out, sizeof *desc);
    desc->header.version = OFP_VERSION;
    desc->header.type = OFPT_MULTIPART_REQUEST;
    desc->header.length = htons(sizeof *desc);
    desc->header.xid = alloc_xid();
    desc->type = htons(OFPMP_PORT_DESC);
    desc->flags = 0x0000;
    memset(desc->pad, 0x0, 4);
    return out;

}

struct ofpbuf *
make_packet_out(const struct ofpbuf *packet, uint32_t buffer_id,
                uint32_t in_port,
                const struct ofp_action_header *actions, size_t n_actions)
{
    size_t actions_len = n_actions * sizeof *actions;
    struct ofp_packet_out *opo;
    size_t size = sizeof *opo + actions_len + (packet ? packet->size : 0);
    struct ofpbuf *out = ofpbuf_new(size);

    opo = ofpbuf_put_uninit(out, sizeof *opo);
    opo->header.version = OFP_VERSION;
    opo->header.type = OFPT_PACKET_OUT;
    opo->header.length = htons(size);
    opo->header.xid = htonl(0);
    opo->buffer_id = htonl(buffer_id);
    opo->in_port = htonl(in_port);
    opo->actions_len = htons(actions_len);
    ofpbuf_put(out, actions, actions_len);
    if (packet) {
        ofpbuf_put(out, packet->data, packet->size);
    }
    return out;
}


struct ofpbuf *
make_unbuffered_packet_out(const struct ofpbuf *packet,
                           uint32_t in_port, uint32_t out_port)
{
    struct ofp_action_output action;
    action.type = htons(OFPAT_OUTPUT);
    action.len = htons(sizeof action);
    action.port = htonl(out_port);
    return make_packet_out(packet, UINT32_MAX, in_port,
                           (struct ofp_action_header *) &action, 1);
}

struct ofpbuf *
make_buffered_packet_out(uint32_t buffer_id,
                         uint32_t in_port, uint32_t out_port)
{
    if (out_port != OFPP_ANY) {
        struct ofp_action_output action;
        action.type = htons(OFPAT_OUTPUT);
        action.len = htons(sizeof action);
        action.port = htonl(out_port);
        return make_packet_out(NULL, buffer_id, in_port,
                               (struct ofp_action_header *) &action, 1);
    } else {
        return make_packet_out(NULL, buffer_id, in_port, NULL, 0);
    }
}


/* Creates and returns an OFPT_ECHO_REQUEST message with an empty payload. */
struct ofpbuf *
make_echo_request(void)
{
    struct ofp_header *rq;
    struct ofpbuf *out = ofpbuf_new(sizeof *rq);
    rq = ofpbuf_put_uninit(out, sizeof *rq);
    rq->version = OFP_VERSION;
    rq->type = OFPT_ECHO_REQUEST;
    rq->length = htons(sizeof *rq);
    rq->xid = alloc_xid();
    return out;
}

/* Creates and returns an OFPT_ECHO_REPLY message matching the
 * OFPT_ECHO_REQUEST message in 'rq'. */
struct ofpbuf *
make_echo_reply(const struct ofp_header *rq)
{
    size_t size = ntohs(rq->length);
    struct ofpbuf *out = ofpbuf_new(size);
    struct ofp_header *reply = ofpbuf_put(out, rq, size);
    reply->type = OFPT_ECHO_REPLY;
    return out;
}


static int
check_message_type(uint8_t got_type, uint8_t want_type)
{
    if (got_type != want_type) {
        VLOG_WARN(LOG_MODULE, "received bad message type %d (expected %d)",
                  got_type, want_type);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_TYPE);;
    }
    return 0;
}

/* Checks that 'msg' has type 'type' and that it is exactly 'size' bytes long.
 * Returns 0 if the checks pass, otherwise an OpenFlow error code (produced
 * with ofp_mkerr()). */
int
check_ofp_message(const struct ofp_header *msg, uint8_t type, size_t size)
{
    size_t got_size;
    int error;

    error = check_message_type(msg->type, type);
    if (error) {
        return error;
    }

    got_size = ntohs(msg->length);
    if (got_size != size) {
        VLOG_WARN(LOG_MODULE, "received %d message of length %zu (expected %zu)",
                     type, got_size, size);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    return 0;
}

/* Checks that 'inst' has type 'type' and that 'inst' is 'size' plus a
 * nonnegative integer multiple of 'array_elt_size' bytes long.  Returns 0 if
 * the checks pass, otherwise an OpenFlow error code (produced with
 * ofp_mkerr()).
 *
 * If 'n_array_elts' is nonnull, then '*n_array_elts' is set to the number of
 * 'array_elt_size' blocks in 'msg' past the first 'min_size' bytes, when
 * successful. */
int
check_ofp_instruction_array(const struct ofp_instruction *inst, uint8_t type,
			    size_t min_size, size_t array_elt_size,
			    size_t *n_array_elts)
{
    size_t got_size;

    assert(array_elt_size);

    if (ntohs(inst->type) != type) {
        VLOG_WARN(LOG_MODULE, "received bad instruction type %X (expected %X)",
                     ntohs(inst->type), type);
        return ofp_mkerr(OFPET_BAD_INSTRUCTION, OFPBIC_UNSUP_INST);
    }

    got_size = ntohs(inst->len);
    if (got_size < min_size) {
        VLOG_WARN(LOG_MODULE, "received %X instruction of length %zu "
                     "(expected at least %zu)",
                     type, got_size, min_size);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if ((got_size - min_size) % array_elt_size) {
        VLOG_WARN(LOG_MODULE, "received %X message of bad length %zu: the "
                     "excess over %zu (%zu) is not evenly divisible by %zu "
                     "(remainder is %zu)",
                     type, got_size, min_size, got_size - min_size,
                     array_elt_size, (got_size - min_size) % array_elt_size);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);;
    }
    if (n_array_elts) {
        *n_array_elts = (got_size - min_size) / array_elt_size;
    }
    return 0;
}


/* Checks that 'msg' has type 'type' and that 'msg' is 'size' plus a
 * nonnegative integer multiple of 'array_elt_size' bytes long.  Returns 0 if
 * the checks pass, otherwise an OpenFlow error code (produced with
 * ofp_mkerr()).
 *
 * If 'n_array_elts' is nonnull, then '*n_array_elts' is set to the number of
 * 'array_elt_size' blocks in 'msg' past the first 'min_size' bytes, when
 * successful.  */
int
check_ofp_message_array(const struct ofp_header *msg, uint8_t type,
                        size_t min_size, size_t array_elt_size,
                        size_t *n_array_elts)
{
    size_t got_size;
    int error;

    assert(array_elt_size);

    error = check_message_type(msg->type, type);
    if (error) {
        return error;
    }

    got_size = ntohs(msg->length);
    if (got_size < min_size) {
        VLOG_WARN(LOG_MODULE, "received %d message of length %zu "
                     "(expected at least %zu)",
                     type, got_size, min_size);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if ((got_size - min_size) % array_elt_size) {
        VLOG_WARN(LOG_MODULE,
                     "received %d message of bad length %zu: the "
                     "excess over %zu (%zu) is not evenly divisible by %zu "
                     "(remainder is %zu)",
                     type, got_size, min_size, got_size - min_size,
                     array_elt_size, (got_size - min_size) % array_elt_size);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if (n_array_elts) {
        *n_array_elts = (got_size - min_size) / array_elt_size;
    }
    return 0;
}


int
check_ofp_packet_out(const struct ofp_header *oh, struct ofpbuf *data,
                     int *n_actionsp, int max_ports)
{
    const struct ofp_packet_out *opo;
    unsigned int actions_len, n_actions;
    size_t extra;
    int error;

    *n_actionsp = 0;
    error = check_ofp_message_array(oh, OFPT_PACKET_OUT,
                                    sizeof *opo, 1, &extra);
    if (error) {
        return error;
    }
    opo = (const struct ofp_packet_out *) oh;

    actions_len = ntohs(opo->actions_len);
    if (actions_len > extra) {
        VLOG_WARN(LOG_MODULE, "packet-out claims %u bytes of actions "
                     "but message has room for only %zu bytes",
                     actions_len, extra);
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    if (actions_len % sizeof(union ofp_action)) {
        VLOG_WARN(LOG_MODULE, "packet-out claims %u bytes of actions, "
                     "which is not a multiple of %zu",
                     actions_len, sizeof(union ofp_action));
        return ofp_mkerr(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    n_actions = actions_len / sizeof(union ofp_action);
    error = validate_actions((const union ofp_action *) opo->actions,
                             n_actions, max_ports, true);
    if (error) {
        return error;
    }

    data->data = (void *) &opo->actions[n_actions];
    data->size = extra - actions_len;
    *n_actionsp = n_actions;
    return 0;
}

/*const struct ofp_flow_stats */
const struct ofp_flow_stats *
flow_stats_first(struct flow_stats_iterator *iter,
                 const struct ofp_multipart_reply *osr)
{
    iter->pos = osr->body;
    iter->end = osr->body + (ntohs(osr->header.length)
                             - offsetof(struct ofp_multipart_reply, body));
    return flow_stats_next(iter);
}

/*const struct ofp_flow_stats */
const struct ofp_flow_stats *
flow_stats_next(struct flow_stats_iterator *iter)
{
    static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 5);
    ptrdiff_t bytes_left = iter->end - iter->pos;
    const struct ofp_flow_stats *fs;
    size_t length;

    if (bytes_left < sizeof *fs) {
        if (bytes_left != 0) {
            VLOG_WARN_RL(LOG_MODULE, &rl, "%td leftover bytes in flow stats reply",
                         bytes_left);
        }
        return NULL;
    }

    fs = (const void *) iter->pos;
    length = ntohs(fs->length);
    if (length < sizeof *fs) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "flow stats length %zu is shorter than min %zu",
        length, sizeof *fs);
        return NULL;
    } else if (length > bytes_left) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "flow stats length %zu but only %td bytes left",
                     length, bytes_left);
        return NULL;
    }
    /* TODO: Change instructions
    else if ((length - sizeof *fs) % sizeof fs->instructions[0]) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "flow stats length %zu has %zu bytes "
                     "left over in final action", length,
                     (length - sizeof *fs) % sizeof fs->instructions[0]);
        return NULL;
    }*/
    iter->pos += length;
    return fs;
}

/* Alignment of ofp_actions. */
#define ACTION_ALIGNMENT 8


static int
check_action_exact_len(const union ofp_action *a, unsigned int len,
                       unsigned int required_len)
{
    if (len != required_len) {
        VLOG_DBG(LOG_MODULE, "action %u has invalid length %"PRIu16" (must be %u)\n",
                    a->type, ntohs(a->header.len), required_len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    return 0;
}

/* Checks that 'port' is a valid output port for the OFPAT_OUTPUT action, given
 * that the switch will never have more than 'max_ports' ports.  Returns 0 if
 * 'port' is valid, otherwise an ofp_mkerr() return code.*/
static int
check_output_port(uint32_t port, int max_ports, bool table_allowed)
{
    switch (port) {
    case OFPP_IN_PORT:
    case OFPP_NORMAL:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_CONTROLLER:
    case OFPP_LOCAL:
        return 0;

    case OFPP_TABLE:
        if (table_allowed) {
            return 0;
        } else {
        	return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);
        }

    default:
        if (port < max_ports) {
            return 0;
        }
        VLOG_WARN(LOG_MODULE, "unknown output port %x", port);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_OUT_PORT);;
    }
}

/* Checks that 'action' is a valid OFPAT_ENQUEUE action, given that the switch
 * will never have more than 'max_ports' ports.  Returns 0 if 'port' is valid,
 * otherwise an ofp_mkerr() return code.*/
static int
check_setqueue_action(const union ofp_action *a, unsigned int len)
{
    const struct ofp_action_set_queue *oaq UNUSED; 
    int error;

    error = check_action_exact_len(a, len, 8);
    if (error) {
        return error;
    }
    /*TODO check if this functions is relevant and finish or
      remove it accordingly */
    /*oaq = (const struct ofp_action_set_queue *) a;*/
    return 0;
}

static int
check_nicira_action(const union ofp_action *a, unsigned int len)
{
    const struct nx_action_header *nah;

    if (len < 16) {
        VLOG_DBG(LOG_MODULE, "Nicira vendor action only %u bytes", len);
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);;
    }
    nah = (const struct nx_action_header *) a;

    switch (ntohs(nah->subtype)) {
    case NXAST_RESUBMIT:
    case NXAST_SET_TUNNEL:
        return check_action_exact_len(a, len, 16);
    default:
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_EXPERIMENTER);
    }
}

static int
check_action(const union ofp_action *a, unsigned int len, int max_ports,
             bool is_packet_out)
{
    int error;

    switch (ntohs(a->type)) {
    case OFPAT_OUTPUT: {
        const struct ofp_action_output *oao;
        error = check_action_exact_len(a, len, 16);
        if (error) {
            return error;
        }
	oao = (const struct ofp_action_output *) a;
        return check_output_port(ntohl(oao->port), max_ports, is_packet_out);
    }


    case OFPAT_EXPERIMENTER:
        return (a->experimenter.experimenter == htonl(NX_VENDOR_ID)
                ? check_nicira_action(a, len)
                : ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_EXPERIMENTER));

    case OFPAT_SET_QUEUE:
        return check_setqueue_action(a, len);

    default:
        VLOG_WARN(LOG_MODULE, "unknown action type %"PRIu16,
                ntohs(a->type));
        return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_TYPE);
    }
}

int
validate_actions(const union ofp_action *actions, size_t n_actions,
                 int max_ports, bool is_packet_out)
{
    const union ofp_action *a;

    for (a = actions; a < &actions[n_actions]; ) {
        unsigned int len = ntohs(a->header.len);
        unsigned int n_slots = len / ACTION_ALIGNMENT;
        unsigned int slots_left = &actions[n_actions] - a;
        int error;

        if (n_slots > slots_left) {
            VLOG_DBG(LOG_MODULE,
                        "action requires %u slots but only %u remain",
                        n_slots, slots_left);
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        } else if (!len) {
            VLOG_DBG(LOG_MODULE, "action has invalid length 0");
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        } else if (len % ACTION_ALIGNMENT) {
            VLOG_DBG(LOG_MODULE, "action length %u is not a multiple "
                        "of %d", len, ACTION_ALIGNMENT);
            return ofp_mkerr(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
        }

        error = check_action(a, len, max_ports, is_packet_out);
        if (error) {
            return error;
        }
        a += n_slots;
    }
    return 0;
}

/* Returns true if 'action' outputs to 'port' (which must be in network byte
 * order), false otherwise. */
bool
action_outputs_to_port(const union ofp_action *action, uint32_t port)
{
    switch (ntohs(action->type)) {
    case OFPAT_OUTPUT: {
        const struct ofp_action_output *oao;
	oao = (const struct ofp_action_output *) action;
        return oao->port == port;
    }
    default:
        return false;
    }
}

/* The set of actions must either come from a trusted source or have been
 * previously validated with validate_actions().*/
const union ofp_action *
actions_first(struct actions_iterator *iter,
              const union ofp_action *oa, size_t n_actions)
{
    iter->pos = oa;
    iter->end = oa + n_actions;
    return actions_next(iter);
}

const union ofp_action *
actions_next(struct actions_iterator *iter)
{
    if (iter->pos < iter->end) {
        const union ofp_action *a = iter->pos;
        unsigned int len = ntohs(a->header.len);
        iter->pos += len / ACTION_ALIGNMENT;
        return a;
    } else {
        return NULL;
    }
}



