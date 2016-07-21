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


/* The original Stanford code has been modified during the implementation of
 * the OpenFlow 1.3 userspace switch.
 *
 */

#include "datapath.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "csum.h"
#include "dp_buffers.h"
#include "dp_control.h"
#include "ofp.h"
#include "ofpbuf.h"
#include "group_table.h"
#include "meter_table.h"
#include "oflib/ofl.h"
#include "oflib/ofl-print.h"
#include "oflib/ofl-log.h"
#include "oflib-exp/ofl-exp.h"
#include "oflib-exp/ofl-exp-nicira.h"
#include "oflib-exp/ofl-exp-beba.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-log.h"
#include "openflow/openflow.h"
#include "openflow/nicira-ext.h"
#include "openflow/private-ext.h"
#include "openflow/openflow-ext.h"
#include "pipeline.h"
#include "poll-loop.h"
#include "rconn.h"
#include "stp.h"
#include "vconn.h"
#define LOG_MODULE VLM_dp

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);


static struct remote *remote_create(struct datapath *dp, struct rconn *rconn, struct rconn *rconn_aux);
static void remote_run(struct datapath *, struct remote *);
static void remote_rconn_run(struct datapath *, struct remote *, uint8_t);
static void remote_wait(struct remote *);
static void remote_destroy(struct remote *);


#define MFR_DESC     "Stanford University, Ericsson Research and CPqD Research"
#define HW_DESC      "OpenFlow 1.3 Reference Userspace Switch"
#define SW_DESC      __DATE__" "__TIME__
#define DP_DESC      "OpenFlow 1.3 Reference Userspace Switch Datapath"
#define SERIAL_NUM   "1"

#define MAIN_CONNECTION 0
#define PTIN_CONNECTION 1


/* Callbacks for processing experimenter messages in OFLib. */
static struct ofl_exp_msg dp_exp_msg =
        {.pack      = ofl_exp_msg_pack,
         .unpack    = ofl_exp_msg_unpack,
         .free      = ofl_exp_msg_free,
         .to_string = ofl_exp_msg_to_string};

/* Callbacks for processing experimenter actions in OFLib.*/
static struct ofl_exp_act dp_exp_act =
        {.pack      = ofl_exp_act_pack,
         .unpack    = ofl_exp_act_unpack,
         .free      = ofl_exp_act_free,
         .ofp_len   = ofl_exp_act_ofp_len,
         .to_string = ofl_exp_act_to_string};

/* Callbacks for processing experimenter stats in OFLib.*/
static struct ofl_exp_stats dp_exp_statistics =
        {.req_pack      = ofl_exp_stats_req_pack,
         .req_unpack    = ofl_exp_stats_req_unpack,
         .req_free      = ofl_exp_stats_req_free,
         .req_to_string = ofl_exp_stats_req_to_string,
         .reply_pack    = ofl_exp_stats_reply_pack,
         .reply_unpack  = ofl_exp_stats_reply_unpack,
         .reply_free    = ofl_exp_stats_reply_free,
         .reply_to_string = ofl_exp_stats_reply_to_string};

/* Callbacks for processing experimenter match fields in OFLib.*/
static struct ofl_exp_field dp_exp_field =
        {.unpack     = ofl_exp_field_unpack,
         .pack       = ofl_exp_field_pack,
         .match      = ofl_exp_field_match,
         .compare    = ofl_exp_field_compare,
         .match_std  = ofl_exp_field_match_std,
         .overlap_a  = ofl_exp_field_overlap_a,
         .overlap_b  = ofl_exp_field_overlap_b};

/* Callbacks for processing experimenter instructions in OFLib.*/
static struct ofl_exp_inst dp_exp_instruction =
		{.pack      = ofl_exp_inst_pack,
         .unpack    = ofl_exp_inst_unpack,
         .free      = ofl_exp_inst_free,
         .ofp_len   = ofl_exp_inst_ofp_len,
         .to_string = ofl_exp_inst_to_string};

/* Callbacks for processing experimenter errors in OFLib. */
static struct ofl_exp_err dp_exp_err =
        {.pack      = ofl_exp_err_pack,
         .free      = ofl_exp_err_free,
         .to_string = ofl_exp_err_to_string};

static struct ofl_exp dp_exp =
        {.act   = &dp_exp_act,
         .inst  = &dp_exp_instruction,
         .match = NULL,
         .stats = &dp_exp_statistics,
         .msg   = &dp_exp_msg,
         .field = &dp_exp_field,
         .err   = &dp_exp_err};

/* Generates and returns a random datapath id. */
static uint64_t
gen_datapath_id(void) {
    uint8_t ea[ETH_ADDR_LEN];
    eth_addr_random(ea);
    return eth_addr_to_uint64(ea);
}


struct datapath *
dp_new(void)
{
    struct datapath *dp;
    dp = xmalloc(sizeof(struct datapath));

    dp->mfr_desc   = strncpy(xmalloc(DESC_STR_LEN), MFR_DESC, DESC_STR_LEN);
    dp->mfr_desc[DESC_STR_LEN-1]     = 0x00;
    dp->hw_desc    = strncpy(xmalloc(DESC_STR_LEN), HW_DESC, DESC_STR_LEN);
    dp->hw_desc[DESC_STR_LEN-1]      = 0x00;
    dp->sw_desc    = strncpy(xmalloc(DESC_STR_LEN), SW_DESC, DESC_STR_LEN);
    dp->sw_desc[DESC_STR_LEN-1]      = 0x00;
    dp->dp_desc    = strncpy(xmalloc(DESC_STR_LEN), DP_DESC, DESC_STR_LEN);
    dp->dp_desc[DESC_STR_LEN-1]      = 0x00;
    dp->serial_num = strncpy(xmalloc(SERIAL_NUM_LEN), SERIAL_NUM, SERIAL_NUM_LEN);
    dp->serial_num[SERIAL_NUM_LEN-1] = 0x00;


    dp->id = gen_datapath_id();

    dp->global_state = 0;

    dp->generation_id = -1;

    dp->last_timeout = time_now();
    list_init(&dp->remotes);
    dp->listeners = NULL;
    dp->n_listeners = 0;
    dp->listeners_aux = NULL;
    dp->n_listeners_aux = 0;

    memset(dp->ports, 0x00, sizeof (dp->ports));
    dp->local_port = NULL;

    dp->buffers = dp_buffers_create(dp);
    dp->pipeline = pipeline_create(dp);
    dp->groups = group_table_create(dp);
    dp->meters = meter_table_create(dp);
    dp->pkttmps = pkttmp_table_create(dp);

    list_init(&dp->port_list);
    dp->ports_num = 0;
    dp->max_queues = NETDEV_MAX_QUEUES;

    dp->exp = &dp_exp;

    dp->config.flags         = OFPC_FRAG_NORMAL;
    dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

    if(strlen(dp->dp_desc) == 0) {
        /* just use "$HOSTNAME pid=$$" */
        char hostnametmp[DESC_STR_LEN];
	    gethostname(hostnametmp, sizeof(hostnametmp));
        snprintf(dp->dp_desc, DESC_STR_LEN,"%s pid=%u",hostnametmp, getpid());
    }

    /* FIXME: Should not depend on udatapath_as_lib */
    #if defined(OF_HW_PLAT) && (defined(UDATAPATH_AS_LIB) || defined(USE_NETDEV))
        dp_hw_drv_init(dp);
    #endif

    return dp;
}


void
dp_add_pvconn(struct datapath *dp, struct pvconn *pvconn, struct pvconn *pvconn_aux) {
    dp->listeners = xrealloc(dp->listeners,
                             sizeof *dp->listeners * (dp->n_listeners + 1));
    dp->listeners[dp->n_listeners++] = pvconn;

    dp->listeners_aux = xrealloc(dp->listeners_aux,
                             sizeof *dp->listeners_aux * (dp->n_listeners_aux + 1));
    dp->listeners_aux[dp->n_listeners_aux++] = pvconn_aux;
}

void
dp_run(struct datapath *dp, int nrun) {
    time_t now = time_now();
    struct remote *r, *rn;
    size_t i;

    if (now != dp->last_timeout) {
        dp->last_timeout = now;
        meter_table_add_tokens(dp->meters);
        pipeline_timeout(dp->pipeline);
    }

    poll_set_timer_wait(100);

    dp_ports_run(dp, nrun);

    DP_RELAX_WITH(nrun)
    {
	    /* Talk to remotes. */
	    LIST_FOR_EACH_SAFE (r, rn, struct remote, node, &dp->remotes) {
		remote_run(dp, r);
	    }

	    for (i = 0; i < dp->n_listeners; ) {
		struct pvconn *pvconn = dp->listeners[i];
		struct vconn *new_vconn;

		int retval = pvconn_accept(pvconn, OFP_VERSION, &new_vconn);
		if (!retval) {
		    struct rconn * rconn_aux = NULL;
		    if (dp->n_listeners_aux && dp->listeners_aux[i] != NULL) {
			struct pvconn *pvconn_aux = dp->listeners_aux[i];
			struct vconn *new_vconn_aux;
			int retval_aux = pvconn_accept(pvconn_aux, OFP_VERSION, &new_vconn_aux);
			if (!retval_aux)
			    rconn_aux = rconn_new_from_vconn("passive_aux", new_vconn_aux);
		    }
		    remote_create(dp, rconn_new_from_vconn("passive", new_vconn), rconn_aux);
		}
		else if (retval != EAGAIN) {
		    VLOG_WARN_RL(LOG_MODULE, &rl, "accept failed (%s)", strerror(retval));
		    dp->listeners[i] = dp->listeners[--dp->n_listeners];
		    if (dp->n_listeners_aux) {
			dp->listeners_aux[i] = dp->listeners_aux[--dp->n_listeners_aux];
		    }
		    continue;
		}
		i++;
	    }
    }
}

static void
remote_run(struct datapath *dp, struct remote *r)
{
    remote_rconn_run(dp, r, MAIN_CONNECTION);

    if (!rconn_is_alive(r->rconn)) {
        remote_destroy(r);
        return;
    }

    if (r->rconn_aux == NULL || !rconn_is_alive(r->rconn_aux))
        return;

    remote_rconn_run(dp, r, PTIN_CONNECTION);
}

static void
remote_rconn_run(struct datapath *dp, struct remote *r, uint8_t conn_id) {
    struct rconn *rconn = NULL;
    ofl_err error;
    size_t i;

    if (conn_id == MAIN_CONNECTION)
        rconn = r->rconn;
    else if (conn_id == PTIN_CONNECTION)
        rconn = r->rconn_aux;

    rconn_run(rconn);
    /* Do some remote processing, but cap it at a reasonable amount so that
     * other processing doesn't starve. */
    for (i = 0; i < 50; i++) {
        if (!r->cb_dump) {
            struct ofpbuf *buffer;

            buffer = rconn_recv(rconn);
            if (buffer == NULL) {
                break;
            } else {
                struct ofl_msg_header *msg = NULL;
                struct sender sender = {.remote = r, .conn_id = conn_id};

                error = ofl_msg_unpack(buffer->data, buffer->size, &msg, &(sender.xid), dp->exp);

                if (!error) {
                    error = handle_control_msg(dp, msg, &sender);
                }

                if (error) {
                    /* [*] The highest bit of 'error' is always set to one, but on-the-wire we
                    need full compliance to OF specification: the 'type' of an experimenter
                    error message must be 0xffff instead of 0x7ffff. */
                    if ((ofl_error_type(error) | 0x8000) == OFPET_EXPERIMENTER){
                        struct ofl_msg_exp_error err =
                               {{.type = OFPT_ERROR},
                                .type = ofl_error_type(error) | 0x8000, // [*]
                                .exp_type = ofl_error_code(error),
                                .experimenter = get_experimenter_id(msg),
                                .data_length = buffer->size,
                                .data        = buffer->data};
                        dp_send_message(dp, (struct ofl_msg_header *)&err, &sender);
                    }
                    else{
                        struct ofl_msg_error err =
                               {{.type = OFPT_ERROR},
                                .type = ofl_error_type(error),
                                .code = ofl_error_code(error),
                                .data_length = buffer->size,
                                .data        = buffer->data};
                        dp_send_message(dp, (struct ofl_msg_header *)&err, &sender);
                    }
                    if (msg != NULL){
                        ofl_msg_free(msg, dp->exp);
                    }
                }

                ofpbuf_delete(buffer);
            }
        } else {
            if (r->n_txq < TXQ_LIMIT) {
                int error = r->cb_dump(dp, r->cb_aux);
                if (error <= 0) {
                    if (error) {
                        VLOG_WARN_RL(LOG_MODULE, &rl, "Callback error: %s.",
                                     strerror(-error));
                    }
                    r->cb_done(r->cb_aux);
                    r->cb_dump = NULL;
                }
            } else {
                break;
            }
        }
    }
}

static void
remote_wait(struct remote *r)
{
    rconn_run_wait(r->rconn);
    rconn_recv_wait(r->rconn);

    if (r->rconn_aux) {
        rconn_run_wait(r->rconn_aux);
        rconn_recv_wait(r->rconn_aux);
    }
}

static void
remote_destroy(struct remote *r)
{
    if (r) {
        if (r->cb_dump && r->cb_done) {
             r->cb_done(r->cb_aux);
        }
        list_remove(&r->node);
        if (r->rconn_aux != NULL) {
            rconn_destroy(r->rconn_aux);
        }
        rconn_destroy(r->rconn);
	if(r->mp_req_msg != NULL) {
	  ofl_msg_free((struct ofl_msg_header *) r->mp_req_msg, NULL);
	}
        free(r);
    }
}

static struct remote *
remote_create(struct datapath *dp, struct rconn *rconn, struct rconn *rconn_aux)
{
    size_t i;
    struct remote *remote = xmalloc(sizeof *remote);
    list_push_back(&dp->remotes, &remote->node);
    remote->rconn = rconn;
    remote->rconn_aux = rconn_aux;
    remote->cb_dump = NULL;
    remote->n_txq = 0;
    remote->mp_req_msg = NULL;
    remote->mp_req_xid = 0;  /* Currently not needed. Jean II. */
    remote->role = OFPCR_ROLE_EQUAL;
    /* Set the remote configuration to receive any asynchronous message*/
    for(i = 0; i < 2; i++){
        memset(&remote->config.packet_in_mask[i], 0x7, sizeof(uint32_t));
        memset(&remote->config.port_status_mask[i], 0x7, sizeof(uint32_t));
        memset(&remote->config.flow_removed_mask[i], 0x1f, sizeof(uint32_t));
    }
    return remote;
}


void
dp_wait(struct datapath *dp, int nrun)
{
    struct sw_port *p;
    struct remote *r;
    size_t i;

    LIST_FOR_EACH (p, struct sw_port, node, &dp->port_list) {
        if (IS_HW_PORT(p)) {
            continue;
        }
        netdev_recv_wait(p->netdev);
    }

    DP_RELAX_WITH(nrun)
    {
	    LIST_FOR_EACH (r, struct remote, node, &dp->remotes) {
		remote_wait(r);
	    }
	    for (i = 0; i < dp->n_listeners; i++) {
		pvconn_wait(dp->listeners[i]);
	    }
    }
}

void
dp_set_dpid(struct datapath *dp, uint64_t dpid) {
    dp->id = dpid;
}

void
dp_set_mfr_desc(struct datapath *dp, char *mfr_desc) {
    strncpy(dp->mfr_desc, mfr_desc, DESC_STR_LEN);
    dp->mfr_desc[DESC_STR_LEN-1] = 0x00;
}

void
dp_set_hw_desc(struct datapath *dp, char *hw_desc) {
    strncpy(dp->hw_desc, hw_desc, DESC_STR_LEN);
    dp->hw_desc[DESC_STR_LEN-1] = 0x00;
}

void
dp_set_sw_desc(struct datapath *dp, char *sw_desc) {
    strncpy(dp->sw_desc, sw_desc, DESC_STR_LEN);
    dp->sw_desc[DESC_STR_LEN-1] = 0x00;
}

void
dp_set_dp_desc(struct datapath *dp, char *dp_desc) {
    strncpy(dp->dp_desc, dp_desc, DESC_STR_LEN);
    dp->dp_desc[DESC_STR_LEN-1] = 0x00;
}

void
dp_set_serial_num(struct datapath *dp, char *serial_num) {
    strncpy(dp->serial_num, serial_num, SERIAL_NUM_LEN);
    dp->serial_num[SERIAL_NUM_LEN-1] = 0x00;
}

void
dp_set_max_queues(struct datapath *dp, uint32_t max_queues) {
    dp->max_queues = max_queues;
}


static int
send_openflow_buffer_to_remote(struct ofpbuf *buffer, struct remote *remote) {
    struct rconn* rconn = remote->rconn;
    int retval;
    if (buffer->conn_id == PTIN_CONNECTION &&
        remote->rconn != NULL &&
        remote->rconn_aux != NULL &&
        rconn_is_connected(remote->rconn) &&
        rconn_is_connected(remote->rconn_aux)) {
            rconn = remote->rconn_aux;
    }
    retval = rconn_send_with_limit(rconn, buffer, &remote->n_txq,
                                      TXQ_LIMIT);

    if (retval) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "send to %s failed: %s",
                     rconn_get_name(rconn), strerror(retval));
    }

    return retval;
}

static int
send_openflow_buffer(struct datapath *dp, struct ofpbuf *buffer,
                     const struct sender *sender) {
    update_openflow_length(buffer);
    if (sender) {
        /* Send back to the sender. */
        return send_openflow_buffer_to_remote(buffer, sender->remote);

    } else {
        /* Broadcast to all remotes. */
        struct remote *r, *prev = NULL;
        uint8_t msg_type;
        /* Get the type of the message */
        memcpy(&msg_type,((char* ) buffer->data) + 1, sizeof(uint8_t));
        LIST_FOR_EACH (r, struct remote, node, &dp->remotes) {
            /* do not send to remotes with slave role apart from port status */
            if (r->role == OFPCR_ROLE_EQUAL || r->role == OFPCR_ROLE_MASTER){
                /*Check if the message is enabled in the asynchronous configuration*/
                switch(msg_type){
                    case (OFPT_PACKET_IN):{
                        struct ofp_packet_in *p = (struct ofp_packet_in*)buffer->data;
                        /* Do not send message if the reason is not enabled */
                        if((p->reason == OFPR_NO_MATCH) && !(r->config.packet_in_mask[0] & 0x1))
                            continue;
                        if((p->reason == OFPR_ACTION) && !(r->config.packet_in_mask[0] & 0x2))
                            continue;
                        if((p->reason == OFPR_INVALID_TTL) && !(r->config.packet_in_mask[0] & 0x4))
                            continue;
                        break;
                    }
                    case (OFPT_PORT_STATUS):{
                        struct ofp_port_status *p = (struct ofp_port_status*)buffer->data;
                        if((p->reason == OFPPR_ADD) && !(r->config.port_status_mask[0] & 0x1))
                            continue;
                        if((p->reason == OFPPR_DELETE) && !(r->config.port_status_mask[0] & 0x2))
                            continue;
                        if((p->reason == OFPPR_MODIFY) && !(r->config.port_status_mask[0] & 0x4))
                            continue;
                    }
                    case (OFPT_FLOW_REMOVED):{
                        struct ofp_flow_removed *p= (struct ofp_flow_removed *)buffer->data;
                        if((p->reason == OFPRR_IDLE_TIMEOUT) && !(r->config.flow_removed_mask[0] & 0x1))
                            continue;
                        if((p->reason == OFPRR_HARD_TIMEOUT) && !(r->config.flow_removed_mask[0] & 0x2))
                            continue;
                        if((p->reason == OFPRR_DELETE) && !(r->config.flow_removed_mask[0] & 0x4))
                            continue;
                        if((p->reason == OFPRR_GROUP_DELETE) && !(r->config.flow_removed_mask[0] & 0x8))
                            continue;
                        if((p->reason == OFPRR_METER_DELETE) && !(r->config.flow_removed_mask[0] & 0x10))
                            continue;
                    }
                }
            }
            else {
                /* In this implementation we assume that a controller with role slave
                   can is able to receive only port stats messages */
                if (r->role == OFPCR_ROLE_SLAVE && msg_type != OFPT_PORT_STATUS) {
                    continue;
                }
                else {
                    struct ofp_port_status *p = (struct ofp_port_status*)buffer->data;
                    if((p->reason == OFPPR_ADD) && !(r->config.port_status_mask[1] & 0x1))
                        continue;
                    if((p->reason == OFPPR_DELETE) && !(r->config.port_status_mask[1] & 0x2))
                        continue;
                    if((p->reason == OFPPR_MODIFY) && !(r->config.port_status_mask[1] & 0x4))
                        continue;
                }
            }
            if (prev) {
                send_openflow_buffer_to_remote(ofpbuf_clone(buffer), prev);
            }
            prev = r;
        }
        if (prev) {
            send_openflow_buffer_to_remote(buffer, prev);
        } else {
            ofpbuf_delete(buffer);
        }
        return 0;
    }
}

int
dp_send_message(struct datapath *dp, struct ofl_msg_header *msg,
                     const struct sender *sender) {
    struct ofpbuf *ofpbuf;
    uint8_t *buf;
    size_t buf_size;
    int error;

    if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        char *msg_str = ofl_msg_to_string(msg, dp->exp);
        VLOG_DBG_RL(LOG_MODULE, &rl, "sending: %.400s", msg_str);
        free(msg_str);
    }

    error = ofl_msg_pack(msg, sender == NULL ? 0 : sender->xid, &buf, &buf_size, dp->exp);
    if (error) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "There was an error packing the message!");
        return error;
    }
    ofpbuf = ofpbuf_new(0);
    ofpbuf_use(ofpbuf, buf, buf_size);
    ofpbuf_put_uninit(ofpbuf, buf_size);

    /* Choose the connection to send the packet to.
       1) By default, we send it to the main connection
       2) If there's an associated sender, send the response to the same
          connection the request came from
       3) If it's a packet in, use the auxiliary connection
    */
    ofpbuf->conn_id = MAIN_CONNECTION;
    if (sender != NULL)
        ofpbuf->conn_id = sender->conn_id;
    if (msg->type == OFPT_PACKET_IN)
        ofpbuf->conn_id = PTIN_CONNECTION;

    error = send_openflow_buffer(dp, ofpbuf, sender);
    if (error) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "There was an error sending the message!");
        /* TODO Zoltan: is delete needed? */
        ofpbuf_delete(ofpbuf);
        return error;
    }
    return 0;
}

ofl_err
dp_handle_set_desc(struct datapath *dp, struct ofl_exp_openflow_msg_set_dp_desc *msg,
                                            const struct sender *sender UNUSED)
{
    dp_set_dp_desc(dp, msg->dp_desc);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

static ofl_err
dp_check_generation_id(struct datapath *dp, uint64_t new_gen_id)
{
    if(new_gen_id < dp->generation_id) {
        return ofl_error(OFPET_ROLE_REQUEST_FAILED, OFPRRFC_STALE);
    }
    else dp->generation_id = new_gen_id;
    return 0;

}

ofl_err
dp_handle_role_request(struct datapath *dp, struct ofl_msg_role_request *msg,
                                            const struct sender *sender)
{
    uint32_t role = msg->role;
    uint64_t generation_id = msg->generation_id;
    switch (msg->role) {
        case OFPCR_ROLE_NOCHANGE:{
            role = sender->remote->role;
            generation_id = dp->generation_id;
            break;
        }
        case OFPCR_ROLE_EQUAL: {
            sender->remote->role = OFPCR_ROLE_EQUAL;
            break;
        }
        case OFPCR_ROLE_MASTER: {
            struct remote *r;
            int error = dp_check_generation_id(dp,msg->generation_id);
            if (error) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Role message generation id is smaller than the current id!");
                return error;
            }
            /* Old master(s) must be changed to slave(s) */
            LIST_FOR_EACH (r, struct remote, node, &dp->remotes) {
                if (r->role == OFPCR_ROLE_MASTER) {
                    r->role = OFPCR_ROLE_SLAVE;
                }
            }
            sender->remote->role = OFPCR_ROLE_MASTER;
            break;
        }
        case OFPCR_ROLE_SLAVE: {
            int error = dp_check_generation_id(dp,msg->generation_id);
            if (error) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "Role message generation id is smaller than the current id!");
                return error;
            }
            sender->remote->role = OFPCR_ROLE_SLAVE;
            break;
        }
        default: {
            VLOG_WARN_RL(LOG_MODULE, &rl, "Role request with unknown role (%u).", msg->role);
            return ofl_error(OFPET_ROLE_REQUEST_FAILED, OFPRRFC_BAD_ROLE);
        }
    }

    {
    struct ofl_msg_role_request reply =
        {{.type = OFPT_ROLE_REPLY},
            .role = role,
            .generation_id = generation_id};

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);
    }
    return 0;
}

ofl_err
dp_handle_async_request(struct datapath *dp, struct ofl_msg_async_config *msg,
                                            const struct sender *sender) {

    uint16_t async_type = msg->header.type;
    switch(async_type){
        case (OFPT_GET_ASYNC_REQUEST):{
            struct ofl_msg_async_config reply =
                    {{.type = OFPT_GET_ASYNC_REPLY},
                     .config = &sender->remote->config};
            dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);

            ofl_msg_free((struct ofl_msg_header*)msg, dp->exp);

            break;
        }
        case (OFPT_SET_ASYNC):{
            memcpy(&sender->remote->config, msg->config, sizeof(struct ofl_async_config));
            break;
        }
    }
    return 0;
}
