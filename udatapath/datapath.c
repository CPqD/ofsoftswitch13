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
 * the OpenFlow 1.2 userspace switch.
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
#include "oflib/ofl.h"
#include "oflib-exp/ofl-exp.h"
#include "oflib-exp/ofl-exp-nicira.h"
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


static struct remote *remote_create(struct datapath *, struct rconn *);
static void remote_run(struct datapath *, struct remote *);
static void remote_wait(struct remote *);
static void remote_destroy(struct remote *);


#define MFR_DESC     "Stanford University and Ericsson Research"
#define HW_DESC      "OpenFlow 1.2 Reference Userspace Switch"
#define SW_DESC      __DATE__" "__TIME__
#define DP_DESC      "OpenFlow 1.2 Reference Userspace Switch Datapath"
#define SERIAL_NUM   "1"


/* Callbacks for processing experimenter messages in OFLib. */
static struct ofl_exp_msg dp_exp_msg =
        {.pack      = ofl_exp_msg_pack,
         .unpack    = ofl_exp_msg_unpack,
         .free      = ofl_exp_msg_free,
         .to_string = ofl_exp_msg_to_string};

static struct ofl_exp dp_exp =
        {.act   = NULL,
         .inst  = NULL,
         .match = NULL,
         .stats = NULL,
         .msg   = &dp_exp_msg};

/* Generates and returns a random datapath id. */
static uint64_t
gen_datapath_id(void) {
    uint8_t ea[ETH_ADDR_LEN];
    eth_addr_random(ea);
    return eth_addr_to_uint64(ea);
}


struct datapath *
dp_new(void) {
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
   
    dp->generation_id = -1; 
    
    dp->last_timeout = time_now();
    list_init(&dp->remotes);
    dp->listeners = NULL;
    dp->n_listeners = 0;

    memset(dp->ports, 0x00, sizeof (dp->ports));
    dp->local_port = NULL;

    dp->buffers = dp_buffers_create(dp);
    dp->pipeline = pipeline_create(dp);
    dp->groups = group_table_create(dp);

    list_init(&dp->port_list);
    dp->ports_num = 0;
    dp->max_queues = NETDEV_MAX_QUEUES;

    dp->exp = &dp_exp;

    dp->config.flags         = OFPC_FRAG_NORMAL;
    dp->config.miss_send_len = OFP_DEFAULT_MISS_SEND_LEN;

    if(strlen(dp->dp_desc) == 0) {
        /* just use "$HOSTNAME pid=$$" */
        char hostnametmp[DESC_STR_LEN];
	    gethostname(hostnametmp,sizeof hostnametmp);
        snprintf(dp->dp_desc, sizeof dp->dp_desc,"%s pid=%u",hostnametmp, getpid());
    }

    /* FIXME: Should not depend on udatapath_as_lib */
    #if defined(OF_HW_PLAT) && (defined(UDATAPATH_AS_LIB) || defined(USE_NETDEV))
        dp_hw_drv_init(dp);
    #endif

    return dp;
}



void
dp_add_pvconn(struct datapath *dp, struct pvconn *pvconn) {
    dp->listeners = xrealloc(dp->listeners,
                             sizeof *dp->listeners * (dp->n_listeners + 1));
    dp->listeners[dp->n_listeners++] = pvconn;
}

void
dp_run(struct datapath *dp) {
    time_t now = time_now();
    struct remote *r, *rn;
    size_t i;

    if (now != dp->last_timeout) {
        dp->last_timeout = now;
        pipeline_timeout(dp->pipeline);
    }
    poll_timer_wait(1000);

    dp_ports_run(dp);

    /* Talk to remotes. */
    LIST_FOR_EACH_SAFE (r, rn, struct remote, node, &dp->remotes) {
        remote_run(dp, r);
    }

    for (i = 0; i < dp->n_listeners; ) {
        struct pvconn *pvconn = dp->listeners[i];
        struct vconn *new_vconn;
        int retval = pvconn_accept(pvconn, OFP_VERSION, &new_vconn);
        if (!retval) {
            remote_create(dp, rconn_new_from_vconn("passive", new_vconn));
        } else if (retval != EAGAIN) {
            VLOG_WARN_RL(LOG_MODULE, &rl, "accept failed (%s)", strerror(retval));
            dp->listeners[i] = dp->listeners[--dp->n_listeners];
            continue;
        }
        i++;
    }
}

static void
remote_run(struct datapath *dp, struct remote *r)
{
    ofl_err error;
    size_t i;

    rconn_run(r->rconn);

    /* Do some remote processing, but cap it at a reasonable amount so that
     * other processing doesn't starve. */
    for (i = 0; i < 50; i++) {
        if (!r->cb_dump) {
            struct ofpbuf *buffer;

            buffer = rconn_recv(r->rconn);
            if (buffer == NULL) {
                break;

            } else {
                struct ofl_msg_header *msg;

                struct sender sender = {.remote = r};

                error = ofl_msg_unpack(buffer->data, buffer->size, &msg, &(sender.xid), dp->exp);

                if (!error) {
                    error = handle_control_msg(dp, msg, &sender);

                    if (error) {
                        ofl_msg_free(msg, dp->exp);
                    }
                }

                if (error) {
                    struct ofl_msg_error err =
                            {{.type = OFPT_ERROR},
                             .type = ofl_error_type(error),
                             .code = ofl_error_code(error),
                             .data_length = buffer->size,
                             .data        = buffer->data};
                    dp_send_message(dp, (struct ofl_msg_header *)&err, &sender);
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

    if (!rconn_is_alive(r->rconn)) {
        remote_destroy(r);
    }
}

static void
remote_wait(struct remote *r)
{
    rconn_run_wait(r->rconn);
    rconn_recv_wait(r->rconn);
}

static void
remote_destroy(struct remote *r)
{
    if (r) {
        if (r->cb_dump && r->cb_done) {
            r->cb_done(r->cb_aux);
        }
        list_remove(&r->node);
        rconn_destroy(r->rconn);
        free(r);
    }
}

static struct remote *
remote_create(struct datapath *dp, struct rconn *rconn)
{
    struct remote *remote = xmalloc(sizeof *remote);
    list_push_back(&dp->remotes, &remote->node);
    remote->rconn = rconn;
    remote->cb_dump = NULL;
    remote->n_txq = 0;
    remote->role = OFPCR_ROLE_EQUAL;
    return remote;
}


void
dp_wait(struct datapath *dp)
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
    LIST_FOR_EACH (r, struct remote, node, &dp->remotes) {
        remote_wait(r);
    }
    for (i = 0; i < dp->n_listeners; i++) {
        pvconn_wait(dp->listeners[i]);
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
    int retval = rconn_send_with_limit(remote->rconn, buffer, &remote->n_txq,
                                      TXQ_LIMIT);
     
    if (retval) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "send to %s failed: %s",
                     rconn_get_name(remote->rconn), strerror(retval));
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
        LIST_FOR_EACH (r, struct remote, node, &dp->remotes) {
            /* do not send to remotes with slave role */
            if (r->role == OFPCR_ROLE_SLAVE) {
                continue;
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
        VLOG_DBG_RL(LOG_MODULE, &rl, "sending: %s", msg_str);
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
                                            const struct sender *sender UNUSED) {
    dp_set_dp_desc(dp, msg->dp_desc);
    ofl_msg_free((struct ofl_msg_header *)msg, dp->exp);
    return 0;
}

static ofl_err
dp_check_generation_id(struct datapath *dp, uint64_t new_gen_id){

    if(dp->generation_id >= 0  && ((int64_t)(dp->generation_id - new_gen_id) < 0) )
        return ofl_error(OFPET_ROLE_REQUEST_FAILED, OFPRRFC_STALE);
    else dp->generation_id = new_gen_id;
    return 0;
    
}

ofl_err
dp_handle_role_request(struct datapath *dp, struct ofl_msg_role_request *msg,
                                            const struct sender *sender) {
    switch (msg->role) {
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

        case OFPCR_ROLE_EQUAL: {
            sender->remote->role = OFPCR_ROLE_EQUAL;
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
            .role = msg->role,
            .generation_id = msg->role};

    dp_send_message(dp, (struct ofl_msg_header *)&reply, sender);
    }
    return 0;
}
