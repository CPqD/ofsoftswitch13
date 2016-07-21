/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
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
 * the OpenFlow 1.1 userspace switch.
 *
 */

#ifndef DATAPATH_H
#define DATAPATH_H 1


#include <stdbool.h>
#include <stdint.h>
#include "dp_buffers.h"
#include "dp_ports.h"
#include "openflow/nicira-ext.h"
#include "ofpbuf.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "oflib/ofl-structs.h"
#include "oflib-exp/ofl-exp-nicira.h"
#include "oflib-exp/ofl-exp-beba.h"
#include "group_table.h"
#include "timeval.h"
#include "list.h"


struct rconn;
struct pvconn;
struct sender;

/****************************************************************************
 * The datapath
 ****************************************************************************/

#define DP_RELAX_FACTOR_MASK	((1UL << BEBA_CTRL_PLANE_RELAX)-1)
#define DP_RELAX_WITH(n)	if ((n & DP_RELAX_FACTOR_MASK)== 0)

struct datapath
{
    /* Strings to describe the manufacturer, hardware, and software. This data
     * is queriable through switch stats request. */

    char  *mfr_desc;
    char  *hw_desc;
    char  *sw_desc;
    char  *dp_desc;
    char  *serial_num;

    uint64_t  id;               /* Unique identifier for this datapath. */

    uint32_t  global_state;    /* Global state for this datapath. */

    struct list remotes;        /* Remote connections. */

    uint64_t generation_id;     /* Identifies a given mastership view */

    /* Listeners. */
    struct pvconn **listeners;
    size_t n_listeners;
    struct pvconn **listeners_aux;
    size_t n_listeners_aux;
    time_t last_timeout;

    struct dp_buffers *buffers;

    struct pipeline *pipeline;  /* Pipeline with multi-tables. */

    struct group_table *groups; /* Group tables */

    struct meter_table *meters; /* Meter tables */

    struct pkttmp_table *pkttmps; /* Packet template table */

    struct ofl_config config; /* Configuration, set from controller. */

    /* Switch ports. */
    /* NOTE: ports are numbered starting at 1 in OF 1.1 */
    uint32_t         max_queues; /* used when creating ports */
    struct sw_port   ports[DP_MAX_PORTS + 1];
    struct sw_port  *local_port;  /* OFPP_LOCAL port, if any. */
    struct list      port_list; /* All ports, including local_port. */
    size_t           ports_num;

    /* Experimenter handling. */
    struct ofl_exp  *exp;

#if defined(OF_HW_PLAT)
    /* Although the chain maintains the pointer to the HW driver
     * for flow operations, the datapath needs the port functions
     * in the driver structure
     */
    of_hw_driver_t *hw_drv;
    struct hw_pkt_q_entry *hw_pkt_list_head, *hw_pkt_list_tail;
#endif
};

/* The origin of a received OpenFlow message, to enable sending a reply. */
struct sender {
    struct remote *remote;      /* The device that sent the message. */
    uint8_t conn_id;            /* The connection that sent the message */
    uint32_t xid;               /* The OpenFlow transaction ID. */
};

/* A connection to a secure channel. */
struct remote {
    struct list node;
    struct rconn *rconn;
    struct rconn *rconn_aux;

#define TXQ_LIMIT 128           /* Max number of packets to queue for tx. */
    int n_txq;                  /* Number of packets queued for tx on rconn. */

    /* Support for reliable, multi-message replies to requests.
     *
     * If an incoming request needs to have a reliable reply that might
     * require multiple messages, it can use remote_start_dump() to set up
     * a callback that will be called as buffer space for replies. */
    int (*cb_dump)(struct datapath *, void *aux);
    void (*cb_done)(void *aux);
    void *cb_aux;

    uint32_t role; /*OpenFlow controller role.*/
    struct ofl_async_config config;  /* Asynchronous messages configuration,
                                            set from controller*/

    /* Multipart request message pending reassembly. */
    struct ofl_msg_multipart_request_header *mp_req_msg; /* Message. */
    uint32_t mp_req_xid;     /* Multipart request OpenFlow transaction ID. */
};

/* Creates a new datapath */
struct datapath *
dp_new(void);

void
dp_add_pvconn(struct datapath *dp, struct pvconn *pvconn, struct pvconn *pvconn_aux);

/* Executes the datapath. The datapath works if this function is run
 * repeatedly. */
void
dp_run(struct datapath *dp, int run);

/* This function should be called after dp_run. It sets up polling on all
 * event sources (listeners, remotes, ...), so that poll_block() will block
 * until an event occurs on any source. */
void
dp_wait(struct datapath *dp, int run);


/* Setter functions for various datapath fields */
void
dp_set_dpid(struct datapath *dp, uint64_t dpid);

void
dp_set_mfr_desc(struct datapath *dp, char *mfr_desc);

void
dp_set_hw_desc(struct datapath *dp, char *hw_desc);

void
dp_set_sw_desc(struct datapath *dp, char *sw_desc);

void
dp_set_dp_desc(struct datapath *dp, char *dp_desc);

void
dp_set_serial_num(struct datapath *dp, char *serial_num);

void
dp_set_max_queues(struct datapath *dp, uint32_t max_queues);


/* Sends the given OFLib message to the connection represented by sender,
 * or to all open connections, if sender is null. */
int
dp_send_message(struct datapath *dp, struct ofl_msg_header *msg,
                     const struct sender *sender);



/* Handles a set description (openflow experimenter) message */
ofl_err
dp_handle_set_desc(struct datapath *dp, struct ofl_exp_openflow_msg_set_dp_desc *msg,
                                            const struct sender *sender);

/* Handles a role request message */
ofl_err
dp_handle_role_request(struct datapath *dp, struct ofl_msg_role_request *msg,
                                            const struct sender *sender);

/* Handles an asynchronous configuration request message */
ofl_err
dp_handle_async_request(struct datapath *dp, struct ofl_msg_async_config *msg,
                                            const struct sender *sender);
#endif /* datapath.h */
