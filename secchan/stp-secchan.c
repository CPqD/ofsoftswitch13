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

#include <config.h>
#include "stp-secchan.h"
#include <arpa/inet.h>
#include <inttypes.h>
#include "flow.h"
#include "secchan.h"
#include "ofp.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "port-watcher.h"
#include "rconn.h"
#include "stp.h"
#include "timeval.h"
#include "vlog.h"

#define LOG_MODULE VLM_stp_secchan

struct stp_data {
    struct stp *stp;
    struct port_watcher *pw;
    struct rconn *local_rconn;
    struct rconn *remote_rconn;
    long long int last_tick;
    int n_txq;
};

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);

static bool
stp_local_packet_cb(struct relay *r, void *stp_)
{
    struct ofpbuf *msg = r->halves[HALF_LOCAL].rxbuf;
    struct ofp_header *oh UNUSED;
    struct stp_data *stp = stp_;
    struct ofp_packet_in *opi;
    struct eth_header *eth;
    struct llc_header *llc;
    struct ofpbuf payload;
    uint32_t port_no;
    struct flow flow;

    oh = msg->data;

    /*if (oh->type == OFPT_FEATURES_REPLY
        && msg->size >= offsetof(struct ofp_switch_features, ports)) {
    	TODO Zoltan: Temporarily removed when moving to Openflow 1.1
        struct ofp_switch_features *osf = msg->data;
        osf->capabilities |= htonl(OFPC_STP); *
        return false;
    }*/

    if (!get_ofp_packet_eth_header(r, &opi, &eth)
        || !eth_addr_equals(eth->eth_dst, stp_eth_addr)) {
        return false;
    }
    port_no = 0;
    /*TODO: Removed to port to OpenFlow 1.2 */
    // port_no = ntohs(opi->in_port);
    // if (port_no >= STP_MAX_PORTS) {
    //    /* STP only supports 255 ports. */
    //   return false;
    // }
    /* TODO Zoltan: Temporarily removed when moving to Openflow 1.1 */
    /*
    if (port_watcher_get_config(stp->pw, port_no) & OFPPC_NO_STP) {
        / * We're not doing STP on this port. * /
        return false;
    }
    */
    if (opi->reason == OFPR_ACTION) {
        /* The controller set up a flow for this, so we won't intercept it. */
        return false;
    }

    get_ofp_packet_payload(opi, &payload);
    flow_extract(&payload, port_no, &flow);
    if (flow.dl_type != htons(0x05ff)) {
        VLOG_DBG(LOG_MODULE, "non-LLC frame received on STP multicast address");
        return false;
    }
    llc = ofpbuf_at_assert(&payload, sizeof *eth, sizeof *llc);
    if (llc->llc_dsap != STP_LLC_DSAP) {
        VLOG_DBG(LOG_MODULE, "bad DSAP 0x%02"PRIx8" received on STP multicast address",
                 llc->llc_dsap);
        return false;
    }

    /* Trim off padding on payload. */
    if (payload.size > ntohs(eth->eth_type) + ETH_HEADER_LEN) {
        payload.size = ntohs(eth->eth_type) + ETH_HEADER_LEN;
    }
    if (ofpbuf_try_pull(&payload, ETH_HEADER_LEN + LLC_HEADER_LEN)) {
        struct stp_port *p = stp_get_port(stp->stp, port_no);
        stp_received_bpdu(p, payload.data, payload.size);
    }

    return true;
}

static void
stp_periodic_cb(void *stp_)
{
    struct stp_data *stp = stp_;
    long long int now = time_msec();
    long long int elapsed = now - stp->last_tick;
    struct stp_port *p;

    if (!port_watcher_is_ready(stp->pw)) {
        /* Can't start STP until we know port flags, because port flags can
         * disable STP. */
        return;
    }
    if (elapsed <= 0) {
        return;
    }

    stp_tick(stp->stp, MIN(INT_MAX, elapsed));
    stp->last_tick = now;

    while (stp_get_changed_port(stp->stp, &p)) {
        int port_no = stp_port_no(p);
        enum stp_state s_state = stp_port_get_state(p);

        if (s_state != STP_DISABLED) {
            VLOG_INFO(LOG_MODULE, "STP: Port %d entered %s state",
                      port_no, stp_state_name(s_state));
        }
    	/* TODO Zoltan: Temporarily removed when moving to Openflow 1.1 */
        /*
        if (!(port_watcher_get_config(stp->pw, port_no) & OFPPC_NO_STP)) {
            uint32_t p_config = 0;
            uint32_t p_state;
            switch (s_state) {
            case STP_LISTENING:
                p_state = OFPPS_STP_LISTEN;
                break;
            case STP_LEARNING:
                p_state = OFPPS_STP_LEARN;
                break;
            case STP_DISABLED:
            case STP_FORWARDING:
                p_state = OFPPS_STP_FORWARD;
                break;
            case STP_BLOCKING:
                p_state = OFPPS_STP_BLOCK;
                break;
            default:
                VLOG_DBG_RL(LOG_MODULE, &rl, "STP: Port %d has bad state %x",
                            port_no, s_state);
                p_state = OFPPS_STP_FORWARD;
                break;
            }
            if (!stp_forward_in_state(s_state)) {
                p_config = OFPPC_NO_FLOOD;
            }
            port_watcher_set_flags(stp->pw, port_no,
                                   p_config, OFPPC_NO_FLOOD,
                                   p_state, OFPPS_STP_MASK);
        } else {
            / * We don't own those flags. * /
        }
        */
    }
}

static void
stp_wait_cb(void *stp_ UNUSED)
{
    poll_set_timer_wait(1000);
}

static void
send_bpdu(struct ofpbuf *pkt, int port_no, void *stp_)
{
    struct stp_data *stp = stp_;
    const uint8_t *port_mac = port_watcher_get_hwaddr(stp->pw, port_no);
    if (port_mac) {
        struct eth_header *eth = pkt->l2;
        struct ofpbuf *opo;

        memcpy(eth->eth_src, port_mac, ETH_ADDR_LEN);
        opo = make_unbuffered_packet_out(pkt, OFPP_ANY, port_no);

        rconn_send_with_limit(stp->local_rconn, opo, &stp->n_txq, OFPP_MAX);
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "cannot send BPDU on missing port %d", port_no);
    }
    ofpbuf_delete(pkt);
}

static bool
stp_is_port_supported(uint32_t port_no)
{
    return port_no < STP_MAX_PORTS;
}

static void
stp_port_changed_cb(uint32_t port_no,
                    const struct ofp_port *old UNUSED,
                    const struct ofp_port *new,
                    void *stp_)
{
    struct stp_data *stp = stp_;
    struct stp_port *p;

    if (!stp_is_port_supported(port_no)) {
        return;
    }

    p = stp_get_port(stp->stp, port_no);
    if (!new
		/* TODO Zoltan: Temporarily removed when moving to Openflow 1.1 */
        /*
        || new->config & htonl(OFPPC_NO_STP | OFPPC_PORT_DOWN)
        || new->state & htonl(OFPPS_LINK_DOWN) */) {
        stp_port_disable(p);
    } else {
        int speed = 0;
        stp_port_enable(p);
        if (new->curr & (OFPPF_10MB_HD | OFPPF_10MB_FD)) {
            speed = 10;
        } else if (new->curr & (OFPPF_100MB_HD | OFPPF_100MB_FD)) {
            speed = 100;
        } else if (new->curr & (OFPPF_1GB_HD | OFPPF_1GB_FD)) {
            speed = 1000;
        } else if (new->curr & OFPPF_10GB_FD) {
            speed = 10000;
        }
        stp_port_set_speed(p, speed);
    }
}

static void
stp_local_port_changed_cb(const struct ofp_port *port, void *stp_)
{
    struct stp_data *stp = stp_;
    if (port) {
        stp_set_bridge_id(stp->stp, eth_addr_to_uint64(port->hw_addr));
    }
}

static struct hook_class stp_hook_class = {
    stp_local_packet_cb,        /* local_packet_cb */
    NULL,                       /* remote_packet_cb */
    stp_periodic_cb,            /* periodic_cb */
    stp_wait_cb,                /* wait_cb */
    NULL,                       /* closing_cb */
};

void
stp_start(struct secchan *secchan, struct port_watcher *pw,
          struct rconn *local, struct rconn *remote)
{
    uint8_t dpid[ETH_ADDR_LEN];
    struct stp_data *stp;

    stp = xcalloc(1, sizeof *stp);
    eth_addr_random(dpid);
    stp->stp = stp_create("stp", eth_addr_to_uint64(dpid), send_bpdu, stp);
    stp->pw = pw;
    stp->local_rconn = local;
    stp->remote_rconn = remote;
    stp->last_tick = time_msec();

    port_watcher_register_callback(pw, stp_port_changed_cb, stp);
    port_watcher_register_local_port_callback(pw, stp_local_port_changed_cb,
                                              stp);
    add_hook(secchan, &stp_hook_class, stp);
}
