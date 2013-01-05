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
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdbool.h>
#include <stdint.h>

#include "dp_buffers.h"
#include "timeval.h"
#include "packet.h"
#include "vlog.h"

#define LOG_MODULE VLM_dp_buf

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);


/* Buffers are identified by a 31-bit opaque ID.  We divide the ID
 * into a buffer number (low bits) and a cookie (high bits).  The buffer number
 * is an index into an array of buffers.  The cookie distinguishes between
 * different packets that have occupied a single buffer.  Thus, the more
 * buffers we have, the lower-quality the cookie... */
#define PKT_BUFFER_BITS 8
#define PKT_COOKIE_BITS (32 - PKT_BUFFER_BITS)

#define N_PKT_BUFFERS (1 << PKT_BUFFER_BITS)
#define PKT_BUFFER_MASK (N_PKT_BUFFERS - 1)


#define OVERWRITE_SECS  1

struct packet_buffer {
    struct packet *pkt;
    uint32_t       cookie;
    time_t         timeout;
};


// NOTE: The current implementation assumes that a packet is only saved once
//       to the buffers. Thus, if two entities save it, and one retrieves it,
//       the other will receive an invalid buffer response.
//       In the current implementation this should not happen.

struct dp_buffers {
    struct datapath       *dp;
    size_t                 buffer_idx;
    size_t                 buffers_num;
    struct packet_buffer   buffers[N_PKT_BUFFERS];
};


struct dp_buffers *
dp_buffers_create(struct datapath *dp) {
    struct dp_buffers *dpb = xmalloc(sizeof(struct dp_buffers));
    size_t i;

    dpb->dp          = dp;
    dpb->buffer_idx  = (size_t)-1;
    dpb->buffers_num = N_PKT_BUFFERS;

    for (i=0; i<N_PKT_BUFFERS; i++) {
        dpb->buffers[i].pkt     = NULL;
        dpb->buffers[i].cookie  = UINT32_MAX;
        dpb->buffers[i].timeout = 0;
    }

    return dpb;
}

size_t
dp_buffers_size(struct dp_buffers *dpb) {
    return dpb->buffers_num;
}

uint32_t
dp_buffers_save(struct dp_buffers *dpb, struct packet *pkt) {
    struct packet_buffer *p;
    uint32_t id;

    /* if packet is already in buffer, do not save again */
    if (pkt->buffer_id != NO_BUFFER) {
        if (dp_buffers_is_alive(dpb, pkt->buffer_id)) {
            return pkt->buffer_id;
        }
    }

    dpb->buffer_idx = (dpb->buffer_idx + 1) & PKT_BUFFER_MASK;

    p = &dpb->buffers[dpb->buffer_idx];
    if (p->pkt != NULL) {
        if (time_now() < p->timeout) {
            return NO_BUFFER;
        } else {
            p->pkt->buffer_id = NO_BUFFER;
            packet_destroy(p->pkt);
        }
    }
    /* Don't use maximum cookie value since the all-bits-1 id is
     * special. */
    if (++p->cookie >= (1u << PKT_COOKIE_BITS) - 1)
        p->cookie = 0;
    p->pkt = pkt;
    p->timeout = time_now() + OVERWRITE_SECS;
    id = dpb->buffer_idx | (p->cookie << PKT_BUFFER_BITS);

    pkt->buffer_id  = id;

    return id;
}

struct packet *
dp_buffers_retrieve(struct dp_buffers *dpb, uint32_t id) {
    struct packet *pkt = NULL;
    struct packet_buffer *p;

    p = &dpb->buffers[id & PKT_BUFFER_MASK];
    if (p->cookie == id >> PKT_BUFFER_BITS && p->pkt != NULL) {
        pkt = p->pkt;
        pkt->buffer_id = NO_BUFFER;
        pkt->packet_out = false;

        p->pkt = NULL;
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "cookie mismatch: %x != %x\n",
                          id >> PKT_BUFFER_BITS, p->cookie);
    }

    return pkt;
}

bool
dp_buffers_is_alive(struct dp_buffers *dpb, uint32_t id) {
    struct packet_buffer *p;

    p = &dpb->buffers[id & PKT_BUFFER_MASK];
    return ((p->cookie == id >> PKT_BUFFER_BITS) &&
            (time_now() < p->timeout));
}


void
dp_buffers_discard(struct dp_buffers *dpb, uint32_t id, bool destroy) {
    struct packet_buffer *p;

    p = &dpb->buffers[id & PKT_BUFFER_MASK];

    if (p->cookie == id >> PKT_BUFFER_BITS) {
        if (destroy) {
            p->pkt->buffer_id = NO_BUFFER;
            packet_destroy(p->pkt);
        }
        p->pkt = NULL;
    }
}
