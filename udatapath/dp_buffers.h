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

#ifndef DP_BUFFERS_H
#define DP_BUFFERS_H 1

#include <stdbool.h>
#include <stdint.h>
#include "ofpbuf.h"


/* Constant for representing "no buffer" */
#define NO_BUFFER 0xffffffff

/****************************************************************************
 * Datapath buffers for storing packets for packet in messages.
 ****************************************************************************/

struct datapath;
struct packet;

/* Creates a set of buffers */
struct dp_buffers *
dp_buffers_create(struct datapath *dp);

/* Returns the number of buffers */
size_t
dp_buffers_size(struct dp_buffers *dpb);

/* Saves the packet into the buffer. Returns the saved buffer ID, or NO_BUFFER
 * if saving was not possible. */
uint32_t
dp_buffers_save(struct dp_buffers *dpb, struct packet *pkt);

/* Retrieves and removes the packet from the buffer. Returns null if it was not
 * found. */
struct packet *
dp_buffers_retrieve(struct dp_buffers *dpb, uint32_t id);

/* Returns true if the buffered packet is not timed out. */
bool
dp_buffers_is_alive(struct dp_buffers *dpb, uint32_t id);

/* Discards the packet in the given buffer, and destroys the packet if destroy is set. */
void
dp_buffers_discard(struct dp_buffers *dpb, uint32_t id, bool destroy);


#endif /* DP_BUFFERS_H */
