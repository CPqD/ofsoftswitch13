/*-
 * Copyright (c) 2008, 2009
 *      The Board of Trustees of The Leland Stanford Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation that
 * others will use, modify and enhance the Software and contribute those
 * enhancements back to the community. However, since we would like to make the
 * Software available for broadest use, with as few restrictions as possible
 * permission is hereby granted, free of charge, to any person obtaining a copy
 * of this Software to deal in the Software under the copyrights without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any derivatives
 * without specific, written prior permission.
 */

#include <config.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "util.h"
#include "rconn.h"
#include "secchan.h"
#include "status.h"
#include "timeval.h"
#include "sat-math.h"
#include "failover.h"
#include "vlog.h"

#define LOG_MODULE VLM_failover

struct failover_peer {
	time_t epoch;
};

struct failover_context {
	const struct settings *settings;
	const struct secchan *secchan;
	struct rconn *remote_rconn;
	int index;
	struct failover_peer *peers[MAX_CONTROLLERS];
};

static void failover_status_cb(struct status_reply *, void *);
static bool is_timed_out(const struct failover_peer *, int);
static void failover_periodic_cb(void *);

static void
failover_status_cb(struct status_reply *status_reply, void *context_)
{
	struct failover_context *context = context_;
	int i;

	status_reply_put(status_reply, "num-controllers=%d",
			 context->settings->num_controllers);

	for (i = 0; i < MAX_CONTROLLERS; ++i) {
		if (context->settings->controller_names[i] == NULL)
			continue;
		status_reply_put(status_reply, "controller#%d=%s",
				 i, context->settings->controller_names[i]);
	}
}

static bool
is_timed_out(const struct failover_peer *peer, int max_backoff)
{
	unsigned int sat_value = sat_add(peer->epoch, max_backoff);
	return time_now() >= sat_value;
}

static void
failover_periodic_cb(void *context_)
{
	struct failover_context *context = context_;
	char *curr_peer = NULL;
	char *prev_peer = NULL;

	if (rconn_is_connected(context->remote_rconn))
		return;

	if (!is_timed_out(context->peers[context->index],
			  context->settings->max_backoff)) {
		return;
	}

	rconn_disconnect(context->remote_rconn);
	prev_peer = (char *)context->settings->controller_names[context->index];
	context->index = (context->index + 1)
		% context->settings->num_controllers;
	curr_peer = (char *)context->settings->controller_names[context->index];
	rconn_connect(context->remote_rconn,
		      context->settings->controller_names[context->index]);
	context->peers[context->index]->epoch = time_now();
	VLOG_INFO(LOG_MODULE, "Switching over to %s, from %s", curr_peer, prev_peer);
}

void
failover_start(struct secchan *secchan, const struct settings *settings,
	       struct switch_status *switch_status, struct rconn *remote_rconn)
{
	struct failover_context *context = NULL;
	int i;
	static struct hook_class failover_hook_class = {
		NULL,		/* local_packet_cb */
		NULL,		/* remote_packet_cb */
		failover_periodic_cb,	/* periodic_cb */
		NULL,		/* wait_cb */
		NULL,		/* closing_cb */
	};

	context = xmalloc(sizeof(*context));
	context->settings = settings;
	context->secchan = secchan;
	context->remote_rconn = remote_rconn;
	context->index = 0;
	for (i = 0; i < MAX_CONTROLLERS; ++i) {
		context->peers[i] = NULL;
		if (settings->controller_names[i] == NULL)
			continue;
		context->peers[i] = xmalloc(sizeof(struct failover_peer));
		context->peers[i]->epoch = time_now();
	}

	switch_status_register_category(switch_status, "failover",
					failover_status_cb, context);
	add_hook(secchan, &failover_hook_class, context);
}
