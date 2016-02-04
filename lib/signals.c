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

#include <config.h>
#include "signals.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <unistd.h>
#include "poll-loop.h"
#include "socket-util.h"
#include "util.h"

#if defined(_NSIG)
#define N_SIGNALS _NSIG
#elif defined(NSIG)
#define N_SIGNALS NSIG
#else
/* We could try harder to get the maximum signal number, but in practice we
 * only care about SIGHUP, which is normally signal 1 anyway. */
#define N_SIGNALS 32
#endif

struct signal {
    int signr;
};

static volatile sig_atomic_t signaled[N_SIGNALS];

static int fds[2];

static void signal_handler(int signr);

/* Initializes the signals subsystem (if it is not already initialized).  Calls
 * exit() if initialization fails.
 *
 * Calling this function is optional; it will be called automatically by
 * signal_start() if necessary.  Calling it explicitly allows the client to
 * prevent the process from exiting at an unexpected time. */
void
signal_init(void)
{
    static bool inited;
    if (!inited) {
        inited = true;
        if (pipe(fds)) {
            ofp_fatal(errno, "could not create pipe");
        }
        set_nonblocking(fds[0]);
        set_nonblocking(fds[1]);
    }
}

/* Sets up a handler for 'signr' and returns a structure that represents it.
 *
 * Only one handler for a given signal may be registered at a time. */
struct signal *
signal_register(int signr)
{
    struct sigaction sa;
    struct signal *s;

    signal_init();

    /* Set up signal handler. */
    assert(signr >= 1 && signr < N_SIGNALS);
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(signr, &sa, NULL)) {
        ofp_fatal(errno, "sigaction(%d) failed", signr);
    }

    /* Return structure. */
    s = xmalloc(sizeof *s);
    s->signr = signr;
    return s;
}

/* Returns true if signal 's' has been received since the last call to this
 * function with argument 's'. */
bool
signal_poll(struct signal *s)
{
    char buf[_POSIX_PIPE_BUF];
    if (read(fds[0], buf, sizeof buf) != sizeof(buf)){
        fprintf(stderr, "read failed: %s\n",
                strerror(errno));    
    }
    if (signaled[s->signr]) {
        signaled[s->signr] = 0;
        return true;
    }
    return false;
}

/* Causes the next call to poll_block() to wake up when signal_poll(s) would
 * return true. */
void
signal_wait(struct signal *s)
{
    if (signaled[s->signr]) {
        poll_immediate_wake();
    } else {
        poll_fd_wait(fds[0], POLLIN);
    }
}

static void
signal_handler(int signr)
{
    if (signr >= 1 && signr < N_SIGNALS) {
        if (write(fds[1], "", 1) != 1){
            fprintf(stderr, "write failed: %s\n",
                strerror(errno));
        }
        signaled[signr] = true;
    }
}
