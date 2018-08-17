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
#include "vconn-provider.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include "dynamic-string.h"
#include "ofp.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "random.h"
#include "util.h"
#include "oflib/ofl.h"
#include "oflib/ofl-messages.h"
#include "oflib-exp/ofl-exp.h"

#define LOG_MODULE VLM_vconn
#include "vlog.h"

/* State of an active vconn.*/
enum vconn_state {
    /* This is the ordinary progression of states. */
    VCS_CONNECTING,             /* Underlying vconn is not connected. */
    VCS_SEND_HELLO,             /* Waiting to send OFPT_HELLO message. */
    VCS_RECV_HELLO,             /* Waiting to receive OFPT_HELLO message. */
    VCS_CONNECTED,              /* Connection established. */

    /* These states are entered only when something goes wrong. */
    VCS_SEND_ERROR,             /* Sending OFPT_ERROR message. */
    VCS_DISCONNECTED            /* Connection failed or connection closed. */
};

static struct ofl_exp_msg ofl_exp_msg =
        {.pack      = ofl_exp_msg_pack,
         .unpack    = ofl_exp_msg_unpack,
         .free      = ofl_exp_msg_free,
         .to_string = ofl_exp_msg_to_string};

static struct ofl_exp ofl_exp =
        {.act   = NULL,
         .inst  = NULL,
         .match = NULL,
         .stats = NULL,
         .msg   = &ofl_exp_msg};

static struct vconn_class *vconn_classes[] = {
    &tcp_vconn_class,
    &unix_vconn_class,
#ifdef HAVE_NETLINK
    &netlink_vconn_class,
#endif
#ifdef HAVE_OPENSSL
    &ssl_vconn_class,
#endif
};

static struct pvconn_class *pvconn_classes[] = {
    &ptcp_pvconn_class,
    &punix_pvconn_class,
#ifdef HAVE_OPENSSL
    &pssl_pvconn_class,
#endif
};

/* High rate limit because most of the rate-limiting here is individual
 * OpenFlow messages going over the vconn.  If those are enabled then we
 * really need to see them. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(600, 600);

static int do_recv(struct vconn *, struct ofpbuf **);
static int do_send(struct vconn *, struct ofpbuf *);

/* Check the validity of the vconn class structures. */
static void
check_vconn_classes(void)
{
#ifndef NDEBUG
    size_t i;

    for (i = 0; i < ARRAY_SIZE(vconn_classes); i++) {
        struct vconn_class *class = vconn_classes[i];
        assert(class->name != NULL);
        assert(class->open != NULL);
        if (class->close || class->recv || class->send || class->wait) {
            assert(class->close != NULL);
            assert(class->recv != NULL);
            assert(class->send != NULL);
            assert(class->wait != NULL);
        } else {
            /* This class delegates to another one. */
        }
    }

    for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
        struct pvconn_class *class = pvconn_classes[i];
        assert(class->name != NULL);
        assert(class->listen != NULL);
        if (class->close || class->accept || class->wait) {
            assert(class->close != NULL);
            assert(class->accept != NULL);
            assert(class->wait != NULL);
        } else {
            /* This class delegates to another one. */
        }
    }
#endif
}

/* Prints information on active (if 'active') and passive (if 'passive')
 * connection methods supported by the vconn.  If 'bootstrap' is true, also
 * advertises options to bootstrap the CA certificate. */
void
vconn_usage(bool active, bool passive, bool bootstrap UNUSED)
{
    /* Really this should be implemented via callbacks into the vconn
     * providers, but that seems too heavy-weight to bother with at the
     * moment. */
    
    printf("\n");
    if (active) {
        printf("Active OpenFlow connection methods:\n");
        printf("  tcp:HOST[:PORT]         "
               "PORT (default: %d) on remote TCP HOST\n", OFP_TCP_PORT);
#ifdef HAVE_OPENSSL
        printf("  ssl:HOST[:PORT]         "
               "SSL PORT (default: %d) on remote HOST\n", OFP_SSL_PORT);
#endif
        printf("  unix:FILE               Unix domain socket named FILE\n");
        printf("  fd:N                    File descriptor N\n");
    }

    if (passive) {
        printf("Passive OpenFlow connection methods:\n");
        printf("  ptcp:[PORT]             "
               "listen to TCP PORT (default: %d)\n",
               OFP_TCP_PORT);
#ifdef HAVE_OPENSSL
        printf("  pssl:[PORT]             "
               "listen for SSL on PORT (default: %d)\n",
               OFP_SSL_PORT);
#endif
        printf("  punix:FILE              "
               "listen on Unix domain socket FILE\n");
    }

#ifdef HAVE_OPENSSL
    printf("PKI configuration (required to use SSL):\n"
           "  -p, --private-key=FILE  file with private key\n"
           "  -c, --certificate=FILE  file with certificate for private key\n"
           "  -C, --ca-cert=FILE      file with peer CA certificate\n");
    if (bootstrap) {
        printf("  --bootstrap-ca-cert=FILE  file with peer CA certificate "
               "to read or create\n");
    }
#endif
}

/* Attempts to connect to an OpenFlow device.  'name' is a connection name in
 * the form "TYPE:ARGS", where TYPE is an active vconn class's name and ARGS
 * are vconn class-specific.
 *
 * The vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * no lower than 'min_version' and no higher than OFP_VERSION.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*vconnp', otherwise a null
 * pointer.  */
int
vconn_open(const char *name, int min_version, struct vconn **vconnp)
{
    size_t prefix_len;
    size_t i;

    check_vconn_classes();

    *vconnp = NULL;
    prefix_len = strcspn(name, ":");
    if (prefix_len == strlen(name)) {
        return EAFNOSUPPORT;
    }
    for (i = 0; i < ARRAY_SIZE(vconn_classes); i++) {
        struct vconn_class *class = vconn_classes[i];
        if (strlen(class->name) == prefix_len
            && !memcmp(class->name, name, prefix_len)) {
            struct vconn *vconn;
            char *suffix_copy = xstrdup(name + prefix_len + 1);
            int retval = class->open(name, suffix_copy, &vconn);
            free(suffix_copy);
            if (!retval) {
                assert(vconn->state != VCS_CONNECTING
                       || vconn->class->connect);
                vconn->min_version = min_version;
                *vconnp = vconn;
            }
            return retval;
        }
    }
    return EAFNOSUPPORT;
}

int
vconn_open_block(const char *name, int min_version, struct vconn **vconnp)
{
    struct vconn *vconn;
    int error;

    error = vconn_open(name, min_version, &vconn);
    while (error == EAGAIN) {
        vconn_connect_wait(vconn);
        poll_block();
        error = vconn_connect(vconn);
        assert(error != EINPROGRESS);
    }
    if (error) {
        vconn_close(vconn);
        *vconnp = NULL;
    } else {
        *vconnp = vconn;
    }
    return error;
}

/* Closes 'vconn'. */
void
vconn_close(struct vconn *vconn)
{
    if (vconn != NULL) {
        char *name = vconn->name;
        (vconn->class->close)(vconn);
        free(name);
    }
}

/* Returns the name of 'vconn', that is, the string passed to vconn_open(). */
const char *
vconn_get_name(const struct vconn *vconn)
{
    return vconn->name;
}

/* Returns the IP address of the peer, or 0 if the peer is not connected over
 * an IP-based protocol or if its IP address is not yet known. */
uint32_t
vconn_get_ip(const struct vconn *vconn) 
{
    return vconn->ip;
}

/* Returns true if, when 'vconn' is closed, it is possible to try to reconnect
 * to it using the name that was originally used.  This is ordinarily the case.
 *
 * Returns false if reconnecting under the same name will never work in the way
 * that you would expect.  This is the case if 'vconn' represents a "fd:N" type
 * vconn; one can never connect to such a vconn more than once, because closing
 * it closes the file descriptor. */
bool
vconn_is_reconnectable(const struct vconn *vconn)
{
    return vconn->reconnectable;
}

static void
vcs_connecting(struct vconn *vconn) 
{
    int retval = (vconn->class->connect)(vconn);
    assert(retval != EINPROGRESS);
    if (!retval) {
        vconn->state = VCS_SEND_HELLO;
    } else if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval;
    }
}

static void
vcs_send_hello(struct vconn *vconn)
{
    struct ofpbuf *b;
    int retval;

    make_openflow(sizeof(struct ofp_header), OFPT_HELLO, &b);
    retval = do_send(vconn, b);
    if (!retval) {
        ++vconn->ofps_sent.ofps_total;
        ++vconn->ofps_sent.ofps_hello;
        vconn->state = VCS_RECV_HELLO;
    } else {
        ofpbuf_delete(b);
        if (retval != EAGAIN) {
            vconn->state = VCS_DISCONNECTED;
            vconn->error = retval;
        }
    }
}

static void
vcs_recv_hello(struct vconn *vconn)
{
    struct ofpbuf *b;
    int retval;

    retval = do_recv(vconn, &b);
    if (!retval) {
        struct ofp_header *oh = b->data;

        if (oh->type == OFPT_HELLO) {
	    /*TODO: handle OFPHET_VERSIONBITMAP */
            /*if (b->size > sizeof *oh) {
             }*/

            vconn->version = MIN(OFP_VERSION, oh->version);
            if (vconn->version < vconn->min_version) {
                VLOG_WARN_RL(LOG_MODULE, &rl, "%s: version negotiation failed: we support "
                             "versions 0x%02x to 0x%02x inclusive but peer "
                             "supports no later than version 0x%02"PRIx8,
                             vconn->name, vconn->min_version, OFP_VERSION,
                             oh->version);
                vconn->state = VCS_SEND_ERROR;
            } else {
                VLOG_DBG(LOG_MODULE, "%s: negotiated OpenFlow version 0x%02x "
                         "(we support versions 0x%02x to 0x%02x inclusive, "
                         "peer no later than version 0x%02"PRIx8")",
                         vconn->name, vconn->version, vconn->min_version,
                         OFP_VERSION, oh->version);
                vconn->state = VCS_CONNECTED;
            }
            ++vconn->ofps_rcvd.ofps_total;
            ++vconn->ofps_rcvd.ofps_hello;
            ofpbuf_delete(b);
            return;
        } else {
            struct ofl_msg_header *msg;
            char *str;

            if (!ofl_msg_unpack(b->data, b->size, &msg, NULL/*xid*/, &ofl_exp)) {
                str = ofl_msg_to_string(msg, &ofl_exp);
                ofl_msg_free(msg, &ofl_exp);
            } else {
                struct ds string = DS_EMPTY_INITIALIZER;
                ds_put_cstr(&string, "\n");
                ds_put_hex_dump(&string, b->data, MIN(b->size, 1024), 0, false);
                str = ds_cstr(&string);
            }
            VLOG_WARN_RL(LOG_MODULE, &rl, "%s: received message while expecting hello: %s",
                         vconn->name, str);

            free(str);

            retval = EPROTO;
            ofpbuf_delete(b);
        }
    }

    if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval;
    }
}

static void
vcs_send_error(struct vconn *vconn)
{
    struct ofp_error_msg *error;
    struct ofpbuf *b;
    char s[128];
    int retval;

    snprintf(s, sizeof s, "We support versions 0x%02x to 0x%02x inclusive but "
             "you support no later than version 0x%02"PRIx8".",
             vconn->min_version, OFP_VERSION, vconn->version);
    error = make_openflow(sizeof *error, OFPT_ERROR, &b);
    error->type = htons(OFPET_HELLO_FAILED);
    error->code = htons(OFPHFC_INCOMPATIBLE);
    ofpbuf_put(b, s, strlen(s));
    update_openflow_length(b);
    retval = do_send(vconn, b);
    if (retval) {
        ++vconn->ofps_sent.ofps_total;
        ++vconn->ofps_sent.ofps_error;
        ++vconn->ofps_sent.ofps_error_type.hello_fail;
        ++vconn->ofps_sent.ofps_error_code.hf_incompat;
        ofpbuf_delete(b);
    }
    if (retval != EAGAIN) {
        vconn->state = VCS_DISCONNECTED;
        vconn->error = retval ? retval : EPROTO;
    }
}

/* Tries to complete the connection on 'vconn', which must be an active
 * vconn.  If 'vconn''s connection is complete, returns 0 if the connection
 * was successful or a positive errno value if it failed.  If the
 * connection is still in progress, returns EAGAIN. */
int
vconn_connect(struct vconn *vconn)
{
    enum vconn_state last_state;

    assert(vconn->min_version >= 0);
    do {
        last_state = vconn->state;
        switch (vconn->state) {
        case VCS_CONNECTING:
            vcs_connecting(vconn);
            break;

        case VCS_SEND_HELLO:
            vcs_send_hello(vconn);
            break;

        case VCS_RECV_HELLO:
            vcs_recv_hello(vconn);
            break;

        case VCS_CONNECTED:
            return 0;

        case VCS_SEND_ERROR:
            vcs_send_error(vconn);
            break;

        case VCS_DISCONNECTED:
            return vconn->error;

        default:
            NOT_REACHED();
        }
    } while (vconn->state != last_state);

    return EAGAIN;
}

/* Tries to receive an OpenFlow message from 'vconn', which must be an active
 * vconn.  If successful, stores the received message into '*msgp' and returns
 * 0.  The caller is responsible for destroying the message with
 * ofpbuf_delete().  On failure, returns a positive errno value and stores a
 * null pointer into '*msgp'.  On normal connection close, returns EOF.
 *
 * vconn_recv will not block waiting for a packet to arrive.  If no packets
 * have been received, it returns EAGAIN immediately. */
int
vconn_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval = vconn_connect(vconn);
    if (!retval) {
        retval = do_recv(vconn, msgp);
    }
    return retval;
}

static int
do_recv(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval;

again:
    retval = (vconn->class->recv)(vconn, msgp);
    if (!retval) {
        struct ofp_header *oh;

        if (VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
            struct ofl_msg_header *msg;
            char *str;

            if (!ofl_msg_unpack((*msgp)->data, (*msgp)->size, &msg, NULL/*xid*/, &ofl_exp)) {
                str = ofl_msg_to_string(msg, &ofl_exp);
                ofl_msg_free(msg, &ofl_exp);
            } else {
                struct ds string = DS_EMPTY_INITIALIZER;
                ds_put_cstr(&string, "\n");
                ds_put_hex_dump(&string, (*msgp)->data, MIN((*msgp)->size, 1024), 0, false);
                str = ds_cstr(&string);
            }
            VLOG_DBG_RL(LOG_MODULE, &rl, "%s: received: %.400s", vconn->name, str);

            free(str);
        }

        oh = ofpbuf_at_assert(*msgp, 0, sizeof *oh);
        if (oh->version != vconn->version
            && oh->type != OFPT_HELLO
            && oh->type != OFPT_ERROR
            && oh->type != OFPT_ECHO_REQUEST
            && oh->type != OFPT_ECHO_REPLY
            && oh->type != OFPT_EXPERIMENTER)
        {
            if (vconn->version < 0) {
                if (oh->type == OFPT_PACKET_IN
                    || oh->type == OFPT_FLOW_REMOVED
                    || oh->type == OFPT_PORT_STATUS) {
                    /* The kernel datapath is stateless and doesn't really
                     * support version negotiation, so it can end up sending
                     * these asynchronous message before version negotiation
                     * is complete.  Just ignore them.
                     *
                     * (After we move OFPT_PORT_STATUS messages from the kernel
                     * into secchan, we won't get those here, since secchan
                     * does proper version negotiation.) */
                    ofpbuf_delete(*msgp);
                    goto again;
                }
                VLOG_ERR_RL(LOG_MODULE, &rl, "%s: received OpenFlow message type %"PRIu8" "
                            "before version negotiation complete",
                            vconn->name, oh->type);
            } else {
                VLOG_ERR_RL(LOG_MODULE, &rl, "%s: received OpenFlow version 0x%02"PRIx8" "
                            "!= expected %02x",
                            vconn->name, oh->version, vconn->version);
            }
            ofpbuf_delete(*msgp);
            retval = EPROTO;
        }
    }
    if (retval) {
        *msgp = NULL;
    }
    return retval;
}

/* Tries to queue 'msg' for transmission on 'vconn', which must be an active
 * vconn.  If successful, returns 0, in which case ownership of 'msg' is
 * transferred to the vconn.  Success does not guarantee that 'msg' has been or
 * ever will be delivered to the peer, only that it has been queued for
 * transmission.
 *
 * Returns a positive errno value on failure, in which case the caller
 * retains ownership of 'msg'.
 *
 * vconn_send will not block.  If 'msg' cannot be immediately accepted for
 * transmission, it returns EAGAIN immediately. */
int
vconn_send(struct vconn *vconn, struct ofpbuf *msg)
{
    int retval = vconn_connect(vconn);
    if (!retval) {
        retval = do_send(vconn, msg);
    }
    return retval;
}

static int
do_send(struct vconn *vconn, struct ofpbuf *buf)
{
    int retval;

    assert(buf->size >= sizeof(struct ofp_header));
    assert(((struct ofp_header *) buf->data)->length == htons(buf->size));
    if (!VLOG_IS_DBG_ENABLED(LOG_MODULE)) {
        retval = (vconn->class->send)(vconn, buf);
    } else {
        struct ofl_msg_header *msg;
        char *str;

        if (!ofl_msg_unpack(buf->data, buf->size, &msg, NULL/*xid*/, &ofl_exp)) {
            str = ofl_msg_to_string(msg, &ofl_exp);
            ofl_msg_free(msg, &ofl_exp);
        } else {
            struct ds string = DS_EMPTY_INITIALIZER;
            ds_put_cstr(&string, "\n");
            ds_put_hex_dump(&string, buf->data, MIN(buf->size, 1024), 0, false);
            str = ds_cstr(&string);
        }

        retval = (vconn->class->send)(vconn, buf);
        if (retval != EAGAIN) {
            VLOG_DBG_RL(LOG_MODULE, &rl, "%s: sent (%s): %.400s",
                        vconn->name, strerror(retval), str);
        }

        free(str);
    }
    return retval;
}

/* Same as vconn_send, except that it waits until 'msg' can be transmitted. */
int
vconn_send_block(struct vconn *vconn, struct ofpbuf *msg)
{
    int retval;
    while ((retval = vconn_send(vconn, msg)) == EAGAIN) {
        vconn_send_wait(vconn);
        poll_block();
    }
    return retval;
}

/* Same as vconn_recv, except that it waits until a message is received. */
int
vconn_recv_block(struct vconn *vconn, struct ofpbuf **msgp)
{
    int retval;
    while ((retval = vconn_recv(vconn, msgp)) == EAGAIN) {
        vconn_recv_wait(vconn);
        poll_block();
    }
    return retval;
}

/* Waits until a message with a transaction ID matching 'xid' is recived on
 * 'vconn'.  Returns 0 if successful, in which case the reply is stored in
 * '*replyp' for the caller to examine and free.  Otherwise returns a positive
 * errno value, or EOF, and sets '*replyp' to null.
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_recv_xid(struct vconn *vconn, uint32_t xid, struct ofpbuf **replyp)
{
    for (;;) {
        uint32_t recv_xid;
        uint16_t reply_flag;
        uint8_t type;
        struct ofpbuf *reply;
        int error;

        error = vconn_recv_block(vconn, &reply);
        if (error) {
            *replyp = NULL;
            return error;
        }
        /* Multipart messages 
           TODO: It's only getting the last message.
           Should return an array of multiparted
           messages*/
        type = ((struct ofp_header*) reply->data)->type;
        if (type == OFPT_MULTIPART_REPLY || type == OFPT_MULTIPART_REQUEST){
            reply_flag = ((struct ofp_multipart_reply *) reply->data)->flags;
            
            while(ntohs(reply_flag) == OFPMPF_REPLY_MORE){
               error = vconn_recv_block(vconn, &reply);
               reply_flag = ((struct ofp_multipart_reply *) reply->data)->flags;
            }
        }    
        recv_xid = ((struct ofp_header *) reply->data)->xid;
        if (xid == recv_xid) {
            *replyp = reply;
            return 0;
        }

        VLOG_DBG_RL(LOG_MODULE, &rl, "%s: received reply with xid %08"PRIx32" != expected "
                    "%08"PRIx32, vconn->name, recv_xid, xid);
        ofpbuf_delete(reply);
    }
}

/* Sends 'request' to 'vconn' and blocks until it receives a reply with a
 * matching transaction ID.  Returns 0 if successful, in which case the reply
 * is stored in '*replyp' for the caller to examine and free.  Otherwise
 * returns a positive errno value, or EOF, and sets '*replyp' to null.
 *
 * 'request' is always destroyed, regardless of the return value. */
int
vconn_transact(struct vconn *vconn, struct ofpbuf *request,
               struct ofpbuf **replyp)
{
    uint32_t send_xid = ((struct ofp_header *) request->data)->xid;
    int error;

    *replyp = NULL;
    error = vconn_send_block(vconn, request);
    if (error) {
        ofpbuf_delete(request);
    }
    return error ? error : vconn_recv_xid(vconn, send_xid, replyp);
}

void
vconn_wait(struct vconn *vconn, enum vconn_wait_type wait)
{
    assert(wait == WAIT_CONNECT || wait == WAIT_RECV || wait == WAIT_SEND);

    switch (vconn->state) {
    case VCS_CONNECTING:
        wait = WAIT_CONNECT;
        break;

    case VCS_SEND_HELLO:
    case VCS_SEND_ERROR:
        wait = WAIT_SEND;
        break;

    case VCS_RECV_HELLO:
        wait = WAIT_RECV;
        break;

    case VCS_CONNECTED:
        break;

    case VCS_DISCONNECTED:
        poll_immediate_wake();
        return;
    }
    (vconn->class->wait)(vconn, wait);
}

void
vconn_connect_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_CONNECT);
}

void
vconn_recv_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_RECV);
}

void
vconn_send_wait(struct vconn *vconn)
{
    vconn_wait(vconn, WAIT_SEND);
}

/* Attempts to start listening for OpenFlow connections.  'name' is a
 * connection name in the form "TYPE:ARGS", where TYPE is an passive vconn
 * class's name and ARGS are vconn class-specific.
 *
 * Returns 0 if successful, otherwise a positive errno value.  If successful,
 * stores a pointer to the new connection in '*pvconnp', otherwise a null
 * pointer.  */
int
pvconn_open(const char *name, struct pvconn **pvconnp)
{
    size_t prefix_len;
    size_t i;

    check_vconn_classes();

    *pvconnp = NULL;
    prefix_len = strcspn(name, ":");
    if (prefix_len == strlen(name)) {
        return EAFNOSUPPORT;
    }
    for (i = 0; i < ARRAY_SIZE(pvconn_classes); i++) {
        struct pvconn_class *class = pvconn_classes[i];
        if (strlen(class->name) == prefix_len
            && !memcmp(class->name, name, prefix_len)) {
            char *suffix_copy = xstrdup(name + prefix_len + 1);
            int retval = class->listen(name, suffix_copy, pvconnp);
            free(suffix_copy);
            if (retval) {
                *pvconnp = NULL;
            }
            return retval;
        }
    }
    return EAFNOSUPPORT;
}

/* Closes 'pvconn'. */
void
pvconn_close(struct pvconn *pvconn)
{
    if (pvconn != NULL) {
        char *name = pvconn->name;
        (pvconn->class->close)(pvconn);
        free(name);
    }
}

/* Tries to accept a new connection on 'pvconn'.  If successful, stores the new
 * connection in '*new_vconn' and returns 0.  Otherwise, returns a positive
 * errno value.
 *
 * The new vconn will automatically negotiate an OpenFlow protocol version
 * acceptable to both peers on the connection.  The version negotiated will be
 * no lower than 'min_version' and no higher than OFP_VERSION.
 *
 * pvconn_accept() will not block waiting for a connection.  If no connection
 * is ready to be accepted, it returns EAGAIN immediately. */
int
pvconn_accept(struct pvconn *pvconn, int min_version, struct vconn **new_vconn)
{
    int retval = (pvconn->class->accept)(pvconn, new_vconn);
    if (retval) {
        *new_vconn = NULL;
    } else {
        assert((*new_vconn)->state != VCS_CONNECTING
               || (*new_vconn)->class->connect);
        (*new_vconn)->min_version = min_version;
    }
    return retval;
}

void
pvconn_wait(struct pvconn *pvconn)
{
    (pvconn->class->wait)(pvconn);
}

void
vconn_init(struct vconn *vconn, struct vconn_class *class, int connect_status,
           uint32_t ip, const char *name, bool reconnectable)
{
    vconn->class = class;
    vconn->state = (connect_status == EAGAIN ? VCS_CONNECTING
                    : !connect_status ? VCS_SEND_HELLO
                    : VCS_DISCONNECTED);
    vconn->error = connect_status;
    vconn->version = -1;
    vconn->min_version = -1;
    vconn->ip = ip;
    vconn->name = xstrdup(name);
    vconn->reconnectable = reconnectable;
    memset(&vconn->ofps_rcvd, 0, sizeof(vconn->ofps_rcvd));
    memset(&vconn->ofps_sent, 0, sizeof(vconn->ofps_sent));
}

void
pvconn_init(struct pvconn *pvconn, struct pvconn_class *class,
            const char *name)
{
    pvconn->class = class;
    pvconn->name = xstrdup(name);
}
