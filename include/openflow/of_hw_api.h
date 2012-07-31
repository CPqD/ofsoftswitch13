/* Copyright (c) 2008, 2009, 2010 The Board of Trustees of The Leland Stanford
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

#if !defined(OF_HW_API_H)
#define OF_HW_API_H

/*
 * OpenFlow hardware API definition
 *
 * This header file provides an abstraction of the flow table and
 * port operations that can be used to build a driver for hardware
 * that implements the OpenFlow protocol.
 *
 * Currently this driver depends (extends) the sw_table defined
 * in the udatapath/table.h file.  Hopefully that file will be
 * moved up to library status to support kernel and userspace
 * implementations.
 *
 */

#include <openflow/openflow.h>
#include <udatapath/table.h>  /* For sw_table */

/* REQUIRES:
 *   struct sw_table defined
 *      TBD: We could remove this restriction; it's mainly so that
 *           current chain.c operations can work.  It also allows
 *           pointer coersion between the two types.
 *
 *           Eventually, sw_table may be extended to include everything in
 *           this driver.
 *
 *   pointer to struct datapath
 */

/****************   basic types   ****************/

typedef uint32_t of_port_t;
typedef struct of_hw_driver of_hw_driver_t;

/****************      packet     ****************/

/* The OpenFlow hardware packet abstraction */
typedef void *os_pkt_t;  /* OS representation of packet */

/* Requires monolithic packet data */
typedef struct of_packet_s {
    unsigned char *data;   /* Pointer to packet data */
    int length;            /* Length in bytes */
    os_pkt_t os_pkt;       /* OS specific representation */
} of_packet_t;

/* Init an of_packet struct from an ofp_buffer struct */
#define OF_PKT_INIT(pkt, ofp_buf) do {              \
        (pkt)->data = (ofp_buf)->data;              \
        (pkt)->length = (ofp_buf)->size;            \
        (pkt)->os_pkt = (ofp_buf);                  \
    } while (0)

/**************** callback protos ****************/

/* packet in callback function prototype */
typedef int (*of_packet_in_f)(of_port_t port,
                              of_packet_t *packet,
                              int reason,
                              void *cookie);

typedef void (*of_port_change_f)(of_port_t port,
                                 int state,
                                 void *cookie);

/****************************************************************
 *
 * Hardware Driver
 *
 ****************************************************************/

/* Hardware capabilities structure */
typedef struct of_hw_driver_caps {
    /* Proposed Flags:
     *    COUNT_PKTS_OR_BYTES  Can count either pkts or bytes, not both
     *    INTERNAL_PRI Support internal priority mapping, and thus
     *       normal enqueuing action
     *    LOCAL_CPU_THRU_TABLE Can send packets from the CPU through
     *       the flow table
     */
    uint32_t flags;

    /* Number of fully qualified flows supported (approx)  */
    int max_flows;
    uint32_t wc_supported;       /* Bitmap of OFPFW_* supported wildcards */
    uint32_t actions_supported;  /* Bitmap of OFPAT_* supported actions */
    uint32_t ofpc_flags;         /* Bitmap of ofp_capabilities flags */
} of_hw_driver_caps_t;

enum of_hw_driver_flags {
    OF_HW_DRV_COUNT_PKTS_OR_BYTES     = 1 << 0,
    OF_HW_DRV_INTERNAL_PRI            = 1 << 1,
    OF_HW_DRV_CPU_PKTS_THRU_TABLE     = 1 << 2
};

/**************** Constructor/Destructor ****************/

extern of_hw_driver_t *new_of_hw_driver(struct datapath *dp);
extern void delete_of_hw_driver(of_hw_driver_t *hw_drv);

/* TBD:  Add a HW/DP init function? */

/**************** HW DataPath Driver Structure ****************/
/* Extends sw_table */
struct of_hw_driver {

    /*
     * Notes on sw_table inheritance:
     *
     * See above as well
     *
     * n_lookup and n_matched are not dynamically updated, but the
     * call to table_stats_update should set them
     */
    struct sw_table sw_table;

    /* HW datapath capabilities structure */
    of_hw_driver_caps_t caps;

    /* OPTIONAL
     * init(table, flags)
     *
     * Initialize necessary hardware and software to run
     * the switching table.  Must be called prior to any other calls
     * into the table (except maybe some ioctls?).
     *
     * Proposed flags include:
     *    BYTES/PACKETS: If COUNT_PKTS_OR_BYTES, which to count by default
     *    REATTACH:  Inidicates HW was running, don't re-initialize HW
     *
     */
    int (*init)(of_hw_driver_t *hw_drv, uint32_t flags);

    /*
     * table_stats_get(table, stats)
     * port_stats_get(port, stats)
     * flow_stats_get(flow_desc, stats)
     * aggregate_stats_get(flow_desc, stats)
     *
     * Fill out the stats object(s) for this table/port/flow(s)/set of flows
     *
     * Returns 0 on success.
     *
     * For all but flow_stats, the routine fills out a pre-allocated
     * stats structure.  For flow stats, an array of stats is allocated
     * by the called routine with *count elements.  It must be freed by
     * the caller.
     *
     * (Optional? If count is NULL for flow_stats_get, find a single
     * match with exactly the given ofp_match.)
     */
    int (*table_stats_get)(of_hw_driver_t *hw_drv, struct
                           ofp_table_stats *stats);
    int (*port_stats_get)(of_hw_driver_t *hw_drv, int of_port,
                          struct ofp_port_stats *stats);
    int (*flow_stats_get)(of_hw_driver_t *hw_drv, struct ofp_match,
                          struct ofp_flow_stats **stats, int *count);
    int (*aggregate_stats_get)(struct ofp_match,
                               struct ofp_aggregate_stats_reply *stats);

    /*
     * port_add/remove(table, port)
     *
     * The indicated port has been added to/removed from the datapath
     * Add also maps the of_port number to the hw_port indicated
     */
    int (*port_add)(of_hw_driver_t *hw_drv, int of_port, const char *hw_name);
    int (*port_remove)(of_hw_driver_t *hw_drv, of_port_t port);

    /*
     * port_link_get(table, port)
     * port_enable_set(table, port, enable)
     * port_enable_get(table, port)
     *
     * Get/set the indicated properties of a port.  Only real ports
     * set with port_add are supported.
     */
    int (*port_link_get)(of_hw_driver_t *hw_drv, int of_port);
    int (*port_enable_set)(of_hw_driver_t *hw_drv, int of_port, int enable);
    int (*port_enable_get)(of_hw_driver_t *hw_drv, int of_port);

    /*
     * port_queue_config(drv, port, qid, min-bw)
     * port_queue_remove(drv, port, qid)
     *
     * Port queue control.  Config will add the queue if not present
     */
    int (*port_queue_config)(of_hw_driver_t *hw_drv, int of_port,
                             uint32_t qid, int min_bw);
    int (*port_queue_remove)(of_hw_driver_t *hw_drv, int of_port,
                             uint32_t qid);

    /*
     * port_change_register
     *
     * Register a callback function to receive port change notifications
     * from ports in this datapath
     */
    int (*port_change_register)(of_hw_driver_t *hw_drv,
                                of_port_change_f callback, void *cookie);

    /*
     * packet_send(table, of_port, pkt, flags)
     *
     * Send packet to an openflow port.
     *
     * Proposed flags:
     *     APPLY_FLOW_TABLE:  If set, and if the hardware supports
     *     it, send the packet through the flow table with the source
     *     port being the local CPU port.  (Would be nice to have
     *     a flexible source port indicated; could hide in flags...)
     *
     * TBD: Owner of pkt and pkt->data after call; sync/async.
     */
    int (*packet_send)(of_hw_driver_t *hw_drv, int of_port, of_packet_t *pkt,
                       uint32_t flags);

    /*
     * packet_receive_register
     *
     * Register a callback function to receive packets from ports in
     * this datapath
     *
     * TBD:  Semantics for owning packets and return codes so indicating.
     */
    int (*packet_receive_register)(of_hw_driver_t *hw_drv,
                                   of_packet_in_f callback, void *cookie);

    /* OPTIONAL
     * ioctl(table, request, io_param)
     *
     * Execute an ioctl on the table.  A few ioctls are predefined,
     * but most will be implementation specific.
     * Returns 0 on success or an implementation specific other code.
     *
     * io_param is an input/output parameter whose value may be
     * returned to the caller.
     * io_len is the length of io_param in bytes.
     * On input, the *io_param pointer may clobbered, so the caller must
     * maintain it for deallocation if necessary.
     * On output, when used -- which depends on the operation --
     * the *io_param is a pointer to a buffer allocated by the ioctl
     * routine, but owned by the calling routine.
     *
     * Question:  Should a full I/O buffer be supported?
     * ioctl(table, op, in_buf, in_len, out_buf, out_len); or
     * ioctl(table, op, io_buf, io_len); where buf/len set on output.
     *
     * Proposed operations:
     *    Set debug level
     *    Clear port/flow/table stats
     *    Select packet or byte counter collection
     */
    int (*ioctl)(of_hw_driver_t *hw_drv, uint32_t op, void **io_param,
                 int *io_len);

};

/**************** IOCTL values ****************/

enum of_hw_ioctl_e {
    OF_HW_IOCTL_TABLE_DEBUG_SET         = 1,
    OF_HW_IOCTL_PORT_DEBUG_SET          = 2,
    OF_HW_IOCTL_BYTE_PKT_CNTR_SET       = 3
};

/* Values for OF_HW_IOCTL_BYTE_PKT_CNTR_SET */
#define OF_HW_CNTR_PACKETS 0
#define OF_HW_CNTR_BYTES 1

enum of_hw_error_e {
    OF_HW_OKAY            = 0,
    OF_HW_ERROR           = -1,
    OF_HW_PORT_DOWN       = -2
};

#endif /* OF_HW_API_H */
