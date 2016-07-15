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
 * THE SOFTWRE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
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
 *
 * Modifications: Reconstruct VLAN header from PACKET_AUXDATA
 *
 * The modification includes code from libpcap; the copyright notice for that
 * code is
 *
 *  pcap-linux.c: Packet capture interface to the Linux kernel
 *
 *  Copyright (c) 2000 Torsten Landschoff <torsten@debian.org>
 *             Sebastian Krahmer  <krahmer@cs.uni-potsdam.de>
 *
 *  License: BSD
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *  3. The names of the authors may not be used to endorse or promote
 *     products derived from this software without specific prior
 *     written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 *  IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 *
 */

#include <config.h>
#include "netdev.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <linux/rtnetlink.h>
#include <linux/if_tun.h>
#include <linux/if_packet.h>

#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
#include <pcap/pcap.h>
#pragma message "BEBA netdev is using libpcap!"
#ifdef HAVE_LINUX_PF_Q_H
#include <linux/pf_q.h>
#endif
#endif

#ifdef PACKET_AUXDATA
#   define HAVE_PACKET_AUXDATA
#endif

/* Fix for some compile issues we were experiencing when setting up openwrt
 * with the 2.4 kernel. linux/ethtool.h seems to use kernel-style inttypes,
 * which breaks in userspace.
 */
#ifndef __KERNEL__
#include <linux/types.h>
#define u8 __u8
#define u16 __u16
#define u32 __u32
#define u64 __u64
#define s8 __s8
#define s16 __s16
#define s32 __s32
#define s64 __s64
#endif

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/version.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/route.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fatal-signal.h"
#include "list.h"
#include "netlink.h"
#include "ofpbuf.h"
#include "openflow/openflow.h"
#include "packets.h"
#include "poll-loop.h"
#include "socket-util.h"
#include "svec.h"

/* linux/if.h defines IFF_LOWER_UP, net/if.h doesn't.
 * net/if.h defines if_nameindex(), linux/if.h doesn't.
 * We can't include both headers, so define IFF_LOWER_UP ourselves. */
#ifndef IFF_LOWER_UP
#define IFF_LOWER_UP 0x10000
#endif

#define LOG_MODULE VLM_netdev
#include "vlog.h"

struct netdev {
    struct list node;
    char *name;

    /* File descriptors.  For ordinary network devices, the two fds below are
     * the same; for tap devices, they differ. */
    int netdev_fd;              /* Network device. */
    int tap_fd;                 /* TAP character device, if any, otherwise the
                                 * network device. */

    int netlink_fd;

#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
    pcap_t *pcap;
#endif

    /* one socket per queue.These are valid only for ordinary network devices*/
    int queue_fd[NETDEV_MAX_QUEUES + 1];
    uint16_t num_queues;

    /* Cached network device information. */
    int ifindex;
    uint8_t etheraddr[ETH_ADDR_LEN];
    struct in6_addr in6;
    int speed;
    int mtu;
    int txqlen;
    int hwaddr_family;

    /* Bitmaps of OFPPF_* that describe features.  All bits disabled if
     * unsupported or unavailable. */
    uint32_t curr;              /* Current features. */
    uint32_t advertised;        /* Features being advertised by the port. */
    uint32_t supported;         /* Features supported by the port. */
    uint32_t peer;              /* Features advertised by the peer. */

    int save_flags;             /* Initial device flags. */
    int changed_flags;          /* Flags that we changed. */
};

/* All open network devices. */
static struct list netdev_list = LIST_INITIALIZER(&netdev_list);

/* An AF_INET socket (used for ioctl operations). */
static int af_inet_sock = -1;

/* This is set pretty low because we probably won't learn anything from the
 * additional log messages. */
static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(5, 20);

static void init_netdev(void);
static int do_open_netdev(const char *name, int ethertype, int tap_fd, struct netdev **netdev_);

static int restore_flags(struct netdev *netdev);
static int get_flags(const char *netdev_name, int *flagsp);
static int set_flags(const char *netdev_name, int flags);

/* Obtains the IPv6 address for 'name' into 'in6'. */
static void
get_ipv6_address(const char *name, struct in6_addr *in6)
{
    FILE *file;
    char line[128];

    file = fopen("/proc/net/if_inet6", "r");
    if (file == NULL) {
        /* This most likely indicates that the host doesn't have IPv6 support,
         * so it's not really a failure condition.*/
        *in6 = in6addr_any;
        return;
    }

    while (fgets(line, sizeof line, file)) {
        uint8_t *s6 = in6->s6_addr;
        char ifname[16 + 1];

#define X8 "%2"SCNx8
        if (sscanf(line, " "X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8 X8
                   "%*x %*x %*x %*x %16s\n",
                   &s6[0], &s6[1], &s6[2], &s6[3],
                   &s6[4], &s6[5], &s6[6], &s6[7],
                   &s6[8], &s6[9], &s6[10], &s6[11],
                   &s6[12], &s6[13], &s6[14], &s6[15],
                   ifname) == 17
            && !strcmp(name, ifname))
        {
            fclose(file);
            return;
        }
    }
    *in6 = in6addr_any;

    fclose(file);
}

/* All queues in a port, lie beneath a qdisc */
#define TC_QDISC 0x0001
/* This is a root class. In order to efficiently share excess bandwidth
 * tc requires that all classes are under a common root class */
#define TC_ROOT_CLASS 0xffff
/* This is the queue_id for packets that do not match in any other queue.
 * It has min_rate = 0. This is a placeholder for best-effort traffic
 * without any bandwidth guarantees */
#define TC_DEFAULT_CLASS 0xfffe
#define TC_MIN_RATE 1
/* This configures an HTB qdisc under the defined device. */
#define COMMAND_ADD_DEV_QDISC "/sbin/tc qdisc add dev %s " \
                              "root handle %x: htb default %x"
#define COMMAND_DEL_DEV_QDISC "/sbin/tc qdisc del dev %s root"
#define COMMAND_ADD_CLASS "/sbin/tc class add dev %s parent %x:%x " \
                          "classid %x:%x htb rate %dkbit ceil %dkbit"
#define COMMAND_CHANGE_CLASS "/sbin/tc class change dev %s parent %x:%x " \
                             "classid %x:%x htb rate %dkbit ceil %dkbit"
#define COMMAND_DEL_CLASS "/sbin/tc class del dev %s parent %x:%x classid %x:%x"

static int
netdev_setup_root_class(const struct netdev *netdev, uint16_t class_id,
                        uint16_t rate)
{
    char command[1024];
    int actual_rate;

    /* we need to translate from .1% to kbps */
    actual_rate = rate*netdev->speed;

    snprintf(command, sizeof(command), COMMAND_ADD_CLASS, netdev->name,
             TC_QDISC,0,TC_QDISC, class_id, actual_rate, netdev->speed*1000);
    if (system(command) != 0) {
        VLOG_ERR(LOG_MODULE, "Problem configuring root class %d for device %s",
                 class_id, netdev->name);
        return -1;
    }

    return 0;
}

/** Defines a class for the specific queue discipline. A class
 * represents an OpenFlow queue.
 *
 * @param netdev the device under configuration
 * @param class_id unique identifier for this queue. TC limits this to 16-bits,
 * so we need to keep an internal mapping between class_id and OpenFlow
 * queue_id
 * @param rate the minimum rate for this queue in kbps
 * @return 0 on success, non-zero value when the configuration was not
 * successful.
 */
int
netdev_setup_class(const struct netdev *netdev, uint16_t class_id,
                   uint16_t rate)
{
    char command[1024];
    int actual_rate;

    /* we need to translate from .1% to kbps */
    actual_rate = rate*netdev->speed;

    snprintf(command, sizeof(command), COMMAND_ADD_CLASS, netdev->name,
             TC_QDISC, TC_ROOT_CLASS, TC_QDISC, class_id, actual_rate,
             netdev->speed*1000);
    if (system(command) != 0) {
        VLOG_ERR(LOG_MODULE, "Problem configuring class %d for device %s",class_id,
                 netdev->name);
        return -1;
    }

    return 0;
}

/** Changes a class already defined.
 *
 * @param netdev the device under configuration
 * @param class_id unique identifier for this queue. TC limits this to 16-bits,
 * so we need to keep an internal mapping between class_id and OpenFlow
 * queue_id
 * @param rate the minimum rate for this queue in kbps
 * @return 0 on success, non-zero value when the configuration was not
 * successful.
 */
int
netdev_change_class(const struct netdev *netdev, uint16_t class_id, uint16_t rate)
{
    char command[1024];
    int actual_rate;

    /* we need to translate from .1% to kbps */
    actual_rate = rate*netdev->speed;

    snprintf(command, sizeof(command), COMMAND_CHANGE_CLASS, netdev->name,
             TC_QDISC, TC_ROOT_CLASS, TC_QDISC, class_id, actual_rate,
             netdev->speed*1000 );
    if (system(command) != 0) {
        VLOG_ERR(LOG_MODULE, "Problem configuring class %d for device %s",
                 class_id, netdev->name);
        return -1;
    }

    return 0;
}

/** Deletes a class already defined to represent an OpenFlow queue.
 *
 * @param netdev the device under configuration
 * @param class_id unique identifier for this queue.
 * @param rate the minimum rate for this queue in kbps
 * @return 0 on success, non-zero value when the configuration was not
 * successful.
 */
int
netdev_delete_class(const struct netdev *netdev, uint16_t class_id)
{
    char command[1024];

    snprintf(command, sizeof(command), COMMAND_DEL_CLASS, netdev->name,
             TC_QDISC, TC_ROOT_CLASS, TC_QDISC, class_id);
    if (system(command) != 0) {
        VLOG_ERR(LOG_MODULE, "Problem deleting class %d for device %s",class_id,
                 netdev->name);
        return -1;
    }

    return 0;
}

static int
open_queue_socket(const char * name, uint16_t class_id, int * fd)
{
    int error;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    uint32_t priority;

    *fd = socket(PF_PACKET, SOCK_RAW, htons(0)); /* this is a write-only sock */
    if (*fd < 0) {
        return errno;
    }

    /* Set non-blocking mode */
    error = set_nonblocking(*fd);
    if (error) {
        goto error_already_set;
    }

    /* Get ethernet device index. */
    strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    if (ioctl(*fd, SIOCGIFINDEX, &ifr) < 0) {
        VLOG_ERR(LOG_MODULE, "ioctl(SIOCGIFINDEX) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }

    /* Bind to specific ethernet device. */
    memset(&sll, 0, sizeof sll);
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    if (bind(*fd, (struct sockaddr *) &sll, sizeof sll) < 0) {
        VLOG_ERR(LOG_MODULE, "bind to %s failed: %s", name, strerror(errno));
        goto error;
    }

    /* set the priority so that packets from this socket will go to the
     * respective class_id/queue. Note that to refer to a tc class we use the
     * following concatenation
     * qdisc:handle on an unsigned integer. */
    priority = (TC_QDISC<<16) + class_id;
    if ( set_socket_priority(*fd,priority) < 0) {
        VLOG_ERR(LOG_MODULE, "set socket priority failed for %s : %s",name,strerror(errno));
        goto error;
    }

    return 0;

 error:
    error = errno;
 error_already_set:
    close(*fd);
    return error;
}


/** Setup a classful queue for the specific device. Configured according to
 * HTB protocol. Note that this is linux specific. You will need to replace
 * this with the appropriate abstraction for different OS.
 *
 * The default configuration includes a root class and a default queue/class.
 * A root class is neccesary for efficient use of "unused" bandwidth. If we
 * have traffic A and B (given 80% and 20% of the link respectively), B can use
 * more than 20% if A doesn't use all its bandwidth. In order to allow this
 * "sharing", all queues must reside under a common root class.
 * A default queue/class is a queue  where "unclassified" traffic will fall to.
 * The default class has a best-effort behavior.
 *
 * More on Linux Traffic Control and Hierarchical Token Bucket at :
 * http://luxik.cdi.cz/~devik/qos/htb/
 * http://luxik.cdi.cz/~devik/qos/htb/manual/userg.htm
 *
 * @param netdev_name the device to be configured
 * @return 0 on success, non-zero value when the configuration was not
 * successful.
 */
static int
do_setup_qdisc(const char *netdev_name)
{
    char command[1024];
    int error;

    snprintf(command, sizeof(command), COMMAND_ADD_DEV_QDISC, netdev_name,
             TC_QDISC, TC_DEFAULT_CLASS);
    error = system(command);
    if (error) {
        VLOG_WARN(LOG_MODULE, "Problem configuring qdisc for device %s",netdev_name);
        return error;
    }
    return 0;
}

/** Remove current queue disciplines from a net device
 * @param netdev_name the device under configuration
 */
static int
do_remove_qdisc(const char *netdev_name)
{
    char command[1024];

    snprintf(command, sizeof(command), COMMAND_DEL_DEV_QDISC, netdev_name);
    system(command);

    /* There is no need for a device to already be configured. Therefore no
     * need to indicate any error */
    return 0;
}



/** Configures a port to support slicing
 * @param netdev_name the device under configuration
 * @return 0 on success
 */
int
netdev_setup_slicing(struct netdev *netdev, uint16_t num_queues)
{
    int i;
    int * fd;
    int error;

    netdev->num_queues = num_queues;

    /* remove any previous queue configuration for this device */
    error = do_remove_qdisc(netdev->name);
    if (error) {
        return error;
    }

    /* Configure tc queue discipline to allow slicing queues */
    error = do_setup_qdisc(netdev->name);
    if (error) {
        return error;
    }

    /* This define a root class for the queue disc. In order to allow spare
     * bandwidth to be used efficiently, we need all the classes under a root
     * class. For details, refer to :
     * http://luxik.cdi.cz/~devik/qos/htb/ */
    error = netdev_setup_root_class(netdev, TC_ROOT_CLASS,1000);
    if (error) {
        return error;
    }
    /* we configure a default class. This would be the best-effort, getting
     * everything that remains from the other queues.tc requires a min-rate
     * to configure a class, we put a min_rate here */
    error = netdev_setup_class(netdev,TC_DEFAULT_CLASS,1);
    if (error) {
        return error;
    }

    /* the tc backend has been configured. Now, we need to create sockets that
     * match the queue configuration. We need one socket per queue, plus one
     * for default traffic.
     * queue-attached sockets are only for outgoing traffic. Data are received
     * only at the default socket.
     * This is a limitation due to userspace implementation. We can map flows
     * to specific queues using the skb->priority field. Having no access to
     * sk_buffs from userspace, the only way to do the mapping is through the
     * SO_PRIORITY option of the socket. This dictates the usage of one socket
     * per queue. */

    for (i=1; i <= netdev->num_queues; i++) {
        fd = &netdev->queue_fd[i];
        error = open_queue_socket(netdev->name,i,fd);
        if (error) {
            return error;
        }
    }

    return 0;
}

static void
do_ethtool(struct netdev *netdev)
{
    struct ifreq ifr;
    struct ethtool_cmd ecmd;

    netdev->curr = 0;
    netdev->supported = 0;
    netdev->advertised = 0;
    netdev->peer = 0;
    netdev->speed = SPEED_1000;  /* default to 1Gbps link */

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_data = (caddr_t) &ecmd;

    memset(&ecmd, 0, sizeof ecmd);
    ecmd.cmd = ETHTOOL_GSET;
    if (ioctl(netdev->netdev_fd, SIOCETHTOOL, &ifr) == 0) {
        if (ecmd.supported & SUPPORTED_10baseT_Half) {
            netdev->supported |= OFPPF_10MB_HD;
        }
        if (ecmd.supported & SUPPORTED_10baseT_Full) {
            netdev->supported |= OFPPF_10MB_FD;
        }
        if (ecmd.supported & SUPPORTED_100baseT_Half)  {
            netdev->supported |= OFPPF_100MB_HD;
        }
        if (ecmd.supported & SUPPORTED_100baseT_Full) {
            netdev->supported |= OFPPF_100MB_FD;
        }
        if (ecmd.supported & SUPPORTED_1000baseT_Half) {
            netdev->supported |= OFPPF_1GB_HD;
        }
        if (ecmd.supported & SUPPORTED_1000baseT_Full) {
            netdev->supported |= OFPPF_1GB_FD;
        }
        if (ecmd.supported & SUPPORTED_10000baseT_Full) {
            netdev->supported |= OFPPF_10GB_FD;
        }
        if (ecmd.supported & SUPPORTED_TP) {
            netdev->supported |= OFPPF_COPPER;
        }
        if (ecmd.supported & SUPPORTED_FIBRE) {
            netdev->supported |= OFPPF_FIBER;
        }
        if (ecmd.supported & SUPPORTED_Autoneg) {
            netdev->supported |= OFPPF_AUTONEG;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
        if (ecmd.supported & SUPPORTED_Pause) {
            netdev->supported |= OFPPF_PAUSE;
        }
        if (ecmd.supported & SUPPORTED_Asym_Pause) {
            netdev->supported |= OFPPF_PAUSE_ASYM;
        }
#endif /* kernel >= 2.6.14 */

        /* Set the advertised features */
        if (ecmd.advertising & ADVERTISED_10baseT_Half) {
            netdev->advertised |= OFPPF_10MB_HD;
        }
        if (ecmd.advertising & ADVERTISED_10baseT_Full) {
            netdev->advertised |= OFPPF_10MB_FD;
        }
        if (ecmd.advertising & ADVERTISED_100baseT_Half) {
            netdev->advertised |= OFPPF_100MB_HD;
        }
        if (ecmd.advertising & ADVERTISED_100baseT_Full) {
            netdev->advertised |= OFPPF_100MB_FD;
        }
        if (ecmd.advertising & ADVERTISED_1000baseT_Half) {
            netdev->advertised |= OFPPF_1GB_HD;
        }
        if (ecmd.advertising & ADVERTISED_1000baseT_Full) {
            netdev->advertised |= OFPPF_1GB_FD;
        }
        if (ecmd.advertising & ADVERTISED_10000baseT_Full) {
            netdev->advertised |= OFPPF_10GB_FD;
        }
        if (ecmd.advertising & ADVERTISED_TP) {
            netdev->advertised |= OFPPF_COPPER;
        }
        if (ecmd.advertising & ADVERTISED_FIBRE) {
            netdev->advertised |= OFPPF_FIBER;
        }
        if (ecmd.advertising & ADVERTISED_Autoneg) {
            netdev->advertised |= OFPPF_AUTONEG;
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,14)
        if (ecmd.advertising & ADVERTISED_Pause) {
            netdev->advertised |= OFPPF_PAUSE;
        }
        if (ecmd.advertising & ADVERTISED_Asym_Pause) {
            netdev->advertised |= OFPPF_PAUSE_ASYM;
        }
#endif /* kernel >= 2.6.14 */

        /* Set the current features */
        if (ecmd.speed == SPEED_10) {
            netdev->curr = (ecmd.duplex) ? OFPPF_10MB_FD : OFPPF_10MB_HD;
        }
        else if (ecmd.speed == SPEED_100) {
            netdev->curr = (ecmd.duplex) ? OFPPF_100MB_FD : OFPPF_100MB_HD;
        }
        else if (ecmd.speed == SPEED_1000) {
            netdev->curr = (ecmd.duplex) ? OFPPF_1GB_FD : OFPPF_1GB_HD;
        }
        else if (ecmd.speed == SPEED_10000) {
            netdev->curr = OFPPF_10GB_FD;
        }

        if (ecmd.port == PORT_TP) {
            netdev->curr |= OFPPF_COPPER;
        }
        else if (ecmd.port == PORT_FIBRE) {
            netdev->curr |= OFPPF_FIBER;
        }

        if (ecmd.autoneg) {
            netdev->curr |= OFPPF_AUTONEG;
        }

        netdev->speed = ecmd.speed;

    } else {
        VLOG_DBG(LOG_MODULE, "ioctl(SIOCETHTOOL) failed: %s", strerror(errno));
    }
}

/* Opens the network device named 'name' (e.g. "eth0") and returns zero if
 * successful, otherwise a positive errno value.  On success, sets '*netdevp'
 * to the new network device, otherwise to null.
 *
 * 'ethertype' may be a 16-bit Ethernet protocol value in host byte order to
 * capture frames of that type received on the device.  It may also be one of
 * the 'enum netdev_pseudo_ethertype' values to receive frames in one of those
 * categories. */
int
netdev_open(const char *name, int ethertype, struct netdev **netdevp)
{
    if (!strncmp(name, "tap:", 4)) {
        return netdev_open_tap(name + 4, netdevp);
    } else {
        return do_open_netdev(name, ethertype, -1, netdevp);
    }
}

/* Opens a TAP virtual network device.  If 'name' is a nonnull, non-empty
 * string, attempts to assign that name to the TAP device (failing if the name
 * is already in use); otherwise, a name is automatically assigned.  Returns
 * zero if successful, otherwise a positive errno value.  On success, sets
 * '*netdevp' to the new network device, otherwise to null.  */
int
netdev_open_tap(const char *name, struct netdev **netdevp)
{
    static const char tap_dev[] = "/dev/net/tun";
    struct ifreq ifr;
    int error;
    int tap_fd;

    tap_fd = open(tap_dev, O_RDWR);
    if (tap_fd < 0) {
        ofp_error(errno, "opening \"%s\" failed", tap_dev);
        return errno;
    }

    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    if (name) {
        strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    }
    if (ioctl(tap_fd, TUNSETIFF, &ifr) < 0) {
        int error = errno;
        ofp_error(error, "ioctl(TUNSETIFF) on \"%s\" failed", tap_dev);
        close(tap_fd);
        return error;
    }

    error = set_nonblocking(tap_fd);
    if (error) {
        ofp_error(error, "set_nonblocking on \"%s\" failed", tap_dev);
        close(tap_fd);
        return error;
    }

    error = do_open_netdev(ifr.ifr_name, NETDEV_ETH_TYPE_NONE, tap_fd,
                           netdevp);
    if (error) {
        close(tap_fd);
    }
    return error;
}

static int
do_open_netdev(const char *name, int ethertype, int tap_fd, struct netdev **netdev_)
{
    int netdev_fd = 0;
    int netlink_fd;
    struct sockaddr_ll sll;
    struct sockaddr_nl snl;
    struct ifreq ifr;
    unsigned int ifindex;
    uint8_t etheraddr[ETH_ADDR_LEN];
    struct in6_addr in6;
    int mtu;
    int txqlen;
    int hwaddr_family;
    int error;
    struct netdev *netdev;
    uint32_t val;

#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = NULL;
#endif

    init_netdev();
    *netdev_ = NULL;

    /* Open netlink socket. */
    netlink_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (netlink_fd < 0) {
        return errno;
    }

    /* Set non-blocking mode. */
    error = set_nonblocking(netlink_fd);
    if (error) {
        goto error_already_set;
    }

    /* Create raw socket. */
    netdev_fd = socket(PF_PACKET, SOCK_RAW,
                       htons(ethertype == NETDEV_ETH_TYPE_NONE ? 0
                             : ethertype == NETDEV_ETH_TYPE_ANY ? ETH_P_ALL
                             : ethertype == NETDEV_ETH_TYPE_802_2 ? ETH_P_802_2
                             : ethertype));
    if (netdev_fd < 0) {
        return errno;
    }
  #ifdef HAVE_PACKET_AUXDATA
        val = 1;
          if (setsockopt(netdev_fd, SOL_PACKET, PACKET_AUXDATA, &val,
               sizeof val) == -1 && errno != ENOPROTOOPT){
              VLOG_ERR(LOG_MODULE, "setsockopt(SO_RCVBUF,%"PRIu32"): %s", val, strerror(errno));
          }
  #endif

    /* Set non-blocking mode. */
    error = set_nonblocking(netdev_fd);
    if (error) {
        goto error_already_set;
    }

    memset (&snl,0,sizeof(snl));
    snl.nl_family = AF_NETLINK;
    snl.nl_groups =  RTMGRP_LINK;

    if (bind(netlink_fd, (struct sockaddr *)&snl, sizeof(snl)) < 0){
        VLOG_ERR(LOG_MODULE, "netlink bind to %s failed: %s", name, strerror(errno));
        goto error;
    }

    /* Get ethernet device index. */
    strncpy(ifr.ifr_name, name, sizeof ifr.ifr_name);
    if (ioctl(netdev_fd, SIOCGIFINDEX, &ifr) < 0) {
        VLOG_ERR(LOG_MODULE, "ioctl(SIOCGIFINDEX) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    ifindex = ifr.ifr_ifindex;

    /* Bind to specific ethernet device. */
    memset(&sll, 0, sizeof sll);
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(netdev_fd, (struct sockaddr *) &sll, sizeof sll) < 0) {
        VLOG_ERR(LOG_MODULE, "bind to %s failed: %s", name, strerror(errno));
        goto error;
    }

    if (ethertype != NETDEV_ETH_TYPE_NONE) {
        /* Between the socket() and bind() calls above, the socket receives all
         * packets of the requested type on all system interfaces.  We do not
         * want to receive that data, but there is no way to avoid it.  So we
         * must now drain out the receive queue. */
        error = drain_rcvbuf(netdev_fd);
        if (error) {
            goto error;
        }
    }

    /* Get MAC address. */
    if (ioctl(netdev_fd, SIOCGIFHWADDR, &ifr) < 0) {
        VLOG_ERR(LOG_MODULE, "ioctl(SIOCGIFHWADDR) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    hwaddr_family = ifr.ifr_hwaddr.sa_family;
    if (hwaddr_family != AF_UNSPEC && hwaddr_family != ARPHRD_ETHER) {
        VLOG_WARN(LOG_MODULE, "%s device has unknown hardware address family %d",
                  name, hwaddr_family);
    }
    memcpy(etheraddr, ifr.ifr_hwaddr.sa_data, sizeof etheraddr);

    /* Get MTU. */
    if (ioctl(netdev_fd, SIOCGIFMTU, &ifr) < 0) {
        VLOG_ERR(LOG_MODULE, "ioctl(SIOCGIFMTU) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    mtu = ifr.ifr_mtu;

    /* Get TX queue length. */
    if (ioctl(netdev_fd, SIOCGIFTXQLEN, &ifr) < 0) {
        VLOG_ERR(LOG_MODULE, "ioctl(SIOCGIFTXQLEN) on %s device failed: %s",
                 name, strerror(errno));
        goto error;
    }
    txqlen = ifr.ifr_qlen;

    get_ipv6_address(name, &in6);

#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
    /* open pcap device if it's not a tap */
    if (strncmp(name, "tap", 3) != 0) {
	    pcap = pcap_open_live(name, 1514, 1, -1, pcap_errbuf);
	    if (!pcap) {
		VLOG_ERR(LOG_MODULE, "pcap: pcap_open_live on %s device failed: %s",
			 name, pcap_errbuf);
		goto error;
	    }
    }
#endif

    /* Allocate network device. */
    netdev = xmalloc(sizeof *netdev);
    netdev->name = xstrdup(name);
    netdev->ifindex = ifindex;
    netdev->txqlen = txqlen;
    netdev->hwaddr_family = hwaddr_family;
    netdev->netdev_fd = netdev_fd;
    netdev->netlink_fd = netlink_fd;
    netdev->tap_fd = tap_fd < 0 ? netdev_fd : tap_fd;
#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
    netdev->pcap = pcap;
#endif
    netdev->queue_fd[0] = netdev->tap_fd;
    memcpy(netdev->etheraddr, etheraddr, sizeof etheraddr);
    netdev->mtu = mtu;
    netdev->in6 = in6;
    netdev->num_queues = 0;

    /* Get speed, features. */
    do_ethtool(netdev);

    /* Save flags to restore at close or exit. */
    error = get_flags(netdev->name, &netdev->save_flags);
    if (error) {
        goto error_already_set;
    }
    netdev->changed_flags = 0;
    fatal_signal_block();
    list_push_back(&netdev_list, &netdev->node);
    fatal_signal_unblock();

    /* Success! */
    *netdev_ = netdev;
    return 0;

error:
    error = errno;

error_already_set:

#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
    if (pcap)
	pcap_close(pcap);
#endif

    if (netdev_fd)
	close(netdev_fd);
    if (tap_fd >= 0) {
        close(tap_fd);
    }
    return error;
}

/* Closes and destroys 'netdev'. */
void
netdev_close(struct netdev *netdev)
{
    int i;

    if (netdev) {
        /* Bring down interface and drop promiscuous mode, if we brought up
         * the interface or enabled promiscuous mode. */
        int error;
        fatal_signal_block();
        error = restore_flags(netdev);
        list_remove(&netdev->node);
        fatal_signal_unblock();
        if (error) {
            VLOG_WARN(LOG_MODULE, "failed to restore network device flags on %s: %s",
                      netdev->name, strerror(error));
        }

        /* Free. */
        free(netdev->name);
        close(netdev->netdev_fd);
#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
	if (netdev->pcap)
		pcap_close(netdev->pcap);
#endif
        if (netdev->netdev_fd != netdev->tap_fd) {
            close(netdev->tap_fd);
        }

        for (i =1; i <= netdev->num_queues; i++) {
            close(netdev->queue_fd[i]);
        }
        free(netdev);
    }
}

/* Pads 'buffer' out with zero-bytes to the minimum valid length of an
 * Ethernet packet, if necessary.  */
static void
pad_to_minimum_length(struct ofpbuf *buffer)
{
    if (buffer->size < ETH_TOTAL_MIN) {
        ofpbuf_put_zeros(buffer, ETH_TOTAL_MIN - buffer->size);
    }
}

int
netdev_link_state(struct netdev *netdev)
{
     int len;
     char buff[4096];
     struct nlmsghdr *nlm;
     struct ifinfomsg *ifa;
     enum netdev_flags flags;
     nlm = (struct nlmsghdr *)buff;
     do
     {
        len = recv (netdev->netlink_fd,nlm,4096,0);
        for (;(NLMSG_OK (nlm, len)) && (nlm->nlmsg_type != NLMSG_DONE); nlm = NLMSG_NEXT(nlm, len))
         {
             if (nlm->nlmsg_type != RTM_NEWLINK)
                continue;
             ifa = (struct ifinfomsg *) NLMSG_DATA (nlm);
             if (ifa->ifi_index == netdev->ifindex){
                 if (ifa->ifi_flags & IFF_UP){
                     netdev_nodev_get_flags(netdev->name, &flags);
                     netdev_set_flags(netdev, flags, false);
                     return NETDEV_LINK_UP;
                 }
                 else {
                     netdev_nodev_get_flags(netdev->name, &flags);
                     netdev_set_flags(netdev, flags, false);
                     return NETDEV_LINK_DOWN;
                 }
	     }
         }
     } while (len < 0 && errno == EINTR);
     return NETDEV_LINK_NO_CHANGE;
}

/* Attempts to receive a packet from 'netdev' into 'buffer', which the caller
 * must have initialized with sufficient room for the packet.  The space
 * required to receive any packet is ETH_HEADER_LEN bytes, plus VLAN_HEADER_LEN
 * bytes, plus the device's MTU (which may be retrieved via netdev_get_mtu()).
 * (Some devices do not allow for a VLAN header, in which case VLAN_HEADER_LEN
 * need not be included.)
 *
 * If a packet is successfully retrieved, returns 0.  In this case 'buffer' is
 * guaranteed to contain at least ETH_TOTAL_MIN bytes.  Otherwise, returns a
 * positive errno value.  Returns EAGAIN immediately if no packet is ready to
 * be returned.
 */

static int
netdev_recv_linux(struct netdev *netdev, struct ofpbuf *buffer, size_t max_mtu)
{
#ifdef HAVE_PACKET_AUXDATA
    /* Code from libpcap to reconstruct VLAN header */
    struct iovec    iov;
    struct cmsghdr    *cmsg;
    struct msghdr     msg;
    struct sockaddr   from;
    union {
      struct cmsghdr  cmsg;
      char    buf[CMSG_SPACE(sizeof(struct tpacket_auxdata))];
    } cmsg_buf;
#else
    struct sockaddr_ll sll;
    socklen_t sll_len;
#endif
    ssize_t n_bytes;

    assert(buffer->size == 0);
    assert(ofpbuf_tailroom(buffer) >= ETH_TOTAL_MIN);

#ifdef HAVE_PACKET_AUXDATA
    /* Code from libpcap to reconstruct VLAN header */
    memset(&msg, 0, sizeof(struct msghdr));
    memset(cmsg_buf.buf, 0, CMSG_SPACE(sizeof(struct tpacket_auxdata)));

    msg.msg_name	= &from;
    msg.msg_namelen	= sizeof(from);
    msg.msg_iov		= &iov;
    msg.msg_iovlen	= 1;
    msg.msg_control     = &cmsg_buf;
    msg.msg_controllen  = sizeof(cmsg_buf);
    msg.msg_flags	= 0;

    iov.iov_len		= max_mtu;
    iov.iov_base	= buffer->data;

#else
    /* prepare to call recvfrom */
    memset(&sll,0,sizeof sll);
    sll_len = sizeof sll;
#endif

    /* cannot execute recvfrom over a tap device */
    if (!strncmp(netdev->name, "tap", 3)) {
        do {
            n_bytes = read(netdev->tap_fd, ofpbuf_tail(buffer),
                           (ssize_t)ofpbuf_tailroom(buffer));
        } while (n_bytes < 0 && errno == EINTR);
    }
    else {
        do {
#ifdef HAVE_PACKET_AUXDATA
            /* Code from libpcap to reconstruct VLAN header */
            n_bytes = recvmsg(netdev->tap_fd, &msg, 0);
#else
            n_bytes = recvfrom(netdev->tap_fd, ofpbuf_tail(buffer),
                               (ssize_t)ofpbuf_tailroom(buffer), 0,
                               (struct sockaddr *)&sll, &sll_len);
#endif /* ifdef HAVE_PACKET_AUXDATA  */
        } while (n_bytes < 0 && errno == EINTR);
    }
    if (n_bytes < 0) {
        if (errno != EAGAIN) {
            VLOG_WARN_RL(LOG_MODULE, &rl, "error receiving Ethernet packet on %s: %s",
                         strerror(errno), netdev->name);
        }
        return errno;
    } else {

#ifdef HAVE_PACKET_AUXDATA
            /* Code from libpcap to reconstruct VLAN header */
            for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                struct tpacket_auxdata *aux;
                struct vlan_tag *tag;
                uint16_t eth_type;
                buffer->size += n_bytes;

                if (cmsg->cmsg_len < CMSG_LEN(sizeof(struct tpacket_auxdata)) ||
                    cmsg->cmsg_level != SOL_PACKET ||
                    cmsg->cmsg_type != PACKET_AUXDATA){
                    continue;
                }
                aux = (struct tpacket_auxdata *)CMSG_DATA(cmsg);
                if (aux->tp_vlan_tci == 0){
                  continue;
                }
                /* VLAN tag found. Shift MAC addresses down and insert VLAN tag */
                /* Create headroom for the VLAN tag */
                eth_type = ntohs(*((uint16_t *)(buffer->data + ETHER_ADDR_LEN * 2)));
                ofpbuf_push_uninit(buffer, VLAN_HEADER_LEN);
                memmove(buffer->data, (uint8_t*)buffer->data+VLAN_HEADER_LEN, ETH_ALEN * 2);
                tag = (struct vlan_tag *)((uint8_t*)buffer->data + ETH_ALEN * 2);
                if (eth_type == ETH_TYPE_VLAN_PBB_S ||
                    eth_type == ETH_TYPE_VLAN_PBB_B ||
                    eth_type == ETH_TYPE_VLAN){
                    tag->vlan_tp_id = htons(ETH_TYPE_VLAN_PBB_B);
                }
                else {
                    tag->vlan_tp_id = htons(ETH_P_8021Q);
                }
                tag->vlan_tci = htons(aux->tp_vlan_tci);
            }
#else
        /* we have multiple raw sockets at the same interface, so we also
         * receive what others send, and need to filter them out.
         * TODO(yiannisy): can we install this as a BPF at kernel?*/
        if (sll.sll_pkttype == PACKET_OUTGOING) {
            return EAGAIN;
        }
        buffer->size += n_bytes;
#endif
        /* When the kernel internally sends out an Ethernet frame on an
         * interface, it gives us a copy *before* padding the frame to the
         * minimum length.  Thus, when it sends out something like an ARP
         * request, we see a too-short frame.  So pad it out to the minimum
         * length. */
        pad_to_minimum_length(buffer);
        return 0;
    }

}

int
netdev_recv(struct netdev *netdev, struct ofpbuf *buffer, size_t max_mtu)
{
#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
	const u_char *pkt;
#ifdef HAVE_LINUX_PF_Q_H
	struct pfq_pcap_pkthdr hdr;
#else
	struct pcap_pkthdr hdr;
#endif

	if (netdev->pcap)
	{
		pkt = pcap_next(netdev->pcap, (struct pcap_pkthdr *)&hdr);
		if (pkt)
		{
			memcpy(ofpbuf_tail(buffer), pkt, MIN(ofpbuf_tailroom(buffer), hdr.caplen));
			buffer->size += hdr.caplen;
			pad_to_minimum_length(buffer);
			return 0;
		}
		return EAGAIN;
	}
#endif
	return netdev_recv_linux(netdev, buffer, max_mtu);
}


/* Registers with the poll loop to wake up from the next call to poll_block()
 * when a packet is ready to be received with netdev_recv() on 'netdev'. */
void
netdev_recv_wait(struct netdev *netdev)
{
    (void)netdev;
#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
    if (netdev->pcap)
	poll_immediate_wake();
    else
#endif
	poll_fd_wait(netdev->tap_fd, POLLIN);
}

/* Discards all packets waiting to be received from 'netdev'. */
int
netdev_drain(struct netdev *netdev)
{
    if (netdev->tap_fd != netdev->netdev_fd) {
        drain_fd(netdev->tap_fd, netdev->txqlen);
        return 0;
    } else {
        return drain_rcvbuf(netdev->netdev_fd);
    }
}

/* Sends 'buffer' on 'netdev'.  Returns 0 if successful, otherwise a positive
 * errno value.  Returns EAGAIN without blocking if the packet cannot be queued
 * immediately.  Returns EMSGSIZE if a partial packet was transmitted or if
 * the packet is too big or too small to transmit on the device.
 *
 * class_id denotes the queue to send the packet. If 0, it goes to the
 * default,best-effort queue.
 *
 * The caller retains ownership of 'buffer' in all cases.
 *
 * The kernel maintains a packet transmission queue, so the caller is not
 * expected to do additional queuing of packets.
 */
static int
netdev_send_linux(struct netdev *netdev, const struct ofpbuf *buffer, uint16_t class_id)
{
    ssize_t n_bytes;

    assert(class_id <= NETDEV_MAX_QUEUES);

    do {
        n_bytes = write(netdev->queue_fd[class_id], buffer->data, buffer->size);
    } while (n_bytes < 0 && errno == EINTR);
    if (n_bytes < 0) {
        /* The Linux AF_PACKET implementation never blocks waiting for room
         * for packets, instead returning ENOBUFS.  Translate this into EAGAIN
         * for the caller. */
        if (errno == ENOBUFS) {
            return EAGAIN;
        } else if (errno != EAGAIN) {
            VLOG_WARN_RL(LOG_MODULE, &rl, "error sending Ethernet packet on %s: %s",
                         netdev->name, strerror(errno));
        }
        return errno;
    } else if (n_bytes != buffer->size) {
        VLOG_WARN_RL(LOG_MODULE, &rl,
                     "send partial Ethernet packet (%d bytes of %zu) on %s",
                     (int) n_bytes, buffer->size, netdev->name);
        return EMSGSIZE;
    } else {
        return 0;
    }
}


int
netdev_send(struct netdev *netdev, const struct ofpbuf *buffer, uint16_t class_id)
{
#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
	if (netdev->pcap) {

		int rc = pcap_inject(netdev->pcap, buffer->data, buffer->size);
		if (rc < 0) {
			VLOG_WARN_RL(LOG_MODULE, &rl, "pcap error sending Ethernet packet on %s: %s",
						netdev->name, pcap_geterr(netdev->pcap));
			return EMSGSIZE;
		}
		return rc == 0 ? EAGAIN : 0;
	}
#endif
	return netdev_send_linux(netdev, buffer, class_id);
}


/* Registers with the poll loop to wake up from the next call to poll_block()
 * when the packet transmission queue has sufficient room to transmit a packet
 * with netdev_send().
 *
 * The kernel maintains a packet transmission queue, so the client is not
 * expected to do additional queuing of packets.  Thus, this function is
 * unlikely to ever be used.  It is included for completeness. */
void
netdev_send_wait(struct netdev *netdev)
{
    (void)netdev;

#if defined(HAVE_LIBPCAP) && defined(BEBA_USE_LIBPCAP)
    if (netdev->pcap)
	poll_immediate_wake();
    else
#endif
    if (netdev->tap_fd == netdev->netdev_fd) {
        poll_fd_wait(netdev->tap_fd, POLLOUT);
    } else {
        /* TAP device always accepts packets.*/
        poll_immediate_wake();
    }
}

/* Attempts to set 'netdev''s MAC address to 'mac'.  Returns 0 if successful,
 * otherwise a positive errno value. */
int
netdev_set_etheraddr(struct netdev *netdev, const uint8_t mac[ETH_ADDR_LEN])
{
    struct ifreq ifr;

    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_hwaddr.sa_family = netdev->hwaddr_family;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, ETH_ADDR_LEN);
    if (ioctl(netdev->netdev_fd, SIOCSIFHWADDR, &ifr) < 0) {
        VLOG_ERR(LOG_MODULE, "ioctl(SIOCSIFHWADDR) on %s device failed: %s",
                 netdev->name, strerror(errno));
        return errno;
    }
    memcpy(netdev->etheraddr, mac, ETH_ADDR_LEN);
    return 0;
}

/* Returns a pointer to 'netdev''s MAC address.  The caller must not modify or
 * free the returned buffer. */
const uint8_t *
netdev_get_etheraddr(const struct netdev *netdev)
{
    return netdev->etheraddr;
}

/* Returns the name of the network device that 'netdev' represents,
 * e.g. "eth0".  The caller must not modify or free the returned string. */
const char *
netdev_get_name(const struct netdev *netdev)
{
    return netdev->name;
}

/* Returns the maximum size of transmitted (and received) packets on 'netdev',
 * in bytes, not including the hardware header; thus, this is typically 1500
 * bytes for Ethernet devices. */
int
netdev_get_mtu(const struct netdev *netdev)
{
    return netdev->mtu;
}

/* Returns the features supported by 'netdev' of type 'type', as a bitmap
 * of bits from enum ofp_phy_features, in host byte order. */
uint32_t
netdev_get_features(struct netdev *netdev, int type)
{
    do_ethtool(netdev);
    switch (type) {
    case NETDEV_FEAT_CURRENT:
        return netdev->curr;
    case NETDEV_FEAT_ADVERTISED:
        return netdev->advertised;
    case NETDEV_FEAT_SUPPORTED:
        return netdev->supported;
    case NETDEV_FEAT_PEER:
        return netdev->peer;
    default:
        VLOG_WARN(LOG_MODULE, "Unknown feature type: %d\n", type);
        return 0;
    }
}

/* If 'netdev' has an assigned IPv4 address, sets '*in4' to that address (if
 * 'in4' is non-null) and returns true.  Otherwise, returns false. */
bool
netdev_get_in4(const struct netdev *netdev, struct in_addr *in4)
{
    struct ifreq ifr;
    struct in_addr ip = { INADDR_ANY };

    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    ifr.ifr_addr.sa_family = AF_INET;
    if (ioctl(af_inet_sock, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *sin = (struct sockaddr_in *) &ifr.ifr_addr;
        ip = sin->sin_addr;
    } else {
        VLOG_DBG_RL(LOG_MODULE, &rl, "%s: ioctl(SIOCGIFADDR) failed: %s",
                    netdev->name, strerror(errno));
    }
    if (in4) {
        *in4 = ip;
    }
    return ip.s_addr != INADDR_ANY;
}

static void
make_in4_sockaddr(struct sockaddr *sa, struct in_addr addr)
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof sin);
    sin.sin_family = AF_INET;
    sin.sin_addr = addr;
    sin.sin_port = 0;

    memset(sa, 0, sizeof *sa);
    memcpy(sa, &sin, sizeof sin);
}

static int
do_set_addr(struct netdev *netdev, int sock,
            int ioctl_nr, const char *ioctl_name, struct in_addr addr)
{
    struct ifreq ifr;
    int error;

    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    make_in4_sockaddr(&ifr.ifr_addr, addr);
    error = ioctl(sock, ioctl_nr, &ifr) < 0 ? errno : 0;
    if (error) {
        VLOG_WARN(LOG_MODULE, "ioctl(%s): %s", ioctl_name, strerror(error));
    }
    return error;
}

/* Assigns 'addr' as 'netdev''s IPv4 address and 'mask' as its netmask.  If
 * 'addr' is INADDR_ANY, 'netdev''s IPv4 address is cleared.  Returns a
 * positive errno value. */
int
netdev_set_in4(struct netdev *netdev, struct in_addr addr, struct in_addr mask)
{
    int error;

    error = do_set_addr(netdev, af_inet_sock,
                        SIOCSIFADDR, "SIOCSIFADDR", addr);
    if (!error && addr.s_addr != INADDR_ANY) {
        error = do_set_addr(netdev, af_inet_sock,
                            SIOCSIFNETMASK, "SIOCSIFNETMASK", mask);
    }
    return error;
}

/* Adds 'router' as a default IP gateway. */
int
netdev_add_router(struct in_addr router)
{
    struct in_addr any = { INADDR_ANY };
    struct rtentry rt;
    int error;

    memset(&rt, 0, sizeof rt);
    make_in4_sockaddr(&rt.rt_dst, any);
    make_in4_sockaddr(&rt.rt_gateway, router);
    make_in4_sockaddr(&rt.rt_genmask, any);
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    error = ioctl(af_inet_sock, SIOCADDRT, &rt) < 0 ? errno : 0;
    if (error) {
        VLOG_WARN(LOG_MODULE, "ioctl(SIOCADDRT): %s", strerror(error));
    }
    return error;
}

/* If 'netdev' has an assigned IPv6 address, sets '*in6' to that address (if
 * 'in6' is non-null) and returns true.  Otherwise, returns false. */
bool
netdev_get_in6(const struct netdev *netdev, struct in6_addr *in6)
{
    if (in6) {
        *in6 = netdev->in6;
    }
    return memcmp(&netdev->in6, &in6addr_any, sizeof netdev->in6) != 0;
}

/* Obtains the current flags for 'netdev' and stores them into '*flagsp'.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_get_flags(const struct netdev *netdev, enum netdev_flags *flagsp)
{
    return netdev_nodev_get_flags(netdev->name, flagsp);
}

static int
nd_to_iff_flags(enum netdev_flags nd)
{
    int iff = 0;
    if (nd & NETDEV_UP) {
        iff |= IFF_UP;
    }
    if (nd & NETDEV_PROMISC) {
        iff |= IFF_PROMISC;
    }
    return iff;
}

/* On 'netdev', turns off the flags in 'off' and then turns on the flags in
 * 'on'.  If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.  Returns 0 if
 * successful, otherwise a positive errno value. */
static int
do_update_flags(struct netdev *netdev, enum netdev_flags off,
                enum netdev_flags on, bool permanent)
{
    int old_flags, new_flags;
    int error;

    error = get_flags(netdev->name, &old_flags);
    if (error) {
        return error;
    }

    new_flags = (old_flags & ~nd_to_iff_flags(off)) | nd_to_iff_flags(on);
    if (!permanent) {
        netdev->changed_flags |= new_flags ^ old_flags;
    }
    if (new_flags != old_flags) {
        error = set_flags(netdev->name, new_flags);
    }
    return error;
}

/* Sets the flags for 'netdev' to 'flags'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_set_flags(struct netdev *netdev, enum netdev_flags flags,
                 bool permanent)
{
    return do_update_flags(netdev, -1, flags, permanent);
}

/* Turns on the specified 'flags' on 'netdev'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_turn_flags_on(struct netdev *netdev, enum netdev_flags flags,
                     bool permanent)
{
    return do_update_flags(netdev, 0, flags, permanent);
}

/* Turns off the specified 'flags' on 'netdev'.
 * If 'permanent' is true, the changes will persist; otherwise, they
 * will be reverted when 'netdev' is closed or the program exits.
 * Returns 0 if successful, otherwise a positive errno value. */
int
netdev_turn_flags_off(struct netdev *netdev, enum netdev_flags flags,
                      bool permanent)
{
    return do_update_flags(netdev, flags, 0, permanent);
}

/* Looks up the ARP table entry for 'ip' on 'netdev'.  If one exists and can be
 * successfully retrieved, it stores the corresponding MAC address in 'mac' and
 * returns 0.  Otherwise, it returns a positive errno value; in particular,
 * ENXIO indicates that there is not ARP table entry for 'ip' on 'netdev'. */
int
netdev_arp_lookup(const struct netdev *netdev,
                  uint32_t ip, uint8_t mac[ETH_ADDR_LEN])
{
    struct arpreq r;
    struct sockaddr_in *pa;
    int retval;

    memset(&r, 0, sizeof r);
    pa = (struct sockaddr_in *) &r.arp_pa;
    pa->sin_family = AF_INET;
    pa->sin_addr.s_addr = ip;
    pa->sin_port = 0;
    r.arp_ha.sa_family = ARPHRD_ETHER;
    r.arp_flags = 0;
    strncpy(r.arp_dev, netdev->name, sizeof r.arp_dev);
    retval = ioctl(af_inet_sock, SIOCGARP, &r) < 0 ? errno : 0;
    if (!retval) {
        memcpy(mac, r.arp_ha.sa_data, ETH_ADDR_LEN);
    } else if (retval != ENXIO) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "%s: could not look up ARP entry for "IP_FMT": %s",
                     netdev->name, IP_ARGS(&ip), strerror(retval));
    }
    return retval;
}

/* Initializes 'svec' with a list of the names of all known network devices. */
void
netdev_enumerate(struct svec *svec)
{
    struct if_nameindex *names;

    svec_init(svec);
    names = if_nameindex();
    if (names) {
        size_t i;

        for (i = 0; names[i].if_name != NULL; i++) {
            svec_add(svec, names[i].if_name);
        }
        if_freenameindex(names);
    } else {
        VLOG_WARN(LOG_MODULE, "could not obtain list of network device names: %s",
                  strerror(errno));
    }
}

/* Obtains the current flags for the network device named 'netdev_name' and
 * stores them into '*flagsp'.  Returns 0 if successful, otherwise a positive
 * errno value.
 *
 * If only device flags are needed, this is more efficient than calling
 * netdev_open(), netdev_get_flags(), netdev_close(). */
int
netdev_nodev_get_flags(const char *netdev_name, enum netdev_flags *flagsp)
{
    int error, flags;

    init_netdev();

    error = get_flags(netdev_name, &flags);
    if (error) {
        return error;
    }

    *flagsp = 0;
    if (flags & IFF_UP) {
        *flagsp |= NETDEV_UP;
    }
    if (flags & IFF_PROMISC) {
        *flagsp |= NETDEV_PROMISC;
    }
    if (flags & IFF_LOWER_UP) {
        *flagsp |= NETDEV_CARRIER;
    }
    return 0;
}

struct netdev_monitor {
    struct nl_sock *sock;
    struct svec netdevs;
    struct svec changed;
};

/* Policy for RTNLGRP_LINK messages.
 *
 * There are *many* more fields in these messages, but currently we only care
 * about interface names. */
static const struct nl_policy rtnlgrp_link_policy[] = {
    [IFLA_IFNAME] = { .type = NL_A_STRING, .optional = false },
};

static const char *lookup_netdev(const struct netdev_monitor *, const char *);
static const char *pop_changed(struct netdev_monitor *);
static const char *all_netdevs_changed(struct netdev_monitor *);

/* Creates a new network device monitor that initially monitors no
 * devices.  On success, sets '*monp' to the new network monitor and returns
 * 0; on failure, sets '*monp' to a null pointer and returns a positive errno
 * value. */
int
netdev_monitor_create(struct netdev_monitor **monp)
{
    struct netdev_monitor *mon;
    struct nl_sock *sock;
    int error;

    *monp = NULL;
    error = nl_sock_create(NETLINK_ROUTE, RTNLGRP_LINK, 0, 0, &sock);
    if (error) {
        /* XXX Fall back to polling?  Non-root is not allowed to subscribe to
         * multicast groups but can still poll network device state. */
        VLOG_WARN(LOG_MODULE, "could not create rtnetlink socket: %s", strerror(error));
        return error;
    }

    mon = *monp = xmalloc(sizeof *mon);
    mon->sock = sock;
    svec_init(&mon->netdevs);
    svec_init(&mon->changed);
    return 0;
}

void
netdev_monitor_destroy(struct netdev_monitor *mon)
{
    if (mon) {
        nl_sock_destroy(mon->sock);
        svec_destroy(&mon->netdevs);
        svec_destroy(&mon->changed);
        free(mon);
    }
}

/* Sets the set of network devices monitored by 'mon' to the 'n_netdevs'
 * network devices named in 'netdevs'.  The caller retains ownership of
 * 'netdevs'. */
void
netdev_monitor_set_devices(struct netdev_monitor *mon,
                           char **netdevs, size_t n_netdevs)
{
    size_t i;

    svec_clear(&mon->netdevs);
    for (i = 0; i < n_netdevs; i++) {
        svec_add(&mon->netdevs, netdevs[i]);
    }
    svec_sort(&mon->netdevs);
}

/* If the state of any network device has changed, returns its name.  The
 * caller must not modify or free the name.
 *
 * This function can return "false positives".  The caller is responsible for
 * verifying that the network device's state actually changed, if necessary.
 *
 * If no network device's state has changed, returns a null pointer. */
const char *
netdev_monitor_poll(struct netdev_monitor *mon)
{
    static struct vlog_rate_limit slow_rl = VLOG_RATE_LIMIT_INIT(1, 5);
    const char *changed_name;

    changed_name = pop_changed(mon);
    if (changed_name) {
        return changed_name;
    }

    for (;;) {
        struct ofpbuf *buf;
        int retval;

        retval = nl_sock_recv(mon->sock, &buf, false);
        if (retval == EAGAIN) {
            return NULL;
        } else if (retval == ENOBUFS) {
            VLOG_WARN_RL(LOG_MODULE, &slow_rl, "network monitor socket overflowed");
            return all_netdevs_changed(mon);
        } else if (retval) {
            VLOG_WARN_RL(LOG_MODULE, &slow_rl, "error on network monitor socket: %s",
                         strerror(retval));
            return NULL;
        } else {
            struct nlattr *attrs[ARRAY_SIZE(rtnlgrp_link_policy)];
            const char *name;

            if (!nl_policy_parse(buf, NLMSG_HDRLEN + sizeof(struct ifinfomsg),
                                 rtnlgrp_link_policy,
                                 attrs, ARRAY_SIZE(rtnlgrp_link_policy))) {
                VLOG_WARN_RL(LOG_MODULE, &slow_rl, "received bad rtnl message");
                return all_netdevs_changed(mon);
            }
            name = lookup_netdev(mon, nl_attr_get_string(attrs[IFLA_IFNAME]));
            ofpbuf_delete(buf);
            if (name) {
                /* Return the looked-up string instead of the attribute string,
                 * because we freed the buffer that contains the attribute. */
                return name;
            }
        }
    }
}

void
netdev_monitor_run(struct netdev_monitor *mon UNUSED)
{
    /* Nothing to do in this implementation. */
}

void
netdev_monitor_wait(struct netdev_monitor *mon)
{
    nl_sock_wait(mon->sock, POLLIN);
}

static const char *
lookup_netdev(const struct netdev_monitor *mon, const char *name)
{
    size_t idx = svec_find(&mon->netdevs, name);
    return idx != SIZE_MAX ? mon->netdevs.names[idx] : NULL;
}

static const char *
pop_changed(struct netdev_monitor *mon)
{
    while (mon->changed.n) {
        const char *name = lookup_netdev(mon, svec_back(&mon->changed));
        svec_pop_back(&mon->changed);
        if (name) {
            return name;
        }
    }
    return NULL;
}

static const char *
all_netdevs_changed(struct netdev_monitor *mon)
{
    svec_clear(&mon->changed);
    svec_append(&mon->changed, &mon->netdevs);
    return pop_changed(mon);
}

static void restore_all_flags(void *aux);

/* Set up a signal hook to restore network device flags on program
 * termination.  */
static void
init_netdev(void)
{
    static bool inited;
    if (!inited) {
        inited = true;
        fatal_signal_add_hook(restore_all_flags, NULL, true);
        af_inet_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (af_inet_sock < 0) {
            ofp_fatal(errno, "socket(AF_INET)");
        }
    }
}

/* Restore the network device flags on 'netdev' to those that were active
 * before we changed them.  Returns 0 if successful, otherwise a positive
 * errno value.
 *
 * To avoid reentry, the caller must ensure that fatal signals are blocked. */
static int
restore_flags(struct netdev *netdev)
{
    struct ifreq ifr;
    int restore_flags;

    /* Get current flags. */
    strncpy(ifr.ifr_name, netdev->name, sizeof ifr.ifr_name);
    if (ioctl(netdev->netdev_fd, SIOCGIFFLAGS, &ifr) < 0) {
        return errno;
    }

    /* Restore flags that we might have changed, if necessary. */
    restore_flags = netdev->changed_flags & (IFF_PROMISC | IFF_UP);
    if ((ifr.ifr_flags ^ netdev->save_flags) & restore_flags) {
        ifr.ifr_flags &= ~restore_flags;
        ifr.ifr_flags |= netdev->save_flags & restore_flags;
        if (ioctl(netdev->netdev_fd, SIOCSIFFLAGS, &ifr) < 0) {
            return errno;
        }
    }

    return 0;
}

/* Retores all the flags on all network devices that we modified.  Called from
 * a signal handler, so it does not attempt to report error conditions. */
static void
restore_all_flags(void *aux UNUSED)
{
    struct netdev *netdev;
    LIST_FOR_EACH (netdev, struct netdev, node, &netdev_list) {
        restore_flags(netdev);
    }
}

static int
get_flags(const char *netdev_name, int *flags)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    if (ioctl(af_inet_sock, SIOCGIFFLAGS, &ifr) < 0) {
        VLOG_ERR(LOG_MODULE, "ioctl(SIOCGIFFLAGS) on %s device failed: %s",
                 netdev_name, strerror(errno));
        return errno;
    }
    *flags = ifr.ifr_flags;
    return 0;
}

static int
set_flags(const char *netdev_name, int flags)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, netdev_name, sizeof ifr.ifr_name);
    ifr.ifr_flags = flags;
    if (ioctl(af_inet_sock, SIOCSIFFLAGS, &ifr) < 0) {
        VLOG_ERR(LOG_MODULE, "ioctl(SIOCSIFFLAGS) on %s device failed: %s",
                 netdev_name, strerror(errno));
        return errno;
    }
    return 0;
}
