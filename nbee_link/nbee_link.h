/*
 * nbee_link.h
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#ifndef NBEE_LINK_H_
#define NBEE_LINK_H_

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>

#include "lib/hmap.h"
#include "lib/ofpbuf.h"
#include "lib/packets.h"

#define ETHADDLEN 6
#define IPV6ADDLEN 16
#define ETHTYPELEN 2
#define ERRBUF_SIZE 256

/* Extensions headers allowed after some EH, considering the the recommended order */
#define HBH_ALLOWED DESTINATION ^ ROUTING ^ FRAGMENT ^ AUTHENTICATION ^ ESP
#define DESTINATION_ALLOWED ROUTING
#define ROUTING_ALLOWED FRAGMENT ^ AUTHENTICATION ^ ESP ^ DESTINATION
#define FRAG_ALLOWED  AUTHENTICATION ^ ESP ^ DESTINATION
#define AUTH_ALLOWED ESP ^ DESTINATION
#define ESP_ALLOWED DESTINATION

#define DOH_BEF_RH 1
#define DOH_AFTER_RH 2
#define DOH_NO_RH 3

typedef struct pcap_pkthdr {	/* needed to make Nbee happy */
	struct timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
}pcap_pkthdr_t;


struct control_eh_fields {
       uint8_t count_DOEH;
       uint32_t position_EH[10];
};


#ifdef __cplusplus
extern "C"
#endif
int nblink_initialize(void);

#ifdef __cplusplus
extern "C"
#endif
int nblink_packet_parse(struct ofpbuf * pktin, struct ofl_match * pktout, struct protocols_std * pkt_proto);



#endif /* NBEE_LINK_H_ */
