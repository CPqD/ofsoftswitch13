/*
 * nbee_link.h 
 *
 *  Created on: Jul 18, 2011
 *      Author: rdenicol
 */

#ifndef NBEE_LINK_H_
#define NBEE_LINK_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "lib/hmap.h"
#include "lib/ofpbuf.h"
#include "lib/packets.h"

#define ETHADDLEN 6
#define IPV6ADDLEN 16
#define ETHTYPELEN 2
#define ERRBUF_SIZE 256


typedef struct pcap_pkthdr {	/* needed to make Nbee happy */
	struct timeval ts;	/* time stamp */
	uint32_t caplen;	/* length of portion present */
	uint32_t len;	/* length this packet (off wire) */
}pcap_pkthdr_t;

// List used to store more than 1 value on the hash map... maybe we'll use it again on the future
//typedef struct field_values {
//       struct list list_node;
//	uint32_t len;
//        uint32_t pos;
//        uint8_t* value;
//}field_values_t;

struct packet_fields {
       struct hmap_node hmap_node;
       uint32_t header;                  /* OXM_* value. */
       uint32_t pos;
       uint8_t *value;              /* List of field values (In one packet, there may be more than one value per field) */
};

#ifdef __cplusplus
extern "C"
#endif
int nblink_initialize(void);

#ifdef __cplusplus
extern "C"
#endif
int nblink_packet_parse(struct ofpbuf * pktin, struct hmap * pktout, struct protocols_std * pkt_proto);

#endif /* NBEE_LINK_H_ */
