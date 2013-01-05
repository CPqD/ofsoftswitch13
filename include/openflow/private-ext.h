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

#ifndef OPENFLOW_PRIVATE_EXT_H_
#define OPENFLOW_PRIVATE_EXT_H_

#ifdef __KERNEL__
#include <asm/byteorder.h>
#endif

#include "openflow/openflow.h"

/*
 * The following PRIVATE vendor extensions are just sample and may never be
 * ready for standardization, so they are not included in openflow.h.
 *
 * As a sample, we use private OUI (AC-DE-48) for PRIVATE vendor ID.
 */

#define PRIVATE_VENDOR_ID			0x00acde48
#define PRIVATEOPT_PROTOCOL_STATS_REQUEST	0x0001
#define PRIVATEOPT_PROTOCOL_STATS_REPLY		0x0002
#define PRIVATEOPT_EMERG_FLOW_PROTECTION	0x0003
#define PRIVATEOPT_EMERG_FLOW_RESTORATION	0x0004

struct private_vxhdr {
	struct ofp_header ofp_hdr;	/* protocol header */
	uint32_t ofp_vxid;	/* vendor extenion ID */
} __attribute__ ((__packed__));

/* TLV encoding */
struct private_vxopt {
	uint16_t pvo_type;	/* type of vendor extension option */
	uint16_t pvo_len;	/* length of value (octet) */
	/* followed by value */
	/* uint8_t pvo_value[0]; */
} __attribute__ ((__packed__));

#endif
