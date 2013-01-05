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

#ifndef OFPSTAT_H_
#define OFPSTAT_H_

struct ofp_header;

struct ofpstat {
	uint64_t ofps_total;
	uint64_t ofps_unknown;

	uint64_t ofps_hello;
	uint64_t ofps_error;
	struct {
		uint64_t hello_fail;
		uint64_t bad_request;
		uint64_t bad_action;
		uint64_t flow_mod_fail;
		uint64_t unknown;
	} ofps_error_type;
	struct {
		uint64_t hf_incompat;
		uint64_t hf_eperm;
		uint64_t br_bad_version;
		uint64_t br_bad_type;
		uint64_t br_bad_stat;
		uint64_t br_bad_vendor;
		uint64_t br_eperm;
		uint64_t ba_bad_type;
		uint64_t ba_bad_len;
		uint64_t ba_bad_vendor;
		uint64_t ba_bad_vendor_type;
		uint64_t ba_bad_out_port;
		uint64_t ba_bad_argument;
		uint64_t ba_eperm;
		uint64_t fmf_all_tables_full;
		uint64_t fmf_overlap;
		uint64_t fmf_eperm;
		uint64_t fmf_emerg;
		uint64_t unknown;
	} ofps_error_code;
	uint64_t ofps_echo_request;
	uint64_t ofps_echo_reply;
	uint64_t ofps_vendor;
	uint64_t ofps_feats_request;
	uint64_t ofps_feats_reply;
	uint64_t ofps_get_config_request;
	uint64_t ofps_get_config_reply;
	uint64_t ofps_set_config;
	uint64_t ofps_packet_in;
	uint64_t ofps_flow_removed;
	uint64_t ofps_port_status;
	uint64_t ofps_packet_out;
	uint64_t ofps_flow_mod;
	struct {
		uint64_t add;
		uint64_t modify;
		uint64_t modify_strict;
		uint64_t delete;
		uint64_t delete_strict;
		uint64_t unknown;
	} ofps_flow_mod_ops;
	uint64_t ofps_port_mod;
	uint64_t ofps_stats_request;
	uint64_t ofps_stats_reply;
	uint64_t ofps_barrier_request;
	uint64_t ofps_barrier_reply;
};

void ofpstat_inc_protocol_stat(struct ofpstat *, struct ofp_header *);

#endif
