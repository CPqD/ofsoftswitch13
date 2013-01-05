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
#include <netinet/in.h>

#include "openflow/openflow.h"
#include "ofpstat.h"

#define INC_IFP_STAT(ifps, tag) do {++(ifps)->tag;} while (0)

static void inc_protocol_message(struct ofpstat *, struct ofp_header *);
static void inc_error_notification(struct ofpstat *, struct ofp_header *);
static void inc_flow_manipulation(struct ofpstat *, struct ofp_header *);

static void
inc_protocol_message(struct ofpstat *ifps, struct ofp_header *hdr)
{
	switch (hdr->type) {
	case OFPT_HELLO:
		INC_IFP_STAT(ifps, ofps_hello);
		break;
	case OFPT_ERROR:
		INC_IFP_STAT(ifps, ofps_error);
		break;
	case OFPT_ECHO_REQUEST:
		INC_IFP_STAT(ifps, ofps_echo_request);
		break;
	case OFPT_ECHO_REPLY:
		INC_IFP_STAT(ifps, ofps_echo_reply);
		break;
	case OFPT_VENDOR:
		INC_IFP_STAT(ifps, ofps_vendor);
		break;
	case OFPT_FEATURES_REQUEST:
		INC_IFP_STAT(ifps, ofps_feats_request);
		break;
	case OFPT_FEATURES_REPLY:
		INC_IFP_STAT(ifps, ofps_feats_reply);
		break;
	case OFPT_GET_CONFIG_REQUEST:
		INC_IFP_STAT(ifps, ofps_get_config_request);
		break;
	case OFPT_GET_CONFIG_REPLY:
		INC_IFP_STAT(ifps, ofps_get_config_reply);
		break;
	case OFPT_SET_CONFIG:
		INC_IFP_STAT(ifps, ofps_set_config);
		break;
	case OFPT_PACKET_IN:
		INC_IFP_STAT(ifps, ofps_packet_in);
		break;
	case OFPT_FLOW_REMOVED:
		INC_IFP_STAT(ifps, ofps_flow_removed);
		break;
	case OFPT_PORT_STATUS:
		INC_IFP_STAT(ifps, ofps_port_status);
		break;
	case OFPT_PACKET_OUT:
		INC_IFP_STAT(ifps, ofps_packet_out);
		break;
	case OFPT_FLOW_MOD:
		INC_IFP_STAT(ifps, ofps_flow_mod);
		break;
	case OFPT_PORT_MOD:
		INC_IFP_STAT(ifps, ofps_port_mod);
		break;
	case OFPT_MULTIPART_REQUEST:
		INC_IFP_STAT(ifps, ofps_stats_request);
		break;
	case OFPT_MULTIPART_REPLY:
		INC_IFP_STAT(ifps, ofps_stats_reply);
		break;
	case OFPT_BARRIER_REQUEST:
		INC_IFP_STAT(ifps, ofps_barrier_request);
		break;
	case OFPT_BARRIER_REPLY:
		INC_IFP_STAT(ifps, ofps_barrier_reply);
		break;
	default:
		INC_IFP_STAT(ifps, ofps_unknown);
		break;
	}
}

static void
inc_error_notification(struct ofpstat *ifps, struct ofp_header *hdr)
{
	struct ofp_error_msg *errmsg = (struct ofp_error_msg *)hdr;
	uint16_t errtype = ntohs(errmsg->type);
	uint16_t errcode = ntohs(errmsg->code);

	switch (errtype) {
	case OFPET_HELLO_FAILED:
		INC_IFP_STAT(ifps, ofps_error_type.hello_fail);
		switch (errcode) {
		case OFPHFC_INCOMPATIBLE:
			INC_IFP_STAT(ifps, ofps_error_code.hf_incompat);
			break;
		case OFPHFC_EPERM:
			INC_IFP_STAT(ifps, ofps_error_code.hf_eperm);
			break;
		default:
			INC_IFP_STAT(ifps, ofps_error_code.unknown);
			break;
		}
		break;
	case OFPET_BAD_REQUEST:
		INC_IFP_STAT(ifps, ofps_error_type.bad_request);
		switch (errcode) {
		case OFPBRC_BAD_VERSION:
			INC_IFP_STAT(ifps, ofps_error_code.br_bad_version);
			break;
		case OFPBRC_BAD_TYPE:
			INC_IFP_STAT(ifps, ofps_error_code.br_bad_type);
			break;
		case OFPBRC_BAD_MULTIPART:
			INC_IFP_STAT(ifps, ofps_error_code.br_bad_stat);
			break;
		case OFPBRC_BAD_VENDOR:
			INC_IFP_STAT(ifps, ofps_error_code.br_bad_vendor);
			break;
		case OFPBRC_EPERM:
			INC_IFP_STAT(ifps, ofps_error_code.br_eperm);
			break;
		default:
			INC_IFP_STAT(ifps, ofps_error_code.unknown);
			break;
		}
		break;
	case OFPET_BAD_ACTION:
		INC_IFP_STAT(ifps, ofps_error_type.bad_action);
		switch (errcode) {
		case OFPBAC_BAD_TYPE:
			INC_IFP_STAT(ifps, ofps_error_code.ba_bad_type);
			break;
		case OFPBAC_BAD_LEN:
			INC_IFP_STAT(ifps, ofps_error_code.ba_bad_len);
			break;
		case OFPBAC_BAD_VENDOR:
			INC_IFP_STAT(ifps, ofps_error_code.ba_bad_vendor);
			break;
		case OFPBAC_BAD_VENDOR_TYPE:
			INC_IFP_STAT(ifps, ofps_error_code.ba_bad_vendor_type);
			break;
		case OFPBAC_BAD_OUT_PORT:
			INC_IFP_STAT(ifps, ofps_error_code.ba_bad_out_port);
			break;
		case OFPBAC_BAD_ARGUMENT:
			INC_IFP_STAT(ifps, ofps_error_code.ba_bad_argument);
			break;
		case OFPBAC_EPERM:
			INC_IFP_STAT(ifps, ofps_error_code.ba_eperm);
			break;
		default:
			INC_IFP_STAT(ifps, ofps_error_code.unknown);
			break;
		}
		break;
	case OFPET_FLOW_MOD_FAILED:
		INC_IFP_STAT(ifps, ofps_error_type.flow_mod_fail);
		switch (errcode) {
		case OFPFMFC_ALL_TABLES_FULL:
			INC_IFP_STAT(ifps, ofps_error_code.fmf_all_tables_full);
			break;
		case OFPFMFC_OVERLAP:
			INC_IFP_STAT(ifps, ofps_error_code.fmf_overlap);
			break;
		case OFPFMFC_EPERM:
			INC_IFP_STAT(ifps, ofps_error_code.fmf_eperm);
			break;
		case OFPFMFC_BAD_EMERG_TIMEOUT:
			INC_IFP_STAT(ifps, ofps_error_code.fmf_emerg);
			break;
		default:
			INC_IFP_STAT(ifps, ofps_error_code.unknown);
			break;
		}
		break;
	default:
		INC_IFP_STAT(ifps, ofps_error_type.unknown);
		break;
	}
}

static void
inc_flow_manipulation(struct ofpstat *ifps, struct ofp_header *hdr)
{
	struct ofp_flow_mod *flowmodmsg = (struct ofp_flow_mod *)hdr;
	uint16_t flowmodops = ntohs(flowmodmsg->command);

	switch (flowmodops) {
	case OFPFC_ADD:
		INC_IFP_STAT(ifps, ofps_flow_mod_ops.add);
		break;
	case OFPFC_MODIFY:
		INC_IFP_STAT(ifps, ofps_flow_mod_ops.modify);
		break;
	case OFPFC_MODIFY_STRICT:
		INC_IFP_STAT(ifps, ofps_flow_mod_ops.modify_strict);
		break;
	case OFPFC_DELETE:
		INC_IFP_STAT(ifps, ofps_flow_mod_ops.delete);
		break;
	case OFPFC_DELETE_STRICT:
		INC_IFP_STAT(ifps, ofps_flow_mod_ops.delete_strict);
		break;
	default:
		INC_IFP_STAT(ifps, ofps_flow_mod_ops.unknown);
		break;
	}
}

void
ofpstat_inc_protocol_stat(struct ofpstat *ifps, struct ofp_header *hdr)
{
	++ifps->ofps_total;
	inc_protocol_message(ifps, hdr);

	switch (hdr->type) {
	case OFPT_ERROR:
		inc_error_notification(ifps, hdr);
		break;
	case OFPT_FLOW_MOD:
		inc_flow_manipulation(ifps, hdr);
		break;
	default:
		break;
	}
}
