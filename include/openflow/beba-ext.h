#ifndef BEBA_EXT_H
#define BEBA_EXT_H 1

#include "openflow/openflow.h"

/*
 * The following are vendor extensions from OpenFlow.  This is a
 * means of allowing the introduction of non-standardized
 * proposed code.
 *
 * Structures in this file are 64-bit aligned in size.
 */

#define BEBA_VENDOR_ID 0xBEBABEBA
#define OFP_GLOBAL_STATE_DEFAULT 0

enum oxm_exp_match_fields {
    OFPXMT_EXP_GLOBAL_STATE,      /* Global state */
    OFPXMT_EXP_STATE       /* Flow State */
};

/****************************************************************
 *
 * OpenFlow experimenter Instructions
 *
 ****************************************************************/
enum ofp_exp_instructions {
    OFPIT_IN_SWITCH_PKT_GEN
};

struct ofp_beba_instruction_experimenter_header {
    struct ofp_instruction_experimenter_header header;   /*  OpenFlow's standard experimenter action header*/
    uint32_t instr_type;   /* type in header is OFPIT_EXPERIMENTER, instr_type is one of ofp_exp_instructions */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_beba_instruction_experimenter_header) == 16);

struct ofp_exp_instruction_in_switch_pkt_gen {
	struct ofp_beba_instruction_experimenter_header header; /* OpenFlow standard experimenter instruction header */
	uint32_t pkttmp_id;
	uint8_t pad[4];
	struct ofp_action_header actions[0]; /* Same actions that can be associated with OFPIT_APPLY_ACTIONS */
};
OFP_ASSERT(sizeof(struct ofp_exp_instruction_in_switch_pkt_gen) == 24);

/****************************************************************
 *
 * OpenFlow experimenter Actions
 *
 ****************************************************************/
enum ofp_exp_actions {
    OFPAT_EXP_SET_STATE,
    OFPAT_EXP_SET_GLOBAL_STATE
};

struct ofp_beba_action_experimenter_header {
    struct ofp_action_experimenter_header header;   /*  OpenFlow's standard experimenter action header*/
    uint32_t act_type;   /* type in header is OFPAT_EXPERIMENTER, act_type is one of ofp_exp_actions */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_beba_action_experimenter_header) == 16);

/* Action structure for OFPAT_EXP_SET_STATE */
struct ofp_exp_action_set_state {
    struct ofp_beba_action_experimenter_header header;
    uint32_t state; /* State instance. */
    uint32_t state_mask; /* State mask */
    uint8_t table_id; /*Stage destination*/
    uint8_t pad[3];
    uint32_t hard_rollback;
    uint32_t idle_rollback;
    uint32_t hard_timeout;
    uint32_t idle_timeout;
    uint8_t bit; /* Swapping bit */
    uint8_t pad2[3];   /* Align to 64-bits. */
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_state) == 48);


/* Action structure for OFPAT_EXP_SET_GLOBAL_STATE */
struct ofp_exp_action_set_global_state {
    struct ofp_beba_action_experimenter_header header;
    uint32_t global_state;
    uint32_t global_state_mask;
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_global_state) == 24);


/*EXPERIMENTER MESSAGES*/
/*
 * State Sync:
 * |--> OFPT_EXP_STATE_CHANGED notifies the controller about a state transition;
 * |--> OFPT_EXP_FLOW_NOTIFICATION notifies the controller about an (actually) installed flow modification in the flow table.
 */
enum ofp_exp_messages {
    OFPT_EXP_STATE_MOD,
    OFPT_EXP_PKTTMP_MOD,
    OFPT_EXP_STATE_CHANGED,
    OFPT_EXP_FLOW_NOTIFICATION
    // Missing type: Notification for missing packet template (after NEC people provide their code)
};

/*EXPERIMENTER ERROR MESSAGES*/
enum ofp_exp_beba_errors{
    OFPEC_EXP_STATE_MOD_FAILED,
    OFPEC_EXP_STATE_MOD_BAD_COMMAND,
    OFPEC_EXP_SET_EXTRACTOR,
    OFPEC_EXP_SET_FLOW_STATE,
    OFPEC_EXP_DEL_FLOW_STATE,
    OFPEC_BAD_EXP_MESSAGE,
    OFPEC_BAD_EXP_ACTION,
    OFPEC_BAD_EXP_LEN,
    OFPEC_BAD_TABLE_ID,
    OFPEC_BAD_MATCH_WILDCARD,
    OFPET_BAD_EXP_INSTRUCTION,
    OFPEC_EXP_PKTTMP_MOD_FAILED,
    OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND
};

/****************************************************************
 *
 *   OFPT_EXP_STATE_MOD
 *
****************************************************************/
#define OFPSC_MAX_FIELD_COUNT 6
#define OFPSC_MAX_KEY_LEN 48

struct ofp_exp_msg_state_mod {
    struct ofp_experimenter_header header; /* OpenFlow's standard experimenter message header */
    uint8_t command;
    uint8_t pad;
    uint8_t payload[];
};

/*
 * State Sync: Message format of a state notification
 * When a state transition occurs in the state table, controller gets notified.
 */
struct ofp_exp_msg_state_ntf {
    struct   ofp_experimenter_header header; // OpenFlow's standard experimenter
    uint32_t table_id;
    uint32_t old_state;
    uint32_t new_state;
    uint32_t state_mask;
    uint32_t key_len;
    uint8_t  key[OFPSC_MAX_KEY_LEN];
};

/*
 * State Sync: Message format of a positive flow modification acknowledgment
 * (i.e., when a flow is really installed in the flow table, switch notifies the controller)
 * Useful for bulk updates
 */
struct ofp_exp_msg_flow_ntf {
    struct   ofp_experimenter_stats_header header;
    uint32_t table_id;
    uint32_t ntf_type;
    struct   ofp_match match;
};

struct ofp_exp_stateful_table_config {
    uint8_t table_id;
    uint8_t stateful;
};

struct ofp_exp_set_extractor {
    uint8_t table_id;
    uint8_t pad[3];
    uint8_t bit;
    uint8_t pad2[3];
    uint32_t field_count;
    uint32_t fields[OFPSC_MAX_FIELD_COUNT];
};

struct ofp_exp_set_flow_state {
    uint8_t table_id;
    uint8_t pad[3];
    uint32_t key_len;
    uint32_t state;
    uint32_t state_mask;
    uint32_t hard_rollback;
    uint32_t idle_rollback;
    uint32_t hard_timeout;
    uint32_t idle_timeout;
    uint8_t key[OFPSC_MAX_KEY_LEN];
};

struct ofp_exp_del_flow_state {
    uint8_t table_id;
    uint8_t pad[3];
    uint32_t key_len;
    uint8_t key[OFPSC_MAX_KEY_LEN];
};

struct ofp_exp_set_global_state {
    uint32_t global_state;
    uint32_t global_state_mask;
};

enum ofp_exp_msg_state_mod_commands {
    OFPSC_STATEFUL_TABLE_CONFIG = 0,
    OFPSC_EXP_SET_L_EXTRACTOR,
    OFPSC_EXP_SET_U_EXTRACTOR,
    OFPSC_EXP_SET_FLOW_STATE,   
    OFPSC_EXP_DEL_FLOW_STATE,
    OFPSC_EXP_SET_GLOBAL_STATE,
    OFPSC_EXP_RESET_GLOBAL_STATE   
};

/****************************************************************
 *
 *   OFPT_EXP_PKTTMP_MOD
 *
****************************************************************/

struct ofp_exp_msg_pkttmp_mod {
    struct ofp_experimenter_header header; /* OpenFlow's standard experimenter message header */
    uint8_t command;
    uint8_t pad;
    uint8_t payload[];
};

struct ofp_exp_add_pkttmp {
	uint32_t pkttmp_id;
	uint8_t pad[4];
	/* uint8_t data[0]; */ /* Packet data. The length is inferred
			from the length field in the header. */
};

struct ofp_exp_del_pkttmp {
	uint32_t pkttmp_id;
	uint8_t pad[4];
};

enum ofp_exp_msg_pkttmp_mod_commands {
    OFPSC_ADD_PKTTMP = 0,
    OFPSC_DEL_PKTTMP
};

/****************************************************************
 *
 *   MULTIPART MESSAGE: OFPMP_EXP_STATE_STATS
 *
****************************************************************/
enum ofp_stats_extension_commands {
    OFPMP_EXP_STATE_STATS,      
    OFPMP_EXP_GLOBAL_STATE_STATS
};

struct ofp_exp_state_entry{
    uint32_t            key_len;
    uint8_t             key[OFPSC_MAX_KEY_LEN];
    uint32_t            state;
};
OFP_ASSERT(sizeof(struct ofp_exp_state_entry) == 56);

/* Body for ofp_multipart_request of type OFPMP_EXP_STATE_STATS. */
struct ofp_exp_state_stats_request {
    struct ofp_experimenter_stats_header header;
    uint8_t                 table_id;       /* ID of table to read (from ofp_table_stats),
                               OFPTT_ALL for all tables. */
    uint8_t                 get_from_state;
    uint8_t                 pad[2];         /* Align to 64 bits. */
    uint32_t                state;   
    struct ofp_match        match; /* Fields to match. Variable size. */
};
OFP_ASSERT(sizeof(struct ofp_exp_state_stats_request) == 24);

/* Body of reply to OFPMP_EXP_STATE_STATS request. */
struct ofp_exp_state_stats_reply{
    struct ofp_experimenter_stats_header header;
    struct ofp_exp_state_stats *stats;
};

struct ofp_exp_state_stats {
    uint16_t length;        /* Length of this entry. */
    uint8_t table_id;       /* ID of table flow came from. */
    uint8_t pad;
    uint32_t duration_sec;  /* Time state entry has been alive in secs. */
    uint32_t duration_nsec; /* Time state entry has been alive in nsecs beyond duration_sec. */
    uint32_t field_count;    /*number of extractor fields*/
    uint32_t fields[OFPSC_MAX_FIELD_COUNT]; /*extractor fields*/ 
    struct ofp_exp_state_entry entry;
    uint32_t hard_rollback;
    uint32_t idle_rollback;
    uint32_t hard_timeout; // [us]
    uint32_t idle_timeout; // [us]
};
OFP_ASSERT(sizeof(struct ofp_exp_state_stats) == 112);

/****************************************************************
 *
 *   MULTIPART MESSAGE: OFPMP_EXP_GLOBAL_STATE_STATS
 *
****************************************************************/

/* Body for ofp_multipart_request of type OFPMP_EXP_GLOBAL_STATE_STATS. */
struct ofp_exp_global_state_stats_request {
    struct ofp_experimenter_stats_header header;
};
OFP_ASSERT(sizeof(struct ofp_exp_global_state_stats_request) == 8);

/* Body of reply to OFPMP_EXP_GLOBAL_STATE_STATS request. */
struct ofp_exp_global_state_stats {
    struct ofp_experimenter_stats_header header;
    uint8_t pad[4];
    uint32_t global_state;
};
OFP_ASSERT(sizeof(struct ofp_exp_global_state_stats) == 16);

#endif /* BEBA_EXT_H */
