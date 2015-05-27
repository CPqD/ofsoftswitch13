#ifndef OPENFLOW_OPENSTATE_EXT_H
#define OPENFLOW_OPENSTATE_EXT_H 1

#include "openflow/openflow.h"

/*
 * The following are vendor extensions from OpenFlow.  This is a
 * means of allowing the introduction of non-standardized
 * proposed code.
 *
 * Structures in this file are 64-bit aligned in size.
 */

#define OPENSTATE_VENDOR_ID 0xBEBABEBA
#define OFP_GLOBAL_STATES_DEFAULT 0

enum oxm_exp_match_fields {
    OFPXMT_EXP_FLAGS,      /* Global States */
    OFPXMT_EXP_STATE       /* Flow State */
};

/****************************************************************
 *
 * OpenFlow experimenter Actions
 *
 ****************************************************************/
enum ofp_exp_actions {
    OFPAT_EXP_SET_STATE,
    OFPAT_EXP_SET_FLAG
};

struct ofp_openstate_action_experimenter_header {
    struct ofp_action_experimenter_header header;   /*  OpenFlow's standard experimenter action header*/
    uint32_t act_type;   /* type in header is OFPAT_EXPERIMENTER, act_type is one of ofp_exp_actions */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_openstate_action_experimenter_header) == 16);

/* Action structure for OFPAT_EXP_SET_STATE */
struct ofp_exp_action_set_state {
    struct ofp_openstate_action_experimenter_header header;
    uint32_t state; /* State instance. */
    uint32_t state_mask; /* State mask */
    uint8_t table_id; /*Stage destination*/
    uint8_t pad[7];   /* Align to 64-bits. */
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_state) == 32);


/* Action structure for OFPAT_EXP_SET_FLAG */
struct ofp_exp_action_set_flag {
    struct ofp_openstate_action_experimenter_header header;
    uint32_t flag; /* flag value */
    uint32_t flag_mask;    /*flag mask*/
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_flag) == 24);


/*EXPERIMENTER MESSAGES*/
enum ofp_exp_messages {
    OFPT_EXP_STATE_MOD,
    OFPT_EXT_FLAG_MOD
};

/****************************************************************
 *
 *   OFPT_EXP_STATE_MOD
 *
****************************************************************/
#define OFPSC_MAX_FIELD_COUNT 6
#define OFPSC_MAX_KEY_LEN 48

struct ofp_exp_message_state_mod {
    struct ofp_experimenter_header header; /* OpenFlow's standard experimenter message header */
    uint8_t table_id;
    uint8_t command;
    uint8_t payload[];
};

struct ofp_exp_state_entry {
    uint32_t key_len;
    uint32_t state;
    uint32_t state_mask;
    uint8_t key[OFPSC_MAX_KEY_LEN];
};

struct ofp_exp_extraction {
    uint32_t field_count;
    uint32_t fields[OFPSC_MAX_FIELD_COUNT];
};

struct ofp_exp_statefulness_config {
    uint8_t statefulness;
    uint8_t pad; //TODO sanvitz: sizeof adds an extra byte to align to multiple of 4 bytes?!
};

enum ofp_exp_message_state_mod_commands {
    OFPSC_SET_L_EXTRACTOR = 0,
    OFPSC_SET_U_EXTRACTOR,
    OFPSC_SET_FLOW_STATE,   
    OFPSC_DEL_FLOW_STATE,
    OFPSC_STATEFULNESS_CONFIG
};

/****************************************************************
 *
 *   OFPT_EXT_FLAG_MOD
 *
****************************************************************/

struct ofp_exp_message_flag_mod {
    struct ofp_experimenter_header header;  /* OpenFlow's standard experimenter message header*/
    uint32_t flag;
    uint32_t flag_mask;
    uint8_t command;
    uint8_t pad[7];                  /* Pad to 64 bits. */
};

enum ofp_exp_message_flag_mod_command { 
    OFPSC_MODIFY_FLAGS = 0,
    OFPSC_RESET_FLAGS
};

#endif /* OPENFLOW_OPENSTATE_EXT_H */