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

#define OPENSTATE_VENDOR_ID 0x0000BEBA

enum oxm_exp_match_fields {
    OFPXMT_EXP_FLAGS = 0,      /* Global States */
    OFPXMT_EXP_STATE = 1       /* Flow State */
};

/****************************************************************
 *
 * OpenFlow experimenter Actions
 *
 ****************************************************************/
struct ofp_action_extension_header {
    struct ofp_action_experimenter_header header;
    uint32_t act_type;   /* One of ofp_action_extension_commands */
    uint8_t pad[4];
};
OFP_ASSERT(sizeof(struct ofp_action_extension_header) == 16);

/* Action structure for OFPAT_EXP_SET_STATE */
struct ofp_exp_action_set_state {
    struct ofp_action_extension_header header;
    uint32_t state; /* State instance. */
    uint32_t state_mask; /* State mask */
    uint8_t table_id; /*Stage destination*/
    uint8_t pad[7];   /* Align to 64-bits. */
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_state) == 32);


/* Action structure for OFPAT_EXP_SET_FLAG */
struct ofp_exp_action_set_flag {
    struct ofp_action_extension_header header;
    uint32_t flag; /* flag value */
    uint32_t flag_mask;    /*flag mask*/
};
OFP_ASSERT(sizeof(struct ofp_exp_action_set_flag) == 24);


/*EXPERIMENTER MESSAGES*/
/****************************************************************
 *
 *   OFP_EXT_STATE_MOD
 *
****************************************************************/
#define OFPSC_MAX_FIELD_COUNT 6
#define OFPSC_MAX_KEY_LEN 48

struct ofp_message_os_ext_header {
    struct ofp_header header;
    uint32_t vendor;            /* OPENFLOW_VENDOR_ID. */
    uint32_t subtype;           /* One of ofp_extension_commands */
};
OFP_ASSERT(sizeof(struct ofp_message_os_ext_header) == 16);

struct ofp_exp_state_mod {
    struct ofp_message_os_ext_header header;
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

enum ofp_exp_state_mod_command {
    OFPSC_SET_L_EXTRACTOR = 0,
    OFPSC_SET_U_EXTRACTOR,
    OFPSC_SET_FLOW_STATE,   
    OFPSC_DEL_FLOW_STATE
};


/****************************************************************
 *
 *   OFP_EXT_FLAG_MOD
 *
****************************************************************/

struct ofp_exp_flag_mod {
    struct ofp_message_os_ext_header header;
    uint32_t flag;
    uint32_t flag_mask;
    uint8_t command;
    uint8_t pad[7];                  /* Pad to 64 bits. */
};

enum ofp_exp_flag_mod_command { 
    OFPSC_MODIFY_FLAGS = 0,
    OFPSC_RESET_FLAGS
};

#endif /* OPENFLOW_OPENSTATE_EXT_H */