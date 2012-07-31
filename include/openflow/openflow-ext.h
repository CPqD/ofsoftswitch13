/*
 * Copyright (c) 2009 The Board of Trustees of The Leland
 * Stanford Junior University
 */

#ifndef OPENFLOW_OPENFLOW_EXT_H
#define OPENFLOW_OPENFLOW_EXT_H 1

#include "openflow/openflow.h"

/*
 * The following are vendor extensions from OpenFlow.  This is a
 * means of allowing the introduction of non-standardized
 * proposed code.
 *
 * Structures in this file are 64-bit aligned in size.
 */

#define OPENFLOW_VENDOR_ID 0x000026e1

enum ofp_extension_commands { /* Queue configuration commands */
    /* Queue Commands */
    OFP_EXT_QUEUE_MODIFY,  /* Add and/or modify */
    OFP_EXT_QUEUE_DELETE,  /* Remove a queue */
    OFP_EXT_SET_DESC,      /* Set ofp_desc_stat->dp_desc */

    OFP_EXT_COUNT
};

struct ofp_extension_header {
    struct ofp_header header;
    uint32_t vendor;            /* OPENFLOW_VENDOR_ID. */
    uint32_t subtype;           /* One of ofp_extension_commands */
};
OFP_ASSERT(sizeof(struct ofp_extension_header) == 16);

/****************************************************************
 *
 * OpenFlow Queue Configuration Operations
 *
 ****************************************************************/

struct openflow_queue_command_header {
    struct ofp_extension_header header;
    uint32_t port;              /* Port for operations */
    uint8_t pad[4];             /* Align to 64-bits */
    uint8_t body[0];            /* Body of ofp_queue objects for op. */
};
OFP_ASSERT(sizeof(struct openflow_queue_command_header) == 24);

/* NOTE
 * Bug number: TBD.
 * The definitions for openflow_queue_error_code conflict with
 * those for ofp_queue_op_failed_code defined in openflow.h.
 * This will be addressed after the release of OpenFlow 1.0.
 * The error codes below for openflow_queue_error_code may be
 * removed at that time.
 */
/*
 * Entries for 'code' in ofp_error_msg with error 'type'
 * OFPET_QUEUE_OP_FAILED
 */
enum openflow_queue_error_code {
    OFQ_ERR_NONE,               /* Success */
    OFQ_ERR_FAIL,               /* Unspecified failure */
    OFQ_ERR_NOT_FOUND,          /* Queue not found */
    OFQ_ERR_DISCIPLINE,         /* Discipline not supported */
    OFQ_ERR_BW_UNAVAIL,         /* Bandwidth unavailable */
    OFQ_ERR_QUEUE_UNAVAIL,      /* Queue unavailable */
    OFQ_ERR_COUNT               /* Last please */
};

#define OPENFLOW_QUEUE_ERROR_STRINGS_DEF {                      \
    "Success",                  /* OFQ_ERR_NONE */              \
    "Unspecified failure",      /* OFQ_ERR_FAIL */              \
    "Queue not found",          /* OFQ_ERR_NOT_FOUND */         \
    "Discipline not supported", /* OFQ_ERR_DISCIPLINE */        \
    "Bandwidth unavailable",    /* OFQ_ERR_BW_UNAVAIL */        \
    "Queue unavailable"         /* OFQ_ERR_QUEUE_UNAVAIL */     \
}

extern char *openflow_queue_error_strings[];

struct openflow_ext_set_dp_desc {
    struct ofp_extension_header header;
    char dp_desc[DESC_STR_LEN];
};
OFP_ASSERT(sizeof(struct openflow_ext_set_dp_desc) == 272);

#define ofq_error_string(rv) (((rv) < OFQ_ERR_COUNT) && ((rv) >= 0) ? \
    openflow_queue_error_strings[rv] : "Unknown error code")

/****************************************************************
 *
 * Unsupported, but potential extended queue properties
 *
 ****************************************************************/

#if 0

#define OPENFLOW_QUEUE_PROP_STRINGS_DEF {                        \
    "No property specified"     /* OFPQT_NONE */                 \
    "Minimum Rate",             /* OFPQT_MIN */                  \
    "Maximum Rate",             /* OFQ_PROP_MAX_RATE */          \
    "Buffer alloc weight",      /* OFQ_PROP_BUF_ALLOC */         \
    "Scheduling weight"         /* OFQ_PROP_SCHED_WEIGHT */      \
}
extern char *openflow_queue_prop_strings[];

#define ofq_prop_string(val) (((val) < OFPQT_EXT_COUNT) && ((val) >= 0) ? \
    openflow_queue_prop_strings[val] : "Unknown property value")


/* Buffer alloc weight queue property description */
struct ofp_queue_prop_buf_alloc {
    struct ofp_queue_prop_header prop_header; /* prop: OFPQT_MIN, len: 16 */
    uint16_t alloc_val;       /* 0 disabled; 1 min; 0xffff max */
    uint8_t pad[6];           /* 64-bit alignment */
};
OFP_ASSERT(sizeof(struct ofp_queue_prop_buf_alloc) == 16);

/* Max-Rate queue property description */
struct ofp_queue_prop_sched_weight {
    struct ofp_queue_prop_header prop_header; /* prop: OFPQT_MIN, len: 16 */
    uint16_t weight;   /* discipline specific; 0 disabled; 1 min; 0xffff max */
    uint8_t pad[6];    /* 64-bit alignment */
};
OFP_ASSERT(sizeof(struct ofp_queue_prop_sched_weight) == 16);

#endif



#endif /* OPENFLOW_OPENFLOW_EXT_H */
