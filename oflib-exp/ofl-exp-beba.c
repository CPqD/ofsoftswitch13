#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include "openflow/openflow.h"
#include "openflow/beba-ext.h"
#include "ofl-exp-beba.h"
#include "oflib/ofl-log.h"
#include "oflib/ofl-print.h"
#include "oflib/ofl-utils.h"
#include "oflib/ofl-structs.h"
#include "oflib/oxm-match.h"
#include "lib/hash.h"
#include "lib/ofp.h"
#include "lib/ofpbuf.h"
#include "timeval.h"


#define LOG_MODULE ofl_exp_os
OFL_LOG_INIT(LOG_MODULE)

/* functions used  by ofp_exp_msg_pkttmp_mod */
static ofl_err
ofl_structs_add_pkttmp_unpack(struct ofp_exp_add_pkttmp const *src, size_t *len, struct ofl_exp_add_pkttmp *dst) {
    //int i;
    //uint8_t key[OFPSC_MAX_KEY_LEN] = {0};
    uint8_t *data = NULL;

    if( *len >= sizeof(struct ofp_exp_add_pkttmp) )
    {
        OFL_LOG_DBG(LOG_MODULE, "Received PKTTMP_MOD message to set pkttmp_id (%"PRIu32") [Msg_len: %zu].", src->pkttmp_id, *len);
        dst->pkttmp_id = ntohl(src->pkttmp_id);

        *len -= sizeof(struct ofp_exp_add_pkttmp);
        data = ((uint8_t *)src) + sizeof(struct ofp_exp_add_pkttmp);

        dst->data_length = *len;
        dst->data = *len > 0 ? (uint8_t *)memcpy(malloc(*len), data, *len) : NULL;
        *len = 0;
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received pkttmp mod add_pkttmp is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    return 0;
}

static ofl_err
ofl_structs_del_pkttmp_unpack(struct ofp_exp_del_pkttmp const *src, size_t *len, struct ofl_exp_del_pkttmp *dst) {
    //int i;
    //uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if( *len == sizeof(struct ofp_exp_del_pkttmp) )
    {
        OFL_LOG_DBG(LOG_MODULE, "NOT IMPLEMENTED! Received PKTTMP_MOD message to delete pkttmp_id (%"PRIu32").", src->pkttmp_id );
        dst->pkttmp_id = ntohl(src->pkttmp_id);
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received pkttmp mod del_pkttmp is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= (sizeof(struct ofp_exp_del_pkttmp));

    return 0;
}

/* functions used by ofp_exp_msg_state_mod*/
static ofl_err
ofl_structs_stateful_table_config_unpack(struct ofp_exp_stateful_table_config const *src, size_t *len, struct ofl_exp_stateful_table_config *dst)
{
    if(*len == sizeof(struct ofp_exp_stateful_table_config))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%d).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        dst->table_id = src->table_id;
        dst->stateful = src->stateful;
    }
    else
    {
       OFL_LOG_WARN(LOG_MODULE, "Received state mod stateful_table_config is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= sizeof(struct ofp_exp_stateful_table_config);

    return 0;
}

static ofl_err
ofl_structs_extraction_unpack(struct ofp_exp_set_extractor const *src, size_t *len, struct ofl_exp_set_extractor *dst)
{
    int i;
    if(*len == ((1+ntohl(src->field_count))*sizeof(uint32_t) + 4*sizeof(uint8_t) + 4*sizeof(uint8_t)) && (ntohl(src->field_count)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%d).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        dst->table_id = src->table_id;
        dst->field_count=ntohl(src->field_count);
        dst->bit = src->bit;
        for (i=0;i<dst->field_count;i++)
        {
            dst->fields[i]=ntohl(src->fields[i]);
        }
    }
    else
    { //check of struct ofp_exp_set_extractor length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod extraction is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= (((1+ntohl(src->field_count))*sizeof(uint32_t)) + 4*sizeof(uint8_t) + 4*sizeof(uint8_t));

    return 0;
}

static ofl_err
ofl_structs_set_flow_state_unpack(struct ofp_exp_set_flow_state const *src, size_t *len, struct ofl_exp_set_flow_state *dst)
{
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if((*len == ((7*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t))) + 4*sizeof(uint8_t)) && (ntohl(src->key_len)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%d).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        dst->table_id = src->table_id;
        dst->key_len=ntohl(src->key_len);
        dst->state=ntohl(src->state);
        dst->state_mask=ntohl(src->state_mask);
        dst->idle_timeout = ntohl(src->idle_timeout);
        dst->idle_rollback = ntohl(src->idle_rollback);
        dst->hard_timeout = ntohl(src->hard_timeout);
        dst->hard_rollback = ntohl(src->hard_rollback);
        for (i=0;i<dst->key_len;i++)
            key[i]=src->key[i];
        memcpy(dst->key, key, dst->key_len);
    }
    else
    { //check of struct ofp_exp_set_flow_state length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod set_flow is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= ((7*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t)) + 4*sizeof(uint8_t));

    return 0;
}

static ofl_err
ofl_structs_del_flow_state_unpack(struct ofp_exp_del_flow_state const *src, size_t *len, struct ofl_exp_del_flow_state *dst)
{
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if((*len == ((sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t))) + 4*sizeof(uint8_t)) && (ntohl(src->key_len)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%d).", src->table_id );
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
        }
        dst->table_id = src->table_id;
        dst->key_len=ntohl(src->key_len);
        for (i=0;i<dst->key_len;i++)
            key[i]=src->key[i];
        memcpy(dst->key, key, dst->key_len);
        OFL_LOG_DBG(LOG_MODULE, "key count is %d\n",dst->key_len);
    }
    else
    { //check of struct ofp_exp_del_flow_state length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod del_flow is too short (%zu).", *len);
       return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= ((sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t)) + 4*sizeof(uint8_t));

    return 0;
}

static ofl_err
ofl_structs_set_global_state_unpack(struct ofp_exp_set_global_state const *src, size_t *len, struct ofl_exp_set_global_state *dst)
{

    if (*len == 2*sizeof(uint32_t)) {
        dst->global_state = ntohl(src->global_state);
        dst->global_state_mask = ntohl(src->global_state_mask);
    }
    else {
        //check of struct ofp_exp_set_global_state length.
        OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD set global state has invalid length (%zu).", *len);
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    *len -= sizeof(struct ofp_exp_set_global_state);

    return 0;
}

int
ofl_exp_beba_msg_pack(struct ofl_msg_experimenter const *msg, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp UNUSED)
{
    struct ofl_exp_beba_msg_header *exp_msg = (struct ofl_exp_beba_msg_header *)msg;
    switch (exp_msg->type) {
       /* State Sync: Pack the state change message */
       case(OFPT_EXP_STATE_CHANGED): {
           struct ofl_exp_msg_notify_state_change *ntf = (struct ofl_exp_msg_notify_state_change *) exp_msg;
           struct ofp_exp_msg_state_ntf *ntf_msg;

           *buf_len = sizeof(struct ofp_experimenter_header) + 5*sizeof(uint32_t) + ntf->key_len*sizeof(uint8_t); //sizeof(struct ofp_exp_msg_state_ntf);
           *buf     = (uint8_t *)malloc(*buf_len);

           ntf_msg = (struct ofp_exp_msg_state_ntf *)(*buf);

           ntf_msg->header.experimenter = htonl(BEBA_VENDOR_ID);
           ntf_msg->header.exp_type = htonl(OFPT_EXP_STATE_CHANGED);
           ntf_msg->table_id = htonl(ntf->table_id);
           ntf_msg->old_state = htonl(ntf->old_state);
           ntf_msg->new_state = htonl(ntf->new_state);
           ntf_msg->state_mask = htonl(ntf->state_mask);
           ntf_msg->key_len = htonl(ntf->key_len);
           memcpy(ntf_msg->key, ntf->key, ntf->key_len);
           return 0;
        }
        /* State Sync: Pack positive flow modification acknowledgment. */
        case (OFPT_EXP_FLOW_NOTIFICATION) :
        {
            struct ofl_exp_msg_notify_flow_change *ntf = (struct ofl_exp_msg_notify_flow_change *)exp_msg;
            struct ofp_exp_msg_flow_ntf * ntf_msg;

            uint8_t * ptr;
            uint32_t * data;
            int i;

            *buf_len = ROUND_UP(sizeof(struct ofp_exp_msg_flow_ntf)-4 + ntf->match->length,8) +
                      ROUND_UP((ntf->instruction_num+1)*sizeof(uint32_t),8);
            *buf     = (uint8_t *)malloc(*buf_len);

            ntf_msg = (struct ofp_exp_msg_flow_ntf *)(*buf);

            ntf_msg->header.experimenter = htonl(BEBA_VENDOR_ID);
            ntf_msg->header.exp_type = htonl(OFPT_EXP_FLOW_NOTIFICATION);
            ntf_msg->table_id = htonl(ntf->table_id);
            ntf_msg->ntf_type = htonl(ntf->ntf_type);

            ptr = *buf + sizeof(struct ofp_exp_msg_flow_ntf)-4;
            ofl_structs_match_pack(ntf->match, &(ntf_msg->match),ptr, exp);

            data = (uint32_t *)(*buf + ROUND_UP(sizeof(struct ofp_exp_msg_flow_ntf)-4+ntf->match->length,8));
            *data = htonl(ntf->instruction_num);
            //NB: instructions are not full 'struct ofp_instruction'. We send back to the ctrl just a list of instruction types

            ++data;
            for (i=0;i<ntf->instruction_num;++i){
               *data = htonl(ntf->instructions[i]);
               ++data;
            }
            return 0;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown Beba Experimenter message.");
            return -1;
        }
    }
}

ofl_err
ofl_exp_beba_msg_unpack(struct ofp_header const *oh, size_t *len, struct ofl_msg_experimenter **msg, struct ofl_exp const *exp)
{
    struct ofp_experimenter_header *exp_header;

    if (*len < sizeof(struct ofp_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message has invalid length (%zu).", *len);
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    exp_header = (struct ofp_experimenter_header *)oh;

    switch (ntohl(exp_header->exp_type)) {
        case (OFPT_EXP_STATE_MOD):
        {
            struct ofp_exp_msg_state_mod *sm;
            struct ofl_exp_msg_state_mod *dm;

            *len -= sizeof(struct ofp_experimenter_header);

            sm = (struct ofp_exp_msg_state_mod *)exp_header;
            dm = (struct ofl_exp_msg_state_mod *)malloc(sizeof(struct ofl_exp_msg_state_mod));

            dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
            dm->header.type                   = ntohl(exp_header->exp_type);

            (*msg) = (struct ofl_msg_experimenter *)dm;

            /*2*sizeof(uint8_t) = enum ofp_exp_msg_state_mod_commands + 1 byte of padding*/
            if (*len < 2*sizeof(uint8_t)) {
                OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            dm->command = (enum ofp_exp_msg_state_mod_commands)sm->command;

            *len -= 2*sizeof(uint8_t);

            switch(dm->command){
                case OFPSC_STATEFUL_TABLE_CONFIG:
                    return ofl_structs_stateful_table_config_unpack((struct ofp_exp_stateful_table_config const *)&(sm->payload[0]), len,
                                                               (struct ofl_exp_stateful_table_config *)&(dm->payload[0]));
                case OFPSC_EXP_SET_L_EXTRACTOR:
                case OFPSC_EXP_SET_U_EXTRACTOR:
                    return ofl_structs_extraction_unpack((struct ofp_exp_set_extractor const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_extractor *)&(dm->payload[0]));
                case OFPSC_EXP_SET_FLOW_STATE:
                    return ofl_structs_set_flow_state_unpack((struct ofp_exp_set_flow_state const *)&(sm->payload[0]), len,
                                                    (struct ofl_exp_set_flow_state *)&(dm->payload[0]));
                case OFPSC_EXP_DEL_FLOW_STATE:
                    return ofl_structs_del_flow_state_unpack((struct ofp_exp_del_flow_state const *)&(sm->payload[0]), len,
                                                        (struct ofl_exp_del_flow_state *)&(dm->payload[0]));
                case OFPSC_EXP_SET_GLOBAL_STATE:
                    return ofl_structs_set_global_state_unpack((struct ofp_exp_set_global_state const *)&(sm->payload[0]), len,
                                                          (struct ofl_exp_set_global_state *)&(dm->payload[0]));
                default:
                    return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_STATE_MOD_BAD_COMMAND);
            }
        }
        case (OFPT_EXP_PKTTMP_MOD):
        {
            struct ofp_exp_msg_pkttmp_mod *sm;
            struct ofl_exp_msg_pkttmp_mod *dm;

            *len -= sizeof(struct ofp_experimenter_header);

            sm = (struct ofp_exp_msg_pkttmp_mod *)exp_header;
            dm = (struct ofl_exp_msg_pkttmp_mod *)malloc(sizeof(struct ofl_exp_msg_pkttmp_mod));

            dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
            dm->header.type                   = ntohl(exp_header->exp_type);

            (*msg) = (struct ofl_msg_experimenter *)dm;

            if (*len < 2*sizeof(uint8_t)) {
                OFL_LOG_WARN(LOG_MODULE, "Received PKTTMP_MOD message has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            dm->command = (enum ofp_exp_msg_pkttmp_mod_commands)sm->command;

            *len -= 2*sizeof(uint8_t);

            switch(dm->command){
                case OFPSC_ADD_PKTTMP:
                    return ofl_structs_add_pkttmp_unpack((struct ofp_exp_add_pkttmp const *)&(sm->payload[0]), len, (struct ofl_exp_add_pkttmp *)&(dm->payload[0]));
                case OFPSC_DEL_PKTTMP:
                    return ofl_structs_del_pkttmp_unpack((struct ofp_exp_del_pkttmp const *)&(sm->payload[0]), len, (struct ofl_exp_del_pkttmp *)&(dm->payload[0]));
                default:
                    return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND);
            }
        }
        case (OFPT_EXP_STATE_CHANGED):
        {
            struct ofp_exp_msg_state_ntf *sm;
            struct ofl_exp_msg_notify_state_change *dm;

            *len -= sizeof(struct ofp_experimenter_header);

            sm = (struct ofp_exp_msg_state_ntf *)exp_header;
            dm = (struct ofl_exp_msg_notify_state_change *)malloc(sizeof(struct ofl_exp_msg_notify_state_change));

            dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
            dm->header.type                   = ntohl(exp_header->exp_type);

            (*msg) = (struct ofl_msg_experimenter *)dm;

            if (*len < 5*sizeof(uint32_t)) {
                OFL_LOG_WARN(LOG_MODULE, "Received OFPT_EXP_STATE_CHANGED message has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            dm->table_id = ntohl(sm->table_id);
            dm->old_state = ntohl(sm->old_state);
            dm->new_state = ntohl(sm->new_state);
            dm->state_mask = ntohl(sm->state_mask);
            dm->key_len = ntohl(sm->key_len);
            memcpy(dm->key, sm->key, dm->key_len);
            *len -= 5*sizeof(uint32_t) + dm->key_len*sizeof(uint8_t);
            return 0;
        }
        case (OFPT_EXP_FLOW_NOTIFICATION):
        {
            struct ofp_exp_msg_flow_ntf * sm;
            struct ofl_exp_msg_notify_flow_change *dm;
            uint32_t * data;
            int i;
            ofl_err error;

            sm = (struct ofp_exp_msg_flow_ntf *)exp_header;
            dm = (struct ofl_exp_msg_notify_flow_change *) malloc(sizeof(struct ofl_exp_msg_notify_flow_change));

            dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
            dm->header.type = ntohl(exp_header->exp_type);

            *msg = (struct ofl_msg_experimenter *)dm;

            dm->table_id = ntohl(sm->table_id);
            dm->ntf_type = ntohl(sm->ntf_type);

            *len -= ((sizeof(struct ofp_exp_msg_flow_ntf)) - sizeof(struct ofp_match));
            error = ofl_structs_match_unpack(&(sm->match), ((uint8_t *)oh)+sizeof(struct ofp_exp_msg_flow_ntf)-4, len, &(dm->match), 0, exp);

            if (error) {
                ofl_structs_free_match(dm->match, NULL);
                free(dm);
                return error;
            }

            data = (uint32_t * )(((uint8_t *)oh) + ROUND_UP(sizeof(struct ofp_exp_msg_flow_ntf)-4 + dm->match->length, 8));
            //NB: instructions are not full 'struct ofp_instruction'. We send back to the ctrl just a list of instruction types
            dm->instruction_num = ntohl(*data);

            if (dm->instruction_num>0) {
                dm->instructions = malloc(dm->instruction_num*sizeof(uint32_t));
                data++;
                for(i=0; i<(dm->instruction_num); i++){
                    dm->instructions[i] = ntohl(*data);
                    data++;
                }
             } else {
                dm->instructions = NULL;
            }

            *len -= ROUND_UP((dm->instruction_num+1)* sizeof(uint32_t), 8);

            return 0;
        }
        default: {
            struct ofl_msg_experimenter *dm;
            dm = (struct ofl_msg_experimenter *)malloc(sizeof(struct ofl_msg_experimenter));
            dm->experimenter_id = ntohl(exp_header->experimenter);
            (*msg) = dm;
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Beba Experimenter message.");
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_MESSAGE);
        }
    }
}

int
ofl_exp_beba_msg_free(struct ofl_msg_experimenter *msg)
{
    struct ofl_exp_beba_msg_header *exp = (struct ofl_exp_beba_msg_header *)msg;
    switch (exp->type) {
        case (OFPT_EXP_STATE_MOD):
        {
            struct ofl_exp_msg_state_mod *state_mod = (struct ofl_exp_msg_state_mod *)exp;
            OFL_LOG_DBG(LOG_MODULE, "Free Beba STATE_MOD Experimenter message. bebaexp{type=\"%u\", command=\"%u\"}", exp->type, state_mod->command);
            free(msg);
            break;
        }
        case (OFPT_EXP_PKTTMP_MOD):
        {
            struct ofl_exp_msg_pkttmp_mod *pkttmp_mod = (struct ofl_exp_msg_pkttmp_mod *)exp;
            OFL_LOG_DBG(LOG_MODULE, "Free Beba PKTTMP_MOD Experimenter message. bebaexp{type=\"%u\", command=\"%u\"}", exp->type, pkttmp_mod->command);
            free(msg);
            break;
        }
        case (OFPT_EXP_STATE_CHANGED):
        {
            OFL_LOG_DBG(LOG_MODULE, "Free Beba OFPT_EXP_STATE_CHANGED Experimenter message. bebaexp{type=\"%u\"}", exp->type);
            free(msg);
            break;
        }
        case (OFPT_EXP_FLOW_NOTIFICATION):
        {
            struct ofl_exp_msg_notify_flow_change * msg = (struct ofl_exp_msg_notify_flow_change *) exp;
            OFL_LOG_DBG(LOG_MODULE, "Free Beba FLOW_NOTIFICATION Experimenter message. bebaexp{type=\"%u\", table_id=\"%u\"}", exp->type, msg->table_id);
            ofl_structs_free_match(msg->match,NULL);
            if (msg->instruction_num>0 && msg->instructions!=NULL){
                free(msg->instructions);
            }
            free(msg);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Beba Experimenter message.");
        }
    }
    return 0;
}

char *
ofl_exp_beba_msg_to_string(struct ofl_msg_experimenter const *msg, struct ofl_exp const *exp)
{
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    struct ofl_exp_beba_msg_header *exp_msg = (struct ofl_exp_beba_msg_header *)msg;
    switch (exp_msg->type) {
        case (OFPT_EXP_STATE_MOD):
        {
            struct ofl_exp_msg_state_mod *state_mod = (struct ofl_exp_msg_state_mod *)exp_msg;
            OFL_LOG_DBG(LOG_MODULE, "Print Beba STATE_MOD Experimenter message BEBA_MSG{type=\"%u\", command=\"%u\"}", exp_msg->type, state_mod->command);
            break;
        }
        case (OFPT_EXP_PKTTMP_MOD):
        {
            struct ofl_exp_msg_pkttmp_mod *pkttmp_mod = (struct ofl_exp_msg_pkttmp_mod *)exp_msg;
            OFL_LOG_DBG(LOG_MODULE, "Print Beba PKTTMP_MOD Experimenter message BEBA_MSG{type=\"%u\", command=\"%u\"}", exp_msg->type, pkttmp_mod->command);
            break;
        }
        case (OFPT_EXP_STATE_CHANGED):
        {
            OFL_LOG_DBG(LOG_MODULE, "Print Beba OFPT_EXP_STATE_CHANGED Experimenter message BEBA_MSG{type=\"%u\"}", exp_msg->type);
            break;
        }
        case (OFPT_EXP_FLOW_NOTIFICATION):{
            struct ofl_exp_msg_notify_flow_change * msg = (struct ofl_exp_msg_notify_flow_change *) exp_msg;
            int i;
            char *s;

            s = ofl_structs_match_to_string(msg->match, exp);
            OFL_LOG_DBG(LOG_MODULE, "Flow modification confirmed, flow table: \"%u\" , match fields \"%s\" ", msg->table_id, s);
            free(s);
            OFL_LOG_DBG(LOG_MODULE, "Instructions : ");
            for(i=0; i<msg->instruction_num; i++){
                s = ofl_instruction_type_to_string(msg->instructions[i]);
                OFL_LOG_DBG(LOG_MODULE, "  \"%s\"  ", s);
                free(s);
            }
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Beba Experimenter message UNKN_BEBA_MSG{type=\"%u\"}", exp_msg->type);
            break;
        }
    }
    fclose(stream);
    return str;
}

/*experimenter action functions*/

ofl_err
ofl_exp_beba_act_unpack(struct ofp_action_header const *src, size_t *len, struct ofl_action_header **dst)
{
    struct ofp_action_experimenter_header const *exp;
    struct ofp_beba_action_experimenter_header const *ext;

    if (*len < sizeof(struct ofp_action_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_action_experimenter_header const *)src;
    ext = (struct ofp_beba_action_experimenter_header const *)exp;

    switch (ntohl(ext->act_type)) {
        case (OFPAT_EXP_SET_STATE):
        {
            struct ofp_exp_action_set_state *sa;
            struct ofl_exp_action_set_state *da;

            sa = (struct ofp_exp_action_set_state *)ext;
            da = (struct ofl_exp_action_set_state *)malloc(sizeof(struct ofl_exp_action_set_state));
            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);
            *dst = (struct ofl_action_header *)da;

            if (*len < sizeof(struct ofp_exp_action_set_state)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET STATE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            if (sa->table_id >= PIPELINE_TABLES) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ts = ofl_table_to_string(sa->table_id);
                    OFL_LOG_WARN(LOG_MODULE, "Received SET STATE action has invalid table_id (%s).", ts);
                    free(ts);
                }
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
            }

            da->state = ntohl(sa->state);
            da->state_mask = ntohl(sa->state_mask);
            da->table_id = sa->table_id;
            da->hard_rollback = ntohl(sa->hard_rollback);
            da->idle_rollback = ntohl(sa->idle_rollback);
            da->hard_timeout = ntohl(sa->hard_timeout);
            da->idle_timeout = ntohl(sa->idle_timeout);
            da->bit = sa->bit;

            *len -= sizeof(struct ofp_exp_action_set_state);
            break;
        }

        case (OFPAT_EXP_SET_GLOBAL_STATE):
        {
            struct ofp_exp_action_set_global_state *sa;
            struct ofl_exp_action_set_global_state *da;
            sa = (struct ofp_exp_action_set_global_state*)ext;
            da = (struct ofl_exp_action_set_global_state *)malloc(sizeof(struct ofl_exp_action_set_global_state));

            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);

            *dst = (struct ofl_action_header *)da;
            if (*len < sizeof(struct ofp_exp_action_set_global_state)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET GLOBAL STATE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            da->global_state = ntohl(sa->global_state);
            da->global_state_mask = ntohl(sa->global_state_mask);

            *len -= sizeof(struct ofp_exp_action_set_global_state);
            break;
        }

        case (OFPAT_EXP_INC_STATE):
        {
            struct ofp_exp_action_inc_state *sa;
            struct ofl_exp_action_inc_state *da;
            sa = (struct ofp_exp_action_inc_state*)ext;
            da = (struct ofl_exp_action_inc_state *)malloc(sizeof(struct ofl_exp_action_inc_state));

            da->header.header.experimenter_id = ntohl(exp->experimenter);
            da->header.act_type = ntohl(ext->act_type);

            *dst = (struct ofl_action_header *)da;
            if (*len < sizeof(struct ofp_exp_action_inc_state)) {
                OFL_LOG_WARN(LOG_MODULE, "Received SET INC STATE action has invalid length (%zu).", *len);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            if (sa->table_id >= PIPELINE_TABLES) {
                if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                    char *ts = ofl_table_to_string(sa->table_id);
                    OFL_LOG_WARN(LOG_MODULE, "Received SET INC STATE action has invalid table_id (%s).", ts);
                    free(ts);
                }
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_TABLE_ID);
            }

            da->table_id = sa->table_id;

            *len -= sizeof(struct ofp_exp_action_inc_state);
            break;
        }

        default:
        {
            struct ofl_action_experimenter *da;
            da = (struct ofl_action_experimenter *)malloc(sizeof(struct ofl_action_experimenter));
            da->experimenter_id = ntohl(exp->experimenter);
            (*dst) = (struct ofl_action_header *)da;
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Beba Experimenter action.");
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_ACTION);
        }
    }
    return 0;
}

int
ofl_exp_beba_act_pack(struct ofl_action_header const *src, struct ofp_action_header *dst)
{

    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) src;
    struct ofl_exp_beba_act_header *ext = (struct ofl_exp_beba_act_header *) exp;

    switch (ext->act_type) {
        case (OFPAT_EXP_SET_STATE):
        {
            struct ofl_exp_action_set_state *sa = (struct ofl_exp_action_set_state *) ext;
            struct ofp_exp_action_set_state *da = (struct ofp_exp_action_set_state *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->header.pad, 0x00, 4);
            da->state = htonl(sa->state);
            da->state_mask = htonl(sa->state_mask);
            da->table_id = sa->table_id;
            memset(da->pad, 0x00, 3);
            da->hard_rollback = htonl(sa->hard_rollback);
            da->idle_rollback = htonl(sa->idle_rollback);
            da->hard_timeout = htonl(sa->hard_timeout);
            da->idle_timeout = htonl(sa->idle_timeout);
            memset(da->pad2, 0x00, 4);
            dst->len = htons(sizeof(struct ofp_exp_action_set_state));
            da->bit = sa->bit;
            memset(da->pad2, 0x00, 3);

            return sizeof(struct ofp_exp_action_set_state);
        }
        case (OFPAT_EXP_SET_GLOBAL_STATE):
        {
            struct ofl_exp_action_set_global_state *sa = (struct ofl_exp_action_set_global_state *) ext;
            struct ofp_exp_action_set_global_state *da = (struct ofp_exp_action_set_global_state *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->header.pad, 0x00, 4);
            da->global_state = htonl(sa->global_state);
            da->global_state_mask = htonl(sa->global_state_mask);
            dst->len = htons(sizeof(struct ofp_exp_action_set_global_state));

            return sizeof(struct ofp_exp_action_set_global_state);
        }
        case (OFPAT_EXP_INC_STATE):
        {
            struct ofl_exp_action_inc_state *sa = (struct ofl_exp_action_inc_state *) ext;
            struct ofp_exp_action_inc_state *da = (struct ofp_exp_action_inc_state *) dst;

            da->header.header.experimenter = htonl(exp->experimenter_id);
            da->header.act_type = htonl(ext->act_type);
            memset(da->header.pad, 0x00, 4);
            da->table_id = sa->table_id;
            memset(da->pad, 0x00, 7);
            dst->len = htons(sizeof(struct ofp_exp_action_inc_state));

            return sizeof(struct ofp_exp_action_inc_state);
        }
        default:
            return 0;
    }
}

size_t
ofl_exp_beba_act_ofp_len(struct ofl_action_header const *act)
{
    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) act;
    struct ofl_exp_beba_act_header *ext = (struct ofl_exp_beba_act_header *) exp;

    switch (ext->act_type) {
        case (OFPAT_EXP_SET_STATE):
            return sizeof(struct ofp_exp_action_set_state);
        case (OFPAT_EXP_SET_GLOBAL_STATE):
            return sizeof(struct ofp_exp_action_set_global_state);
        case (OFPAT_EXP_INC_STATE):
            return sizeof(struct ofp_exp_action_inc_state);
        default:
            return 0;
    }
}

char *
ofl_exp_beba_act_to_string(struct ofl_action_header const *act)
{
    struct ofl_action_experimenter *exp = (struct ofl_action_experimenter *) act;
    struct ofl_exp_beba_act_header *ext = (struct ofl_exp_beba_act_header *) exp;

    switch (ext->act_type) {
        case (OFPAT_EXP_SET_STATE):
        {
            struct ofl_exp_action_set_state *a = (struct ofl_exp_action_set_state *)ext;
            char *string = malloc(200);
            sprintf(string, "{set_state=[state=\"%u\",state_mask=\"%"PRIu32"\",table_id=\"%u\",idle_to=\"%u\",hard_to=\"%u\",idle_rb=\"%u\",hard_rb=\"%u\",bit=\"%u\"]}", a->state, a->state_mask, a->table_id,a->idle_timeout,a->hard_timeout,a->idle_rollback,a->hard_rollback,a->bit);
            return string;
        }
        case (OFPAT_EXP_SET_GLOBAL_STATE):
        {
            struct ofl_exp_action_set_global_state *a = (struct ofl_exp_action_set_global_state *)ext;
            char *string = malloc(100);
            char string_value[33];
            masked_value_print(string_value,decimal_to_binary(a->global_state),decimal_to_binary(a->global_state_mask));
            sprintf(string, "{set_global_state=[global_state=%s]}", string_value);
            return string;
        }
        case (OFPAT_EXP_INC_STATE):
        {
            struct ofl_exp_action_inc_state *a = (struct ofl_exp_action_inc_state *)ext;
            char *string = malloc(100);
            sprintf(string, "{inc_state=[table_id=\"%u\"]}", a->table_id);
            return string;
        }
    }
    return NULL;
}

int
ofl_exp_beba_act_free(struct ofl_action_header *act)
{
    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) act;
    struct ofl_exp_beba_act_header *ext = (struct ofl_exp_beba_act_header *)exp;
    switch (ext->act_type) {
        case (OFPAT_EXP_SET_STATE):
        {
            struct ofl_exp_action_set_state *a = (struct ofl_exp_action_set_state *)ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_SET_GLOBAL_STATE):
        {
            struct ofl_exp_action_set_global_state *a = (struct ofl_exp_action_set_global_state *)ext;
            free(a);
            break;
        }
        case (OFPAT_EXP_INC_STATE):
        {
            struct ofl_exp_action_inc_state *a = (struct ofl_exp_action_inc_state *)ext;
            free(a);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Beba Experimenter action.");
        }
    }
    return 0;
}

int
ofl_exp_beba_stats_req_pack(struct ofl_msg_multipart_request_experimenter const *ext, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp)
{
    struct ofl_exp_beba_msg_multipart_request *e = (struct ofl_exp_beba_msg_multipart_request *)ext;
    switch (e->type){
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_request_state *msg = (struct ofl_exp_msg_multipart_request_state *)e;
            struct ofp_multipart_request *req;
            struct ofp_exp_state_stats_request *stats;
            struct ofp_experimenter_stats_header *exp_header;
            uint8_t *ptr;
            *buf_len = ROUND_UP(sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request) -4 + msg->match->length,8);
            *buf     = (uint8_t *)malloc(*buf_len);

            req = (struct ofp_multipart_request *)(*buf);
            stats = (struct ofp_exp_state_stats_request *)req->body;
            exp_header = (struct ofp_experimenter_stats_header *)stats;
            exp_header -> experimenter = htonl(BEBA_VENDOR_ID);
            exp_header -> exp_type = htonl(OFPMP_EXP_STATE_STATS);
            if (e->type == OFPMP_EXP_STATE_STATS)
                exp_header -> exp_type = htonl(OFPMP_EXP_STATE_STATS);
            else if (e->type == OFPMP_EXP_STATE_STATS_AND_DELETE)
                exp_header -> exp_type = htonl(OFPMP_EXP_STATE_STATS_AND_DELETE);
            stats->table_id = msg->table_id;
            stats->get_from_state = msg->get_from_state;
            stats->state = htonl(msg->state);
            memset(stats->pad, 0x00, 2);
            ptr = (*buf) + sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request);
            ofl_structs_match_pack(msg->match, &(stats->match),ptr, exp);

            return 0;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):
        {
            struct ofp_multipart_request *req;
            struct ofp_exp_global_state_stats_request *stats;
            struct ofp_experimenter_stats_header *exp_header;
            *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_global_state_stats_request);
            *buf     = (uint8_t *)malloc(*buf_len);

            req = (struct ofp_multipart_request *)(*buf);
            stats = (struct ofp_exp_global_state_stats_request *)req->body;
            exp_header = (struct ofp_experimenter_stats_header *)stats;
            exp_header -> experimenter = htonl(BEBA_VENDOR_ID);
            exp_header -> exp_type = htonl(OFPMP_EXP_GLOBAL_STATE_STATS);

            return 0;

        }
        default:
            return -1;
    }
}


int
ofl_exp_beba_stats_reply_pack(struct ofl_msg_multipart_reply_experimenter const *ext, uint8_t **buf, size_t *buf_len, struct ofl_exp const *exp)
{
    struct ofl_exp_beba_msg_multipart_reply *e = (struct ofl_exp_beba_msg_multipart_reply *)ext;
    switch (e->type){
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_state *msg = (struct ofl_exp_msg_multipart_reply_state *)e;
            struct ofp_experimenter_stats_header *ext_header;
            struct ofp_multipart_reply *resp;
            size_t i;
            uint8_t * data;

            *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_experimenter_stats_header) + ofl_structs_state_stats_ofp_total_len(msg->stats, msg->stats_num, exp);
            *buf     = (uint8_t *)malloc(*buf_len);
            resp = (struct ofp_multipart_reply *)(*buf);
            data = (uint8_t*) resp->body;
            ext_header = (struct ofp_experimenter_stats_header*) data;
            ext_header->experimenter = htonl(BEBA_VENDOR_ID);
            ext_header->exp_type = htonl(OFPMP_EXP_STATE_STATS);
            if (e->type == OFPMP_EXP_STATE_STATS)
                ext_header->exp_type = htonl(OFPMP_EXP_STATE_STATS);
            else if (e->type == OFPMP_EXP_STATE_STATS_AND_DELETE)
                ext_header->exp_type = htonl(OFPMP_EXP_STATE_STATS_AND_DELETE);

            data += sizeof(struct ofp_experimenter_stats_header);
            for (i=0; i<msg->stats_num; i++) {
                data += ofl_structs_state_stats_pack(msg->stats[i], data, exp);
            }
            return 0;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_global_state *msg = (struct ofl_exp_msg_multipart_reply_global_state *)e;
            struct ofp_multipart_reply *resp;
            struct ofp_exp_global_state_stats *stats;
            struct ofp_experimenter_stats_header * exp_header;

            *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_exp_global_state_stats);
            *buf     = (uint8_t *)malloc(*buf_len);

            resp = (struct ofp_multipart_reply *)(*buf);
            stats = (struct ofp_exp_global_state_stats *)resp->body;
            exp_header = (struct ofp_experimenter_stats_header *)stats;

            exp_header -> experimenter = htonl(BEBA_VENDOR_ID);
            exp_header -> exp_type = htonl(OFPMP_EXP_GLOBAL_STATE_STATS);
            memset(stats->pad, 0x00, 4);
            stats->global_state=htonl(msg->global_state);
            return 0;
        }
        default:
            return -1;
    }
}

ofl_err
ofl_exp_beba_stats_req_unpack(struct ofp_multipart_request const *os, uint8_t const *buf, size_t *len, struct ofl_msg_multipart_request_header **msg, struct ofl_exp const *exp)
{
    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *)os->body;
    switch (ntohl(ext->exp_type)){
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofp_exp_state_stats_request *sm;
            struct ofl_exp_msg_multipart_request_state *dm;
            ofl_err error = 0;
            int match_pos;
            bool check_prereq = 0;

            // ofp_multipart_request length was checked at ofl_msg_unpack_multipart_request

            if (*len < (sizeof(struct ofp_exp_state_stats_request) - sizeof(struct ofp_match))) {
                OFL_LOG_WARN(LOG_MODULE, "Received STATE stats request has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }
            *len -= ((sizeof(struct ofp_exp_state_stats_request)) - sizeof(struct ofp_match));

            sm = (struct ofp_exp_state_stats_request *)ext;
            dm = (struct ofl_exp_msg_multipart_request_state *) malloc(sizeof(struct ofl_exp_msg_multipart_request_state));

            if (sm->table_id != OFPTT_ALL && sm->table_id >= PIPELINE_TABLES) {
                 OFL_LOG_WARN(LOG_MODULE, "Received MULTIPART REQUEST STATE message has invalid table id (%d).", sm->table_id );
                 free(dm);
                 return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
            }
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            dm->table_id = sm->table_id;
            dm->get_from_state = sm->get_from_state;
            dm->state = ntohl(sm->state);
            match_pos = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request) - 4;
            error = ofl_structs_match_unpack(&(sm->match),buf + match_pos, len, &(dm->match), check_prereq, exp);
            if (error) {
                free(dm);
                return error;
            }

            *msg = (struct ofl_msg_multipart_request_header *)dm;
            return 0;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_request_global_state *dm;
            dm = (struct ofl_exp_msg_multipart_request_global_state *) malloc(sizeof(struct ofl_exp_msg_multipart_request_global_state));
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            *len -= sizeof(struct ofp_exp_global_state_stats_request);
            *msg = (struct ofl_msg_multipart_request_header *)dm;
            return 0;
        }
        default:
            return -1;
    }
}

ofl_err
ofl_exp_beba_stats_reply_unpack(struct ofp_multipart_reply const *os, uint8_t const *buf, size_t *len, struct ofl_msg_multipart_reply_header **msg, struct ofl_exp const *exp)
{
    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *)os->body;
    switch (ntohl(ext->exp_type)){
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofp_exp_state_stats *stat;
            struct ofl_exp_msg_multipart_reply_state *dm;
            ofl_err error;
            size_t i, ini_len;
            uint8_t const *ptr;

            // ofp_multipart_reply was already checked and subtracted in unpack_multipart_reply
            stat = (struct ofp_exp_state_stats *) (os->body + sizeof(struct ofp_experimenter_stats_header));
            dm = (struct ofl_exp_msg_multipart_reply_state *)malloc(sizeof(struct ofl_exp_msg_multipart_reply_state));
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            *len -= (sizeof(struct ofp_experimenter_stats_header));
            error = ofl_utils_count_ofp_state_stats(stat, *len, &dm->stats_num);
            if (error) {
                free(dm);
                return error;
            }
            dm->stats = (struct ofl_exp_state_stats **)malloc(dm->stats_num * sizeof(struct ofl_exp_state_stats *));

            ini_len = *len;
            ptr = buf + sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_experimenter_stats_header);
            for (i = 0; i < dm->stats_num; i++) {
                error = ofl_structs_state_stats_unpack(stat, ptr, len, &(dm->stats[i]), exp);
                ptr += ini_len - *len;
                ini_len = *len;
                if (error) {
                    free (dm);
                    return error;
                }
                stat = (struct ofp_exp_state_stats *)((uint8_t *)stat + ntohs(stat->length));
            }

            *msg = (struct ofl_msg_multipart_reply_header *)dm;
            return 0;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):
        {
            struct ofp_exp_global_state_stats *sm;
            struct ofl_exp_msg_multipart_reply_global_state *dm;

            if (*len < sizeof(struct ofp_exp_global_state_stats)) {
                OFL_LOG_WARN(LOG_MODULE, "Received GLOBAL STATE stats reply has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }
            *len -= sizeof(struct ofp_exp_global_state_stats);

            sm = (struct ofp_exp_global_state_stats *)os->body;
            dm = (struct ofl_exp_msg_multipart_reply_global_state *) malloc(sizeof(struct ofl_exp_msg_multipart_reply_global_state));
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            dm->global_state =  ntohl(sm->global_state);

            *msg = (struct ofl_msg_multipart_reply_header *)dm;
            return 0;
        }
        default:
            return -1;
    }
}

char *
ofl_exp_beba_stats_request_to_string(struct ofl_msg_multipart_request_experimenter const *ext, struct ofl_exp const *exp)
{
    struct ofl_exp_beba_msg_multipart_request const *e = (struct ofl_exp_beba_msg_multipart_request const *)ext;
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    switch (e->type){
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_request_state const *msg = (struct ofl_exp_msg_multipart_request_state const *)e;
            fprintf(stream, "{exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", table=\"");
            ofl_table_print(stream, msg->table_id);
            if(msg->get_from_state)
                fprintf(stream, "\", state=\"%u\"", msg->state);
            fprintf(stream, "\", match=");
            ofl_structs_match_print(stream, msg->match, exp);
            break;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):
        {
            fprintf(stream, "{stat_exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\"");
            break;
        }
    }
    fclose(stream);
    return str;
}

char *
ofl_exp_beba_stats_reply_to_string(struct ofl_msg_multipart_reply_experimenter const *ext, struct ofl_exp const *exp)
{
    struct ofl_exp_beba_msg_multipart_reply *e = (struct ofl_exp_beba_msg_multipart_reply *)ext;
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    switch (e->type){
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_state *msg = (struct ofl_exp_msg_multipart_reply_state *)e;
            size_t i;
            size_t last_table_id = -1;

            fprintf(stream, "{exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", stats=[");

            for (i=0; i<msg->stats_num; i++) {

                if(last_table_id != msg->stats[i]->table_id && ofl_colored_output())
                    fprintf(stream, "\n\n\x1B[33mTABLE = %d\x1B[0m\n\n",msg->stats[i]->table_id);
                last_table_id = msg->stats[i]->table_id;
                ofl_structs_state_stats_print(stream, msg->stats[i], exp);
                if (i < msg->stats_num - 1) {
                    if(ofl_colored_output())
                        fprintf(stream, ",\n\n");
                    else
                        fprintf(stream, ", "); };
            }
            if(ofl_colored_output())
                fprintf(stream, "\n\n");
            fprintf(stream, "]");
            break;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_global_state *msg = (struct ofl_exp_msg_multipart_reply_global_state *)e;

            char *bin_value = decimal_to_binary(msg->global_state);
            fprintf(stream, "{stat_exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", global_state=\"%s\"", bin_value);
            free(bin_value);
            break;
        }
    }
    fclose(stream);
    return str;
}

int
ofl_exp_beba_stats_req_free(struct ofl_msg_multipart_request_header *msg)
{
    struct ofl_msg_multipart_request_experimenter* exp = (struct ofl_msg_multipart_request_experimenter *) msg;
    struct ofl_exp_beba_msg_multipart_request *ext = (struct ofl_exp_beba_msg_multipart_request *)exp;
    switch (ext->type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_request_state *a = (struct ofl_exp_msg_multipart_request_state *) ext;
            ofl_structs_free_match(a->match,NULL);

            free(a);
            break;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_request_global_state *a = (struct ofl_exp_msg_multipart_request_global_state *) ext;
            free(a);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Beba Experimenter message.");
        }
    }
    return 0;
}

int
ofl_exp_beba_stats_reply_free(struct ofl_msg_multipart_reply_header *msg)
{
    struct ofl_msg_multipart_reply_experimenter* exp = (struct ofl_msg_multipart_reply_experimenter *) msg;
    struct ofl_exp_beba_msg_multipart_reply *ext = (struct ofl_exp_beba_msg_multipart_reply *)exp;
    int i;
    switch (ext->type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_state *a = (struct ofl_exp_msg_multipart_reply_state *) ext;
            for (i=0; i<a->stats_num; i++) {
                free(a->stats[i]);
            }
            free(a->stats);
            free(a);
            break;
        }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_global_state *a = (struct ofl_exp_msg_multipart_reply_global_state *) ext;
            free(a);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Beba Experimenter message.");
        }
    }
    return 0;
}

int
ofl_exp_beba_field_unpack(struct ofl_match *match, struct oxm_field const *f, void const *experimenter_id, void const *value, void const *mask)
{
    switch (f->index) {
        case OFI_OXM_EXP_STATE:{
            ofl_structs_match_exp_put32(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)));
            return 0;
        }
        case OFI_OXM_EXP_STATE_W:{
            ofl_structs_match_exp_put32m(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)));
            if (check_bad_wildcard32(ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)))){
                return ofp_mkerr(OFPET_EXPERIMENTER, OFPEC_BAD_MATCH_WILDCARD);
            }
            return 0;
        }
        case OFI_OXM_EXP_GLOBAL_STATE:{
            ofl_structs_match_exp_put32(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)));
            return 0;
        }
        case OFI_OXM_EXP_GLOBAL_STATE_W:{
            ofl_structs_match_exp_put32m(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)));
            if (check_bad_wildcard32(ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)))){
                return ofp_mkerr(OFPET_EXPERIMENTER, OFPEC_BAD_MATCH_WILDCARD);
            }
            return 0;
        }
        default:
            NOT_REACHED();
    }
}

void
ofl_exp_beba_field_pack(struct ofpbuf *buf, struct ofl_match_tlv const *oft)
{
    uint8_t length = OXM_LENGTH(oft->header);
    bool has_mask =false;

    length = length - EXP_ID_LEN;      /* field length should exclude experimenter_id */
    if (OXM_HASMASK(oft->header)){
        length = length / 2;
        has_mask = true;
    }
    switch (length){
        case (sizeof(uint8_t)):{
            uint32_t experimenter_id;
            uint8_t value;
            memcpy(&experimenter_id, oft->value, sizeof(uint32_t));
            memcpy(&value, oft->value + EXP_ID_LEN, sizeof(uint8_t));
            if(!has_mask)
                oxm_put_exp_8(buf,oft->header, htonl(experimenter_id), value);
            else {
                uint8_t mask;
                memcpy(&mask, oft->value + EXP_ID_LEN + length , sizeof(uint8_t));
                oxm_put_exp_8w(buf, oft->header, htonl(experimenter_id), value, mask);
            }
            break;
          }
        case (sizeof(uint16_t)):{
            uint32_t experimenter_id;
            uint16_t value;
            memcpy(&experimenter_id, oft->value, sizeof(uint32_t));
            memcpy(&value, oft->value + EXP_ID_LEN, sizeof(uint16_t));
            if(!has_mask)
                oxm_put_exp_16(buf,oft->header, htonl(experimenter_id), htons(value));
            else {
                uint16_t mask;
                memcpy(&mask, oft->value + EXP_ID_LEN + length , sizeof(uint16_t));
                oxm_put_exp_16w(buf, oft->header, htonl(experimenter_id), htons(value), htons(mask));
            }
            break;
        }
        case (sizeof(uint32_t)):{
            uint32_t experimenter_id, value;
            memcpy(&experimenter_id, oft->value, sizeof(uint32_t));
            memcpy(&value, oft->value + EXP_ID_LEN, sizeof(uint32_t));
            if(!has_mask)
                oxm_put_exp_32(buf,oft->header, htonl(experimenter_id), htonl(value));
            else {
                uint32_t mask;
                memcpy(&mask, oft->value + EXP_ID_LEN + length , sizeof(uint32_t));
                oxm_put_exp_32w(buf, oft->header, htonl(experimenter_id), htonl(value), htonl(mask));
            }
            break;
        }
        case (sizeof(uint64_t)):{
            uint32_t experimenter_id;
            uint64_t value;
            memcpy(&experimenter_id, oft->value, sizeof(uint32_t));
            memcpy(&value, oft->value + EXP_ID_LEN, sizeof(uint64_t));
            if(!has_mask)
                oxm_put_exp_64(buf,oft->header, htonl(experimenter_id), hton64(value));
            else {
                uint64_t mask;
                memcpy(&mask, oft->value + EXP_ID_LEN + length , sizeof(uint64_t));
                oxm_put_exp_64w(buf, oft->header, htonl(experimenter_id), hton64(value), hton64(mask));
            }
            break;
        }
    }
}

void
ofl_exp_beba_field_match(struct ofl_match_tlv *f, int *packet_header, int *field_len, uint8_t **flow_val, uint8_t **flow_mask)
{
    bool has_mask = OXM_HASMASK(f->header);
    (*field_len) = (OXM_LENGTH(f->header) - EXP_ID_LEN);
    *flow_val = f->value + EXP_ID_LEN;
    if (has_mask) {
        /* Clear the has_mask bit and divide the field_len by two in the packet field header */
        *field_len /= 2;
        (*packet_header) &= 0xfffffe00;
        (*packet_header) |= (*field_len) + EXP_ID_LEN;
        *flow_mask = f->value + EXP_ID_LEN + (*field_len);
    }
}

void
ofl_exp_beba_field_compare (struct ofl_match_tlv *packet_f, uint8_t **packet_val)
{
    *packet_val = packet_f->value + EXP_ID_LEN;
}

void
ofl_exp_beba_field_match_std (struct ofl_match_tlv *flow_mod_match, struct ofl_match_tlv *flow_entry_match UNUSED, int *field_len, uint8_t **flow_mod_val, uint8_t **flow_entry_val, uint8_t **flow_mod_mask, uint8_t **flow_entry_mask)
{
    bool has_mask = OXM_HASMASK(flow_mod_match->header);
    *field_len =  OXM_LENGTH(flow_mod_match->header) - EXP_ID_LEN;
    *flow_mod_val = ((*flow_mod_val) + EXP_ID_LEN);
    *flow_entry_val = ((*flow_entry_val) + EXP_ID_LEN);
    if (has_mask)
        {
            *field_len /= 2;
            *flow_mod_mask = ((*flow_mod_val) + (*field_len));
            *flow_entry_mask = ((*flow_entry_val) + (*field_len));
        }
}

void
ofl_exp_beba_field_overlap_a (struct ofl_match_tlv *f_a, int *field_len, uint8_t **val_a, uint8_t **mask_a, int *header, int *header_m, uint64_t *all_mask)
{
    *field_len = OXM_LENGTH(f_a->header) - EXP_ID_LEN;
    *val_a = f_a->value + EXP_ID_LEN;
    if (OXM_HASMASK(f_a->header)) {
        *field_len /= 2;
        *header = ((f_a->header & 0xfffffe00) | ((*field_len) + EXP_ID_LEN));
        *header_m = f_a->header;
        *mask_a = f_a->value + EXP_ID_LEN + (*field_len);
    } else {
        *header = f_a->header;
        *header_m = (f_a->header & 0xfffffe00) | 0x100 | (*field_len << 1);
        /* Set a dummy mask with all bits set to 0 (valid) */
        *mask_a = (uint8_t *) all_mask;
    }
}

void
ofl_exp_beba_field_overlap_b (struct ofl_match_tlv *f_b, int *field_len, uint8_t **val_b, uint8_t **mask_b, uint64_t *all_mask)
{
    *val_b = f_b->value + EXP_ID_LEN;
    if (OXM_HASMASK(f_b->header)) {
        *mask_b = f_b->value + EXP_ID_LEN + (*field_len);
    } else {
        /* Set a dummy mask with all bits set to 0 (valid) */
        *mask_b = (uint8_t *) all_mask;
    }
}

/*Experimenter error functions*/
void
ofl_exp_beba_error_pack (struct ofl_msg_exp_error const *msg, uint8_t **buf, size_t *buf_len)
{
    struct ofp_error_experimenter_msg *exp_err;
    *buf_len = sizeof(struct ofp_error_experimenter_msg) + msg->data_length;
    *buf     = (uint8_t *)malloc(*buf_len);

    exp_err = (struct ofp_error_experimenter_msg *)(*buf);
    exp_err->type = htons(msg->type);
    exp_err->exp_type = htons(msg->exp_type);
    exp_err->experimenter = htonl(msg->experimenter);
    memcpy(exp_err->data, msg->data, msg->data_length);
}

void
ofl_exp_beba_error_free (struct ofl_msg_exp_error *msg)
{
    free(msg->data);
    free(msg);
}

char *
ofl_exp_beba_error_to_string(struct ofl_msg_exp_error const *msg){
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    fprintf(stream, "{type=\"");
    ofl_error_type_print(stream, msg->type);
    fprintf(stream, "\", exp_type=\"");
    ofl_error_beba_exp_type_print(stream,  msg->exp_type);
    fprintf(stream, "\", dlen=\"%zu\"}", msg->data_length);
    fprintf(stream, "{id=\"0x%"PRIx32"\"}", msg->experimenter);
    fclose(stream);
    return str;
}

void
ofl_error_beba_exp_type_print(FILE *stream, uint16_t exp_type)
{
    switch (exp_type) {
        case (OFPEC_EXP_STATE_MOD_FAILED): {     fprintf(stream, "OFPEC_EXP_STATE_MOD_FAILED"); return; }
        case (OFPEC_EXP_STATE_MOD_BAD_COMMAND): {     fprintf(stream, "OFPEC_EXP_STATE_MOD_BAD_COMMAND"); return; }
        case (OFPEC_EXP_SET_EXTRACTOR): {        fprintf(stream, "OFPEC_EXP_SET_EXTRACTOR"); return; }
        case (OFPEC_EXP_SET_FLOW_STATE): {       fprintf(stream, "OFPEC_EXP_SET_FLOW_STATE"); return; }
        case (OFPEC_EXP_DEL_FLOW_STATE): {       fprintf(stream, "OFPEC_EXP_DEL_FLOW_STATE"); return; }
        case (OFPEC_BAD_EXP_MESSAGE): {          fprintf(stream, "OFPEC_BAD_EXP_MESSAGE"); return; }
        case (OFPEC_BAD_EXP_ACTION): {           fprintf(stream, "OFPEC_BAD_EXP_ACTION"); return; }
        case (OFPEC_BAD_EXP_LEN): {              fprintf(stream, "OFPEC_BAD_EXP_LEN"); return; }
        case (OFPEC_BAD_TABLE_ID): {             fprintf(stream, "OFPEC_BAD_TABLE_ID"); return; }
        case (OFPEC_BAD_MATCH_WILDCARD): {       fprintf(stream, "OFPEC_BAD_MATCH_WILDCARD"); return; }
        case (OFPET_BAD_EXP_INSTRUCTION): {       fprintf(stream, "OFPET_BAD_EXP_INSTRUCTION"); return; }
        case (OFPEC_EXP_PKTTMP_MOD_FAILED): {       fprintf(stream, "OFPEC_EXP_PKTTMP_MOD_FAILED"); return; }
        case (OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND): {       fprintf(stream, "OFPEC_EXP_PKTTMP_MOD_BAD_COMMAND"); return; }
        default: {                               fprintf(stream, "?(%u)", exp_type); return; }
    }
}

/* Instruction expertimenter callback implementation */
//TODO implement callbacks
int
ofl_exp_beba_inst_pack (struct ofl_instruction_header const *src, struct ofp_instruction *dst) {

    struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) src;
    struct ofl_exp_beba_instr_header *ext = (struct ofl_exp_beba_instr_header *) exp;

    switch (ext->instr_type) {
        case OFPIT_IN_SWITCH_PKT_GEN: {
            size_t total_len;
            size_t len;
            uint8_t *data;
            size_t i;

            struct ofl_exp_instruction_in_switch_pkt_gen *si = (struct ofl_exp_instruction_in_switch_pkt_gen *)src;
            struct ofp_exp_instruction_in_switch_pkt_gen *di = (struct ofp_exp_instruction_in_switch_pkt_gen *)dst;

            OFL_LOG_DBG(LOG_MODULE, "ofl_exp_beba_inst_pack OFPIT_IN_SWITCH_PKT_GEN");

            //TODO may need to pass callbacks instead of NULL
            total_len = sizeof(struct ofp_exp_instruction_in_switch_pkt_gen) + ofl_actions_ofp_total_len((struct ofl_action_header const **)si->actions, si->actions_num, NULL);

            di->header.header.type = htons(src->type); //OFPIT_EXPERIMENTER
            di->header.header.experimenter  = htonl(exp->experimenter_id); //BEBA_VENDOR_ID
            di->header.instr_type = htonl(ext->instr_type); //OFPIT_IN_SWITCH_PKT_GEN

            di->header.header.len = htons(total_len);
            memset(di->header.pad, 0x00, 4);

            di->pkttmp_id = htons(si->pkttmp_id);
            memset(di->header.pad, 0x00, 4);
            data = (uint8_t *)dst + sizeof(struct ofp_exp_instruction_in_switch_pkt_gen);

            for (i=0; i<si->actions_num; i++) {
                //TODO may need to pass callbacks instead of NULL
                len = ofl_actions_pack(si->actions[i], (struct ofp_action_header *)data, data, NULL);
                data += len;
            }
            return total_len;
        }
        default:
            OFL_LOG_WARN(LOG_MODULE, "Trying to pack unknown instruction type.");
            return 0;
    }
}

ofl_err
ofl_exp_beba_inst_unpack (struct ofp_instruction const *src, size_t *len, struct ofl_instruction_header **dst) {

    struct ofl_instruction_header *inst = NULL;
    size_t ilen;
    ofl_err error = 0;
    struct ofp_instruction_experimenter_header *exp;
    struct ofp_beba_instruction_experimenter_header *beba_exp;

    OFL_LOG_DBG(LOG_MODULE, "ofl_exp_beba_inst_unpack");

    if (*len < sizeof(struct ofp_instruction_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER instruction has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp = (struct ofp_instruction_experimenter_header *) src;

    if (*len < ntohs(exp->len)) {
        OFL_LOG_WARN(LOG_MODULE, "Received instruction has invalid length (set to %u, but only %zu received).", ntohs(exp->len), *len);
        return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
    ilen = ntohs(exp->len);

    beba_exp = (struct ofp_beba_instruction_experimenter_header *) exp;
    switch (ntohl(beba_exp->instr_type)) {
        case OFPIT_IN_SWITCH_PKT_GEN: {
            struct ofp_exp_instruction_in_switch_pkt_gen *si;
            struct ofl_exp_instruction_in_switch_pkt_gen *di;
            struct ofp_action_header *act;
            size_t i;

            di = (struct ofl_exp_instruction_in_switch_pkt_gen *)malloc(sizeof(struct ofl_exp_instruction_in_switch_pkt_gen));
            di->header.header.experimenter_id  = ntohl(exp->experimenter); //BEBA_VENDOR_ID
            inst = (struct ofl_instruction_header *)di;

            if (ilen < sizeof(struct ofp_exp_instruction_in_switch_pkt_gen)) {
                OFL_LOG_WARN(LOG_MODULE, "Received IN_SWITCH_PKT_GEN instruction has invalid length (%zu).", *len);
                error = ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
            }

            ilen -= sizeof(struct ofp_exp_instruction_in_switch_pkt_gen);

            si = (struct ofp_exp_instruction_in_switch_pkt_gen *)src;

            di->header.instr_type = ntohl(beba_exp->instr_type); //OFPIT_IN_SWITCH_PKT_GEN
            di->pkttmp_id = ntohl(si->pkttmp_id);

            error = ofl_utils_count_ofp_actions((uint8_t *)si->actions, ilen, &di->actions_num);
            if (error) {
                break;
            }
            di->actions = (struct ofl_action_header **)malloc(di->actions_num * sizeof(struct ofl_action_header *));

            act = si->actions;
            for (i = 0; i < di->actions_num; i++) {
                // TODO We may need to pass the ofl_exp callbacks instead of NULL
                //error = ofl_actions_unpack(act, &ilen, &(di->actions[i]), exp);
                error = ofl_actions_unpack(act, &ilen, &(di->actions[i]), NULL);
                if (error) {
                    break;
                }
                act = (struct ofp_action_header *)((uint8_t *)act + ntohs(act->len));
            }

            break;
        }
        default: {
            struct ofl_instruction_experimenter *di;
            di = (struct ofl_instruction_experimenter *)malloc(sizeof(struct ofl_instruction_experimenter));
            di->experimenter_id  = ntohl(exp->experimenter); //BEBA_VENDOR_ID
            inst = (struct ofl_instruction_header *)di;
            OFL_LOG_WARN(LOG_MODULE, "The received BEBA instruction type (%u) is invalid.", ntohs(beba_exp->instr_type));
            error = ofl_error(OFPET_EXPERIMENTER, OFPET_BAD_EXP_INSTRUCTION);
            break;
        }
    }

    (*dst) = inst;

    if (!error && ilen != 0) {
        *len = *len - ntohs(src->len) + ilen;
        OFL_LOG_WARN(LOG_MODULE, "The received instruction contained extra bytes (%zu).", ilen);
        ofl_exp_beba_inst_free(inst);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    *len -= ntohs(src->len);
    return error;
}

int
ofl_exp_beba_inst_free (struct ofl_instruction_header *i) {
    struct ofl_instruction_experimenter* exp = (struct ofl_instruction_experimenter *) i;
    struct ofl_exp_beba_instr_header *ext = (struct ofl_exp_beba_instr_header *)exp;
    struct ofl_exp_instruction_in_switch_pkt_gen *instr;
    switch (ext->instr_type) {
        case (OFPIT_IN_SWITCH_PKT_GEN):
        {
            OFL_LOG_DBG(LOG_MODULE, "Freeing BEBA instruction IN_SWITCH_PKT_GEN.");
            instr = (struct ofl_exp_instruction_in_switch_pkt_gen *)ext;
            // TODO We may need to use OFL_UTILS_FREE_ARR_FUN2 and pass the ofl_exp callbacks instead of NULL
            OFL_UTILS_FREE_ARR_FUN2(instr->actions, instr->actions_num,
                                ofl_actions_free, NULL);
            free(instr);
            OFL_LOG_DBG(LOG_MODULE, "Done.");
            return 0;
            break;
        }
        default:
        {
            OFL_LOG_WARN(LOG_MODULE, "Unknown BEBA instruction type. Perhaps not freed correctly");
        }
    }
    free(i);
    return 1;
}

size_t
ofl_exp_beba_inst_ofp_len (struct ofl_instruction_header const *i) {
    struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) i;

    struct ofl_exp_beba_instr_header *ext = (struct ofl_exp_beba_instr_header *)exp;
    switch (ext->instr_type) {
        case OFPIT_IN_SWITCH_PKT_GEN: {
            struct ofl_exp_instruction_in_switch_pkt_gen *i = (struct ofl_exp_instruction_in_switch_pkt_gen *)ext;
            OFL_LOG_DBG(LOG_MODULE, "ofl_exp_beba_inst_ofp_len");
            // TODO We may need to pass the ofl_exp callbacks instead of NULL
//              return sizeof(struct ofl_exp_beba_instr_header)
//                      + ofl_actions_ofp_total_len(i->actions, i->actions_num, exp);
            return sizeof(struct ofp_exp_instruction_in_switch_pkt_gen)
                    + ofl_actions_ofp_total_len((struct ofl_action_header const **)i->actions, i->actions_num, NULL);
        }
        default:
            OFL_LOG_WARN(LOG_MODULE, "Trying to len unknown BEBA instruction type.");
            return 0;
    }
}

char *
ofl_exp_beba_inst_to_string (struct ofl_instruction_header const *i)
{
    struct ofl_instruction_experimenter *exp = (struct ofl_instruction_experimenter *) i;

    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    struct ofl_exp_beba_instr_header *ext = (struct ofl_exp_beba_instr_header *)exp;
    switch (ext->instr_type) {
        case (OFPIT_IN_SWITCH_PKT_GEN): {
            OFL_LOG_DBG(LOG_MODULE, "Trying to print BEBA Experimenter instruction. Not implemented yet!");
            fprintf(stream, "OFPIT{type=\"%u\"}", ext->instr_type);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown BEBA Experimenter instruction.");
            fprintf(stream, "OFPIT{type=\"%u\"}", ext->instr_type);
        }
    }

    fclose(stream);
    return str;

}

/*experimenter table functions*/

struct state_table * state_table_create(void)
{
    struct state_table *table = malloc(sizeof(struct state_table));
    memset(table, 0, sizeof(*table));

    table->state_entries = (struct hmap) HMAP_INITIALIZER(&table->state_entries);

    table->default_state_entry.state = STATE_DEFAULT;
    table->default_state_entry.stats = xmalloc(sizeof(struct ofl_exp_state_stats));
    memset(table->default_state_entry.stats, 0, sizeof(struct ofl_exp_state_stats));
    // table_id,field_count and fields will be set during lookup-scope configuration
    table->default_state_entry.stats->entry.state = STATE_DEFAULT;

    table->null_state_entry.state = STATE_NULL;
    //TODO Davide should we zero-set all the other fields (stats, etc..)?

    table->last_lookup_state_entry = NULL;
    table->update_scope_is_eq_lookup_scope = false;
    table->bit_update_scope_is_eq_lookup_scope = false;

    table->stateful = 0;

    return table;
}

bool state_table_is_enabled(struct state_table *table)
{
    return table->stateful
           && table->lookup_key_extractor.field_count != 0
           && table->update_key_extractor.field_count != 0;
}

ofl_err state_table_configure_stateful(struct state_table *table, uint8_t stateful)
{
    if (stateful!=0)
        table->stateful = 1;
    else
        table->stateful = 0;

    return 0;
}

void state_table_destroy(struct state_table *table)
{
    struct state_entry *entry, *next;

    HMAP_FOR_EACH_SAFE(entry, next, struct state_entry, hmap_node, &table->state_entries){
        hmap_remove(&table->state_entries, &entry->hmap_node);
        free(entry->stats);
        free(entry);
    }
    free(table->default_state_entry.stats);
    hmap_destroy(&table->state_entries);
    free(table);
}
/* having the key extractor field goes to look for these key inside the packet and map to corresponding value and copy the value into buf. */
int __extract_key(uint8_t *buf, struct key_extractor *extractor, struct packet *pkt)
{
    int i;
    uint32_t extracted_key_len=0;
    struct ofl_match_tlv *f;

    for (i=0; i<extractor->field_count; i++) {
        uint32_t type = (int)extractor->fields[i];
        HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
            hmap_node, hash_int(type, 0), &pkt->handle_std.match.match_fields){
                if (type == f->header) {
                    memcpy(&buf[extracted_key_len], f->value, OXM_LENGTH(f->header));
                    extracted_key_len += OXM_LENGTH(f->header);
                    break;
                }
        }
    }
    /* check if the full key has been extracted: if key is extracted partially or not at all, we cannot access the state table */
    return extracted_key_len == extractor->key_len;
}

static bool
state_entry_apply_idle_timeout(struct state_entry *entry, uint64_t now_us)
{
    if (entry->stats->idle_timeout != 0) {
        if (now_us > entry->last_used + entry->stats->idle_timeout) {
            entry->state = entry->stats->idle_rollback;
            entry->created = now_us;
            entry->stats->idle_timeout = 0;
            entry->stats->hard_timeout = 0;
            entry->stats->idle_rollback = 0;
            entry->stats->hard_rollback = 0;
            return true;
        }
    }
    return false;
}

static bool
state_entry_apply_hard_timeout(struct state_entry *entry, uint64_t now_us)
{
    if (entry->stats->hard_timeout != 0) {
        if (now_us > entry->remove_at) {
            entry->state = entry->stats->hard_rollback;
            entry->created = now_us;
            entry->stats->idle_timeout = 0;
            entry->stats->hard_timeout = 0;
            entry->stats->idle_rollback = 0;
            entry->stats->hard_rollback = 0;
            return true;
        }
    }
    return false;
}

void
state_table_flush(struct state_table *table, uint64_t now_us)
{
    struct state_entry *entry, *next;
    HMAP_FOR_EACH_SAFE(entry, next, struct state_entry, hmap_node, &table->state_entries){
        state_entry_apply_hard_timeout(entry, now_us);
        state_entry_apply_idle_timeout(entry, now_us);
        if (entry->state == STATE_DEFAULT && entry->stats->hard_timeout == 0 && entry->stats->idle_timeout == 0){
            hmap_remove(&table->state_entries, &entry->hmap_node);
            free(entry->stats);
            free(entry);
        }
    }
}

/*having the read_key, look for the state value inside the state_table */
struct state_entry * state_table_lookup(struct state_table* table, struct packet *pkt)
{
    struct state_entry * e = NULL;
    uint8_t key[MAX_STATE_KEY_LEN] = {0};
    uint64_t now_us;

    if(!__extract_key(key, &table->lookup_key_extractor, pkt))
    {
        OFL_LOG_DBG(LOG_MODULE, "lookup key fields not found in the packet's header -> STATE_NULL");
        return &table->null_state_entry;
    }

    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry,
        hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
                OFL_LOG_DBG(LOG_MODULE, "state entry FOUND: %u",e->state);

                now_us = 1000000 * pkt->ts.tv_sec + pkt->ts.tv_usec;

                state_entry_apply_hard_timeout(e, now_us);
                state_entry_apply_idle_timeout(e, now_us);

                e->last_used = now_us;

                // cache the last state entry to avoid re-extracting it if two scopes are the same
                table->last_lookup_state_entry = e;

                return e;
            }
    }

    table->last_lookup_state_entry = NULL;

    OFL_LOG_DBG(LOG_MODULE, "state entry NOT FOUND, returning DEFAULT");
    return &table->default_state_entry;
}

void state_table_write_state_header(struct state_entry *entry, struct ofl_match_tlv *f) {
    uint32_t *state = (uint32_t *) (f->value + EXP_ID_LEN);
    *state = entry->state;
}

ofl_err state_table_del_state(struct state_table *table, uint8_t *key, uint32_t len) {
    struct state_entry *e;
    uint8_t found = 0;
    struct key_extractor *extractor = &table->update_key_extractor;

    if (extractor->key_len != len) {
        OFL_LOG_WARN(LOG_MODULE, "key extractor length != received key length");
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry,
        hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
                hmap_remove_and_shrink(&table->state_entries, &e->hmap_node);
                free(e->stats);
                free(e);
                found = 1;
                break;
            }
    }

    if (!found){
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_DEL_FLOW_STATE);
    }

    return 0;
}

bool extractors_are_equal(struct key_extractor *ke1, struct key_extractor *ke2)
{
    int i;

    if (ke1->key_len != ke2->key_len){
        return false;
    }

    for (i = 0; i < ke1->field_count; i++) {
        if (ke1->fields[i] != ke2->fields[i]) {
            return false;
        }
    }

    return true;
}

ofl_err state_table_set_extractor(struct state_table *table, struct key_extractor *ke, int update)
{
    struct key_extractor *dest;
    uint32_t key_len = 0;

    int i;
    for (i = 0; i < ke->field_count; i++) {
        key_len += OXM_LENGTH((int) ke->fields[i]);
    }

    if (key_len == 0) {
        OFL_LOG_WARN(LOG_MODULE, "Can't set extractor for a 0 length key\n");
        return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
    }

    if (update) {
        // Setting the update scope.

        // Ensure conformity with the length of a previously configured scope
        if (table->lookup_key_extractor.key_len != 0
            && table->lookup_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Update-scope should provide same length keys of lookup-scope: %d vs %d\n",
                         key_len, table->lookup_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        if (ke->bit == 0 && table->bit_update_key_extractor.key_len != 0
            && table->bit_update_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Update-scope should provide same length keys of bit-update-scope: %d vs %d\n",
                         key_len, table->bit_update_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        if (ke->bit == 1 && table->update_key_extractor.key_len != 0
            && table->update_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Bit-update-scope should provide same length keys of update-scope: %d vs %d\n",
                         key_len, table->update_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        // Select the right write key
        if (ke->bit == 0) {
            // Update the normal key extractor
            dest = &table->update_key_extractor;
            OFL_LOG_DBG(LOG_MODULE, "Update-scope set");
        } else {
            // Update the "bit" key extractor
            dest = &table->bit_update_key_extractor;
            OFL_LOG_DBG(LOG_MODULE, "Bit Update-scope set");
        }
    } else {
        // Setting the lookup scope.

        // Ensure conformity with the length of a previously configured scope
        if (table->update_key_extractor.key_len != 0
            && table->update_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Lookup-scope should provide same length keys of update-scope: %d vs %d\n",
                         key_len, table->update_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        if (table->bit_update_key_extractor.key_len != 0
            && table->bit_update_key_extractor.key_len != key_len) {
            OFL_LOG_WARN(LOG_MODULE, "Lookup-scope should provide same length keys of bit-update-scope: %d vs %d\n",
                         key_len, table->bit_update_key_extractor.key_len);
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        dest = &table->lookup_key_extractor;
        OFL_LOG_DBG(LOG_MODULE, "Lookup-scope set");

        table->default_state_entry.stats->table_id = ke->table_id;
        table->default_state_entry.stats->field_count = ke->field_count;
        memcpy(table->default_state_entry.stats->fields, ke->fields, sizeof(uint32_t) * ke->field_count);
    }
    dest->table_id = ke->table_id;
    dest->field_count = ke->field_count;
    dest->key_len = key_len;
    memcpy(dest->fields, ke->fields, sizeof(uint32_t) * ke->field_count);

    if (extractors_are_equal(&table->lookup_key_extractor,&table->update_key_extractor)){
        table->update_scope_is_eq_lookup_scope = true;
    }

    if (extractors_are_equal(&table->lookup_key_extractor,&table->bit_update_key_extractor)){
        table->bit_update_scope_is_eq_lookup_scope = true;
    }

    return 0;
}

ofl_err state_table_set_state(struct state_table *table, struct packet *pkt,
                           struct ofl_exp_set_flow_state *msg, struct ofl_exp_action_set_state *act,
                           struct ofl_exp_msg_notify_state_change *ntf_message)
{
    uint8_t key[MAX_STATE_KEY_LEN] = {0};
    struct state_entry *e;
    uint32_t state, state_mask,
            idle_rollback, hard_rollback,
            idle_timeout, hard_timeout,
            old_state, new_state;
    uint64_t now_us;
    ofl_err res = 0;
    bool entry_found = 0;
    bool entry_created = 0;
    bool entry_to_update_is_cached = act && table->last_lookup_state_entry != NULL &&
            ((act->bit == 0 && table->update_scope_is_eq_lookup_scope) ||
                    (act->bit == 1 && table->bit_update_scope_is_eq_lookup_scope));

    if (act) {
        //SET_STATE action
        struct key_extractor *key_extractor_ptr;

        now_us = 1000000 * pkt->ts.tv_sec + pkt->ts.tv_usec;
        state = act->state;
        state_mask = act->state_mask;
        idle_rollback = act->idle_rollback;
        hard_rollback = act->hard_rollback;
        idle_timeout = act->idle_timeout;
        hard_timeout = act->hard_timeout;

        // Bi-flow handling.
        // FIXME: rename 'bit' to something more meaningful.
        key_extractor_ptr = (act->bit == 0) ? &table->update_key_extractor : &table->bit_update_key_extractor;

        //Extract the key (we avoid to re-extract it if bit-update/update-scope == lookup-scope and the cached entry is not the default)
        if (!entry_to_update_is_cached) {
            if (!__extract_key(key, key_extractor_ptr, pkt)) {
                OFL_LOG_DBG(LOG_MODULE, "update key fields not found in the packet's header");
                return res;
            }
        }

    } else {
        //SET_STATE message - should we check if msg != null?
        struct timeval tv;

        gettimeofday(&tv,NULL);
        now_us = 1000000 * tv.tv_sec + tv.tv_usec;
        state = msg->state;
        state_mask = msg->state_mask;
        idle_rollback = msg->idle_rollback;
        hard_rollback = msg->hard_rollback;
        idle_timeout = msg->idle_timeout;
        hard_timeout = msg->hard_timeout;

        if (table->update_key_extractor.key_len != msg->key_len) {
            OFL_LOG_WARN(LOG_MODULE, "update key extractor length != received key length");
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_BAD_EXP_LEN);
        }

        memcpy(key, msg->key, msg->key_len);
    }

    /*
    Look if state entry already exists in hash map.
    We avoid browsing again the hash map if bit-update/update-scope == lookup-scope, but only if
    a. we are not going to insert a new state entry (otherwise the cached state entry would be the DEFAULT one!)
    b. we are not executing a transition by a ctrl msg (there's no state lookup phase so there's no cached state entry)
    */
    if (entry_to_update_is_cached) {
        e = table->last_lookup_state_entry;
        OFL_LOG_DBG(LOG_MODULE, "cached state entry FOUND in hash map");
        entry_found = 1;
    } else {
        HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, hmap_node,
                                hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries)
        {
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)) {
                OFL_LOG_DBG(LOG_MODULE, "state entry FOUND in hash map");
                entry_found = 1;
                break;
            }
        }
    }

    if (entry_found) {
        new_state = (e->state & ~(state_mask)) | (state & state_mask);
        old_state = e->state;
    } else {
        // Key not found in hash map.
        new_state = state & state_mask;
        old_state = STATE_DEFAULT;

        // Allocate memory only if new state is not DEFAULT or there's a timeout that will transition it to other value.
        if (new_state != STATE_DEFAULT
            || (hard_timeout > 0 && hard_rollback != STATE_DEFAULT)
            || (idle_timeout > 0 && idle_rollback != STATE_DEFAULT))
        {
            entry_created = 1;
            e = xmalloc(sizeof(struct state_entry));
            memset(e,0,sizeof(struct state_entry));
            e->stats = xmalloc(sizeof(struct ofl_exp_state_stats));
            memset(e->stats,0,sizeof(struct ofl_exp_state_stats));
            memcpy(e->key, key, MAX_STATE_KEY_LEN);
            hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
            OFL_LOG_DBG(LOG_MODULE, "state entry CREATED is hash map");
        }
    }

    if (entry_found || entry_created) {

        OFL_LOG_DBG(LOG_MODULE, "executing state transition to %u", new_state);

        e->state = new_state;

        // FIXME: renaming created to last_updated would be more appropriate.
        e->created = now_us;

        // Update timeouts, only if rollback state != current state
        if (hard_timeout > 0 && hard_rollback != new_state) {
            OFL_LOG_DBG(LOG_MODULE, "configuring hard_timeout = %u", hard_timeout);
            e->remove_at = now_us + hard_timeout;
            e->stats->hard_timeout = hard_timeout;
            e->stats->hard_rollback = hard_rollback;
        } else {
            e->stats->hard_timeout = 0;
            e->stats->hard_rollback = 0;
        }

        if (idle_timeout > 0 && idle_rollback != new_state) {
            OFL_LOG_DBG(LOG_MODULE, "configuring idle_timeout = %u", idle_timeout);
            e->stats->idle_timeout = idle_timeout;
            e->stats->idle_rollback = idle_rollback;
            e->last_used = now_us;
        } else {
            e->stats->idle_timeout = 0;
            e->stats->idle_rollback = 0;
        }

        // all the statistics except timeouts and rollbacks are updated on request

        #if BEBA_STATE_NOTIFICATIONS != 0
        *ntf_message = (struct ofl_exp_msg_notify_state_change)
                {{{{.type = OFPT_EXPERIMENTER},
                        .experimenter_id = BEBA_VENDOR_ID},
                        .type = OFPT_EXP_STATE_CHANGED},
                        .table_id = e->stats->table_id,
                        .old_state = old_state,
                        .new_state = new_state,
                        .state_mask = state_mask,
                        .key_len = OFPSC_MAX_KEY_LEN,
                        .key = {}};
        memcpy(ntf_message->key, e->key, ntf_message->key_len);
        #endif
    }

    return res;
}

ofl_err state_table_inc_state(struct state_table *table, struct packet *pkt){

    uint8_t key[MAX_STATE_KEY_LEN] = {0};
    struct state_entry *e;
    uint64_t now_us;
    ofl_err res = 0;
    bool entry_to_update_is_cached = table->update_scope_is_eq_lookup_scope && table->last_lookup_state_entry != NULL;

    //Extract the key (we avoid to re-extract it if update-scope == lookup-scope)
    if (!entry_to_update_is_cached) {
        if (!__extract_key(key, &table->update_key_extractor, pkt)) {
            OFL_LOG_DBG(LOG_MODULE, "update key fields not found in the packet's header");
            return res;
        }

        HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, hmap_node,
                                hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries)
        {
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)) {
                e->state += (uint32_t) 1;
                return 0;
            }
        }
    } else {
        e = table->last_lookup_state_entry;
        e->state += (uint32_t) 1;
        return 0;
    }

    now_us = 1000000 * pkt->ts.tv_sec + pkt->ts.tv_usec;
    e = xmalloc(sizeof(struct state_entry));
    e->created = now_us;
    e->stats = xmalloc(sizeof(struct ofl_exp_state_stats));
    e->stats->idle_timeout = 0;
    e->stats->hard_timeout = 0;
    e->stats->idle_rollback = 0;
    e->stats->hard_rollback = 0;
    e->state = (uint32_t) 1; // Initial condition
    memcpy(e->key, key, MAX_STATE_KEY_LEN);
    hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
    return 0;
}

/*
 * State Sync: One extra argument (i.e., ntf_message) is passed to this function to notify about
 * a state change in the state table.
 */
ofl_err
handle_state_mod(struct pipeline *pl, struct ofl_exp_msg_state_mod *msg,
                const struct sender *sender UNUSED, struct ofl_exp_msg_notify_state_change * ntf_message) {
    switch (msg->command){
        case OFPSC_STATEFUL_TABLE_CONFIG:{
            struct ofl_exp_stateful_table_config *p = (struct ofl_exp_stateful_table_config *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            return state_table_configure_stateful(st, p->stateful);
            break;}

        case OFPSC_EXP_SET_L_EXTRACTOR:
        case OFPSC_EXP_SET_U_EXTRACTOR:{
            struct ofl_exp_set_extractor *p = (struct ofl_exp_set_extractor *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            if (st->stateful){
                int update = 0;
                if (msg->command == OFPSC_EXP_SET_U_EXTRACTOR)
                    update = 1;
                return state_table_set_extractor(st, (struct key_extractor *)p, update);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD: cannot configure extractor (stage %u is not stateful)", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_SET_EXTRACTOR);
            }
            break;}

        case OFPSC_EXP_SET_FLOW_STATE:{
            struct ofl_exp_set_flow_state *p = (struct ofl_exp_set_flow_state *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            // State Sync: Now state_table_set_state function contains this extra parameter related to the
            // state notification.
            if (state_table_is_enabled(st)){
                return state_table_set_state(st, NULL, p, NULL, ntf_message);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful or not configured", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_SET_FLOW_STATE);
            }
            break;}

        case OFPSC_EXP_DEL_FLOW_STATE:{
            struct ofl_exp_del_flow_state *p = (struct ofl_exp_del_flow_state *) msg->payload;
            struct state_table *st = pl->tables[p->table_id]->state_table;
            if (state_table_is_enabled(st)){
                return state_table_del_state(st, p->key, p->key_len);
            }
            else{
                OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful or not configured", p->table_id);
                return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_DEL_FLOW_STATE);
            }
            break;}

        case OFPSC_EXP_SET_GLOBAL_STATE:{
            uint32_t global_state = pl->dp->global_state;
            struct ofl_exp_set_global_state *p = (struct ofl_exp_set_global_state *) msg->payload;
            global_state = (global_state & ~(p->global_state_mask)) | (p->global_state & p->global_state_mask);
            pl->dp->global_state = global_state;
            return 0;
            break;}

        case OFPSC_EXP_RESET_GLOBAL_STATE:{
            pl->dp->global_state = OFP_GLOBAL_STATE_DEFAULT;
            return 0;
            break;}

        default:
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_STATE_MOD_FAILED);
    }
    return 0;
}

ofl_err
handle_pkttmp_mod(struct pipeline *pl, struct ofl_exp_msg_pkttmp_mod *msg,
                                                const struct sender *sender UNUSED) {
    OFL_LOG_DBG(LOG_MODULE, "Handling PKTTMP_MOD");
    /* TODO: complete handling of creating and deleting pkttmp entry */
    switch (msg->command){
        case OFPSC_ADD_PKTTMP:{
            struct ofl_exp_add_pkttmp *p = (struct ofl_exp_add_pkttmp *) msg->payload;
            struct pkttmp_entry *e;
            e = pkttmp_entry_create(pl->dp, pl->dp->pkttmps, p);

            hmap_insert(&pl->dp->pkttmps->entries, &e->node, e->pkttmp_id);
            OFL_LOG_DBG(LOG_MODULE, "PKTTMP id is %d, inserted to hash map", e->pkttmp_id);
            break;}

        default:
            return ofl_error(OFPET_EXPERIMENTER, OFPEC_EXP_PKTTMP_MOD_FAILED);
    }
    return 0;
}

ofl_err
handle_stats_request_state(struct pipeline *pl, struct ofl_exp_msg_multipart_request_state *msg, const struct sender *sender UNUSED, struct ofl_exp_msg_multipart_reply_state *reply) {
    struct ofl_exp_state_stats **stats = xmalloc(sizeof(struct ofl_exp_state_stats *));
    size_t stats_size = 1;
    size_t stats_num = 0;
    if (msg->table_id == 0xff) {
        size_t i;
        for (i=0; i<PIPELINE_TABLES; i++) {
            if (state_table_is_enabled(pl->tables[i]->state_table))
                state_table_stats(pl->tables[i]->state_table, msg, &stats, &stats_size, &stats_num, i, msg->header.type == OFPMP_EXP_STATE_STATS_AND_DELETE);
        }
    } else {
        if (state_table_is_enabled(pl->tables[msg->table_id]->state_table))
            state_table_stats(pl->tables[msg->table_id]->state_table, msg, &stats, &stats_size, &stats_num, msg->table_id, msg->header.type == OFPMP_EXP_STATE_STATS_AND_DELETE);
    }
    *reply = (struct ofl_exp_msg_multipart_reply_state)
            {{{{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_EXPERIMENTER, .flags = 0x0000},
             .experimenter_id = BEBA_VENDOR_ID},
             .type = msg->header.type},
             .stats = stats,
             .stats_num = stats_num};
    return 0;
}

ofl_err
handle_stats_request_global_state(struct pipeline *pl, const struct sender *sender UNUSED, struct ofl_exp_msg_multipart_reply_global_state *reply) {
    uint32_t global_state = pl->dp->global_state;

    *reply = (struct ofl_exp_msg_multipart_reply_global_state)
            {{{{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_EXPERIMENTER, .flags = 0x0000},
             .experimenter_id = BEBA_VENDOR_ID},
             .type = OFPMP_EXP_GLOBAL_STATE_STATS},
             .global_state = global_state};
    return 0;
}

void
state_table_stats(struct state_table *table, struct ofl_exp_msg_multipart_request_state *msg,
                 struct ofl_exp_state_stats ***stats, size_t *stats_size, size_t *stats_num, uint8_t table_id, bool delete_entries)
{
    struct state_entry *entry, *next;
    size_t  i;
    uint32_t fields[MAX_EXTRACTION_FIELD_COUNT] = {0};
    struct timeval tv;
    gettimeofday(&tv,NULL);
    uint64_t now_us = 1000000 * tv.tv_sec + tv.tv_usec;
    struct key_extractor *extractor=&table->lookup_key_extractor;

    struct ofl_match const * a = (struct ofl_match const *)msg->match;
    struct ofl_match_tlv *state_key_match;
    uint8_t count = 0;
    uint8_t found = 0;
    uint8_t len = 0;
    uint8_t aux = 0;

    uint8_t offset[MAX_EXTRACTION_FIELD_COUNT] = {0};
    uint8_t length[MAX_EXTRACTION_FIELD_COUNT] = {0};


    for (i=0; i<extractor->field_count; i++) {
        fields[i] = (int)extractor->fields[i];
     }

    //for each received match_field we must verify if it can be found in the key extractor and (if yes) save its position in the key (offset) and its length
    HMAP_FOR_EACH(state_key_match, struct ofl_match_tlv, hmap_node, &a->match_fields)
    {
        len = 0;
        found = 0;
        for (i=0;i<extractor->field_count;i++)
        {
                if(OXM_TYPE(state_key_match->header)==OXM_TYPE(fields[i]))
                {
                    offset[count] = len;
                    length[count] = OXM_LENGTH(fields[i]);
                    count++;
                    found = 1;
                    break;
                }
                len += OXM_LENGTH(fields[i]);
        }
        if(!found)
            return; //If at least one of the received match_field is not found in the key extractor, the function returns an empty list of entries
    }

    //for each state entry
    HMAP_FOR_EACH_SAFE(entry, next, struct state_entry, hmap_node, &table->state_entries) {
        if(entry == NULL)
            break;

        //for each received match_field compare the received value with the state entry's key
        aux = 0;
        found = 1;
        HMAP_FOR_EACH(state_key_match, struct ofl_match_tlv, hmap_node, &a->match_fields)
        {
            if(memcmp(state_key_match->value,&entry->key[offset[aux]], length[aux]))
                found = 0;
            aux+=1;
        }

        state_entry_apply_hard_timeout(entry, now_us);
        state_entry_apply_idle_timeout(entry, now_us);

        if(found && ((msg->get_from_state && msg->state == entry->state) || (!msg->get_from_state)))
        {
            if ((*stats_size) == (*stats_num)) {
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_exp_state_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
            }

            // entry->stats are referenced by the reply message, NOT copied
            (*stats)[(*stats_num)] = entry->stats;
            (*stats)[(*stats_num)]->table_id = table_id;
            (*stats)[(*stats_num)]->duration_sec = (now_us - entry->created) / 1000000;
            (*stats)[(*stats_num)]->duration_nsec = ((now_us - entry->created) % 1000000) * 1000;
            (*stats)[(*stats_num)]->field_count = extractor->field_count;
            memcpy((*stats)[(*stats_num)]->fields, extractor->fields, sizeof(uint32_t) * extractor->field_count);
            // timeouts and rollbacks have been already set
            (*stats)[(*stats_num)]->entry.state = entry->state;
            memcpy((*stats)[(*stats_num)]->entry.key, entry->key, extractor->key_len);
            (*stats)[(*stats_num)]->entry.key_len = extractor->key_len;
            
            (*stats_num)++;

            if (delete_entries){
                // state_entries are removed from hmap but entry->stats are freed only after reply msg has been sent
                // because the reply message contains references to entry->stats!
                hmap_remove_and_shrink(&table->state_entries, &entry->hmap_node);
                free(entry);
            }
        }

    }

     /*DEFAULT ENTRY*/
    if(!msg->get_from_state || (msg->get_from_state && msg->state == STATE_DEFAULT))
    {
        if ((*stats_size) == (*stats_num)) {
            (*stats) = xrealloc(*stats, (sizeof(struct ofl_exp_state_stats *)) * (*stats_size) * 2);
            *stats_size *= 2;
        }
        (*stats)[(*stats_num)] = table->default_state_entry.stats;
        (*stats_num)++;
    }
}

size_t
ofl_structs_state_stats_ofp_len(struct ofl_exp_state_stats *stats UNUSED, struct ofl_exp const *exp UNUSED)
{
    return ROUND_UP((sizeof(struct ofp_exp_state_stats)),8);
}

size_t
ofl_structs_state_stats_ofp_total_len(struct ofl_exp_state_stats ** stats UNUSED, size_t stats_num, struct ofl_exp const *exp UNUSED)
{
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN2(sum, stats, stats_num,
            ofl_structs_state_stats_ofp_len, exp);
    return sum;
}

size_t
ofl_structs_state_stats_pack(struct ofl_exp_state_stats const *src, uint8_t *dst, struct ofl_exp const *exp UNUSED)
{
    struct ofp_exp_state_stats *state_stats;
    size_t total_len;
    size_t  i;
    total_len = ROUND_UP(sizeof(struct ofp_exp_state_stats),8);
    state_stats = (struct ofp_exp_state_stats*) dst;
    memset(state_stats, 0, sizeof(struct ofp_exp_state_stats));
    state_stats->length = htons(total_len);
    state_stats->table_id = src->table_id;
    state_stats->duration_sec = htonl(src->duration_sec);
    state_stats->duration_nsec = htonl(src->duration_nsec);

    state_stats->pad = 0;
    state_stats->field_count = htonl(src->field_count);

    for (i=0;i<src->field_count;i++)
           state_stats->fields[i]=htonl(src->fields[i]);
    state_stats->entry.key_len = htonl(src->entry.key_len);
    memcpy(state_stats->entry.key, src->entry.key, src->entry.key_len);
    state_stats->entry.state = htonl(src->entry.state);
    state_stats->idle_timeout = htonl(src->idle_timeout);
    state_stats->idle_rollback = htonl(src->idle_rollback);
    state_stats->hard_timeout = htonl(src->hard_timeout);
    state_stats->hard_rollback = htonl(src->hard_rollback);
    return total_len;
}

void
ofl_structs_state_entry_print(FILE *stream, uint32_t field, uint8_t *key, uint8_t *offset)
{

    switch (OXM_FIELD(field)) {

        case OFPXMT_OFB_IN_PORT:
            fprintf(stream, "in_port=\"%d\"", *((uint32_t*) key));
            break;
        case OFPXMT_OFB_IN_PHY_PORT:
            fprintf(stream, "in_phy_port=\"%d\"", *((uint32_t*) key));
            break;
        case OFPXMT_OFB_VLAN_VID: {
            uint16_t v = *((uint16_t *) key);
            fprintf(stream, "vlan_vid=\"%d\"",v & VLAN_VID_MASK);
            break;
        }
        case OFPXMT_OFB_VLAN_PCP:
            fprintf(stream, "vlan_pcp=\"%d\"", *key & 0x7);
            break;
        case OFPXMT_OFB_METADATA: {
            fprintf(stream, "metadata=\"0x%"PRIx64"\"", *((uint64_t*) key));
            break;
        }
        case OFPXMT_OFB_ETH_TYPE:
            fprintf(stream, "eth_type=\"0x%x\"",  *((uint16_t *) key));
            break;
        case OFPXMT_OFB_TCP_SRC:
            fprintf(stream, "tcp_src=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_TCP_DST:
            fprintf(stream, "tcp_dst=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_TCP_FLAGS:
            fprintf(stream,"tcp_flags=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_UDP_SRC:
            fprintf(stream, "udp_src=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_UDP_DST:
            fprintf(stream, "udp_dst=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_SCTP_SRC:
            fprintf(stream, "sctp_src=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_SCTP_DST:
            fprintf(stream, "sctp_dst=\"%d\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_ETH_SRC:
            fprintf(stream, "eth_src=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_ETH_DST:
            fprintf(stream, "eth_dst=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_IPV4_DST:
            fprintf(stream, "ipv4_dst=\""IP_FMT"\"", IP_ARGS(key));
            break;
        case OFPXMT_OFB_IPV4_SRC:
            fprintf(stream, "ipv4_src=\""IP_FMT"\"", IP_ARGS(key));
            break;
        case OFPXMT_OFB_IP_PROTO:
            fprintf(stream, "ip_proto=\"%d\"", *key);
            break;
        case OFPXMT_OFB_IP_DSCP:
            fprintf(stream, "ip_dscp=\"%d\"", *key & 0x3f);
            break;
        case OFPXMT_OFB_IP_ECN:
            fprintf(stream, "ip_ecn=\"%d\"", *key & 0x3);
            break;
        case OFPXMT_OFB_ICMPV4_TYPE:
            fprintf(stream, "icmpv4_type= \"%d\"", *key);
            break;
        case OFPXMT_OFB_ICMPV4_CODE:
            fprintf(stream, "icmpv4_code=\"%d\"", *key);
            break;
        case OFPXMT_OFB_ARP_SHA:
            fprintf(stream, "arp_sha=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_ARP_THA:
            fprintf(stream, "arp_tha=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_ARP_SPA:
            fprintf(stream, "arp_spa=\""IP_FMT"\"", IP_ARGS(key));
            break;
        case OFPXMT_OFB_ARP_TPA:
            fprintf(stream, "arp_tpa=\""IP_FMT"\"", IP_ARGS(key));
            break;
        case OFPXMT_OFB_ARP_OP:
            fprintf(stream, "arp_op=\"0x%x\"", *((uint16_t*) key));
            break;
        case OFPXMT_OFB_IPV6_SRC: {
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, key, addr_str, INET6_ADDRSTRLEN);
            fprintf(stream, "nw_src_ipv6=\"%s\"", addr_str);
            break;
        }
        case OFPXMT_OFB_IPV6_DST: {
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, key, addr_str, INET6_ADDRSTRLEN);
            fprintf(stream, "nw_dst_ipv6=\"%s\"", addr_str);
            break;
        }
        case OFPXMT_OFB_IPV6_ND_TARGET: {
            char addr_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, key, addr_str, INET6_ADDRSTRLEN);
            fprintf(stream, "ipv6_nd_target=\"%s\"", addr_str);
            break;
        }
        case OFPXMT_OFB_IPV6_ND_SLL:
            fprintf(stream, "ipv6_nd_sll=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_IPV6_ND_TLL:
            fprintf(stream, "ipv6_nd_tll=\""ETH_ADDR_FMT"\"", ETH_ADDR_ARGS(key));
            break;
        case OFPXMT_OFB_IPV6_FLABEL:
            fprintf(stream, "ipv6_flow_label=\"%d\"", *((uint32_t*) key) & 0x000fffff);
            break;
        case OFPXMT_OFB_ICMPV6_TYPE:
            fprintf(stream, "icmpv6_type=\"%d\"", *key);
            break;
        case OFPXMT_OFB_ICMPV6_CODE:
            fprintf(stream, "icmpv6_code=\"%d\"", *key);
            break;
        case OFPXMT_OFB_MPLS_LABEL:
            fprintf(stream, "mpls_label=\"%d\"",((uint32_t) *key) & 0x000fffff);
            break;
        case OFPXMT_OFB_MPLS_TC:
            fprintf(stream, "mpls_tc=\"%d\"", *key & 0x3);
            break;
        case OFPXMT_OFB_MPLS_BOS:
            fprintf(stream, "mpls_bos=\"%d\"", *key & 0x1);
            break;
        case OFPXMT_OFB_PBB_ISID   :
            fprintf(stream, "pbb_isid=\"%d\"", *((uint32_t*) key));
            break;
        case OFPXMT_OFB_TUNNEL_ID:
            fprintf(stream, "tunnel_id=\"%"PRIu64"\"", *((uint64_t*) key));
            break;
        case OFPXMT_OFB_IPV6_EXTHDR:
            fprintf(stream, "ext_hdr=\"");
            ofl_ipv6_ext_hdr_print(stream, *((uint16_t*) key));
            fprintf(stream, "\"");
            break;
        default:
            fprintf(stream, "unknown type %d", field);
    }
    *offset += OXM_LENGTH(field);
}

void
ofl_structs_state_entry_print_default(FILE *stream, uint32_t field)
{

    switch (OXM_FIELD(field)) {

        case OFPXMT_OFB_IN_PORT:
            fprintf(stream, "in_port=\"*\"");
            break;
        case OFPXMT_OFB_IN_PHY_PORT:
            fprintf(stream, "in_phy_port=\"*\"");
            break;
        case OFPXMT_OFB_VLAN_VID:
            fprintf(stream, "vlan_vid=\"*\"");
            break;
        case OFPXMT_OFB_VLAN_PCP:
            fprintf(stream, "vlan_pcp=\"*\"");
            break;
        case OFPXMT_OFB_METADATA:
            fprintf(stream, "metadata=\"*\"");
            break;
        case OFPXMT_OFB_ETH_TYPE:
            fprintf(stream, "eth_type=\"*\"");
            break;
        case OFPXMT_OFB_TCP_SRC:
            fprintf(stream, "tcp_src=\"*\"");
            break;
        case OFPXMT_OFB_TCP_DST:
            fprintf(stream, "tcp_dst=\"*\"");
            break;
        case OFPXMT_OFB_TCP_FLAGS:
            fprintf(stream,"tcp_flags=\"*\"");
            break;
        case OFPXMT_OFB_UDP_SRC:
            fprintf(stream, "udp_src=\"*\"");
            break;
        case OFPXMT_OFB_UDP_DST:
            fprintf(stream, "udp_dst=\"*\"");
            break;
        case OFPXMT_OFB_SCTP_SRC:
            fprintf(stream, "sctp_src=\"*\"");
            break;
        case OFPXMT_OFB_SCTP_DST:
            fprintf(stream, "sctp_dst=\"*\"");
            break;
        case OFPXMT_OFB_ETH_SRC:
            fprintf(stream, "eth_src=\"*\"");
            break;
        case OFPXMT_OFB_ETH_DST:
            fprintf(stream, "eth_dst=\"*\"");
            break;
        case OFPXMT_OFB_IPV4_DST:
            fprintf(stream, "ipv4_dst=\"*\"");
            break;
        case OFPXMT_OFB_IPV4_SRC:
            fprintf(stream, "ipv4_src=\"*\"");
            break;
        case OFPXMT_OFB_IP_PROTO:
            fprintf(stream, "ip_proto=\"*\"");
            break;
        case OFPXMT_OFB_IP_DSCP:
            fprintf(stream, "ip_dscp=\"*\"");
            break;
        case OFPXMT_OFB_IP_ECN:
            fprintf(stream, "ip_ecn=\"*\"");
            break;
        case OFPXMT_OFB_ICMPV4_TYPE:
            fprintf(stream, "icmpv4_type= \"*\"");
            break;
        case OFPXMT_OFB_ICMPV4_CODE:
            fprintf(stream, "icmpv4_code=\"*\"");
            break;
        case OFPXMT_OFB_ARP_SHA:
            fprintf(stream, "arp_sha=\"*\"");
            break;
        case OFPXMT_OFB_ARP_THA:
            fprintf(stream, "arp_tha=\"*\"");
            break;
        case OFPXMT_OFB_ARP_SPA:
            fprintf(stream, "arp_spa=\"*\"");
            break;
        case OFPXMT_OFB_ARP_TPA:
            fprintf(stream, "arp_tpa=\"*\"");
            break;
        case OFPXMT_OFB_ARP_OP:
            fprintf(stream, "arp_op=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_SRC:
            fprintf(stream, "nw_src_ipv6=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_DST:
            fprintf(stream, "nw_dst_ipv6=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_ND_TARGET:
            fprintf(stream, "ipv6_nd_target=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_ND_SLL:
            fprintf(stream, "ipv6_nd_sll=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_ND_TLL:
            fprintf(stream, "ipv6_nd_tll=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_FLABEL:
            fprintf(stream, "ipv6_flow_label=\"*\"");
            break;
        case OFPXMT_OFB_ICMPV6_TYPE:
            fprintf(stream, "icmpv6_type=\"*\"");
            break;
        case OFPXMT_OFB_ICMPV6_CODE:
            fprintf(stream, "icmpv6_code=\"*\"");
            break;
        case OFPXMT_OFB_MPLS_LABEL:
            fprintf(stream, "mpls_label=\"*\"");
            break;
        case OFPXMT_OFB_MPLS_TC:
            fprintf(stream, "mpls_tc=\"*\"");
            break;
        case OFPXMT_OFB_MPLS_BOS:
            fprintf(stream, "mpls_bos=\"*\"");
            break;
        case OFPXMT_OFB_PBB_ISID   :
            fprintf(stream, "pbb_isid=\"*\"");
            break;
        case OFPXMT_OFB_TUNNEL_ID:
            fprintf(stream, "tunnel_id=\"*\"");
            break;
        case OFPXMT_OFB_IPV6_EXTHDR:
            fprintf(stream, "ext_hdr=\"*\"");
            fprintf(stream, "\"");
            break;
        default:
            fprintf(stream, "unknown type %d", field);
    }
}

void
ofl_structs_state_stats_print(FILE *stream, struct ofl_exp_state_stats *s, struct ofl_exp const *exp UNUSED)
{
    size_t i;
    uint8_t offset=0;
    if(ofl_colored_output())
    {
        fprintf(stream, "{\x1B[31mtable\x1B[0m=\"");
        ofl_table_print(stream, s->table_id);
        fprintf(stream, "\", \x1B[31mkey\x1B[0m={");

        for(i=0;i<s->field_count;i++)
        {
            if(s->entry.key_len==0)
                ofl_structs_state_entry_print_default(stream,s->fields[i]);
            else
                ofl_structs_state_entry_print(stream,s->fields[i], s->entry.key+offset, &offset);
            if (s->field_count!=1 && i<s->field_count-1)
                fprintf(stream, ", ");
        }
        fprintf(stream, "}, \x1B[31mstate\x1B[0m=\"");
        fprintf(stream, "%"PRIu32"\"", s->entry.state);
        if(s->entry.key_len!=0)
            fprintf(stream, ", dur_s=\"%u\", dur_ns=\"%09u\", idle_to=\"%u\", idle_rb=\"%u\", hard_to=\"%u\", hard_rb=\"%u\"",s->duration_sec, s->duration_nsec, s->idle_timeout, s->idle_rollback, s->hard_timeout, s->hard_rollback);
    }

    else
    {
        fprintf(stream, "{table=\"");
        ofl_table_print(stream, s->table_id);
        fprintf(stream, "\", key={");

        for(i=0;i<s->field_count;i++)
        {
            if(s->entry.key_len==0)
                ofl_structs_state_entry_print_default(stream,s->fields[i]);
            else
                ofl_structs_state_entry_print(stream,s->fields[i], s->entry.key+offset, &offset);
            if (s->field_count!=1 && i<s->field_count-1)
                fprintf(stream, ", ");
        }
        fprintf(stream, "}, state=\"");
        fprintf(stream, "%"PRIu32"\"", s->entry.state);
        if(s->entry.key_len!=0)
            fprintf(stream, ", dur_s=\"%u\", dur_ns=\"%09u\", idle_to=\"%u\", idle_rb=\"%u\", hard_to=\"%u\", hard_rb=\"%u\"",s->duration_sec, s->duration_nsec, s->idle_timeout, s->idle_rollback, s->hard_timeout, s->hard_rollback);
    }

    fprintf(stream, "}");
}

ofl_err
ofl_structs_state_stats_unpack(struct ofp_exp_state_stats const *src, uint8_t const *buf UNUSED, size_t *len, struct ofl_exp_state_stats **dst, struct ofl_exp const *exp UNUSED)
{
    struct ofl_exp_state_stats *s;
    size_t slen;
    size_t i;
    if (*len < sizeof(struct ofp_exp_state_stats) ) {
        OFL_LOG_WARN(LOG_MODULE, "Received state stats has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received state stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (src->table_id >= PIPELINE_TABLES) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(src->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received state stats has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }

    slen = ntohs(src->length) - sizeof(struct ofp_exp_state_stats);

    s = (struct ofl_exp_state_stats *)malloc(sizeof(struct ofl_exp_state_stats));
    s->table_id =  src->table_id;
    s->duration_sec = ntohl(src->duration_sec);
    s->duration_nsec = ntohl(src->duration_nsec);
    s->field_count = ntohl(src->field_count);
    for (i=0;i<s->field_count;i++)
               s->fields[i]=ntohl(src->fields[i]);

    s->entry.key_len = ntohl(src->entry.key_len);
    for (i=0;i<s->entry.key_len;i++)
               s->entry.key[i]=src->entry.key[i];
    s->entry.state = ntohl(src->entry.state);

    s->idle_timeout = ntohl(src->idle_timeout);
    s->idle_rollback = ntohl(src->idle_rollback);
    s->hard_timeout = ntohl(src->hard_timeout);
    s->hard_rollback = ntohl(src->hard_rollback);

    if (slen != 0) {
        *len = *len - ntohs(src->length) + slen;
        OFL_LOG_WARN(LOG_MODULE, "The received state stats contained extra bytes (%zu).", slen);
        free(s);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    *len -= ntohs(src->length);
    *dst = s;
    return 0;
}

ofl_err
ofl_utils_count_ofp_state_stats(void *data, size_t data_len, size_t *count)
{
    struct ofp_exp_state_stats *stat;
    uint8_t *d;

    d = (uint8_t *)data;
    *count = 0;
    while (data_len >= sizeof(struct ofp_exp_state_stats)) {
        stat = (struct ofp_exp_state_stats *)d;
        if (data_len < ntohs(stat->length) || ntohs(stat->length) < sizeof(struct ofp_exp_state_stats)) {
            OFL_LOG_WARN(LOG_MODULE, "Received state stat has invalid length.");
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
        }
        data_len -= ntohs(stat->length);
        d += ntohs(stat->length);
        (*count)++;
    }

    return 0;
}

void
ofl_exp_stats_type_print(FILE *stream, uint32_t type)
{
    switch (type) {
        case (OFPMP_EXP_STATE_STATS_AND_DELETE):
        case (OFPMP_EXP_STATE_STATS):          { fprintf(stream, "state"); return; }
        case (OFPMP_EXP_GLOBAL_STATE_STATS):          { fprintf(stream, "global_state"); return; }
        default: {                    fprintf(stream, "?(%u)", type); return; }
    }
}


/*Functions used by experimenter match fields*/

struct ofl_match_tlv *
ofl_structs_match_exp_put8(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint8_t value)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put8m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint8_t value, uint8_t mask)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + sizeof(mask) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    memcpy(m->value + EXP_ID_LEN + sizeof(value), &mask, sizeof(mask));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + sizeof(mask) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put16(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint16_t value)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put16m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint16_t value, uint16_t mask)
{
	struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value)+sizeof(mask) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    memcpy(m->value + EXP_ID_LEN + sizeof(value), &mask, sizeof(mask));
    hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + sizeof(mask) + 4;
    return m;
}

// TODO: functions like ofl_structs_match_exp_put32 are not related to BEBA, move somewhere else.
struct ofl_match_tlv *
ofl_structs_match_exp_put32(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint32_t value)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put32m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint32_t value, uint32_t mask)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + sizeof(mask) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    memcpy(m->value + EXP_ID_LEN + sizeof(value), &mask, sizeof(mask));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + sizeof(mask) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put64(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint64_t value)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + 4;
    return m;
}

struct ofl_match_tlv *
ofl_structs_match_exp_put64m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint64_t value, uint64_t mask)
{
    struct ofl_match_tlv *m = ofl_alloc_match_tlv(match, sizeof(value) + sizeof(mask) + EXP_ID_LEN);
    m->header = header;
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, sizeof(value));
    memcpy(m->value + EXP_ID_LEN + sizeof(value), &mask, sizeof(mask));
    hmap_insert(&match->match_fields, &m->hmap_node, hash_int(header, 0));
    match->header.length += EXP_ID_LEN + sizeof(value) + sizeof(mask) + 4;
    return m;
}

/*Functions used by experimenter errors*/

uint32_t
get_experimenter_id(struct ofl_msg_header const *msg)
{
    uint32_t exp_id;
    exp_id = BEBA_VENDOR_ID;
    /*check if the msg that triggers the err is experimenter*/
    if (msg->type == OFPT_EXPERIMENTER){
        exp_id = ((struct ofl_msg_experimenter *) msg)->experimenter_id;
    }
    /*if not, the error is triggered by an experimenter match/action*/
    else if(msg->type == OFPT_FLOW_MOD) {
        struct ofl_msg_flow_mod *flow_mod = (struct ofl_msg_flow_mod *)msg;
        struct ofl_match_header *flow_mod_match = flow_mod->match;
        exp_id = get_experimenter_id_from_match((struct ofl_match*)flow_mod_match);
        if(!exp_id){
            int i;
            for(i=0; i<flow_mod->instructions_num; i++){
                struct ofl_instruction_header *inst = flow_mod->instructions[i];
                switch(inst->type) {
                    case (OFPIT_WRITE_ACTIONS):
                    case (OFPIT_APPLY_ACTIONS): {
                        struct ofl_instruction_actions *act = (struct ofl_instruction_actions *)inst;
                        exp_id = get_experimenter_id_from_action(act);
                        break;
                    }
                    case (OFPIT_EXPERIMENTER): {
                        struct ofl_instruction_experimenter *exp_inst = (struct ofl_instruction_experimenter *) inst;
                        exp_id = exp_inst -> experimenter_id;
                        break;
                    }
                    case (OFPIT_CLEAR_ACTIONS):
                    case (OFPIT_GOTO_TABLE):
                    case (OFPIT_WRITE_METADATA):
                    case (OFPIT_METER):
            OFL_LOG_WARN(LOG_MODULE, "Get experimenter id: unexpected instruction!");
                }
            }
        }
    }
    return exp_id;
}

uint32_t
get_experimenter_id_from_match(struct ofl_match const *flow_mod_match)
{
    struct ofl_match_tlv *f;
    HMAP_FOR_EACH(f, struct ofl_match_tlv, hmap_node, &flow_mod_match->match_fields){
        switch (OXM_VENDOR(f->header))
        {
            case(OFPXMC_EXPERIMENTER):
                return *((uint32_t*) (f->value));
        }

    }
    return 0;
}

uint32_t
get_experimenter_id_from_action(struct ofl_instruction_actions const *act)
{
    int j;
    for(j=0; j<act->actions_num; j++) {
        struct ofl_action_header *action = act->actions[j];
        if (action->type == OFPAT_EXPERIMENTER) {
           return ((struct ofl_action_experimenter *)action)->experimenter_id;
        }
    }
    return 0;
}

/*Functions used by INsP experimenter instruction*/
struct pkttmp_table *
pkttmp_table_create(struct datapath *dp) {
    struct pkttmp_table *table;
    //size_t i;

    OFL_LOG_DBG(LOG_MODULE, "Creating PKTTMP TABLE.");

    table = xmalloc(sizeof(struct pkttmp_table));
    table->dp = dp;

    table->entries_num = 0;
    hmap_init(&table->entries);

    return table;
}

void
pkttmp_table_destroy(struct pkttmp_table *table) {
    struct pkttmp_entry *entry, *next;

    HMAP_FOR_EACH_SAFE(entry, next, struct pkttmp_entry, node, &table->entries) {
        pkttmp_entry_destroy(entry);
    }

    free(table);
}

struct pkttmp_entry *
pkttmp_entry_create(struct datapath *dp, struct pkttmp_table *table, struct ofl_exp_add_pkttmp *mod) {
    struct pkttmp_entry *e;
    //size_t i;
    uint64_t now_ms;
    now_ms = time_msec();

    e = xmalloc(sizeof(struct pkttmp_entry));
    e->created = now_ms;
    e->dp = dp;
    e->table = table;
    e->pkttmp_id = mod->pkttmp_id;
    e->data = NULL;
    e->data_length = mod->data_length;
    if (e->data_length > 0) {
        e->data = xmalloc(e->data_length);
        memcpy(e->data, mod->data, e->data_length);
    }
    //e->data = mod->data_length > 0 ? (uint8_t *)memcpy(malloc(mod->data_length), mod->data, mod->data_length) : NULL;


    OFL_LOG_DBG(LOG_MODULE, "Creating PKTTMP entry with following values id %u, data_len %zu.",e->pkttmp_id, e->data_length);

    return e;
}

void
pkttmp_entry_destroy(struct pkttmp_entry *entry) {
    free(entry->data);
    free(entry);
}
