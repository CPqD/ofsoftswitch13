#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "openflow/openflow.h"
#include "openflow/openstate-ext.h"
#include "ofl-exp-openstate.h"
#include "oflib/ofl-log.h"
#include "oflib/ofl-print.h"
#include "oflib/ofl-utils.h"
#include "oflib/ofl-structs.h" 
#include "oflib/oxm-match.h"
#include "lib/hash.h"
#include "lib/ofp.h"
#include "timeval.h"


#define LOG_MODULE ofl_exp_os
OFL_LOG_INIT(LOG_MODULE)



/* functions used by ofp_exp_msg_state_mod*/
static ofl_err
ofl_structs_stateful_table_config_unpack(struct ofp_exp_stateful_table_config *src, size_t *len, struct ofl_exp_stateful_table_config *dst) {
    int i;
    if(*len == sizeof(struct ofp_exp_stateful_table_config))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%zu).", src->table_id );
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
        } 
        dst->table_id = src->table_id;
        dst->stateful = src->stateful;
    }
    else
    { 
       OFL_LOG_WARN(LOG_MODULE, "Received state mod stateful_table is too short (%zu).", *len);
       return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    *len -= sizeof(struct ofp_exp_stateful_table_config);
 
    return 0;
}

static ofl_err
ofl_structs_extraction_unpack(struct ofp_exp_set_extractor *src, size_t *len, struct ofl_exp_set_extractor *dst) {
    int i;
    if(*len == ((1+ntohl(src->field_count))*sizeof(uint32_t) + 4*sizeof(uint8_t)) && (ntohl(src->field_count)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%zu).", src->table_id );
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
        } 
        dst->table_id = src->table_id;
        dst->field_count=ntohl(src->field_count);
        for (i=0;i<dst->field_count;i++)
        {
            dst->fields[i]=ntohl(src->fields[i]);
        }
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod extraction is too short (%zu).", *len);       
       return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    *len -= (((1+ntohl(src->field_count))*sizeof(uint32_t)) + 4*sizeof(uint8_t));
 
    return 0;
}

static ofl_err
ofl_structs_set_flow_state_unpack(struct ofp_exp_set_flow_state *src, size_t *len, struct ofl_exp_set_flow_state *dst) {
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};
    
    if((*len == ((7*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t))) + 4*sizeof(uint8_t)) && (ntohl(src->key_len)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%zu).", src->table_id );
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
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
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod set_flow is too short (%zu).", *len);
       return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    *len -= ((7*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t)) + 4*sizeof(uint8_t));
    
    return 0;
}

static ofl_err
ofl_structs_del_flow_state_unpack(struct ofp_exp_del_flow_state *src, size_t *len, struct ofl_exp_del_flow_state *dst) {
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if((*len == ((sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t))) + 4*sizeof(uint8_t)) && (ntohl(src->key_len)>0))
    {
        if (src->table_id >= PIPELINE_TABLES) {
            OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%zu).", src->table_id );
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
        } 
        dst->table_id = src->table_id;
        dst->key_len=ntohl(src->key_len);
        for (i=0;i<dst->key_len;i++)
            key[i]=src->key[i];
        memcpy(dst->key, key, dst->key_len);
        OFL_LOG_WARN(LOG_MODULE, "key count is %d\n",dst->key_len);
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod del_flow is too short (%zu).", *len);
       return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
 
    *len -= ((sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t)) + 4*sizeof(uint8_t));
 
    return 0;
}

static ofl_err
ofl_structs_set_global_state_unpack(struct ofp_exp_set_global_state *src, size_t *len, struct ofl_exp_set_global_state *dst) {

    if (*len == 2*sizeof(uint32_t)) {
        dst->flag = ntohl(src->flag);
        dst->flag_mask = ntohl(src->flag_mask);
    }
    else {
        OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD set global state has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }
    
    *len -= sizeof(struct ofp_exp_set_global_state);

    return 0;
}

int
ofl_exp_openstate_msg_pack(struct ofl_msg_experimenter *msg, uint8_t **buf, size_t *buf_len) {
    if (msg->experimenter_id == OPENSTATE_VENDOR_ID) {
        struct ofl_exp_openstate_msg_header *exp = (struct ofl_exp_openstate_msg_header *)msg;
        switch (exp->type) {
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Openstate Experimenter message.");
                return -1;
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-Openstate Experimenter message.");
        return -1;
    }
}

ofl_err
ofl_exp_openstate_msg_unpack(struct ofp_header *oh, size_t *len, struct ofl_msg_experimenter **msg) {
    
    ofl_err error;
    struct ofp_experimenter_header *exp_header;

    if (*len < sizeof(struct ofp_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER message has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    exp_header = (struct ofp_experimenter_header *)oh;


    if (ntohl(exp_header->experimenter) == OPENSTATE_VENDOR_ID) {

        switch (ntohl(exp_header->exp_type)) {
            case (OFPT_EXP_STATE_MOD): 
            {
                struct ofp_exp_msg_state_mod *sm;
                struct ofl_exp_msg_state_mod *dm;
                
                if (*len < sizeof(struct ofp_experimenter_header) + 2*sizeof(uint8_t)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }

                *len -= sizeof(struct ofp_experimenter_header);

                sm = (struct ofp_exp_msg_state_mod *)exp_header;
                dm = (struct ofl_exp_msg_state_mod *)malloc(sizeof(struct ofl_exp_msg_state_mod));

                dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
                dm->header.type                   = ntohl(exp_header->exp_type);
                dm->command = (enum ofp_exp_msg_state_mod_commands)sm->command;
                
                *len -= 2*sizeof(uint8_t);

                if (dm->command == OFPSC_STATEFUL_TABLE_CONFIG){
                error = ofl_structs_stateful_table_config_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                }

                else if (dm->command == OFPSC_SET_L_EXTRACTOR || dm->command == OFPSC_SET_U_EXTRACTOR){
                error = ofl_structs_extraction_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                }

                else if (dm->command == OFPSC_SET_FLOW_STATE){
                error = ofl_structs_set_flow_state_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                } 

                else if (dm->command == OFPSC_DEL_FLOW_STATE){
                error = ofl_structs_del_flow_state_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                }                 

                else if (dm->command == OFPSC_SET_GLOBAL_STATE){
                error = ofl_structs_set_global_state_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                }

                else if (dm->command == OFPSC_RESET_GLOBAL_STATE){
                // payload is empty
                }


                (*msg) = (struct ofl_msg_experimenter *)dm;
                return 0;
            }

            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Openstate Experimenter message.");
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to unpack non-Openstate Experimenter message.");
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
    }
    free(msg);
    return 0;
}

int
ofl_exp_openstate_msg_free(struct ofl_msg_experimenter *msg) {
    if (msg->experimenter_id == OPENSTATE_VENDOR_ID) {
        struct ofl_exp_openstate_msg_header *exp = (struct ofl_exp_openstate_msg_header *)msg;
        switch (exp->type) {
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Openstate Experimenter message.");
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to free non-Openstate Experimenter message.");
    }
    free(msg);
    return 0;
}

char *
ofl_exp_openstate_msg_to_string(struct ofl_msg_experimenter *msg) {
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

    if (msg->experimenter_id == OPENSTATE_VENDOR_ID) {
        struct ofl_exp_openstate_msg_header *exp = (struct ofl_exp_openstate_msg_header *)msg;
        switch (exp->type) {
            default: {
                OFL_LOG_WARN(LOG_MODULE, "Trying to print unknown Openstate Experimenter message.");
                fprintf(stream, "ofexp{type=\"%u\"}", exp->type);
            }
        }
    } else {
        OFL_LOG_WARN(LOG_MODULE, "Trying to print non-Openstate Experimenter message.");
        fprintf(stream, "exp{exp_id=\"%u\"}", msg->experimenter_id);
    }

    fclose(stream);
    return str;
}

/*experimenter action functions*/

ofl_err
ofl_exp_openstate_act_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst) {

    if (*len < sizeof(struct ofp_action_experimenter_header)) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    struct ofp_action_experimenter_header *exp;
    exp = (struct ofp_action_experimenter_header *)src;

    if (ntohl(exp->experimenter) == OPENSTATE_VENDOR_ID) {
        struct ofp_openstate_action_experimenter_header *ext;
        ext = (struct ofp_openstate_action_experimenter_header *)exp;

        switch (ntohl(ext->act_type)) {
            case (OFPAT_EXP_SET_STATE): 
            {
                struct ofp_exp_action_set_state *sa;
                struct ofl_exp_action_set_state *da;
                if (*len < sizeof(struct ofp_exp_action_set_state)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received SET STATE action has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
                }
                sa = (struct ofp_exp_action_set_state *)ext;
                da = (struct ofl_exp_action_set_state *)malloc(sizeof(struct ofl_exp_action_set_state));


                if (sa->table_id >= PIPELINE_TABLES) {
                    if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
                        char *ts = ofl_table_to_string(sa->table_id);
                        OFL_LOG_WARN(LOG_MODULE, "Received SET STATE action has invalid table_id (%s).", ts);
                        free(ts);
                    }
                    free(da);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
                }

                da->header.header.experimenter_id = ntohl(exp->experimenter);
                da->header.act_type = ntohl(ext->act_type);
                da->state = ntohl(sa->state);
                da->state_mask = ntohl(sa->state_mask);
                da->table_id = sa->table_id;
                da->hard_rollback = ntohl(sa->hard_rollback);
                da->idle_rollback = ntohl(sa->idle_rollback);
                da->hard_timeout = ntohl(sa->hard_timeout);
                da->idle_timeout = ntohl(sa->idle_timeout);

                *dst = (struct ofl_action_header *)da;
                *len -= sizeof(struct ofp_exp_action_set_state);
                break; 
            }

            case (OFPAT_EXP_SET_FLAG): 
            {
                struct ofp_exp_action_set_flag *sa;
                struct ofl_exp_action_set_flag *da;
                if (*len < sizeof(struct ofp_exp_action_set_flag)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received SET FLAG action has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_ACTION, OFPBRC_BAD_LEN);
                }
                sa = (struct ofp_exp_action_set_flag*)ext;
                da = (struct ofl_exp_action_set_flag *)malloc(sizeof(struct ofl_exp_action_set_flag));

                da->header.header.experimenter_id = ntohl(exp->experimenter);
                da->header.act_type = ntohl(ext->act_type);
                da->flag = ntohl(sa->flag);
                da->flag_mask = ntohl(sa->flag_mask);

                *dst = (struct ofl_action_header *)da;
                *len -= sizeof(struct ofp_exp_action_set_flag);
                break; 
            }

            default: 
            {
                OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown Openstate Experimenter action.");
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
            }
        }
    }
    return 0;
}

int 
ofl_exp_openstate_act_pack(struct ofl_action_header *src, struct ofp_action_header *dst){
    
    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) src;
    
    if (exp->experimenter_id == OPENSTATE_VENDOR_ID) {
        struct ofl_exp_openstate_act_header *ext = (struct ofl_exp_openstate_act_header *)exp;
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

                return sizeof(struct ofp_exp_action_set_state);
            }
            case (OFPAT_EXP_SET_FLAG): 
            {
                struct ofl_exp_action_set_flag *sa = (struct ofl_exp_action_set_flag *) ext;
                struct ofp_exp_action_set_flag *da = (struct ofp_exp_action_set_flag *) dst;

                da->header.header.experimenter = htonl(exp->experimenter_id);
                da->header.act_type = htonl(ext->act_type);
                memset(da->header.pad, 0x00, 4);
                da->flag = htonl(sa->flag);
                da->flag_mask = htonl(sa->flag_mask);
                dst->len = htons(sizeof(struct ofp_exp_action_set_flag));

                return sizeof(struct ofp_exp_action_set_flag);
            }
            default:
                return 0;
        }
    }
}

size_t
ofl_exp_openstate_act_ofp_len(struct ofl_action_header *act)
{
    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) act;
    if (exp->experimenter_id == OPENSTATE_VENDOR_ID) {
        struct ofl_exp_openstate_act_header *ext = (struct ofl_exp_openstate_act_header *)exp;
        switch (ext->act_type) {

            case (OFPAT_EXP_SET_STATE):
                return sizeof(struct ofp_exp_action_set_state);

            case (OFPAT_EXP_SET_FLAG):
                return sizeof(struct ofp_exp_action_set_flag);

            default:
                return 0;
        }
    }
}

char *
ofl_exp_openstate_act_to_string(struct ofl_action_header *act)
{
    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) act;
    
    if (exp->experimenter_id == OPENSTATE_VENDOR_ID) {
        struct ofl_exp_openstate_act_header *ext = (struct ofl_exp_openstate_act_header *)exp;
        switch (ext->act_type) {
            case (OFPAT_EXP_SET_STATE):
            {
                struct ofl_exp_action_set_state *a = (struct ofl_exp_action_set_state *)ext;
                char *string = malloc(200);
                sprintf(string, "{set_state=[state=\"%u\",state_mask=\"%"PRIu32"\",table_id=\"%u\",idle_to=\"%u\",hard_to=\"%u\",idle_rb=\"%u\",hard_rb=\"%u\"]}", a->state, a->state_mask, a->table_id,a->idle_timeout,a->hard_timeout,a->idle_rollback,a->hard_rollback);
                return string;
                break;
            }
            case (OFPAT_EXP_SET_FLAG): 
            {
                struct ofl_exp_action_set_flag *a = (struct ofl_exp_action_set_flag *)ext;
                char *string = malloc(100);
                char string_value[33];
                masked_value_print(string_value,decimal_to_binary(a->flag),decimal_to_binary(a->flag_mask));
                sprintf(string, "{set_flag=[flag=%s]}", string_value);
                return string;
                break;
            }
        }
    }
}

int     
ofl_exp_openstate_act_free(struct ofl_action_header *act){

    struct ofl_action_experimenter* exp = (struct ofl_action_experimenter *) act;
    struct ofl_exp_openstate_act_header *ext = (struct ofl_exp_openstate_act_header *)exp;
    if (exp->experimenter_id == OPENSTATE_VENDOR_ID) {
        switch (ext->act_type) {
            case (OFPAT_EXP_SET_STATE):
            {
                struct ofl_exp_action_set_state *a = (struct ofl_exp_action_set_state *)ext;
                free(a);
                return;
                break;
            }
            case (OFPAT_EXP_SET_FLAG):
            {
                struct ofl_exp_action_set_flag *a = (struct ofl_exp_action_set_flag *)ext;
                free(a);
                return;
                break;
            }
        }
    }
    free(act);
}

int
ofl_exp_openstate_stats_req_pack(struct ofl_msg_multipart_request_experimenter *ext, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) { 
    struct ofl_exp_openstate_msg_multipart_request *e = (struct ofl_exp_openstate_msg_multipart_request *)ext;
    switch (e->type){
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_request_state *msg = (struct ofl_exp_msg_multipart_request_state *)e;
            struct ofp_multipart_request *req;
            struct ofp_exp_state_stats_request *stats;
            struct ofp_experimenter_stats_header *exp_header;
            uint8_t *ptr;
            *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request) + msg->match->length;
            *buf     = (uint8_t *)malloc(*buf_len);

            req = (struct ofp_multipart_request *)(*buf);
            stats = (struct ofp_exp_state_stats_request *)req->body;
            exp_header = (struct ofp_experimenter_stats_header *)stats;
            exp_header -> experimenter = htonl(OPENSTATE_VENDOR_ID);
            exp_header -> exp_type = htonl(OFPMP_EXP_STATE_STATS);
            stats->table_id = msg->table_id;
            stats->get_from_state = msg->get_from_state;
            stats->state = htonl(msg->state);
            memset(stats->pad, 0x00, 2);
            ptr = (*buf) + sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request);
            ofl_structs_match_pack(msg->match, &(stats->match),ptr, exp);

            return 0;
        }
        case (OFPMP_EXP_FLAGS_STATS):
        {
            struct ofl_exp_msg_multipart_request_global_state *msg = (struct ofl_exp_msg_multipart_request_global_state *)e;           
            struct ofp_multipart_request *req;
            struct ofp_exp_global_state_stats_request *stats;
            struct ofp_experimenter_stats_header *exp_header;
            uint8_t *ptr;
            *buf_len = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_global_state_stats_request);
            *buf     = (uint8_t *)malloc(*buf_len);

            req = (struct ofp_multipart_request *)(*buf);
            stats = (struct ofp_exp_global_state_stats_request *)req->body;
            exp_header = (struct ofp_experimenter_stats_header *)stats;
            exp_header -> experimenter = htonl(OPENSTATE_VENDOR_ID);
            exp_header -> exp_type = htonl(OFPMP_EXP_FLAGS_STATS);

            return 0;

        }
        default:
            return -1;
    }
}


int
ofl_exp_openstate_stats_reply_pack(struct ofl_msg_multipart_reply_experimenter *ext, uint8_t **buf, size_t *buf_len, struct ofl_exp *exp) { 

    struct ofl_exp_openstate_msg_multipart_reply *e = (struct ofl_exp_openstate_msg_multipart_reply *)ext;
    switch (e->type){
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_state *msg = (struct ofl_exp_msg_multipart_reply_state *)e;
            struct ofp_multipart_reply *resp;
            size_t i;
            uint8_t * data;

            *buf_len = sizeof(struct ofp_multipart_reply) + sizeof(struct ofp_experimenter_stats_header) + ofl_structs_state_stats_ofp_total_len(msg->stats, msg->stats_num, exp);
            *buf     = (uint8_t *)malloc(*buf_len);
            resp = (struct ofp_multipart_reply *)(*buf);
            data = (uint8_t*) resp->body;
            struct ofp_experimenter_stats_header *ext_header = (struct ofp_experimenter_stats_header*) data;   
            ext_header->experimenter = htonl(OPENSTATE_VENDOR_ID);
            ext_header->exp_type = htonl(OFPMP_EXP_STATE_STATS);
            data += sizeof(struct ofp_experimenter_stats_header);
            for (i=0; i<msg->stats_num; i++) {
                data += ofl_structs_state_stats_pack(msg->stats[i], data, exp);
            }
            return 0;
        }
        case (OFPMP_EXP_FLAGS_STATS):
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

            exp_header -> experimenter = htonl(OPENSTATE_VENDOR_ID);
            exp_header -> exp_type = htonl(OFPMP_EXP_FLAGS_STATS);
            memset(stats->pad, 0x00, 4);
            stats->global_states=htonl(msg->global_states);
            return 0;
        }
        default:
            return -1;
    }
}

ofl_err
ofl_exp_openstate_stats_req_unpack(struct ofp_multipart_request *os, uint8_t* buf, size_t *len, struct ofl_msg_multipart_request_header **msg, struct ofl_exp *exp) {
    
    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *)os->body;    
    switch (ntohl(ext->exp_type)){
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
        case (OFPMP_EXP_FLAGS_STATS):
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
ofl_exp_openstate_stats_reply_unpack(struct ofp_multipart_reply *os, uint8_t* buf, size_t *len, struct ofl_msg_multipart_reply_header **msg, struct ofl_exp *exp) {

    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *)os->body;
    
    switch (ntohl(ext->exp_type)){
        case (OFPMP_EXP_STATE_STATS):
        {    
            struct ofp_exp_state_stats *stat;
            struct ofl_exp_msg_multipart_reply_state *dm;
            ofl_err error;
            size_t i, ini_len;
            uint8_t *ptr;

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
                stat = (struct ofp_state_stats *)((uint8_t *)stat + ntohs(stat->length));
            }

            *msg = (struct ofl_msg_multipart_request_header *)dm;
            return 0;
        }
        case (OFPMP_EXP_FLAGS_STATS):
        {
            struct ofp_exp_global_state_stats *sm;
            struct ofl_exp_msg_multipart_reply_global_state *dm;

            if (*len < sizeof(struct ofp_exp_global_state_stats)) {
                OFL_LOG_WARN(LOG_MODULE, "Received FLAGS stats reply has invalid length (%zu).", *len);
                return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
            }
            *len -= sizeof(struct ofp_exp_global_state_stats);

            sm = (struct ofp_exp_global_state_stats *)os->body;
            dm = (struct ofl_exp_msg_multipart_reply_global_state *) malloc(sizeof(struct ofl_exp_msg_multipart_reply_global_state));
            dm->header.type = ntohl(ext->exp_type);
            dm->header.header.experimenter_id = ntohl(ext->experimenter);
            dm->global_states =  ntohl(sm->global_states);

            *msg = (struct ofl_msg_multipart_request_header *)dm;
            return 0;
        }
        default:
            return -1;
    }
}

char *
ofl_exp_openstate_stats_request_to_string(struct ofl_msg_multipart_request_experimenter *ext, struct ofl_exp *exp) {
    struct ofl_exp_openstate_msg_multipart_request *e = (struct ofl_exp_openstate_msg_multipart_request *)ext; 
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    switch (e->type){
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_request_state *msg = (struct ofl_exp_msg_multipart_request_state *)e;
            fprintf(stream, "{exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", table=\"");
            ofl_table_print(stream, msg->table_id);
            if(msg->get_from_state)
                fprintf(stream, "\", state=\"%lu\"", msg->state);
            fprintf(stream, "\", match=");
            ofl_structs_match_print(stream, msg->match, exp);
            break;
        }
        case (OFPMP_EXP_FLAGS_STATS):
        {
            fprintf(stream, "{stat_exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\"");
            struct ofl_exp_msg_multipart_request_global_state *msg = (struct ofl_exp_msg_multipart_request_global_state *)e;
            break;
        }
    }
    fclose(stream);
    return str;
}

char *
ofl_exp_openstate_stats_reply_to_string(struct ofl_msg_multipart_reply_experimenter *ext, struct ofl_exp *exp) {
    struct ofl_exp_openstate_msg_multipart_reply *e = (struct ofl_exp_openstate_msg_multipart_reply *)ext; 
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);
    switch (e->type){
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_state *msg = (struct ofl_exp_msg_multipart_reply_state *)e;
            size_t i;
            size_t last_table_id = -1;
            extern int colors;
            fprintf(stream, "{exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", stats=[");
            
            for (i=0; i<msg->stats_num; i++) {

                if(last_table_id != msg->stats[i]->table_id && colors)
                    fprintf(stream, "\n\n\x1B[33mTABLE = %d\x1B[0m\n\n",msg->stats[i]->table_id);
                last_table_id = msg->stats[i]->table_id;
                ofl_structs_state_stats_print(stream, msg->stats[i], exp);
                if (i < msg->stats_num - 1) { 
                    if(colors)
                        fprintf(stream, ",\n\n");
                    else
                        fprintf(stream, ", "); };
            }
            if(colors)
                fprintf(stream, "\n\n");
            fprintf(stream, "]");
            break;
        }
        case (OFPMP_EXP_FLAGS_STATS):
        {
            struct ofl_exp_msg_multipart_reply_global_state *msg = (struct ofl_exp_msg_multipart_reply_global_state *)e;
            size_t i;
            size_t last_table_id = -1;
            extern int colors;
            fprintf(stream, "{stat_exp_type=\"");
            ofl_exp_stats_type_print(stream, e->type);
            fprintf(stream, "\", global_states=\"%s\"",decimal_to_binary(msg->global_states));
            break;
        }
    }
    fclose(stream);
    return str;
}

int
ofl_exp_openstate_stats_req_free(struct ofl_msg_multipart_request_header *msg) {
    struct ofl_msg_multipart_request_experimenter* exp = (struct ofl_msg_multipart_request_experimenter *) msg;
    struct ofl_exp_openstate_msg_multipart_request *ext = (struct ofl_exp_openstate_msg_multipart_request *)exp;
    switch (ext->type) {
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_request_state *a = (struct ofl_exp_msg_multipart_request_state *) ext;
            free(a);
            break;
        }
        case (OFPMP_EXP_FLAGS_STATS):
        {
            struct ofl_exp_msg_multipart_request_state *a = (struct ofl_exp_msg_multipart_reqeust_state *) ext;
            free(a);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Openstate Experimenter message.");
        }
    }
    return 0;
}

int
ofl_exp_openstate_stats_reply_free(struct ofl_msg_multipart_reply_header *msg) {
    struct ofl_msg_multipart_reply_experimenter* exp = (struct ofl_msg_multipart_reply_experimenter *) msg;
    struct ofl_exp_openstate_msg_multipart_reply *ext = (struct ofl_exp_openstate_msg_multipart_reply *)exp;
    switch (ext->type) {
        case (OFPMP_EXP_STATE_STATS):
        {
            struct ofl_exp_msg_multipart_reply_state *a = (struct ofl_exp_msg_multipart_reply_state *) ext;
            free(a);
            break;
        }
        case (OFPMP_EXP_FLAGS_STATS):
        {
            struct ofl_exp_msg_multipart_reply_state *a = (struct ofl_exp_msg_multipart_reply_state *) ext;
            free(a);
            break;
        }
        default: {
            OFL_LOG_WARN(LOG_MODULE, "Trying to free unknown Openstate Experimenter message.");
        }
    }
    return 0;
}

/*experimenter match fields*/

static void
oxm_put_exp_header(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id)
{
    uint32_t n_header = htonl(header);
    ofpbuf_put(buf, &n_header, sizeof n_header);
    ofpbuf_put(buf, &experimenter_id, EXP_ID_LEN);

}

static void
oxm_put_exp_8(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id, uint8_t value)
{
    oxm_put_exp_header(buf, header, experimenter_id);
    ofpbuf_put(buf, &value, sizeof value);
}

static void
oxm_put_exp_8w(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id, uint8_t value, uint8_t mask)
{
    oxm_put_exp_header(buf, header, experimenter_id);
    ofpbuf_put(buf, &value, sizeof value);
    ofpbuf_put(buf, &mask, sizeof mask);
}

static void
oxm_put_exp_16(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id, uint16_t value)
{
    oxm_put_exp_header(buf, header, experimenter_id);
    ofpbuf_put(buf, &value, sizeof value);
}

static void
oxm_put_exp_16w(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id, uint16_t value, uint16_t mask)
{
    oxm_put_exp_header(buf, header, experimenter_id);
    ofpbuf_put(buf, &value, sizeof value);
    ofpbuf_put(buf, &mask, sizeof mask);
}

static void
oxm_put_exp_32(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id, uint32_t value)
{
    oxm_put_exp_header(buf, header, experimenter_id);
    ofpbuf_put(buf, &value, sizeof value);
}

static void
oxm_put_exp_32w(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id, uint32_t value, uint32_t mask)
{
    oxm_put_exp_header(buf, header, experimenter_id);
    ofpbuf_put(buf, &value, sizeof value);
    ofpbuf_put(buf, &mask, sizeof mask);
}

static void
oxm_put_exp_64(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id, uint64_t value)
{
    oxm_put_exp_header(buf, header, experimenter_id);
    ofpbuf_put(buf, &value, sizeof value);
}

static void
oxm_put_exp_64w(struct ofpbuf *buf, uint32_t header, uint32_t experimenter_id, uint64_t value, uint64_t mask)
{
    oxm_put_exp_header(buf, header, experimenter_id);
    ofpbuf_put(buf, &value, sizeof value);
    ofpbuf_put(buf, &mask, sizeof mask); 
}

int
ofl_exp_openstate_field_unpack(struct ofl_match *match, struct oxm_field *f, void *experimenter_id, void *value, void *mask) {
    switch (f->index) {
        case OFI_OXM_EXP_STATE:{
            ofl_structs_match_exp_put32(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)));
            return 0;
        }
        case OFI_OXM_EXP_STATE_W:{
            if (check_bad_wildcard32(ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)))){
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_WILDCARDS);
            }
            ofl_structs_match_exp_put32m(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)));
            return 0;
        }
        case OFI_OXM_EXP_FLAGS:{
            ofl_structs_match_exp_put32(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)));
            return 0;
        }
        case OFI_OXM_EXP_FLAGS_W:{
            if (check_bad_wildcard32(ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)))){
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_WILDCARDS);
            }
            ofl_structs_match_exp_put32m(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)));
            return 0;
        }
        default:
            NOT_REACHED();
    }
}

void  
ofl_exp_openstate_field_pack(struct ofpbuf *buf, struct ofl_match_tlv *oft){
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
ofl_exp_openstate_field_match(struct ofl_match_tlv *f, int *packet_header, int *field_len, uint8_t **flow_val, uint8_t **flow_mask){
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
ofl_exp_openstate_field_compare (struct ofl_match_tlv *packet_f, uint8_t **packet_val){
    *packet_val = packet_f->value + EXP_ID_LEN;
}                   

void
ofl_exp_openstate_field_match_std (struct ofl_match_tlv *flow_mod_match, struct ofl_match_tlv *flow_entry_match, int *field_len, uint8_t **flow_mod_val, uint8_t **flow_entry_val, uint8_t **flow_mod_mask, uint8_t **flow_entry_mask){
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
ofl_exp_openstate_field_overlap_a (struct ofl_match_tlv *f_a, int *field_len, uint8_t **val_a, uint8_t **mask_a, int *header, int *header_m, uint64_t *all_mask){
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
ofl_exp_openstate_field_overlap_b (struct ofl_match_tlv *f_b, int *field_len, uint8_t **val_b, uint8_t **mask_b, uint64_t *all_mask){
    *val_b = f_b->value + EXP_ID_LEN;
    if (OXM_HASMASK(f_b->header)) {
        *mask_b = f_b->value + EXP_ID_LEN + (*field_len);
    } else {
        /* Set a dummy mask with all bits set to 0 (valid) */
        *mask_b = (uint8_t *) all_mask;
    }
}

/*experimenter table functions*/

int __extract_key(uint8_t *, struct key_extractor *, struct packet *);

struct state_table * state_table_create(void) {
    struct state_table *table = malloc(sizeof(struct state_table));
    memset(table, 0, sizeof(*table));
     
    table->state_entries = (struct hmap) HMAP_INITIALIZER(&table->state_entries);
    table->hard_entries = (struct hmap) HMAP_INITIALIZER(&table->hard_entries);
    table->idle_entries = (struct hmap) HMAP_INITIALIZER(&table->idle_entries);

    /* default state entry */
    table->default_state_entry.state = STATE_DEFAULT;

    table->stateful = 0;
    
    return table;
}

uint8_t state_table_is_stateful(struct state_table *table){
    return table->stateful;
}

uint8_t state_table_is_configured(struct state_table *table){
    if (table->read_key.field_count!=0 && table->write_key.field_count!=0)
        return 1;

    return 0;
}

void state_table_configure_stateful(struct state_table *table, uint8_t stateful){
    if (stateful!=0)
        table->stateful = 1;
    else
        table->stateful = 0;
}

void state_table_destroy(struct state_table *table) {
    hmap_destroy(&table->state_entries);
    hmap_destroy(&table->hard_entries);
    hmap_destroy(&table->idle_entries);
    free(table);
}
/* having the key extractor field goes to look for these key inside the packet and map to corresponding value and copy the value into buf. */ 
int __extract_key(uint8_t *buf, struct key_extractor *extractor, struct packet *pkt) {
    int i, extracted_key_len=0, expected_key_len=0;
    struct ofl_match_tlv *f;

    for (i=0; i<extractor->field_count; i++) {
        uint32_t type = (int)extractor->fields[i];
        HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
            hmap_node, hash_int(type, 0), &pkt->handle_std->match.match_fields){
                if (type == f->header) {
                    memcpy(&buf[extracted_key_len], f->value, OXM_LENGTH(f->header));
                    extracted_key_len = extracted_key_len + OXM_LENGTH(f->header);//keeps only 8 last bits of oxm_header that contains oxm_length(in which length of oxm_payload)
                    break;
                }
        }   
        expected_key_len = expected_key_len + OXM_LENGTH(type);
    }
    /* check if the full key has been extracted: if key is extracted partially or not at all, we cannot access the state table */
    if (extracted_key_len==expected_key_len)
        return 1;
    else
        return 0;
}

static bool
state_entry_idle_timeout(struct state_table *table, struct state_entry *entry) {
    bool timeout;
    int found = 0;
    struct state_entry *e;
    struct timeval tv;
    gettimeofday(&tv,NULL);

    timeout = (entry->stats->idle_timeout != 0) &&
              (1000000 * tv.tv_sec + tv.tv_usec > entry->last_used + entry->stats->idle_timeout);
       
    if (timeout) {
        hmap_remove_and_shrink(&table->idle_entries, &entry->idle_node);
        if(entry->stats->hard_timeout > 0)
            hmap_remove_and_shrink(&table->hard_entries, &entry->hard_node);
        

        if(entry->stats->idle_rollback == STATE_DEFAULT){
            hmap_remove_and_shrink(&table->state_entries, &entry->hmap_node);
            entry->state = entry->stats->idle_rollback;
        }
        else{
            entry->state = entry->stats->idle_rollback;
            entry->created = 1000000 * tv.tv_sec + tv.tv_usec;
            entry->stats->idle_timeout = 0;
            entry->stats->hard_timeout = 0;
            entry->stats->idle_rollback = 0;
            entry->stats->hard_rollback = 0;
        }
    }
    return timeout;
}

static bool
state_entry_hard_timeout(struct state_table *table, struct state_entry *entry) {
    bool timeout;
    int found = 0;
    struct state_entry *e;
    struct timeval tv;
    gettimeofday(&tv,NULL);
    
    timeout = (entry->remove_at != 0) && (1000000 * tv.tv_sec + tv.tv_usec > entry->remove_at);
    
    if (timeout) {
        hmap_remove_and_shrink(&table->hard_entries, &entry->hard_node);
        if(entry->stats->idle_timeout > 0)
            hmap_remove_and_shrink(&table->idle_entries, &entry->idle_node);
        
        if(entry->stats->hard_rollback == STATE_DEFAULT){
            hmap_remove_and_shrink(&table->state_entries, &entry->hmap_node);
            entry->state = entry->stats->hard_rollback;
        }
        else{
            entry->state = entry->stats->hard_rollback;
            entry->created = 1000000 * tv.tv_sec + tv.tv_usec;
            entry->stats->idle_timeout = 0;
            entry->stats->hard_timeout = 0;
            entry->stats->idle_rollback = 0;
            entry->stats->hard_rollback = 0;

        }
    }
    return timeout;
}

void
state_table_timeout(struct state_table *table) {
    struct state_entry *entry;

    /* NOTE: hard timeout entries are ordered by the time they should be removed at,
     * so if one is not removed, the rest will not be either. */
    HMAP_FOR_EACH(entry, struct state_entry, hard_node, &table->hard_entries){
        state_entry_hard_timeout(table, entry);
    }

    HMAP_FOR_EACH(entry, struct state_entry, idle_node, &table->idle_entries){
        state_entry_idle_timeout(table, entry);
    }
}

/*having the read_key, look for the state vaule inside the state_table */
struct state_entry * state_table_lookup(struct state_table* table, struct packet *pkt) {
    struct state_entry * e = NULL;  
    uint8_t key[MAX_STATE_KEY_LEN] = {0};
    struct timeval tv;

    if(!__extract_key(key, &table->read_key, pkt))
    {
        OFL_LOG_WARN(LOG_MODULE, "lookup key fields not found in the packet's header -> NULL");
        return NULL;
    }
    
    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
        hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
                OFL_LOG_WARN(LOG_MODULE, "found corresponding state %u",e->state);

                //check if the hard_timeout of matched state entry has expired
                if ((e->stats->hard_timeout>0) && state_entry_hard_timeout(table,e)) {
                    if (e->state==STATE_DEFAULT)
                        e == NULL;
                    break;
                }
                //check if the idle_timeout of matched state entry has expired
                if ((e->stats->idle_timeout>0) && state_entry_idle_timeout(table,e)) {
                    if (e->state==STATE_DEFAULT)
                        e == NULL;
                    break;
                }
                gettimeofday(&tv,NULL);
                e->last_used = 1000000 * tv.tv_sec + tv.tv_usec;
                break;
            }
    }

    if (e == NULL)
    {    
        OFL_LOG_WARN(LOG_MODULE, "not found the corresponding state value\n");
        return &table->default_state_entry;
    }
    else 
        return e;
}
/* having the state value  */
void state_table_write_state(struct state_entry *entry, struct packet *pkt) {
    struct  ofl_match_tlv *f;
    
    HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv, 
        hmap_node, hash_int(OXM_EXP_STATE,0), &pkt->handle_std->match.match_fields){
                uint32_t *state = (uint32_t*) (f->value + EXP_ID_LEN);
                *state = (*state & 0x00000000) | (entry->state);
    }
}
void state_table_del_state(struct state_table *table, uint8_t *key, uint32_t len) {
    struct state_entry *e;

    int i;
    uint32_t key_len=0; //update-scope key extractor length
    struct key_extractor *extractor=&table->write_key;
    for (i=0; i<extractor->field_count; i++) {
        uint32_t type = (int)extractor->fields[i];
        key_len = key_len + OXM_LENGTH(type);
     }
    if(key_len != len)
    {
        OFL_LOG_WARN(LOG_MODULE, "key extractor length != received key length");
        return;
    }
    
    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
        hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
                hmap_remove_and_shrink(&table->state_entries, &e->hmap_node);
                break;
            }
    }

    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
        hard_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->hard_entries){
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
                hmap_remove_and_shrink(&table->hard_entries, &e->hard_node);
                break;
            }
    }

    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
        idle_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->idle_entries){
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
                hmap_remove_and_shrink(&table->idle_entries, &e->idle_node);
                break;
            }
    }
}


void state_table_set_extractor(struct state_table *table, struct key_extractor *ke, int update) {
    struct key_extractor *dest;
    if (update){
        if (table->read_key.field_count!=0){
            if (table->read_key.field_count != ke->field_count){
                OFL_LOG_WARN(LOG_MODULE, "Update-scope should provide same length keys of lookup-scope: %d vs %d\n",ke->field_count,table->read_key.field_count);
                return;
            }
        }
        dest = &table->write_key;
        OFL_LOG_WARN(LOG_MODULE, "Update-scope set");
        }
    else{
        if (table->write_key.field_count!=0){
            if (table->write_key.field_count != ke->field_count){
                OFL_LOG_WARN(LOG_MODULE, "Lookup-scope should provide same length keys of update-scope: %d vs %d\n",ke->field_count,table->write_key.field_count);
                return;
            }
        }
        dest = &table->read_key;
        OFL_LOG_WARN(LOG_MODULE, "Lookup-scope set");
        }
    dest->field_count = ke->field_count;
    memcpy(dest->fields, ke->fields, sizeof(uint32_t)*ke->field_count);
    return;
}

void state_table_set_state(struct state_table *table, struct packet *pkt, struct ofl_exp_set_flow_state *msg, struct ofl_exp_action_set_state *act) {
    uint8_t key[MAX_STATE_KEY_LEN] = {0};   
    struct state_entry *e;
    uint32_t state,state_mask;
    uint32_t idle_rollback,hard_rollback;
    uint32_t idle_timeout,hard_timeout;
    uint64_t now;
    struct timeval tv;
    
    int i;
    uint32_t key_len=0; //update-scope key extractor length
    struct key_extractor *extractor=&table->write_key;
    for (i=0; i<extractor->field_count; i++) 
    {
        uint32_t type = (int)extractor->fields[i];
        key_len = key_len + OXM_LENGTH(type);
    }

    if (pkt)
    {   
        //SET_STATE action
        state = act->state;
        state_mask = act->state_mask;
        idle_rollback = act->idle_rollback;
        hard_rollback = act->hard_rollback;
        idle_timeout = act->idle_timeout;
        hard_timeout = act->hard_timeout;
        
        if(!__extract_key(key, &table->write_key, pkt)){
            OFL_LOG_WARN(LOG_MODULE, "lookup key fields not found in the packet's header");
            return;
        }
    }

    else if (msg){
        //SET_STATE message
        state = msg->state;
        state_mask = msg->state_mask;
        idle_rollback = msg->idle_rollback;
        hard_rollback = msg->hard_rollback;
        idle_timeout = msg->idle_timeout;
        hard_timeout = msg->hard_timeout;
        if(key_len == msg->key_len)
        {
            memcpy(key, msg->key, msg->key_len);
        }
        else
        {
            OFL_LOG_WARN(LOG_MODULE, "key extractor length != received key length");
            return;
        }
    }
    
    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
        hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
                OFL_LOG_WARN(LOG_MODULE, "state value is %u updated to hash map", state);
                if ((((e->state & ~(state_mask)) | (state & state_mask)) == STATE_DEFAULT) && hard_timeout==0 && idle_timeout==0){
                    state_table_del_state(table, key, key_len);
                }
                else {
                    e->state = (e->state & ~(state_mask)) | (state & state_mask);
                    gettimeofday(&tv,NULL);
                    now = 1000000 * tv.tv_sec + tv.tv_usec;

                    e->created = now;

                    if (e->stats->idle_timeout)
                        hmap_remove_and_shrink(&table->idle_entries, &e->idle_node);
                    if (e->stats->hard_timeout)
                        hmap_remove_and_shrink(&table->hard_entries, &e->hard_node);

                    e->stats->idle_timeout = 0;
                    e->stats->hard_timeout = 0;
                    e->stats->idle_rollback = 0;
                    e->stats->hard_rollback = 0;
                    
                    if (hard_timeout>0 && hard_rollback!=((e->state & ~(state_mask)) | (state & state_mask))) {
                        e->stats->hard_timeout = hard_timeout;
                        e->stats->hard_rollback = hard_rollback;
                        e->remove_at = now + hard_timeout;                       
                        hmap_insert(&table->hard_entries, &e->hard_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
                    }
                    if (idle_timeout>0 && idle_rollback!=((e->state & ~(state_mask)) | (state & state_mask))) {
                        e->stats->idle_timeout = idle_timeout;
                        e->stats->idle_rollback = idle_rollback;
                        e->last_used = now;                        
                        hmap_insert(&table->idle_entries, &e->idle_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
                    }
                }
                return;
            }
    }

    gettimeofday(&tv,NULL);
    now = 1000000 * tv.tv_sec + tv.tv_usec;
    e = xmalloc(sizeof(struct state_entry));
    e->created = now;
    e->stats = xmalloc(sizeof(struct ofl_exp_state_stats));
    e->stats->idle_timeout = 0;
    e->stats->hard_timeout = 0;
    e->stats->idle_rollback = 0;
    e->stats->hard_rollback = 0;
    memcpy(e->key, key, MAX_STATE_KEY_LEN);
    e->state = state & state_mask;

    // A new state entry with state!=DEF is always installed.
    if ((state & state_mask) != STATE_DEFAULT)
    {       
        OFL_LOG_WARN(LOG_MODULE, "state value is %u inserted to hash map", e->state);
        hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
    }
    else
    {
        // Otherwise a new state entry with state=DEF will be installed only if at least one timeout is set with rollback!=DEF
        if ((hard_timeout>0 && hard_rollback!=STATE_DEFAULT) || (idle_timeout>0 && idle_rollback!=STATE_DEFAULT))
            hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
    }

    // Configuring a timeout with rollback state=state makes no sense
    if (hard_timeout>0 && hard_rollback!=(state & state_mask)){
        e->remove_at = hard_timeout>0 == 0 ? 0 : now + hard_timeout;
        e->stats->hard_timeout = hard_timeout;
        e->stats->hard_rollback = hard_rollback;
        hmap_insert(&table->hard_entries, &e->hard_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
    }
    if (idle_timeout>0 && idle_rollback!=(state & state_mask)){
        e->stats->idle_timeout = idle_timeout;
        e->stats->idle_rollback = idle_rollback;
        e->last_used = now;
        hmap_insert(&table->idle_entries, &e->idle_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
    }
}

ofl_err
handle_state_mod(struct pipeline *pl, struct ofl_exp_msg_state_mod *msg,
                                                const struct sender *sender) {
    
    if (msg->command == OFPSC_STATEFUL_TABLE_CONFIG) {
        struct ofl_exp_stateful_table_config *p = (struct ofl_exp_stateful_table_config *) msg->payload;
        struct state_table *st = pl->tables[p->table_id]->state_table;
        state_table_configure_stateful(st, p->stateful);
    }
    else if (msg->command == OFPSC_SET_L_EXTRACTOR || msg->command == OFPSC_SET_U_EXTRACTOR) {
        struct ofl_exp_set_extractor *p = (struct ofl_exp_set_extractor *) msg->payload;
        struct state_table *st = pl->tables[p->table_id]->state_table;
        if (state_table_is_stateful(st)){
            int update = 0;
            if (msg->command == OFPSC_SET_U_EXTRACTOR) 
                update = 1;
            state_table_set_extractor(st, (struct key_extractor *)p, update);
        }
        else{
            //TODO sanvitz: return an experimenter error msg
            OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD: cannot configure extractor (stage %u is not stateful)", p->table_id);
        }
    }
    else if (msg->command == OFPSC_SET_FLOW_STATE) {
        struct ofl_exp_set_flow_state *p = (struct ofl_exp_set_flow_state *) msg->payload;
        struct state_table *st = pl->tables[p->table_id]->state_table;
        if (state_table_is_stateful(st) && state_table_is_configured(st)){
            state_table_set_state(st, NULL, p, NULL);
        }
        else{
            //TODO sanvitz: return an experimenter error msg
            OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful or not configured", p->table_id);
        }
    }
    else if (msg->command == OFPSC_DEL_FLOW_STATE) {
        struct ofl_exp_del_flow_state *p = (struct ofl_exp_del_flow_state *) msg->payload;
        struct state_table *st = pl->tables[p->table_id]->state_table;
        if (state_table_is_stateful(st) && state_table_is_configured(st)){
            state_table_del_state(st, p->key, p->key_len);
        }
        else{
            //TODO sanvitz: return an experimenter error msg
             OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful or not configured", p->table_id);
        }
    }
    else if (msg->command == OFPSC_SET_GLOBAL_STATE) {
        uint32_t global_states = pl->dp->global_states;
        struct ofl_exp_set_global_state *p = (struct ofl_exp_set_global_state *) msg->payload;
        global_states = (global_states & ~(p->flag_mask)) | (p->flag & p->flag_mask);
        pl->dp->global_states = global_states;
    }
    else if (msg->command == OFPSC_RESET_GLOBAL_STATE) {
        pl->dp->global_states = OFP_GLOBAL_STATES_DEFAULT;
    }
    else
        return 1;

    return 0;
}

ofl_err
handle_stats_request_state(struct pipeline *pl, struct ofl_exp_msg_multipart_request_state *msg, const struct sender *sender, struct ofl_exp_msg_multipart_reply_state *reply) {
    struct ofl_exp_state_stats **stats = xmalloc(sizeof(struct ofl_exp_state_stats *));
    size_t stats_size = 1;
    size_t stats_num = 0;
    if (msg->table_id == 0xff) {
        size_t i;
        for (i=0; i<PIPELINE_TABLES; i++) {
            if (state_table_is_stateful(pl->tables[i]->state_table) && state_table_is_configured(pl->tables[i]->state_table))
                state_table_stats(pl->tables[i]->state_table, msg, &stats, &stats_size, &stats_num, i);
        }
    } else {
        if (state_table_is_stateful(pl->tables[msg->table_id]->state_table) && state_table_is_configured(pl->tables[msg->table_id]->state_table))
            state_table_stats(pl->tables[msg->table_id]->state_table, msg, &stats, &stats_size, &stats_num, msg->table_id);
    }
    *reply = (struct ofl_exp_msg_multipart_reply_state)
            {{{{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_EXPERIMENTER, .flags = 0x0000},
             .experimenter_id = OPENSTATE_VENDOR_ID},
             .type = OFPMP_EXP_STATE_STATS},
             .stats = stats,
             .stats_num = stats_num};
    return 0;
}

ofl_err
handle_stats_request_global_state(struct pipeline *pl, const struct sender *sender, struct ofl_exp_msg_multipart_reply_global_state *reply) {
    uint32_t global_states = pl->dp->global_states;
    
    *reply = (struct ofl_exp_msg_multipart_reply_global_state)
            {{{{{.type = OFPT_MULTIPART_REPLY},
              .type = OFPMP_EXPERIMENTER, .flags = 0x0000},
             .experimenter_id = OPENSTATE_VENDOR_ID},
             .type = OFPMP_EXP_FLAGS_STATS},
             .global_states = global_states};
    return 0;
}

void
state_table_stats(struct state_table *table, struct ofl_exp_msg_multipart_request_state *msg,
                 struct ofl_exp_state_stats ***stats, size_t *stats_size, size_t *stats_num, uint8_t table_id) {
    struct state_entry *entry;
    size_t  i;
    uint32_t key_len = 0; //update-scope key extractor length
    uint32_t fields[MAX_EXTRACTION_FIELD_COUNT] = {0};
    struct timeval tv;
    struct key_extractor *extractor=&table->read_key;
    for (i=0; i<extractor->field_count; i++) {
        fields[i] = (int)extractor->fields[i];
        key_len = key_len + OXM_LENGTH(fields[i]);
     }

    struct ofl_match * a = (struct ofl_match *)msg->match;
    struct ofl_match_tlv *state_key_match;
    uint8_t count = 0; 
    uint8_t found = 0;
    uint8_t len = 0;
    uint8_t aux = 0;

    uint8_t offset[MAX_EXTRACTION_FIELD_COUNT] = {0};
    uint8_t length[MAX_EXTRACTION_FIELD_COUNT] = {0};

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
    HMAP_FOR_EACH(entry, struct state_entry, hmap_node, &table->state_entries) {
        if ((*stats_size) == (*stats_num)) {
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_exp_state_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
            }
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

        
            if(found && ((msg->get_from_state && msg->state == entry->state) || (!msg->get_from_state)))
            {
                gettimeofday(&tv,NULL);
                (*stats)[(*stats_num)] = malloc(sizeof(struct ofl_exp_state_stats));
                (*stats)[(*stats_num)]->idle_timeout = entry->stats->idle_timeout;
                (*stats)[(*stats_num)]->hard_timeout = entry->stats->hard_timeout;
                (*stats)[(*stats_num)]->idle_rollback = entry->stats->idle_rollback;
                (*stats)[(*stats_num)]->hard_rollback = entry->stats->hard_rollback;
                (*stats)[(*stats_num)]->duration_sec  =  (1000000 * tv.tv_sec + tv.tv_usec - entry->created) / 1000000;
                (*stats)[(*stats_num)]->duration_nsec = ((1000000 * tv.tv_sec + tv.tv_usec - entry->created) % 1000000)*1000;
                for (i=0;i<extractor->field_count;i++)
                    (*stats)[(*stats_num)]->fields[i]=fields[i];
                (*stats)[(*stats_num)]->table_id = table_id;
                (*stats)[(*stats_num)]->field_count = extractor->field_count;                   
                (*stats)[(*stats_num)]->entry.key_len = key_len;
                for (i=0;i<key_len;i++)
                    (*stats)[(*stats_num)]->entry.key[i]=entry->key[i];
                (*stats)[(*stats_num)]->entry.state = entry->state;
                (*stats_num)++;
             }
        }
     /*DEFAULT ENTRY*/
    if(!msg->get_from_state || (msg->get_from_state && msg->state == STATE_DEFAULT))
    {
        if ((*stats_size) == (*stats_num)) {
                    (*stats) = xrealloc(*stats, (sizeof(struct ofl_exp_state_stats *)) * (*stats_size) * 2);
                    *stats_size *= 2;
        }
        (*stats)[(*stats_num)] = malloc(sizeof(struct ofl_exp_state_stats));
        for (i=0;i<extractor->field_count;i++)
            (*stats)[(*stats_num)]->fields[i]=fields[i];
        (*stats)[(*stats_num)]->table_id = table_id;
        (*stats)[(*stats_num)]->field_count = extractor->field_count;                   
        (*stats)[(*stats_num)]->entry.key_len = 0;
        (*stats)[(*stats_num)]->entry.state = STATE_DEFAULT;
        (*stats)[(*stats_num)]->idle_timeout = 0;
        (*stats)[(*stats_num)]->hard_timeout = 0;
        (*stats)[(*stats_num)]->idle_rollback = 0;
        (*stats)[(*stats_num)]->hard_rollback = 0;
        (*stats_num)++;
    }
}

size_t
ofl_structs_state_stats_ofp_len(struct ofl_exp_state_stats *stats, struct ofl_exp *exp) {

    return ROUND_UP((sizeof(struct ofp_exp_state_stats)),8);
}

size_t
ofl_structs_state_stats_ofp_total_len(struct ofl_exp_state_stats ** stats, size_t stats_num, struct ofl_exp *exp) {
    size_t sum;
    OFL_UTILS_SUM_ARR_FUN2(sum, stats, stats_num,
            ofl_structs_state_stats_ofp_len, exp);
    return sum;
}

size_t
ofl_structs_state_stats_pack(struct ofl_exp_state_stats *src, uint8_t *dst, struct ofl_exp *exp) {
    struct ofp_exp_state_stats *state_stats;
    size_t total_len;
    uint8_t *data;
    size_t  i;
    total_len = ROUND_UP(sizeof(struct ofp_exp_state_stats),8);
    state_stats = (struct ofp_exp_state_stats*) dst;
    state_stats->length = htons(total_len);
    state_stats->table_id = src->table_id;
    state_stats->duration_sec = htonl(src->duration_sec);
    state_stats->duration_nsec = htonl(src->duration_nsec);

    state_stats->pad = 0;
    state_stats->field_count = htonl(src->field_count);
    
    for (i=0;i<src->field_count;i++)
           state_stats->fields[i]=htonl(src->fields[i]);
    state_stats->entry.key_len = htonl(src->entry.key_len);   
    for (i=0;i<src->entry.key_len;i++)
           state_stats->entry.key[i]=src->entry.key[i];
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
ofl_structs_state_stats_print(FILE *stream, struct ofl_exp_state_stats *s, struct ofl_exp *exp) {
    size_t i;
    uint8_t offset=0;
    extern int colors;
    if(colors) 
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
            fprintf(stream, ", dur_s=\"%u\", dur_ns=\"%09u\", idle_to=\"%lu\", idle_rb=\"%u\", hard_to=\"%lu\", hard_rb=\"%u\"",s->duration_sec, s->duration_nsec, s->idle_timeout, s->idle_rollback, s->hard_timeout, s->hard_rollback);
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
            fprintf(stream, ", dur_s=\"%u\", dur_ns=\"%09u\", idle_to=\"%lu\", idle_rb=\"%u\", hard_to=\"%lu\", hard_rb=\"%u\"",s->duration_sec, s->duration_nsec, s->idle_timeout, s->idle_rollback, s->hard_timeout, s->hard_rollback);
    }

    fprintf(stream, "}");
}

ofl_err
ofl_structs_state_stats_unpack(struct ofp_exp_state_stats *src, uint8_t *buf, size_t *len, struct ofl_exp_state_stats **dst, struct ofl_exp *exp) {
    struct ofl_exp_state_stats *s;
    ofl_err error;
    size_t slen;
    size_t i;
    int match_pos;
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
ofl_utils_count_ofp_state_stats(void *data, size_t data_len, size_t *count) {
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
ofl_exp_stats_type_print(FILE *stream, uint32_t type) {
    switch (type) {
        case (OFPMP_EXP_STATE_STATS):          { fprintf(stream, "state"); return; }
        case (OFPMP_EXP_FLAGS_STATS):          { fprintf(stream, "global_states"); return; }
        default: {                    fprintf(stream, "?(%u)", type); return; }
    }
}


/*Functions used by experimenter match fields*/

void
ofl_structs_match_exp_put8(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint8_t value){
   struct ofl_match_tlv *m = xmalloc(sizeof (struct ofl_match_tlv));
   int len = sizeof(uint8_t);

   m->header = header;
   m->value = malloc(EXP_ID_LEN + len);
   memcpy(m->value, &experimenter_id, EXP_ID_LEN);
   memcpy(m->value + EXP_ID_LEN, &value, len);
   hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
   match->header.length += EXP_ID_LEN + len + 4;
}

void
ofl_structs_match_exp_put8m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint8_t value, uint8_t mask){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(uint8_t);

    m->header = header;
    m->value = malloc(EXP_ID_LEN + len*2);
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, len);
    memcpy(m->value + EXP_ID_LEN + len, &mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
    match->header.length += EXP_ID_LEN + len*2 + 4;
}

void
ofl_structs_match_exp_put16(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint16_t value){
   struct ofl_match_tlv *m = xmalloc(sizeof (struct ofl_match_tlv));
   int len = sizeof(uint16_t);

   m->header = header;
   m->value = malloc(EXP_ID_LEN + len);
   memcpy(m->value, &experimenter_id, EXP_ID_LEN);
   memcpy(m->value + EXP_ID_LEN, &value, len);
   hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
   match->header.length += EXP_ID_LEN + len + 4;
}

void
ofl_structs_match_exp_put16m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint16_t value, uint16_t mask){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(uint16_t);

    m->header = header;
    m->value = malloc(EXP_ID_LEN + len*2);
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, len);
    memcpy(m->value + EXP_ID_LEN + len, &mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
    match->header.length += EXP_ID_LEN + len*2 + 4;
}

void
ofl_structs_match_exp_put32(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint32_t value){
   struct ofl_match_tlv *m = xmalloc(sizeof (struct ofl_match_tlv));
   int len = sizeof(uint32_t);

   m->header = header;
   m->value = malloc(EXP_ID_LEN + len);
   memcpy(m->value, &experimenter_id, EXP_ID_LEN);
   memcpy(m->value + EXP_ID_LEN, &value, len);
   hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
   match->header.length += EXP_ID_LEN + len + 4;
}

void
ofl_structs_match_exp_put32m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint32_t value, uint32_t mask){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(uint32_t);

    m->header = header;
    m->value = malloc(EXP_ID_LEN + len*2);
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, len);
    memcpy(m->value + EXP_ID_LEN + len, &mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
    match->header.length += EXP_ID_LEN + len*2 + 4;
}

void
ofl_structs_match_exp_put64(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint64_t value){
   struct ofl_match_tlv *m = xmalloc(sizeof (struct ofl_match_tlv));
   int len = sizeof(uint64_t);

   m->header = header;
   m->value = malloc(EXP_ID_LEN + len);
   memcpy(m->value, &experimenter_id, EXP_ID_LEN);
   memcpy(m->value + EXP_ID_LEN, &value, len);
   hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
   match->header.length += EXP_ID_LEN + len + 4;
}

void
ofl_structs_match_exp_put64m(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint64_t value, uint64_t mask){
    struct ofl_match_tlv *m = malloc(sizeof (struct ofl_match_tlv));
    int len = sizeof(uint64_t);

    m->header = header;
    m->value = malloc(EXP_ID_LEN + len*2);
    memcpy(m->value, &experimenter_id, EXP_ID_LEN);
    memcpy(m->value + EXP_ID_LEN, &value, len);
    memcpy(m->value + EXP_ID_LEN + len, &mask, len);
    hmap_insert(&match->match_fields,&m->hmap_node,hash_int(header, 0));
    match->header.length += EXP_ID_LEN + len*2 + 4;
}
