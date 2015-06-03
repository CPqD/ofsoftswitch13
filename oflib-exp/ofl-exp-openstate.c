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


#define LOG_MODULE ofl_exp_os
OFL_LOG_INIT(LOG_MODULE)



/* functions used by ofp_exp_message_state_mod*/
static ofl_err
ofl_structs_statefulness_config_unpack(struct ofp_exp_statefulness_config *src, size_t *len, struct ofl_exp_msg_statefulness_config *dst) {
    int i;
    if(*len == sizeof(struct ofp_exp_statefulness_config))
    {
        dst->statefulness = src->statefulness;
    }
    else
    { 
       OFL_LOG_WARN(LOG_MODULE, "Received state mod statefulness is too short (%zu).", *len);
       return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }

    *len -= sizeof(struct ofp_exp_statefulness_config);
 
    return 0;
}

static ofl_err
ofl_structs_extraction_unpack(struct ofp_exp_extraction *src, size_t *len, struct ofl_exp_msg_extraction *dst) {
    int i;
    if(*len == (1+ntohl(src->field_count))*sizeof(uint32_t) && (ntohl(src->field_count)>0))
    {
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

    *len -= ((1+ntohl(src->field_count))*sizeof(uint32_t));
 
    return 0;
}

static ofl_err
ofl_structs_key_unpack(struct ofp_exp_state_mod_entry *src, size_t *len, struct ofl_exp_msg_state_entry *dst) {
    int i;
    uint8_t key[OFPSC_MAX_KEY_LEN] = {0};

    if((*len == (3*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t))) && (ntohl(src->key_len)>0))
    {
        dst->key_len=ntohl(src->key_len);
        dst->state=ntohl(src->state);
        dst->state_mask=ntohl(src->state_mask);
        for (i=0;i<dst->key_len;i++)
            key[i]=src->key[i];
        memcpy(dst->key, key, OFPSC_MAX_KEY_LEN);
        OFL_LOG_WARN(LOG_MODULE, "key count is %d\n",dst->key_len);
        OFL_LOG_WARN(LOG_MODULE, "state is %d\n",dst->state);
        OFL_LOG_WARN(LOG_MODULE, "state_mask is %d\n",dst->state_mask);  
    }
    else
    { //control of struct ofp_extraction length.
       OFL_LOG_WARN(LOG_MODULE, "Received state mod add flow is too short (%zu).", *len);
       return ofl_error(OFPET_BAD_ACTION, OFPBAC_BAD_LEN);
    }
 

    *len -= (3*sizeof(uint32_t) + ntohl(src->key_len)*sizeof(uint8_t));
 
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
                struct ofp_exp_message_state_mod *sm;
                struct ofl_exp_msg_state_mod *dm;
                
                if (*len < sizeof(struct ofp_exp_message_state_mod)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }

                *len -= sizeof(struct ofp_experimenter_header);

                sm = (struct ofp_exp_message_state_mod *)exp_header;
                dm = (struct ofl_exp_msg_state_mod *)malloc(sizeof(struct ofl_exp_msg_state_mod));
                
                if (sm->table_id >= PIPELINE_TABLES) {
                    OFL_LOG_WARN(LOG_MODULE, "Received STATE_MOD message has invalid table id (%zu).", sm->table_id );
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
                } 
                
                dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
                dm->header.type                   = ntohl(exp_header->exp_type);
                dm->table_id = sm->table_id;
                dm->command = (enum ofp_exp_message_state_mod_commands)sm->command;
                
                *len -= sizeof(dm->table_id) + 1;

                
                if (dm->command == OFPSC_SET_FLOW_STATE || dm->command == OFPSC_DEL_FLOW_STATE){
                error = ofl_structs_key_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                } 

                else if(dm->command == OFPSC_SET_L_EXTRACTOR || dm->command == OFPSC_SET_U_EXTRACTOR){
                error = ofl_structs_extraction_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                }

                else if(dm->command == OFPSC_STATEFULNESS_CONFIG){
                error = ofl_structs_statefulness_config_unpack(&(sm->payload[0]), len, &(dm->payload[0]));
                    if (error) {
                        free(dm);
                        return error;
                    }

                }


                (*msg) = (struct ofl_msg_experimenter *)dm;
                return 0;
            }

            case (OFPT_EXT_FLAG_MOD): 
            {
                struct ofp_exp_message_flag_mod *sm;
                struct ofl_exp_msg_flag_mod *dm;
                              
                if (*len < sizeof(struct ofp_exp_message_flag_mod)) {
                    OFL_LOG_WARN(LOG_MODULE, "Received FLAG_MOD message has invalid length (%zu).", *len);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
                }
                sm = (struct ofp_exp_message_flag_mod *)exp_header;
                dm = (struct ofl_exp_msg_flag_mod *)malloc(sizeof(struct ofl_exp_msg_flag_mod));
                
                *len -= sizeof(struct ofp_exp_message_flag_mod);

                dm->header.header.experimenter_id = ntohl(exp_header->experimenter);
                dm->header.type                   = ntohl(exp_header->exp_type);
                dm->flag = ntohl(sm->flag);
                dm->flag_mask = ntohl(sm->flag_mask);
                dm->command = (enum ofp_exp_message_flag_mod_command)sm->command;
            
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
                char *string = malloc(80);
                sprintf(string, "{set_state=[state=\"%u\",state_mask=\"%"PRIu32"\",table_id=\"%u\"]}", a->state, a->state_mask, a->table_id);
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
            memset(stats->pad, 0x00, 7);
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
ofl_exp_openstate_stats_req_unpack(struct ofp_multipart_request *os, uint8_t *buf, size_t *len, struct ofl_msg_multipart_request_header **msg, struct ofl_exp *exp) {
    
    struct ofp_experimenter_stats_header *ext = (struct ofp_experimenter_stats_header *)os->body;    
    switch (ntohl(ext->exp_type)){
        case (OFPMP_EXP_STATE_STATS):
        {    
            struct ofp_exp_state_stats_request *sm;
            struct ofl_exp_msg_multipart_request_state *dm;
            ofl_err error = 0;
            int match_pos;

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
            match_pos = sizeof(struct ofp_multipart_request) + sizeof(struct ofp_exp_state_stats_request) - 4;
            /*TODO pollins: la funzione commentata è quella che non fa il check dei prerequisiti*/
            //error = ofl_structs_match_unpack_no_prereqs(&(sm->match),buf + match_pos, len, &(dm->match), exp);
            error = ofl_structs_match_unpack(&(sm->match),buf + match_pos, len, &(dm->match), exp);
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
ofl_exp_openstate_stats_reply_unpack(struct ofp_multipart_reply *os, uint8_t *buf, size_t *len, struct ofl_msg_multipart_request_header **msg, struct ofl_exp *exp) {

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

            *msg = (struct ofl_msg_header *)dm;
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
            ofl_structs_match_put32e(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)));
            return 0;
        }
        case OFI_OXM_EXP_STATE_W:{
            if (check_bad_wildcard32(ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)))){
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_WILDCARDS);
            }
            ofl_structs_match_put32me(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)));
            return 0;
        }
        case OFI_OXM_EXP_FLAGS:{
            ofl_structs_match_put32e(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)));
            return 0;
        }
        case OFI_OXM_EXP_FLAGS_W:{
            if (check_bad_wildcard32(ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)))){
                return ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_WILDCARDS);
            }
            ofl_structs_match_put32me(match, f->header, ntohl(*((uint32_t*) experimenter_id)), ntohl(*((uint32_t*) value)), ntohl(*((uint32_t*) mask)));
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

/*experimenter table functions*/

int __extract_key(uint8_t *, struct key_extractor *, struct packet *);

struct state_table * state_table_create(void) {
    struct state_table *table = malloc(sizeof(struct state_table));
    memset(table, 0, sizeof(*table));
     
    table->state_entries = (struct hmap) HMAP_INITIALIZER(&table->state_entries);

    /* default state entry */
    table->default_state_entry.state = STATE_DEFAULT;

    table->statefulness = 0;
    
    return table;
}

uint8_t state_table_is_stateful(struct state_table *table){
    return table->statefulness;
}

void state_table_configure_statefulness(struct state_table *table, uint8_t statefulness){
    if (statefulness!=0)
        table->statefulness = 1;
    else
        table->statefulness = 0;
}

void state_table_destroy(struct state_table *table) {
    hmap_destroy(&table->state_entries);
    free(table);
}
/* having the key extractor field goes to look for these key inside the packet and map to corresponding value and copy the value into buf. */ 
int __extract_key(uint8_t *buf, struct key_extractor *extractor, struct packet *pkt) {
    int i, l=0, a=0;
    struct ofl_match_tlv *f;

    for (i=0; i<extractor->field_count; i++) {
        uint32_t type = (int)extractor->fields[i];
        HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv,
            hmap_node, hash_int(type, 0), &pkt->handle_std->match.match_fields){
                if (type == f->header) {
                    memcpy(&buf[l], f->value, OXM_LENGTH(f->header));
                    l = l + OXM_LENGTH(f->header);//keeps only 8 last bits of oxm_header that contains oxm_length(in which length of oxm_payload)
                    break;
                }
        }   
    }
    /*check if the full key has been extracted*/
    for (i=0; i<extractor->field_count; i++) {
        uint32_t type = (int)extractor->fields[i];
        a = a + OXM_LENGTH(type);
    }
    if (l==a)
        return 1;
    else
        return 0;
}
/*having the read_key, look for the state vaule inside the state_table */
struct state_entry * state_table_lookup(struct state_table* table, struct packet *pkt) {
    struct state_entry * e = NULL;  
    uint8_t key[MAX_STATE_KEY_LEN] = {0};

    if(!__extract_key(key, &table->read_key, pkt))
    {
        OFL_LOG_WARN(LOG_MODULE, "lookup key fields not found in the packet's header -> NULL");
        return NULL;
    }

    
    HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
        hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
            if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
                OFL_LOG_WARN(LOG_MODULE, "found corresponding state %u",e->state);
                return e;
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
                int32_t *state = (uint32_t*) (f->value + EXP_ID_LEN);
                *state = (*state & 0x00000000) | (entry->state);
    }
}
void state_table_del_state(struct state_table *table, uint8_t *key, uint32_t len) {
    struct state_entry *e;
    int found = 0;

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
                found = 1;
                break;
            }
    }
    if (found)
        hmap_remove_and_shrink(&table->state_entries, &e->hmap_node);
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

    memcpy(dest->fields, ke->fields, 4*ke->field_count);
    return;
}

void state_table_set_state(struct state_table *table, struct packet *pkt, uint32_t state, uint32_t state_mask, uint8_t *k, uint32_t len) {
    uint8_t key[MAX_STATE_KEY_LEN] = {0};   
    struct state_entry *e;

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
        if(!__extract_key(key, &table->write_key, pkt)){
            OFL_LOG_WARN(LOG_MODULE, "lookup key fields not found in the packet's header");
            return;
        }
    }
            

    else {
        //SET_STATE message

        if(key_len == len)
        {
            memcpy(key, k, MAX_STATE_KEY_LEN);
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
                if(((e->state & ~(state_mask)) | (state & state_mask)) == STATE_DEFAULT)
                   state_table_del_state(table, k, len);
                else
                   e->state = (e->state & ~(state_mask)) | (state & state_mask);
                return;
            }
    }

    if((state & state_mask) != STATE_DEFAULT)
    {
        e = malloc(sizeof(struct state_entry));
        memcpy(e->key, key, MAX_STATE_KEY_LEN);
        e->state = state & state_mask;
        OFL_LOG_WARN(LOG_MODULE, "state value is %u inserted to hash map", e->state);
        hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
    }
}

/*handling functions*/
ofl_err
handle_flag_mod(struct pipeline *pl, struct ofl_exp_msg_flag_mod *msg,
                                                const struct sender *sender) {
    
    uint32_t global_states = pl->dp->global_states;

    if (msg->command == OFPSC_MODIFY_FLAGS) {
        global_states = (global_states & ~(msg->flag_mask)) | (msg->flag & msg->flag_mask);
        pl->dp->global_states = global_states;
    }
    else if (msg->command == OFPSC_RESET_FLAGS) {
        pl->dp->global_states = OFP_GLOBAL_STATES_DEFAULT;
    }
    else
        return 1;
    return 0;
}

ofl_err
handle_state_mod(struct pipeline *pl, struct ofl_exp_msg_state_mod *msg,
                                                const struct sender *sender) {
    
    struct state_table *st = pl->tables[msg->table_id]->state_table;

    if (msg->command == OFPSC_SET_L_EXTRACTOR || msg->command == OFPSC_SET_U_EXTRACTOR) {
        struct ofl_exp_msg_extraction *p = (struct ofl_exp_msg_extraction *) msg->payload;  
        int update = 0;
        if (msg->command == OFPSC_SET_U_EXTRACTOR) 
            update = 1;
        state_table_set_extractor(st, (struct key_extractor *)p, update);
    }
    else if (msg->command == OFPSC_SET_FLOW_STATE) {
        if (state_table_is_stateful(st)){
            struct ofl_exp_msg_state_entry *p = (struct ofl_exp_msg_state_entry *) msg->payload;
            state_table_set_state(st, NULL, p->state, p->state_mask, p->key, p->key_len);
        }
        else{
            OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful", msg->table_id);
        }
    }
    else if (msg->command == OFPSC_DEL_FLOW_STATE) {
        if (state_table_is_stateful(st)){
            struct ofl_exp_msg_state_entry *p = (struct ofl_exp_msg_state_entry *) msg->payload;
            state_table_del_state(st, p->key, p->key_len);
        }
        else{
             OFL_LOG_WARN(LOG_MODULE, "ERROR STATE MOD at stage %u: stage not stateful", msg->table_id);
        }

    }
    else if (msg->command == OFPSC_STATEFULNESS_CONFIG) {
        struct ofl_exp_msg_statefulness_config *p = (struct ofl_exp_msg_state_entry *) msg->payload;
        state_table_configure_statefulness(st, p->statefulness);
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
            if (state_table_is_stateful(pl->tables[i]->state_table))
                state_table_stats(pl->tables[i]->state_table, msg, &stats, &stats_size, &stats_num, i);
        }
    } else {
        if (state_table_is_stateful(pl->tables[msg->table_id]->state_table))
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
        
            if(found)
            {
                (*stats)[(*stats_num)] = malloc(sizeof(struct ofl_exp_state_stats));
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
    (*stats_num)++;
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
    state_stats->pad = 0;
    state_stats->field_count = htonl(src->field_count);
    
    for (i=0;i<src->field_count;i++)
           state_stats->fields[i]=htonl(src->fields[i]);
    state_stats->entry.key_len = htonl(src->entry.key_len);   
    for (i=0;i<src->entry.key_len;i++)
           state_stats->entry.key[i]=src->entry.key[i];
    state_stats->entry.state = htonl(src->entry.state);
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
        OFL_LOG_WARN(LOG_MODULE, "Received flow stats has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (*len < ntohs(src->length)) {
        OFL_LOG_WARN(LOG_MODULE, "Received flow stats reply has invalid length (set to %u, but only %zu received).", ntohs(src->length), *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
    }

    if (src->table_id >= PIPELINE_TABLES) {
        if (OFL_LOG_IS_WARN_ENABLED(LOG_MODULE)) {
            char *ts = ofl_table_to_string(src->table_id);
            OFL_LOG_WARN(LOG_MODULE, "Received flow stats has invalid table_id (%s).", ts);
            free(ts);
        }
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_TABLE_ID);
    }

    slen = ntohs(src->length) - sizeof(struct ofp_exp_state_stats);

    s = (struct ofl_state_stats *)malloc(sizeof(struct ofl_exp_state_stats));
    s->table_id =  src->table_id;
    s->field_count = ntohl(src->field_count);
    for (i=0;i<s->field_count;i++)
               s->fields[i]=ntohl(src->fields[i]);

    s->entry.key_len = ntohl(src->entry.key_len);
    for (i=0;i<s->entry.key_len;i++)
               s->entry.key[i]=src->entry.key[i];
    s->entry.state = ntohl(src->entry.state);
    
    if (slen != 0) {
        *len = *len - ntohs(src->length) + slen;
        OFL_LOG_WARN(LOG_MODULE, "The received flow stats contained extra bytes (%zu).", slen);
        ofl_structs_free_flow_stats(s, exp);
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

/*
ofl_err
ofl_structs_match_unpack_no_prereqs(struct ofp_match *src,uint8_t * buf, size_t *len, struct ofl_match_header **dst, struct ofl_exp *exp) {

    switch (ntohs(src->type)) {
        case (OFPMT_OXM): {
             return ofl_structs_oxm_match_unpack_no_prereqs(src, buf, len, (struct ofl_match**) dst );               
        }
        default: {
            if (exp == NULL || exp->match == NULL || exp->match->unpack == NULL) {
                OFL_LOG_WARN(LOG_MODULE, "Received match is experimental, but no callback was given.");
                return ofl_error(OFPET_BAD_MATCH, OFPBMC_BAD_TYPE);
            }
            return exp->match->unpack(src, len, dst);
        }
    }
}


ofl_err
ofl_structs_oxm_match_unpack_no_prereqs(struct ofp_match* src, uint8_t* buf, size_t *len, struct ofl_match **dst){

     int error = 0;
     struct ofpbuf *b = ofpbuf_new(0);
     struct ofl_match *m = (struct ofl_match *) malloc(sizeof(struct ofl_match));
    *len -= ROUND_UP(ntohs(src->length),8);
     if(ntohs(src->length) > sizeof(struct ofp_match)){
         ofpbuf_put(b, buf, ntohs(src->length) - (sizeof(struct ofp_match) -4)); 
         error = oxm_pull_match_no_prereqs(b, m, ntohs(src->length) - (sizeof(struct ofp_match) -4));
         m->header.length = ntohs(src->length) - 4;
     }
    else {
         m->header.length = 0;
         m->header.type = ntohs(src->type);
         m->match_fields = (struct hmap) HMAP_INITIALIZER(&m->match_fields);    
    }
    ofpbuf_delete(b);    
    *dst = m;
    return error;
}



/* Puts the match in a hash_map structure */
/*
int
oxm_pull_match_no_prereqs(struct ofpbuf *buf, struct ofl_match * match_dst, int match_len)
{

    uint32_t header;
    uint8_t *p;
    p = ofpbuf_try_pull(buf, match_len);

    if (!p) {
         OFL_LOG_WARN(LOG_MODULE, "oxm_match length %u, rounded up to a "
                    "multiple of 8, is longer than space in message (max "
                    "length %zd)", match_len, buf->size);

        return ofp_mkerr(OFPET_BAD_MATCH, OFPBRC_BAD_LEN);
    }

    /* Initialize the match hashmap */
 /*   ofl_structs_match_init(match_dst);

    while ((header = oxm_entry_ok(p, match_len)) != 0) {

        unsigned length = OXM_LENGTH(header);
        const struct oxm_field *f;
        int error;
        f = oxm_field_lookup(header);

        if (!f) {
            error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_FIELD);
        }
        else if (OXM_HASMASK(header) && !f->maskable){
            error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_MASK);
        }
        else if (check_oxm_dup(match_dst,f)){
            error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_DUP_FIELD);
        }
        else {
            switch (OXM_VENDOR(header))
              {
                    case(OFPXMC_OPENFLOW_BASIC):
                        /* 'hasmask' and 'length' are known to be correct at this point
                         * because they are included in 'header' and oxm_field_lookup()
                         * checked them already. */
                      /*  error = parse_oxm_entry(match_dst, f, p + 4, p + 4 + length / 2);
                        break;
                    case(OFPXMC_EXPERIMENTER):
                        /* 'hasmask' and 'length' are known to be correct at this point
                         * because they are included in 'header' and oxm_field_lookup()
                         * checked them already. */
                         //parse_exp_oxm_entry accepts match, oxm_fields, experimenter_id, value and mask
                         //sizeof(header) is 4 byte
                         //sizeof(experimenter_id) is 4 byte
                         //experimenter_id is @ p + 4 (p + header)
                         //value is @ p + 8 (p + header + experimenter_id)
                         //mask depends on field's size
                      /*  error = parse_exp_oxm_entry(match_dst, f, p + 4, p + 8, p + 8 + (length-4) / 2);
                        break;
                    default:
                        error = ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_FIELD);
              }
        }
        if (error) {
             OFL_LOG_WARN(LOG_MODULE, "bad oxm_entry with vendor=%"PRIu32", "
                        "field=%"PRIu32", hasmask=%"PRIu32", type=%"PRIu32" "
                        "(error %x)",
                        OXM_VENDOR(header), OXM_FIELD(header),
                        OXM_HASMASK(header), OXM_TYPE(header),
                        error);
            return error;
        }
        p += 4 + length;
        match_len -= 4 + length;
    }
    return match_len ? ofp_mkerr(OFPET_BAD_MATCH, OFPBMC_BAD_LEN) : 0;
}

*/

/*Functions used by experimenter match fields*/

void
ofl_structs_match_put8e(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint8_t value){
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
ofl_structs_match_put8me(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint8_t value, uint8_t mask){
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
ofl_structs_match_put16e(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint16_t value){
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
ofl_structs_match_put16me(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint16_t value, uint16_t mask){
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
ofl_structs_match_put32e(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint32_t value){
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
ofl_structs_match_put32me(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint32_t value, uint32_t mask){
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
ofl_structs_match_put64e(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint64_t value){
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
ofl_structs_match_put64me(struct ofl_match *match, uint32_t header, uint32_t experimenter_id, uint64_t value, uint64_t mask){
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

