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
ofl_structs_key_unpack(struct ofp_exp_state_entry *src, size_t *len, struct ofl_exp_msg_state_entry *dst) {
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
        int i;
        uint32_t key_len=0; //update-scope key extractor length
        struct key_extractor *extractor=&table->write_key;
        for (i=0; i<extractor->field_count; i++) {
            uint32_t type = (int)extractor->fields[i];
            key_len = key_len + OXM_LENGTH(type);
         }
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