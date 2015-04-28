#include "state_table.h"
#include "oflib/ofl-structs.h" 
#include "oflib/oxm-match.h"
#include "lib/hash.h"

#include <sys/types.h>
#include <sys/socket.h>

#include "vlog.h"

#define LOG_MODULE VLM_pipeline

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(6000000, 60000000);

int __extract_key(uint8_t *, struct key_extractor *, struct packet *);

struct state_table * state_table_create(void) {
    struct state_table *table = malloc(sizeof(struct state_table));
	memset(table, 0, sizeof(*table));
	 
    table->state_entries = (struct hmap) HMAP_INITIALIZER(&table->state_entries);

	/* default state entry */
	table->default_state_entry.state = STATE_DEFAULT;
	
    return table;
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
    	VLOG_WARN_RL(LOG_MODULE, &rl, "lookup key fields not found in the packet's header -> NULL");
    	return NULL;
    }

 	
	HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
		hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
			if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
				VLOG_WARN_RL(LOG_MODULE, &rl, "found corresponding state %u",e->state);
				return e;
			}
	}

	if (e == NULL)
	{	 
		VLOG_WARN_RL(LOG_MODULE, &rl, "not found the corresponding state value\n");
		return &table->default_state_entry;
	}
	else 
		return e;
}
/* having the state value  */
void state_table_write_state(struct state_entry *entry, struct packet *pkt) {
	struct  ofl_match_tlv *f;
    
	HMAP_FOR_EACH_WITH_HASH(f, struct ofl_match_tlv, 
		hmap_node, hash_int(OXM_OF_STATE,0), &pkt->handle_std->match.match_fields){
                uint32_t *state = (uint32_t*) f->value;
                *state = (*state & 0x0) | (entry->state);
    }
}
void state_table_del_state(struct state_table *table, uint8_t *key, uint32_t len, uint8_t table_id, struct datapath *dp) {
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
    	VLOG_WARN_RL(LOG_MODULE, &rl, "key extractor length != received key length");
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
	{
		hmap_remove_and_shrink(&table->state_entries, &e->hmap_node);
		{
		    /* Notify the controllers that this port has been added */
		    struct ofl_msg_state_notification msg =
		            {{.type = OFPT_STATE_NOTIFICATION},
		             .table_id = table_id, .state = STATE_DEFAULT,
		         	 .key_length = key_len, .key = key};

		    dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL/*sender*/);
		}
	}

}

void state_table_set_extractor(struct state_table *table, struct key_extractor *ke, int update) {
	struct key_extractor *dest;
	if (update){
		if (table->read_key.field_count!=0){
			if (table->read_key.field_count != ke->field_count){
				VLOG_WARN_RL(LOG_MODULE, &rl, "Update-scope should provide same length keys of lookup-scope: %d vs %d\n",ke->field_count,table->read_key.field_count);
				return;
			}
		}
		dest = &table->write_key;
        VLOG_WARN_RL(LOG_MODULE, &rl, "Update-scope set");
		}
	else{
		if (table->write_key.field_count!=0){
			if (table->write_key.field_count != ke->field_count){
				VLOG_WARN_RL(LOG_MODULE, &rl, "Lookup-scope should provide same length keys of update-scope: %d vs %d\n",ke->field_count,table->write_key.field_count);
				return;
			}
		}
		dest = &table->read_key;
        VLOG_WARN_RL(LOG_MODULE, &rl, "Lookup-scope set");
		}
	dest->field_count = ke->field_count;

	memcpy(dest->fields, ke->fields, 4*ke->field_count);
	return;
}

void state_table_set_state(struct state_table *table, struct packet *pkt, uint32_t state, uint32_t state_mask, uint8_t *k, uint32_t len, uint8_t table_id, struct datapath *dp) {
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
			VLOG_WARN_RL(LOG_MODULE, &rl, "lookup key fields not found in the packet's header");
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
	    	VLOG_WARN_RL(LOG_MODULE, &rl, "key extractor length != received key length");
	    	return;
	    }
	}
	
	HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
		hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
			if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
				VLOG_WARN_RL(LOG_MODULE, &rl, "state value is %u updated to hash map", state);
				if(((e->state & ~(state_mask)) | (state & state_mask)) == STATE_DEFAULT)
					state_table_del_state(table, key, key_len, table_id, dp);
				else
				{
					if (e->state != ((e->state & ~(state_mask)) | (state & state_mask)))
					{
						e->state = (e->state & ~(state_mask)) | (state & state_mask);
						{
					    /* Notify the controllers that this port has been added */
					    struct ofl_msg_state_notification msg =
					            {{.type = OFPT_STATE_NOTIFICATION},
					             .table_id = table_id, .state = e->state,
					         	 .key_length = key_len, .key = key};

					    dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL/*sender*/);
					    }
					}
				}
				return;
			}
	}
	if((state & state_mask) != STATE_DEFAULT)
	{
		e = malloc(sizeof(struct state_entry));
		memcpy(e->key, key, MAX_STATE_KEY_LEN);
		e->state = state & state_mask;
		VLOG_WARN_RL(LOG_MODULE, &rl, "state value is %u inserted to hash map", e->state);
	    hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
	    {
		    /* Notify the controllers that this port has been added */
		    struct ofl_msg_state_notification msg =
		            {{.type = OFPT_STATE_NOTIFICATION},
		             .table_id = table_id, .state = e->state,
		         	 .key_length = key_len, .key = key};

		    dp_send_message(dp, (struct ofl_msg_header *)&msg, NULL/*sender*/);
		}
	}
}

void
state_table_stats(struct state_table *table, struct ofl_msg_multipart_request_state *msg,
                 struct ofl_state_stats ***stats, size_t *stats_size, size_t *stats_num, uint8_t table_id) {
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
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_state_stats *)) * (*stats_size) * 2);
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
			    (*stats)[(*stats_num)] = malloc(sizeof(struct ofl_state_stats));
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
                (*stats) = xrealloc(*stats, (sizeof(struct ofl_state_stats *)) * (*stats_size) * 2);
                *stats_size *= 2;
    }
    (*stats)[(*stats_num)] = malloc(sizeof(struct ofl_state_stats));
    for (i=0;i<extractor->field_count;i++)
    	(*stats)[(*stats_num)]->fields[i]=fields[i];
	(*stats)[(*stats_num)]->table_id = table_id;
	(*stats)[(*stats_num)]->field_count = extractor->field_count;           		
    (*stats)[(*stats_num)]->entry.key_len = 0;
    (*stats)[(*stats_num)]->entry.state = STATE_DEFAULT;
    (*stats_num)++;
}