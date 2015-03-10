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
		hmap_node, hash_int(OXM_EXP_STATE,0), &pkt->handle_std->match.match_fields){
                uint32_t *state = (uint32_t*) f->value;
                *state = (*state & 0x0) | (entry->state);
    }
}
void state_table_del_state(struct state_table *table, uint8_t *key, uint32_t len) {
	struct state_entry *e;
	int found = 0;

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
		dest = &table->write_key;
                printf("writing key\n");
		}
	else{
		dest = &table->read_key;
                printf("reading key\n");
		}
	dest->field_count = ke->field_count;

	memcpy(dest->fields, ke->fields, 4*ke->field_count);
	return;
}

void state_table_set_state(struct state_table *table, struct packet *pkt, uint32_t state, uint8_t *k, uint32_t len) {
	uint8_t key[MAX_STATE_KEY_LEN] = {0};	
	struct state_entry *e;
	//FILE *pFile;
    //pFile = fopen("/tmp/myfile.txt","a+");
		

	if (pkt)
	{	
		//SET_STATE action
		//fprintf(pFile,"\nstate mod: Key_len = %"PRIu32", state = %"PRIu32"", len, state);
		if(!__extract_key(key, &table->write_key, pkt)){
			VLOG_WARN_RL(LOG_MODULE, &rl, "lookup key fields not found in the packet's header");
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
	    /*FILE *pFile;
			pFile = fopen ("/tmp/myfile.txt","a+");
			fprintf(pFile,"\nlunghezza extractor %"PRIu32":", key_len);
			fprintf(pFile,"\nlen passata alla funzione %"PRIu32":", len);
			fclose(pFile);*/
	    if(key_len == len)
	    {
			memcpy(key, k, MAX_STATE_KEY_LEN);
	    }
	    else
	    {
	    	VLOG_WARN_RL(LOG_MODULE, &rl, "Wrong key length received");
	    	return;
	    }
	}
	
	HMAP_FOR_EACH_WITH_HASH(e, struct state_entry, 
		hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0), &table->state_entries){
			if (!memcmp(key, e->key, MAX_STATE_KEY_LEN)){
				VLOG_WARN_RL(LOG_MODULE, &rl, "state value is %u updated to hash map", state);
				e->state = state;
				return;
			}
	}

	e = malloc(sizeof(struct state_entry));
	memcpy(e->key, key, MAX_STATE_KEY_LEN);
	e->state = state;
	VLOG_WARN_RL(LOG_MODULE, &rl, "state value is %u inserted to hash map", e->state);
        hmap_insert(&table->state_entries, &e->hmap_node, hash_bytes(key, MAX_STATE_KEY_LEN, 0));
}