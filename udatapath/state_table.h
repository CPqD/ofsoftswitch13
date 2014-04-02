#ifndef STATE_TABLE_H
#define STATE_TABLE_H 1

#include "hmap.h"
#include "packet.h"

#define MAX_EXTRACTION_FIELD_COUNT 8
#define MAX_STATE_KEY_LEN 48

#define STATE_DEFAULT 0

struct key_extractor {
	uint32_t    				field_count;
//	uint8_t 					fields[MAX_EXTRACTION_FIELD_COUNT];
	uint32_t 					fields[MAX_EXTRACTION_FIELD_COUNT];
};

struct state_entry {
    struct hmap_node 			hmap_node;
    uint8_t				key[MAX_STATE_KEY_LEN];
    //uint32_t				state;
    uint64_t 				state;
};

struct state_table {
    struct key_extractor		read_key;
    struct key_extractor 		write_key;
    struct hmap					state_entries; 
	struct state_entry			default_state_entry;
};


struct state_table * state_table_create(void);
void state_table_destroy(struct state_table *);
struct state_entry * state_table_lookup(struct state_table*, struct packet *);
void state_table_write_metadata(struct state_entry *, struct packet *);
void state_table_set_state(struct state_table *, struct packet *, uint32_t, uint8_t *, uint32_t);
void state_table_set_extractor(struct state_table *, struct key_extractor *, int);
void state_table_del_state(struct state_table *, uint8_t *, uint32_t);
#endif /* FLOW_TABLE_H */
