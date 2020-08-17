/* Copyright (c) 2008, 2009 The Board of Trustees of The Leland Stanford
 * Junior University
 *
 * We are making the OpenFlow specification and associated documentation
 * (Software) available for public use and benefit with the expectation
 * that others will use, modify and enhance the Software and contribute
 * those enhancements back to the community. However, since we would
 * like to make the Software available for broadest use, with as few
 * restrictions as possible permission is hereby granted, free of
 * charge, to any person obtaining a copy of this Software to deal in
 * the Software under the copyrights without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT.  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * The name and trademarks of copyright holder(s) may NOT be used in
 * advertising or publicity pertaining to the Software or any
 * derivatives without specific, written prior permission.
 */

#include <config.h>
#include "mac-learning.h"

#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

#include "hash.h"
#include "list.h"
#include "openflow/openflow.h"
#include "poll-loop.h"
#include "tag.h"
#include "timeval.h"
#include "util.h"

#define LOG_MODULE VLM_mac_learning
#include "vlog.h"

#define MAC_HASH_BITS 10
#define MAC_HASH_MASK (MAC_HASH_SIZE - 1)
#define MAC_HASH_SIZE (1u << MAC_HASH_BITS)

#define MAC_MAX 1024

/* A MAC learning table entry. */
struct mac_entry {
    struct list hash_node;      /* Element in a mac_learning 'table' list. */
    struct list lru_node;       /* Element in 'lrus' or 'free' list. */
    time_t expires;             /* Expiration time. */
    uint8_t mac[ETH_ADDR_LEN];  /* Known MAC address. */
    uint16_t vlan;              /* VLAN tag. */
    int port;                   /* Port on which MAC was most recently seen. */
    tag_type tag;               /* Tag for this learning entry. */
};

/* MAC learning table. */
struct mac_learning {
    struct list free;           /* Not-in-use entries. */
    struct list lrus;           /* In-use entries, least recently used at the
                                   front, most recently used at the back. */
    struct list table[MAC_HASH_SIZE]; /* Hash table. */
    struct mac_entry entries[MAC_MAX]; /* All entries. */
    uint32_t secret;            /* Secret for  */
};

static uint32_t
mac_table_hash(const uint8_t mac[ETH_ADDR_LEN], uint16_t vlan)
{
    return hash_bytes(mac, ETH_ADDR_LEN, vlan);
}

static struct mac_entry *
mac_entry_from_lru_node(struct list *list)
{
    return CONTAINER_OF(list, struct mac_entry, lru_node);
}

/* Returns a tag that represents that 'mac' is on an unknown port in 'vlan'.
 * (When we learn where 'mac' is in 'vlan', this allows flows that were
 * flooded to be revalidated.) */
static tag_type
make_unknown_mac_tag(const struct mac_learning *ml,
                     const uint8_t mac[ETH_ADDR_LEN], uint16_t vlan)
{
    uint32_t h = hash_bytes(&ml->secret, sizeof ml->secret,
                            mac_table_hash(mac, vlan));
    return tag_create_deterministic(h);
}

static struct list *
mac_table_bucket(const struct mac_learning *ml,
                 const uint8_t mac[ETH_ADDR_LEN],
                 uint16_t vlan)
{
    uint32_t hash = mac_table_hash(mac, vlan);
    const struct list *list = &ml->table[hash & MAC_HASH_BITS];
    return CONST_CAST(struct list *, list);
}

static struct mac_entry *
search_bucket(struct list *bucket, const uint8_t mac[ETH_ADDR_LEN],
              uint16_t vlan)
{
    struct mac_entry *e;
    LIST_FOR_EACH (e, struct mac_entry, hash_node, bucket) {
        if (eth_addr_equals(e->mac, mac) && e->vlan == vlan) {
            return e;
        }
    }
    return NULL;
}

/* If the LRU list is not empty, stores the least-recently-used entry in '*e'
 * and returns true.  Otherwise, if the LRU list is empty, stores NULL in '*e'
 * and return false. */
static bool
get_lru(struct mac_learning *ml, struct mac_entry **e)
{
    if (!list_is_empty(&ml->lrus)) {
        *e = mac_entry_from_lru_node(ml->lrus.next);
        return true;
    } else {
        *e = NULL;
        return false;
    }
}

/* Removes 'e' from the 'ml' hash table.  'e' must not already be on the free
 * list. */
static void
free_mac_entry(struct mac_learning *ml, struct mac_entry *e)
{
    list_remove(&e->hash_node);
    list_remove(&e->lru_node);
    list_push_front(&ml->free, &e->lru_node);
}

/* Creates and returns a new MAC learning table. */
struct mac_learning *
mac_learning_create(void)
{
    struct mac_learning *ml;
    int i;

    ml = xmalloc(sizeof *ml);
    list_init(&ml->lrus);
    list_init(&ml->free);
    for (i = 0; i < MAC_HASH_SIZE; i++) {
        list_init(&ml->table[i]);
    }
    for (i = 0; i < MAC_MAX; i++) {
        struct mac_entry *s = &ml->entries[i];
        list_push_front(&ml->free, &s->lru_node);
    }
    ml->secret = random_uint32();
    return ml;
}

/* Destroys MAC learning table 'ml'. */
void
mac_learning_destroy(struct mac_learning *ml)
{
    free(ml);
}

/* Attempts to make 'ml' learn from the fact that a frame from 'src_mac' was
 * just observed arriving from 'src_port' on the given 'vlan'.
 *
 * Returns nonzero if we actually learned something from this, zero if it just
 * confirms what we already knew.  The nonzero return value is the tag of flows
 * that now need revalidation.
 *
 * The 'vlan' parameter is used to maintain separate per-VLAN learning tables.
 * Specify 0 if this behavior is undesirable. */
tag_type
mac_learning_learn(struct mac_learning *ml,
                   const uint8_t src_mac[ETH_ADDR_LEN], uint16_t vlan,
                   uint16_t src_port)
{
    struct mac_entry *e;
    struct list *bucket;

    if (eth_addr_is_multicast(src_mac)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(30, 30);
        VLOG_DBG_RL(LOG_MODULE, &rl, "multicast packet source "ETH_ADDR_FMT,
                    ETH_ADDR_ARGS(src_mac));
        return 0;
    }

    bucket = mac_table_bucket(ml, src_mac, vlan);
    e = search_bucket(bucket, src_mac, vlan);
    if (!e) {
        if (!list_is_empty(&ml->free)) {
            e = mac_entry_from_lru_node(ml->free.next);
        } else {
            e = mac_entry_from_lru_node(ml->lrus.next);
            list_remove(&e->hash_node);
        }
        memcpy(e->mac, src_mac, ETH_ADDR_LEN);
        list_push_front(bucket, &e->hash_node);
        e->port = -1;
        e->vlan = vlan;
        e->tag = make_unknown_mac_tag(ml, src_mac, vlan);
    }

    /* Make the entry most-recently-used. */
    list_remove(&e->lru_node);
    list_push_back(&ml->lrus, &e->lru_node);
    e->expires = time_now() + 60;

    /* Did we learn something? */
    if (e->port != src_port) {
        tag_type old_tag = e->tag;
        e->port = src_port;
        e->tag = tag_create_random();
        return old_tag;
    }
    return 0;
}

/* Looks up MAC 'dst' for VLAN 'vlan' in 'ml'.  Returns the port on which a
 * frame destined for 'dst' should be sent, OFPP_FLOOD if unknown. */
uint16_t
mac_learning_lookup(const struct mac_learning *ml,
                    const uint8_t dst[ETH_ADDR_LEN], uint16_t vlan)
{
    tag_type tag = 0;
    return mac_learning_lookup_tag(ml, dst, vlan, &tag);
}

/* Looks up MAC 'dst' for VLAN 'vlan' in 'ml'.  Returns the port on which a
 * frame destined for 'dst' should be sent, OFPP_FLOOD if unknown.
 *
 * Adds to '*tag' (which the caller must have initialized) the tag that should
 * be attached to any flow created based on the return value, if any, to allow
 * those flows to be revalidated when the MAC learning entry changes. */
uint32_t
mac_learning_lookup_tag(const struct mac_learning *ml,
                        const uint8_t dst[ETH_ADDR_LEN], uint16_t vlan,
                        tag_type *tag)
{
    if (eth_addr_is_multicast(dst)) {
        return OFPP_FLOOD;
    } else {
        struct mac_entry *e = search_bucket(mac_table_bucket(ml, dst, vlan),
                                            dst, vlan);
        if (e) {
            *tag |= e->tag;
            return e->port;
        } else {
            *tag |= make_unknown_mac_tag(ml, dst, vlan);
            return OFPP_FLOOD;
        }
    }
}

/* Expires all the mac-learning entries in 'ml'.  The tags in 'ml' are
 * discarded, so the client is responsible for revalidating any flows that
 * depend on 'ml', if necessary. */
void
mac_learning_flush(struct mac_learning *ml)
{
    struct mac_entry *e;
    while (get_lru(ml, &e)){
        free_mac_entry(ml, e);
    }
}

void
mac_learning_run(struct mac_learning *ml, struct tag_set *set)
{
    struct mac_entry *e;
    while (get_lru(ml, &e) && time_now() >= e->expires) {
        if (set) {
            tag_set_add(set, e->tag);
        }
        free_mac_entry(ml, e);
    }
}

void
mac_learning_wait(struct mac_learning *ml)
{
    if (!list_is_empty(&ml->lrus)) {
        struct mac_entry *e = mac_entry_from_lru_node(ml->lrus.next);
        poll_set_timer_wait((e->expires - time_now()) * 1000);
    }
}
