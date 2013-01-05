/* Copyright (c) 2009 The Board of Trustees of The Leland Stanford Junior
 * University
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
#include "shash.h"
#include <assert.h>
#include "hash.h"

static size_t
hash_name(const char *name)
{
    return hash_bytes(name, strlen(name), 0);
}

void
shash_init(struct shash *sh)
{
    hmap_init(&sh->map);
}

void
shash_destroy(struct shash *sh)
{
    if (sh) {
        shash_clear(sh);
        free(sh);
    }
}

void
shash_clear(struct shash *sh)
{
    struct shash_node *node, *next;

    HMAP_FOR_EACH_SAFE (node, next, struct shash_node, node, &sh->map) {
        hmap_remove(&sh->map, &node->node);
        free(node->name);
        free(node);
    }
}

/* It is the caller's responsible to avoid duplicate names, if that is
 * desirable. */
void
shash_add(struct shash *sh, const char *name, void *data)
{
    struct shash_node *node = xmalloc(sizeof *node);
    node->name = xstrdup(name);
    node->data = data;
    hmap_insert(&sh->map, &node->node, hash_name(name));
}

void
shash_delete(struct shash *sh, struct shash_node *node)
{
    hmap_remove(&sh->map, &node->node);
    free(node->name);
    free(node);
}

/* If there are duplicates, returns a random element. */
struct shash_node *
shash_find(const struct shash *sh, const char *name)
{
    struct shash_node *node;

    HMAP_FOR_EACH_WITH_HASH (node, struct shash_node, node,
                             hash_name(name), &sh->map) {
        if (!strcmp(node->name, name)) {
            return node;
        }
    }
    return NULL;
}

void *
shash_find_data(const struct shash *sh, const char *name)
{
    struct shash_node *node = shash_find(sh, name);
    return node ? node->data : NULL;
}
