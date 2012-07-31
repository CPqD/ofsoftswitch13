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
#include "tag.h"
#include <limits.h>
#include "random.h"
#include "type-props.h"
#include "util.h"

#define N_TAG_BITS (CHAR_BIT * sizeof(tag_type))
BUILD_ASSERT_DECL(IS_POW2(N_TAG_BITS));

#define LOG2_N_TAG_BITS (N_TAG_BITS == 32 ? 5 : N_TAG_BITS == 64 ? 6 : 0)
BUILD_ASSERT_DECL(LOG2_N_TAG_BITS > 0);

/* Returns a randomly selected tag. */
tag_type
tag_create_random(void)
{
    int x, y;
    do {
        uint16_t r = random_uint16();
        x = r & (N_TAG_BITS - 1);
        y = r >> (16 - LOG2_N_TAG_BITS);
    } while (x == y);
    return (1u << x) | (1u << y);
}

/* Returns a tag deterministically generated from 'seed'.
 *
 * 'seed' should have data in all of its bits; if it has data only in its
 * low-order bits then the resulting tags will be poorly distributed.  Use a
 * hash function such as hash_bytes() to generate 'seed' if necessary. */
tag_type
tag_create_deterministic(uint32_t seed)
{
    int x = seed & (N_TAG_BITS - 1);
    int y = (seed >> LOG2_N_TAG_BITS) % 31;
    y += y >= x;
    return (1u << x) | (1u << y);
}

/* Initializes 'set' as an empty tag set. */
void
tag_set_init(struct tag_set *set)
{
    memset(set, 0, sizeof *set);
}

/* Adds 'tag' to 'set'. */
void
tag_set_add(struct tag_set *set, tag_type tag)
{
    if (tag && (!tag_is_valid(tag) || !tag_set_intersects(set, tag))) {
        /* XXX We could do better by finding the set member to which we would
         * add the fewest number of 1-bits.  This would reduce the amount of
         * ambiguity, since e.g. three 1-bits match 3 * 2 / 2 = 3 unique tags
         * whereas four 1-bits match 4 * 3 / 2 = 6 unique tags. */
        tag_type *t = &set->tags[set->n++ % TAG_SET_SIZE];
        *t |= tag;
        if (*t == TYPE_MAXIMUM(tag_type)) {
            set->tags[0] = *t;
        }

        set->total |= tag;
    }
}

