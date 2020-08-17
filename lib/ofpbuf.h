/* Copyright (c) 2008 The Board of Trustees of The Leland Stanford
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

#ifndef OFPBUF_H
#define OFPBUF_H 1

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#include "dynamic-string.h"
#include "util.h"

/* Buffer for holding arbitrary data.  An ofpbuf is automatically reallocated
 * as necessary if it grows too large for the available memory. */
struct ofpbuf {
    void *base;                 /* First byte of area malloc()'d area. */
    size_t allocated;           /* Number of bytes allocated. */

    uint8_t conn_id;            /* Connection ID. Application-defined value to
                                   associate a connection to the buffer. */

    void *data;                 /* First byte actually in use. */
    size_t size;                /* Number of bytes in use. */

    void *l2;                   /* Link-level header. */
    void *l3;                   /* Network-level header. */
    void *l4;                   /* Transport-level header. */
    void *l7;                   /* Application data. */

    struct ofpbuf *next;        /* Next in a list of ofpbufs. */
    void *private_p;            /* Private pointer for use by owner. */

    bool ownership;
};

// void ofpbuf_use(struct ofpbuf *, void *, size_t);
//
// void ofpbuf_init(struct ofpbuf *, size_t);
// void ofpbuf_uninit(struct ofpbuf *);
// void ofpbuf_reinit(struct ofpbuf *, size_t);
//
// struct ofpbuf *ofpbuf_new(size_t);
// struct ofpbuf *ofpbuf_new_with_headroom(size_t, size_t headroom);
//
// void ofpbuf_emplace(struct ofpbuf *buf, size_t, size_t headroom);
//
// struct ofpbuf *ofpbuf_clone(const struct ofpbuf *);
// struct ofpbuf *ofpbuf_clone_with_headroom(const struct ofpbuf *,
//                                           size_t headroom);

static struct ofpbuf *ofpbuf_clone_data(const void *, size_t);

// void ofpbuf_delete(struct ofpbuf *);
//
// void *ofpbuf_at(const struct ofpbuf *, size_t offset, size_t size);
// void *ofpbuf_at_assert(const struct ofpbuf *, size_t offset, size_t size);
static void *ofpbuf_tail(const struct ofpbuf *);
static void *ofpbuf_end(const struct ofpbuf *);
//
// void *ofpbuf_put_uninit(struct ofpbuf *, size_t);
// void *ofpbuf_put_zeros(struct ofpbuf *, size_t);
static void *ofpbuf_put(struct ofpbuf *, const void *, size_t);

static void ofpbuf_reserve(struct ofpbuf *, size_t);

// void *ofpbuf_push_uninit(struct ofpbuf *b, size_t);
// void *ofpbuf_push_zeros(struct ofpbuf *, size_t);
// void *ofpbuf_push(struct ofpbuf *b, const void *, size_t);
//
// size_t ofpbuf_headroom(const struct ofpbuf *);
// size_t ofpbuf_tailroom(const struct ofpbuf *);
// void ofpbuf_prealloc_headroom(struct ofpbuf *, size_t);
// void ofpbuf_prealloc_tailroom(struct ofpbuf *, size_t);
// void ofpbuf_trim(struct ofpbuf *);
//
// void ofpbuf_clear(struct ofpbuf *);
// void *ofpbuf_pull(struct ofpbuf *, size_t);
// void *ofpbuf_try_pull(struct ofpbuf *, size_t);

/* Initializes 'b' as an empty ofpbuf that contains the 'allocated' bytes of
 * memory starting at 'base'.
 *
 * 'base' should ordinarily be the first byte of a region obtained from
 * malloc(), but in circumstances where it can be guaranteed that 'b' will
 * never need to be expanded or freed, it can be a pointer into arbitrary
 * memory. */

static inline void
ofpbuf_use(struct ofpbuf *b, void *base, size_t allocated)
{
    b->base = b->data = base;
    b->allocated = allocated;
    b->size = 0;
    b->l2 = b->l3 = b->l4 = b->l7 = NULL;
    b->next = NULL;
    b->private_p = NULL;
}


/* Initializes 'b' as an empty ofpbuf with an initial capacity of 'size'
 * bytes. */
static inline void
ofpbuf_init(struct ofpbuf *b, size_t size)
{
    ofpbuf_use(b, size ? xmalloc(size) : NULL, size);
}

/* Frees memory that 'b' points to. */
static inline void
ofpbuf_uninit(struct ofpbuf *b)
{
    if (b) {
        free(b->base);
    }
}

/* Frees memory that 'b' points to and allocates a new ofpbuf */
static inline void
ofpbuf_reinit(struct ofpbuf *b, size_t size)
{
    ofpbuf_uninit(b);
    ofpbuf_init(b, size);
}

/* Creates and returns a new ofpbuf with an initial capacity of 'size'
 * bytes. */
static inline struct ofpbuf *
ofpbuf_new(size_t size)
{
    struct ofpbuf *b = xmalloc(sizeof *b);
    ofpbuf_init(b, size);
    b->ownership = true;
    return b;
}

/* Creates and returns a new ofpbuf with an initial capacity of 'size +
 * headroom' bytes, reserving the first 'headroom' bytes as headroom. */
static inline struct ofpbuf *
ofpbuf_new_with_headroom(size_t size, size_t headroom)
{
    struct ofpbuf *b = ofpbuf_new(size + headroom);
    ofpbuf_reserve(b, headroom);
    return b;
}

/* Emplace a ofpbuf with an initial capacity of 'size'
 * bytes. */
static inline void
ofpbuf_emplace(struct ofpbuf *b, size_t size, size_t headroom)
{
    ofpbuf_init(b, size + headroom);
    ofpbuf_reserve(b, headroom);
    b->ownership = false;
}


static inline struct ofpbuf *
ofpbuf_clone(const struct ofpbuf *buffer)
{
    return ofpbuf_clone_data(buffer->data, buffer->size);
}

/* Creates and returns a new ofpbuf whose data are copied from 'buffer'.   The
 * returned ofpbuf will additionally have 'headroom' bytes of headroom. */
static inline struct ofpbuf *
ofpbuf_clone_with_headroom(const struct ofpbuf *buffer, size_t headroom)
{
    struct ofpbuf *b = ofpbuf_new_with_headroom(buffer->size, headroom);
    ofpbuf_put(b, buffer->data, buffer->size);
    return b;
}

static inline struct ofpbuf *
ofpbuf_clone_data(const void *data, size_t size)
{
    struct ofpbuf *b = ofpbuf_new(size);
    ofpbuf_put(b, data, size);
    return b;
}

/* Frees memory that 'b' points to, as well as 'b' itself. */
static inline void
ofpbuf_delete(struct ofpbuf *b)
{
    if (b) {
        ofpbuf_uninit(b);
        if (b->ownership)
		free(b);
    }
}

/* Returns the number of bytes of headroom in 'b', that is, the number of bytes
 * of unused space in ofpbuf 'b' before the data that is in use.  (Most
 * commonly, the data in a ofpbuf is at its beginning, and thus the ofpbuf's
 * headroom is 0.) */
static inline size_t
ofpbuf_headroom(const struct ofpbuf *b)
{
    return (char*)b->data - (char*)b->base;
}

/* Returns the number of bytes that may be appended to the tail end of ofpbuf
 * 'b' before the ofpbuf must be reallocated. */
static inline size_t
ofpbuf_tailroom(const struct ofpbuf *b)
{
    return (char*)ofpbuf_end(b) - (char*)ofpbuf_tail(b);
}

/* Changes 'b->base' to 'new_base' and adjusts all of 'b''s internal pointers
 * to reflect the change. */
inline static void
ofpbuf_rebase__(struct ofpbuf *b, void *new_base)
{
    if (b->base != new_base) {
        uintptr_t base_delta = (char*)new_base - (char*)b->base;
        b->base = new_base;
        b->data = (char*)b->data + base_delta;
        if (b->l2) {
            b->l2 = (char*)b->l2 + base_delta;
        }
        if (b->l3) {
            b->l3 = (char*)b->l3 + base_delta;
        }
        if (b->l4) {
            b->l4 = (char*)b->l4 + base_delta;
        }
        if (b->l7) {
            b->l7 = (char*)b->l7 + base_delta;
        }
    }
}

/* Reallocates 'b' so that it has exactly 'new_tailroom' bytes of tailroom. */
inline static void
ofpbuf_resize_tailroom__(struct ofpbuf *b, size_t new_tailroom)
{
    b->allocated = ofpbuf_headroom(b) + b->size + new_tailroom;
    ofpbuf_rebase__(b, xrealloc(b->base, b->allocated));
}

/* Ensures that 'b' has room for at least 'size' bytes at its tail end,
 * reallocating and copying its data if necessary.  Its headroom, if any, is
 * preserved. */
static inline void
ofpbuf_prealloc_tailroom(struct ofpbuf *b, size_t size)
{
    if (size > ofpbuf_tailroom(b)) {
        ofpbuf_resize_tailroom__(b, MAX(size, 64));
    }
}

static inline void
ofpbuf_prealloc_headroom(struct ofpbuf *b, size_t size)
{
    assert(size <= ofpbuf_headroom(b));
}

/* Trims the size of 'b' to fit its actual content, reducing its tailroom to
 * 0.  Its headroom, if any, is preserved. */
static inline void
ofpbuf_trim(struct ofpbuf *b)
{
    if (ofpbuf_tailroom(b) > 0) {
        ofpbuf_resize_tailroom__(b, 0);
    }
}

/* Appends 'size' bytes of data to the tail end of 'b', reallocating and
 * copying its data if necessary.  Returns a pointer to the first byte of the
 * new data, which is left uninitialized. */
static inline void *
ofpbuf_put_uninit(struct ofpbuf *b, size_t size)
{
    void *p;
    ofpbuf_prealloc_tailroom(b, size);
    p = ofpbuf_tail(b);
    b->size += size;
    return p;
}

/* Appends 'size' zeroed bytes to the tail end of 'b'.  Data in 'b' is
 * reallocated and copied if necessary.  Returns a pointer to the first byte of
 * the data's location in the ofpbuf. */
static inline void *
ofpbuf_put_zeros(struct ofpbuf *b, size_t size)
{
    void *dst = ofpbuf_put_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

/* Appends the 'size' bytes of data in 'p' to the tail end of 'b'.  Data in 'b'
 * is reallocated and copied if necessary.  Returns a pointer to the first
 * byte of the data's location in the ofpbuf. */
static inline void *
ofpbuf_put(struct ofpbuf *b, const void *p, size_t size)
{
    void *dst = ofpbuf_put_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* Reserves 'size' bytes of headroom so that they can be later allocated with
 * ofpbuf_push_uninit() without reallocating the ofpbuf. */
static inline void
ofpbuf_reserve(struct ofpbuf *b, size_t size)
{
    assert(!b->size);
    ofpbuf_prealloc_tailroom(b, size);
    b->data = (char*)b->data + size;
}

static inline void *
ofpbuf_push_uninit(struct ofpbuf *b, size_t size)
{
    ofpbuf_prealloc_headroom(b, size);
    b->data = (char*)b->data - size;
    b->size += size;
    return b->data;
}

/* Prefixes 'size' zeroed bytes to the head end of 'b'.  'b' must have at least
 * 'size' bytes of headroom.  Returns a pointer to the first byte of the data's
 * location in the ofpbuf. */
static inline void *
ofpbuf_push_zeros(struct ofpbuf *b, size_t size)
{
    void *dst = ofpbuf_push_uninit(b, size);
    memset(dst, 0, size);
    return dst;
}

static inline void *
ofpbuf_push(struct ofpbuf *b, const void *p, size_t size)
{
    void *dst = ofpbuf_push_uninit(b, size);
    memcpy(dst, p, size);
    return dst;
}

/* If 'b' contains at least 'offset + size' bytes of data, returns a pointer to
 * byte 'offset'.  Otherwise, returns a null pointer. */
static inline void *
ofpbuf_at(const struct ofpbuf *b, size_t offset, size_t size)
{
    return offset + size <= b->size ? (char *) b->data + offset : NULL;
}

/* Returns a pointer to byte 'offset' in 'b', which must contain at least
 * 'offset + size' bytes of data. */
static inline void *
ofpbuf_at_assert(const struct ofpbuf *b, size_t offset, size_t size)
{
    assert(offset + size <= b->size);
    return ((char *) b->data) + offset;
}

/* Returns the byte following the last byte of data in use in 'b'. */
static inline void *
ofpbuf_tail(const struct ofpbuf *b)
{
    return (char *) b->data + b->size;
}

/* Returns the byte following the last byte allocated for use (but not
 * necessarily in use) by 'b'. */
static inline void *
ofpbuf_end(const struct ofpbuf *b)
{
    return (char *) b->base + b->allocated;
}

/* Clears any data from 'b'. */
static inline void
ofpbuf_clear(struct ofpbuf *b)
{
    b->data = b->base;
    b->size = 0;
}

/* Removes 'size' bytes from the head end of 'b', which must contain at least
 * 'size' bytes of data.  Returns the first byte of data removed. */
static inline void *
ofpbuf_pull(struct ofpbuf *b, size_t size)
{
    void *data = b->data;
    assert(b->size >= size);
    b->data = (char*)b->data + size;
    b->size -= size;
    return data;
}

/* If 'b' has at least 'size' bytes of data, removes that many bytes from the
 * head end of 'b' and returns the first byte removed.  Otherwise, returns a
 * null pointer without modifying 'b'. */
static inline void *
ofpbuf_try_pull(struct ofpbuf *b, size_t size)
{
    return b->size >= size ? ofpbuf_pull(b, size) : NULL;
}

#endif /* ofpbuf.h */
