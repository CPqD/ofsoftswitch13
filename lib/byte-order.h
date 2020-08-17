/*
 * Copyright (c) 2008, 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef BYTE_ORDER_H
#define BYTE_ORDER_H 1

#include <arpa/inet.h>
#include <sys/types.h>
#include <inttypes.h>

enum byte_order
{
    NETWORK_ORDER = 0,
    HOST_ORDER = 1,
};

static inline uint64_t
htonll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

static inline uint64_t
ntohll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) ntohl(n) << 32) | ntohl(n >> 32);
}



/* These macros may substitute for htons(), htonl(), and htonll() in contexts
 * where function calls are not allowed, such as case labels.  They should not
 * be used elsewhere because all of them evaluate their argument many times. */
#ifdef WORDS_BIGENDIAN
#define CONSTANT_HTONS(VALUE) ((uint16_t) (VALUE))
#define CONSTANT_HTONL(VALUE) ((uint32_t) (VALUE))
#define CONSTANT_HTONLL(VALUE) ((uint64_t) (VALUE))
#else
#define CONSTANT_HTONS(VALUE)                       \
        (((((uint16_t) (VALUE)) & 0xff00) >> 8) |   \
         ((((uint16_t) (VALUE)) & 0x00ff) << 8))
#define CONSTANT_HTONL(VALUE)                           \
        (((((uint32_t) (VALUE)) & 0x000000ff) << 24) |  \
         ((((uint32_t) (VALUE)) & 0x0000ff00) <<  8) |  \
         ((((uint32_t) (VALUE)) & 0x00ff0000) >>  8) |  \
         ((((uint32_t) (VALUE)) & 0xff000000) >> 24))
#define CONSTANT_HTONLL(VALUE)                                           \
        (((((uint64_t) (VALUE)) & UINT64_C(0x00000000000000ff)) << 56) | \
         ((((uint64_t) (VALUE)) & UINT64_C(0x000000000000ff00)) << 40) | \
         ((((uint64_t) (VALUE)) & UINT64_C(0x0000000000ff0000)) << 24) | \
         ((((uint64_t) (VALUE)) & UINT64_C(0x00000000ff000000)) <<  8) | \
         ((((uint64_t) (VALUE)) & UINT64_C(0x000000ff00000000)) >>  8) | \
         ((((uint64_t) (VALUE)) & UINT64_C(0x0000ff0000000000)) >> 24) | \
         ((((uint64_t) (VALUE)) & UINT64_C(0x00ff000000000000)) >> 40) | \
         ((((uint64_t) (VALUE)) & UINT64_C(0xff00000000000000)) >> 56))
#endif

#endif /* byte-order.h */
