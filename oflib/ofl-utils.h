/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * Copyright (c) 2012, CPqD, Brazil 
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 */

#ifndef OFL_UTILS_H
#define OFL_UTILS_H 1


#include <netinet/in.h>


/* Given an array of pointers _elem_, and the number of elements in the array
   _elem_num_, this function frees each element, as well as the array
   itself. */
#define OFL_UTILS_FREE_ARR(ELEMS, ELEM_NUM)     \
{                                               \
     size_t _iter;                              \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {   \
         free(ELEMS[_iter]);                    \
     }                                          \
     free(ELEMS);                               \
}

 /* Given an array of pointers _elem_, and the number of elements in the array
    _elem_num_, this function frees each element using the provided _free_fun_
    function, and frees the array itself as well. */
#define OFL_UTILS_FREE_ARR_FUN(ELEMS, ELEM_NUM, FREE_FUN) \
{                                               \
     size_t _iter;                              \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {   \
         FREE_FUN(ELEMS[_iter]);                \
     }                                          \
     free(ELEMS);                               \
}

#define OFL_UTILS_FREE_ARR_FUN2(ELEMS, ELEM_NUM, FREE_FUN, ARG2) \
{                                                \
     size_t _iter;                               \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {    \
         FREE_FUN(ELEMS[_iter], ARG2);           \
     }                                           \
     free(ELEMS);                                \
}



/* Given an array of pointers _elem_, and the number of elements in the array
   _elem_num_, this function sums the result of calling the provided _len_fun_
   function for each element. */
#define OFL_UTILS_SUM_ARR_FUN(RESULT, ELEMS, ELEM_NUM, LEN_FUN) \
{                                                \
     size_t _iter, _ret;                         \
                                                 \
     _ret = 0;                                   \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {    \
         _ret += LEN_FUN(ELEMS[_iter]);          \
     }                                           \
                                                 \
     RESULT = _ret;                              \
}


#define OFL_UTILS_SUM_ARR_FUN2(RESULT, ELEMS, ELEM_NUM, LEN_FUN, ARG2) \
{                                                    \
     size_t _iter, _ret;                             \
                                                     \
     _ret = 0;                                       \
     for (_iter=0; _iter<ELEM_NUM; _iter++) {        \
         _ret += LEN_FUN(ELEMS[_iter], ARG2);        \
     }                                               \
                                                     \
     RESULT = _ret;                                  \
}


static inline uint64_t
hton64(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)htonl(n)) << 32) + htonl(n >> 32);
#endif
}

static inline uint64_t
ntoh64(uint64_t n) {
#if __BYTE_ORDER == __BIG_ENDIAN
    return n;
#else
    return (((uint64_t)ntohl(n)) << 32) + ntohl(n >> 32);
#endif
}


#endif /* OFL_UTILS_H */
