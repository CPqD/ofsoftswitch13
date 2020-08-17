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

#ifndef CSUM_H
#define CSUM_H 1

#include <stddef.h>
#include <stdint.h>

uint16_t csum(const void *, size_t);
uint32_t csum_add16(uint32_t partial, uint16_t);
uint32_t csum_add32(uint32_t partial, uint32_t);
uint32_t csum_continue(uint32_t partial, const void *, size_t);
uint16_t csum_finish(uint32_t partial);
uint16_t recalc_csum16(uint16_t old_csum, uint16_t old_u16, uint16_t new_u16);
uint16_t recalc_csum32(uint16_t old_csum, uint32_t old_u32, uint32_t new_u32);
uint16_t recalc_csum64(uint16_t old_csum, uint64_t old_u64, uint64_t new_u64);
uint16_t recalc_csum128(uint16_t old_csum, uint8_t const old_u128[16], uint8_t const new_u128[16]);

#endif /* csum.h */
