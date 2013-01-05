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

#ifndef LEAK_CHECKER_H
#define LEAK_CHECKER_H 1

#include <sys/types.h>

#define LEAK_CHECKER_OPTION_ENUMS               \
    OPT_CHECK_LEAKS,                            \
    OPT_LEAK_LIMIT
#define LEAK_CHECKER_LONG_OPTIONS                           \
    {"check-leaks", required_argument, 0, OPT_CHECK_LEAKS}, \
    {"leak-limit", required_argument, 0, OPT_LEAK_LIMIT}
#define LEAK_CHECKER_OPTION_HANDLERS                \
        case OPT_CHECK_LEAKS:                       \
            leak_checker_start(optarg);             \
            break;                                  \
        case OPT_LEAK_LIMIT:                        \
            leak_checker_set_limit(atol(optarg));   \
            break;
void leak_checker_start(const char *file_name);
void leak_checker_set_limit(off_t limit);
void leak_checker_stop(void);
void leak_checker_claim(const void *);
void leak_checker_usage(void);

#endif /* leak-checker.h */
