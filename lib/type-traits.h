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

#ifndef TYPE_TRAITS_H
#define TYPE_TRAITS_H

#include <limits.h>
#include <values.h>


#define TYPE_IS_INTEGRAL(t) \
	__builtin_choose_expr( __builtin_types_compatible_p(t, char),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, signed char),	    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned char),	    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, short),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned short),	    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, int),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned int),	    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, long),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned long),	    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, long long),	    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned long long), 1, \
	0)))))))))))


#define TYPE_IS_FLOATING_POINT(t)  \
	__builtin_choose_expr( __builtin_types_compatible_p(t, float),	     1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, double),	     1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, long double), 1, \
	0)))


#define TYPE_IS_ARITHMETIC(t)	(TYPE_IS_INTEGRAL(t) || TYPE_IS_FLOATING_POINT(t))


#define TYPE_IS_SIGNED(t)  \
	__builtin_choose_expr( __builtin_types_compatible_p(t, char),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, short),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, int),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, long),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, long long),	    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned long long), 1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, float),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, double),		    1, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, long double),	    1, \
	0)))))))))


#define TYPE_IS_UNSIGNED(t) (!TYPE_IS_SIGNED(t))


#define TYPE_VALUE_BITS(t) \
	__builtin_choose_expr(TYPE_IS_INTEGRAL(t), (sizeof(t) * CHAR_BIT - TYPE_IS_SIGNED(t)), (void)0)


#define TYPE_LIMITS_MIN(t) \
	__builtin_choose_expr( __builtin_types_compatible_p(t, char),		    CHAR_MIN,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, signed char),	    SCHAR_MIN,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned char),	    0,		\
	__builtin_choose_expr( __builtin_types_compatible_p(t, short),		    SHRT_MIN,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned short),	    0,		\
	__builtin_choose_expr( __builtin_types_compatible_p(t, int),		    INT_MIN,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned int),	    0,		\
	__builtin_choose_expr( __builtin_types_compatible_p(t, long),		    LONG_MIN,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned long),	    0,		\
	__builtin_choose_expr( __builtin_types_compatible_p(t, long long),	    LLONG_MIN,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned long long), 0,		\
	__builtin_choose_expr( __builtin_types_compatible_p(t, float),		    FLT_MIN,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, double),		    DBL_MIN,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, long double),	    LDBL_MIN,	\
	(void)0))))))))))))))


#define TYPE_LIMITS_MAX(t) \
	__builtin_choose_expr( __builtin_types_compatible_p(t, char),		    CHAR_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, signed char),	    SCHAR_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned char),	    UCHAR_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, short),		    SHRT_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned short),	    USHRT_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, int),		    INT_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned int),	    UINT_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, long),		    LONG_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned long),	    ULONG_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, long long),	    LLONG_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, unsigned long long), ULLONG_MAX, \
	__builtin_choose_expr( __builtin_types_compatible_p(t, float),		    FLT_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, double),		    DBL_MAX,	\
	__builtin_choose_expr( __builtin_types_compatible_p(t, long double),	    LDBL_MAX,	\
	(void)0))))))))))))))


#endif /* type-traits.h */

