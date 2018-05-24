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
#include "backtrace.h"
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include "compiler.h"

#define LOG_MODULE VLM_backtrace
#include "vlog.h"

static uintptr_t UNUSED
get_max_stack(void)
{
    static const char file_name[] = "/proc/self/maps";
    char line[1024];
    int line_number;
    FILE *f;

    f = fopen(file_name, "r");
    if (f == NULL) {
        VLOG_WARN(LOG_MODULE, "opening %s failed: %s", file_name, strerror(errno));
        return -1;
    }

    for (line_number = 1; fgets(line, sizeof line, f); line_number++) {
        if (strstr(line, "[stack]")) {
            uintptr_t end;
            if (sscanf(line, "%*x-%"SCNxPTR, &end) != 1)  {
                VLOG_WARN(LOG_MODULE, "%s:%d: parse error", file_name, line_number);
                continue;
            }
            fclose(f);
            return end;
        }
    }
    fclose(f);

    VLOG_WARN(LOG_MODULE, "%s: no stack found", file_name);
    return -1;
}

static uintptr_t
stack_high(void)
{
    static uintptr_t high;
    if (!high) {
        high = get_max_stack();
    }
    return high;
}

static uintptr_t
stack_low(void)
{
#ifdef __i386__
    uintptr_t low;
    asm("movl %%esp,%0" : "=g" (low));
    return low;
#elif __x86_64__
    uintptr_t low;
    asm("movq %%rsp,%0" : "=g" (low));
    return low;
#else
    /* This causes a warning in GCC that cannot be disabled, so use it only on
     * non-x86. */
    int dummy;
    return (uintptr_t) &dummy;
#endif
}

static bool
in_stack(void *p)
{
    uintptr_t address = (uintptr_t) p;
    return address >= stack_low() && address < stack_high();
}

void
backtrace_capture(struct backtrace *backtrace)
{
    void **frame;
    size_t n;

    n = 0;
    for (frame = __builtin_frame_address(0);
         frame != NULL && in_stack(frame) && frame[0] != NULL
             && n < BACKTRACE_MAX_FRAMES;
         frame = frame[0])
    {
        backtrace->frames[n++] = (uintptr_t) frame[1];
    }
    backtrace->n_frames = n;
}
