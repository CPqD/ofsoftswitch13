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
#include "leak-checker.h"
#include <inttypes.h>
#include "backtrace.h"

#define LOG_MODULE VLM_leak_checker
#include "vlog.h"

#ifndef HAVE_MALLOC_HOOKS
void
leak_checker_start(const char *file_name UNUSED)
{
    VLOG_WARN(LOG_MODULE, "not enabling leak checker because the libc in use does not "
              "have the required hooks");
}

void
leak_checker_set_limit(off_t max_size UNUSED)
{
}

void
leak_checker_claim(const void *p UNUSED)
{
}

void
leak_checker_usage(void)
{
    printf("  --check-leaks=FILE      (accepted but ignored in this build)\n");
}
#else /* HAVE_MALLOC_HOOKS */
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <sys/stat.h>

typedef void *malloc_hook_type(size_t, const void *);
typedef void *realloc_hook_type(void *, size_t, const void *);
typedef void free_hook_type(void *, const void *);

struct hooks {
    malloc_hook_type *malloc_hook_func;
    realloc_hook_type *realloc_hook_func;
    free_hook_type *free_hook_func;
};

static malloc_hook_type hook_malloc;
static realloc_hook_type hook_realloc;
static free_hook_type hook_free;

static struct hooks libc_hooks;
static const struct hooks our_hooks = { hook_malloc, hook_realloc, hook_free };

static FILE *file;
static off_t limit = 10 * 1000 * 1000;

static void
get_hooks(struct hooks *hooks)
{
    hooks->malloc_hook_func = __malloc_hook;
    hooks->realloc_hook_func = __realloc_hook;
    hooks->free_hook_func = __free_hook;
}

static void
set_hooks(const struct hooks *hooks)
{
    __malloc_hook = hooks->malloc_hook_func;
    __realloc_hook = hooks->realloc_hook_func;
    __free_hook = hooks->free_hook_func;
}

void
leak_checker_start(const char *file_name)
{
    if (!file) {
        file = fopen(file_name, "w");
        if (!file) {
            VLOG_WARN(LOG_MODULE, "failed to create \"%s\": %s",
                      file_name, strerror(errno));
            return;
        }
        setvbuf(file, NULL, _IONBF, 0);
        VLOG_WARN(LOG_MODULE, "enabled memory leak logging to \"%s\"", file_name);
        get_hooks(&libc_hooks);
        set_hooks(&our_hooks);
    }
}

void
leak_checker_stop(void)
{
    if (file) {
        fclose(file);
        file = NULL;
        set_hooks(&libc_hooks);
        VLOG_WARN(LOG_MODULE, "disabled memory leak logging");
    }
}

void
leak_checker_set_limit(off_t limit_)
{
    limit = limit_;
}

void
leak_checker_usage(void)
{
    printf("  --check-leaks=FILE      log malloc and free calls to FILE\n");
}

static void PRINTF_FORMAT(1, 2)
log_callers(const char *format, ...)
{
    struct backtrace backtrace;
    va_list args;
    int i;

    va_start(args, format);
    vfprintf(file, format, args);
    va_end(args);

    putc(':', file);
    backtrace_capture(&backtrace);
    for (i = 0; i < backtrace.n_frames; i++) {
        fprintf(file, " 0x%"PRIxPTR"", backtrace.frames[i]);
    }
    putc('\n', file);
}

static void
reset_hooks(void)
{
    static int count;

    if (count++ >= 100 && limit && file) {
        struct stat s;
        count = 0;
        if (fstat(fileno(file), &s) < 0) {
            VLOG_WARN(LOG_MODULE, "cannot fstat leak checker log file: %s",
                      strerror(errno));
            return;
        }
        if (s.st_size > limit) {
            VLOG_WARN(LOG_MODULE, "leak checker log file size exceeded limit");
            leak_checker_stop();
            return;
        }
    }
    if (file) {
        set_hooks(&our_hooks);
    }
}

static void *
hook_malloc(size_t size, const void *caller UNUSED)
{
    void *p;

    set_hooks(&libc_hooks);
    p = malloc(size);
    get_hooks(&libc_hooks);

    log_callers("malloc(%zu) -> %p", size, p);

    reset_hooks();
    return p;
}

void
leak_checker_claim(const void *p)
{
    if (!file) {
        return;
    }

    if (p) {
        set_hooks(&libc_hooks);
        log_callers("claim(%p)", p);
        reset_hooks();
    }
}

static void
hook_free(void *p, const void *caller UNUSED)
{
    if (!p) {
        return;
    }

    set_hooks(&libc_hooks);
    free(p);
    get_hooks(&libc_hooks);

    log_callers("free(%p)", p);

    reset_hooks();
}

static void *
hook_realloc(void *p, size_t size, const void *caller UNUSED)
{
    void *q;

    set_hooks(&libc_hooks);
    q = realloc(p, size);
    get_hooks(&libc_hooks);

    if (p != q) {
        log_callers("realloc(%p, %zu) -> %p", p, size, q);
    }

    reset_hooks();

    return q;
}
#endif /* HAVE_MALLOC_HOOKS */
