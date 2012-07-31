/* Copyright (c) 2009 The Board of Trustees of The Leland Stanford
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
#include "pcap.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include "compiler.h"
#include "ofpbuf.h"

#define LOG_MODULE VLM_pcap
#include "vlog.h"

struct pcap_hdr {
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t thiszone;        /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets */
    uint32_t network;        /* data link type */
} PACKED;

struct pcaprec_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} PACKED;

FILE *
pcap_open(const char *file_name, const char *mode)
{
    FILE *file;

    assert(!strcmp(mode, "rb") || !strcmp(mode, "wb"));

    file = fopen(file_name, mode);
    if (file == NULL) {
        VLOG_WARN(LOG_MODULE, "%s: failed to open pcap file for %s",
                  file_name, mode[0] == 'r' ? "reading" : "writing");
        return NULL;
    }

    if (mode[0] == 'r') {
        if (!pcap_read_header(file)) {
            fclose(file);
            return NULL;
        }
    } else {
        pcap_write_header(file);
    }
    return file;
}

int
pcap_read_header(FILE *file)
{
    struct pcap_hdr ph;
    if (fread(&ph, sizeof ph, 1, file) != 1) {
        int error = ferror(file) ? errno : EOF;
        VLOG_WARN(LOG_MODULE, "failed to read pcap header: %s",
                  error > 0 ? strerror(error) : "end of file");
        return error;
    }
    if (ph.magic_number != 0xa1b2c3d4 && ph.magic_number != 0xd4c3b2a1) {
        VLOG_WARN(LOG_MODULE, "bad magic 0x%08"PRIx32" reading pcap file "
                  "(expected 0xa1b2c3d4 or 0xd4c3b2a1)", ph.magic_number);
        return EPROTO;
    }
    return 0;
}

void
pcap_write_header(FILE *file)
{
    /* The pcap reader is responsible for figuring out endianness based on the
     * magic number, so the lack of htonX calls here is intentional. */
    struct pcap_hdr ph;
    ph.magic_number = 0xa1b2c3d4;
    ph.version_major = 2;
    ph.version_minor = 4;
    ph.thiszone = 0;
    ph.sigfigs = 0;
    ph.snaplen = 1518;
    ph.network = 1;             /* Ethernet */
    fwrite(&ph, sizeof ph, 1, file);
}

int
pcap_read(FILE *file, struct ofpbuf **bufp)
{
    struct pcaprec_hdr prh;
    struct ofpbuf *buf;
    void *data;
    size_t len;

    *bufp = NULL;

    /* Read header. */
    if (fread(&prh, sizeof prh, 1, file) != 1) {
        int error = ferror(file) ? errno : EOF;
        VLOG_WARN(LOG_MODULE, "failed to read pcap record header: %s",
                  error > 0 ? strerror(error) : "end of file");
        return error;
    }

    /* Calculate length. */
    len = prh.incl_len;
    if (len > 0xffff) {
        uint32_t swapped_len = (((len & 0xff000000) >> 24) |
                                ((len & 0x00ff0000) >>  8) |
                                ((len & 0x0000ff00) <<  8) |
                                ((len & 0x000000ff) << 24));
        if (swapped_len > 0xffff) {
            VLOG_WARN(LOG_MODULE, "bad packet length %zu or %"PRIu32" "
                      "reading pcap file",
                      len, swapped_len);
            return EPROTO;
        }
        len = swapped_len;
    }

    /* Read packet. */
    buf = ofpbuf_new(len);
    data = ofpbuf_put_uninit(buf, len);
    if (fread(data, len, 1, file) != 1) {
        int error = ferror(file) ? errno : EOF;
        VLOG_WARN(LOG_MODULE, "failed to read pcap packet: %s",
                  error > 0 ? strerror(error) : "end of file");
        ofpbuf_delete(buf);
        return error;
    }
    *bufp = buf;
    return 0;
}

void
pcap_write(FILE *file, struct ofpbuf *buf)
{
    struct pcaprec_hdr prh;
    prh.ts_sec = 0;
    prh.ts_usec = 0;
    prh.incl_len = buf->size;
    prh.orig_len = buf->size;
    fwrite(&prh, sizeof prh, 1, file);
    fwrite(buf->data, buf->size, 1, file);
}
