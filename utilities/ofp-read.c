/* Copyright (c) 2013, Marco Canini
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
 *   * Neither the name of the software nor the names of its
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
 */

#include <config.h>
#include <stdlib.h>
#include <stdio.h>

#include "oflib/ofl-messages.h"

#include "timeval.h"
#include "vlog.h"

static size_t read_all(FILE *file, uint8_t **buf)
{
	size_t buf_len;
	uint8_t *data;
	*buf = NULL;

	fseek(file, 0, SEEK_END);
	buf_len = ftell(file);
	rewind(file);

	data = (uint8_t*) malloc(buf_len);
	if (fread(data, buf_len, 1, file) != 1){
		if (ferror(file)) {
			fprintf(stderr, "Cannot read msg file.\n");
		}
		return -1;		
	}
	*buf = data;
	return buf_len;
}

int main(int argc, char **argv)
{
	uint8_t *buf ,*buf0;
	size_t buf_len = 0;
	ofl_err err;
	struct ofl_msg_header *msg = NULL;
	uint32_t xid;
	FILE *msg_file;
	struct ofp_header *oh;

	if (argc < 2) {
		fprintf(stderr, "Expecting msg file.\n");
		return 1;
	}

	time_init();
	vlog_init();
	vlog_set_verbosity(NULL);

	msg_file = fopen(argv[1], "r");
	if (msg_file == NULL) {
		fprintf(stderr, "Cannot open msg file.\n");
		return 1;
	}
	buf_len = read_all(msg_file, &buf);
	buf0 = buf;

	while (buf_len > 0) {
		oh = (struct ofp_header *)buf;
		err = ofl_msg_unpack(buf, ntohs(oh->length), &msg, &xid, NULL);
		if (err == 0) {
			//printf("Success!\n");
			ofl_msg_print(stdout, msg, NULL);
			printf("\n\n");
			ofl_msg_free(msg, NULL);
		} else {
			free(buf);
			printf("Failed :-( error type: %d code %d\n", ofl_error_type(err), ofl_error_code(err));
			return 1;
		}
		buf_len -= ntohs(oh->length);
		buf += ntohs(oh->length);
	}
	free(buf0);
	return 0;
}

