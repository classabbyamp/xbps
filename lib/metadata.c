/*-
 * Copyright (c) 2024 classabbyamp.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdint.h>
#include <endian.h>
#include <errno.h>

/**
 * @file lib/metadata.c
 * @defgroup metadata XBPS Metadata Frames
 *
 * XBPS metadata frames use the skippable frame format of zstd and lz4. When
 * extracting, this is entirely transparent to both XBPS and manual extraction
 * utilities.
 *
 * For ease of parsing, XBPS metadata frames MUST be prepended to the XBPS file.
 *
 * Each XBPS metadata frame consists of a 16 byte header and at most 2^32 - 8 bytes
 * of arbitrary data.
 *
 * ## Header
 *
 * The frame header consists a magic string, a length, four bytes with ASCII ``'XBPS'``,
 * a type, and a subtype. Two null bytes are included for alignment purposes.
 *
 *     +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 *     |       MAGIC       |        LEN        | X    B    P    S  | TY | ST | 00   00 |
 *     +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 *
 * - The magic string MUST be the little-endian 32-bit number ``0x184d2a5c``. This
 *   indicates to zstd and lz4 that it is to be skipped.
 * - The length should be the number of bytes of data in the frame plus 8 bytes,
 *   as a little-endian 32-bit number
 * - The type is a single byte, allowing for 256 possible kinds of metadata.
 *   The currently defined types are:
 *     - ``'M'`` (``0x49``): General metadata information
 *     - ``'S'`` (``0x53``): Signature
 * - The subtype is a single byte, allowing for 256 possible kinds of metadata for
 *   each type. The currently defined types are:
 *     - For type ``'M'`` (``0x49``): None
 *     - For type ``'S'`` (``0x53``):
 *         - ``0x01``: Original signature format (RSA sha256 with sha1 ASN1 prefix)
 *         - ``0x02``: sig2 signature format (RSA sha256)
 *
 * An example of a signature frame of subtype sig2 is shown:
 *
 *     +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 *     | 5c   2a   4d   18 | 08   02   00   00 | X    B    P    S  | S  | 02 | 00   00 |
 *     +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
 *     | DATA                                                                          |
 *     | ...                                                                           |
 *     +----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+----+
*/

//! zstd/lz4 skippable magic
#define XBPS_METADATA_FRAME_MAGIC	htole32(0x184d2a5c)
//! identifier string used in frames (XBPS)
#define XBPS_METADATA_FRAME_ID		htole32(0x53504258)
//! number of bytes in the skippable frame used for headers
#define XBPS_METADATA_HEADER_LEN	8
//! maximum length of the contents of a metadata frame
#define XBPS_METADATA_LEN_MAX		(UINT32_MAX - XBPS_METADATA_HEADER_LEN)
//! convenience method for getting the length for the header
#define XBPS_METADATA_LEN(x)		htole32(x + XBPS_METADATA_HEADER_LEN)

typedef enum xbps_metadata_type {
	XBPS_METADATA_INFO = 'M',
	XBPS_METADATA_SIG = 'S',
} xbps_metadata_t;

typedef enum xbps_signature_type {
	XBPS_SIGNATURE_SIG = 1,
	XBPS_SIGNATURE_SIG2 = 2,
} xbps_signature_t;

struct __attribute__((__packed__)) xbps_metadata_header {
	uint32_t magic;
	uint32_t len;
	uint8_t id[4];
	uint8_t type;
	uint8_t subtype;
	uint8_t pad[2];
};

static ssize_t
xbps_metadata_write_header(FILE *fp, struct xbps_metadata_header hdr) {
	ssize_t rv;
	if ((rv = fwrite(&hdr, 1, sizeof hdr, fp)) != sizeof hdr)
		return -1;
	return rv;
}

static ssize_t
xbps_metadata_write(FILE *fp, uint8_t type, uint8_t subtype, uint8_t *buf, uint32_t len) {
	struct xbps_metadata_header hdr = {
		.magic = XBPS_METADATA_FRAME_MAGIC,
		.len = 0,
		.id = XBPS_METADATA_FRAME_ID,
		.type = type,
		.subtype = subtype,
	};

	if (len > XBPS_METADATA_LEN_MAX) {
		// Frame data too large
		errno = -ERANGE;
		return -1;
	}
	hdr.len = XBPS_METADATA_LEN(len);

	// TODO: err handling
	if (xbps_metadata_write_header(fp, hdr) == -1)
		return -1;

	if (fwrite(&buf, 1, len, fp) != len)
		return -1;
	// TODO: what ret?
	return len;
}

static ssize_t
xbps_metadata_read_header(FILE *fp, struct xbps_metadata_header *hdr) {
	// read into struct
	if (fread(hdr, 1, sizeof(struct xbps_metadata_header), fp) != sizeof(struct xbps_metadata_header))
		return -1;
	// if valid header (magic, XBPS), return it
	if ((hdr->magic == XBPS_METADATA_FRAME_MAGIC) && (strcmp((char *)hdr->id, XBPS_METADATA_FRAME_ID) == 0))
		return 0;
	// else error
	return -1;
}

static ssize_t
xbps_metadata_peek_header(FILE *fp, struct xbps_metadata_header *hdr) {
	// TODO: err/eof handling
	off_t pos = ftello(fp);
	xbps_metadata_read_header(fp, hdr);
	fseeko(fp, pos, SEEK_SET);
	return 0;
}

static ssize_t
xbps_metadata_read(FILE *fp, void *buf) {
	uint32_t len;
	struct xbps_metadata_header hdr = {};
	xbps_metadata_read_header(fp, &hdr);
	// TODO: if valid, alloc buf and read len into buf
	len = hdr.len - XBPS_METADATA_HEADER_LEN;
	if (fread(buf, 1, len, fp) != len)
		return -1;
	return 0;
}

static ssize_t
xbps_metadata_skip_frame(FILE *fp) {
	// TODO: err/eof handling
	struct xbps_metadata_header hdr = {};
	xbps_metadata_read_header(fp, &hdr);
	fseeko(fp, (off_t)hdr.len, SEEK_CUR);
	return 0;
}

static ssize_t
xbps_metadata_skip_frames(FILE *fp) {
	int rv;
	while ((rv = xbps_metadata_skip_frame(fp)) > 0) {
		continue;
	}
	return rv;
}
