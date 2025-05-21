#define _GNU_SOURCE

#include <stdlib.h>
#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#define FRAME_MAGIC 0x184d2a5c

enum xbps_metadata_type {
	XBPS_SIG  = 1,
	XBPS_SIG2 = 2,
};

static char *
xbps_xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *buf = NULL;

	va_start(ap, fmt);
	if (vasprintf(&buf, fmt, ap) == -1) {
		va_end(ap);
		assert(buf);
	}
	va_end(ap);
	assert(buf);

	return buf;
}

static int
append_metadata(int fd, const void *buf, const uint32_t sz) {
	const uint32_t frame_magic = htole32(FRAME_MAGIC);
	const uint32_t lesz = htole32(sz);

	return 0;
}

// static int
// read_metadata(int fd, void *buf) {
// 	return 0;
// }

int
main(int argc, char **argv) {
	// test input.xbps input.sig -> append sig to xbps
	const char *pkg = NULL, *sig = NULL;
	FILE *pkgfp, *outfp;
	int outfd;
	size_t bytes;
	char *temp = xbps_xasprintf("sig-test.xbps.XXXXXX");

	if (argc == 1) {
		pkg = argv[1];
		sig = "nononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononononono";
	} else {
		return EINVAL;
	}

	if ((pkgfp = fopen(pkg, "r")) == NULL) {
		printf("fopen pkg: %s\n", strerror(errno));
		return 1;
	}

	if ((outfd = mkstemp(temp)) == -1) {
		printf("mkstemp out: %s\n", strerror(errno));
		return 1;
	}

	if ((outfp = fdopen(outfd, "w")) == NULL) {
		printf("fdopen out: %s\n", strerror(errno));
		return 1;
	}

	while (!feof(pkgfp)) {
		bytes = fread(c)
	}

	return 0;
}
