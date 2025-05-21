/*-
 * Copyright (c) 2013-2019 Juan Romero Pardines.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <endian.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>

#include "defs.h"

static RSA *
load_rsa_privkey(const char *path)
{
	FILE *fp;
	RSA *rsa = NULL;
	const char *p;
	char *passphrase = NULL;

	if ((fp = fopen(path, "r")) == 0)
		return NULL;

	p = getenv("XBPS_PASSPHRASE");
	if (p) {
		passphrase = strdup(p);
	}
	rsa = PEM_read_RSAPrivateKey(fp, 0, NULL, passphrase);
	if (passphrase) {
		free(passphrase);
		passphrase = NULL;
	}
	fclose(fp);
	return rsa;
}

static char *
pubkey_from_privkey(RSA *rsa)
{
	BIO *bp;
	char *buf = NULL;
	int len;

	bp = BIO_new(BIO_s_mem());
	assert(bp);

	if (!PEM_write_bio_RSA_PUBKEY(bp, rsa)) {
		xbps_error_printf("error writing public key: %s\n",
		    ERR_error_string(ERR_get_error(), NULL));
		BIO_free(bp);
		return NULL;
	}
	/* XXX (xtraeme) 8192 should be always enough? */
	buf = malloc(8192);
	assert(buf);
	len = BIO_read(bp, buf, 8191);
	BIO_free(bp);
	buf[len] = '\0';

	return buf;
}

static bool
rsa_sign_file(RSA *rsa, const char *file,
	 unsigned char **sigret, unsigned int *siglen)
{
	unsigned char digest[XBPS_SHA256_DIGEST_SIZE];

	if (!xbps_file_sha256_raw(digest, sizeof digest, file))
		return false;

	if ((*sigret = calloc(1, RSA_size(rsa) + 1)) == NULL) {
		return false;
	}

	if (!RSA_sign(NID_sha256, digest, XBPS_SHA256_DIGEST_SIZE,
				*sigret, siglen, rsa)) {
		free(*sigret);
		return false;
	}

	return true;
}

static RSA *
load_rsa_key(const char *privkey)
{
	RSA *rsa = NULL;
	char *defprivkey;

	/*
	 * If privkey not set, default to ~/.ssh/id_rsa.
	 */
	if (privkey == NULL)
		defprivkey = xbps_xasprintf("%s/.ssh/id_rsa", getenv("HOME"));
	else
		defprivkey = strdup(privkey);

	if ((rsa = load_rsa_privkey(defprivkey)) == NULL) {
		xbps_error_printf("%s: failed to read the RSA privkey\n", _XBPS_RINDEX);
		exit(EXIT_FAILURE);
	}
	free(defprivkey);
	defprivkey = NULL;

	return rsa;
}

static void
ssl_init(void)
{
	SSL_load_error_strings();
	SSL_library_init();
}

int
sign_repo(struct xbps_handle *xhp, const char *repodir,
	const char *privkey, const char *signedby, const char *compression)
{
	struct xbps_repo *repo = NULL;
	xbps_dictionary_t meta = NULL;
	xbps_data_t data = NULL, rpubkey = NULL;
	RSA *rsa = NULL;
	uint16_t rpubkeysize, pubkeysize;
	const char *rsignedby = NULL;
	char *buf = NULL, *rlockfname = NULL;
	int rlockfd = -1, rv = 0;
	bool flush_failed = false, flush = false;

	if (signedby == NULL) {
		xbps_error_printf("--signedby unset! cannot initialize signed repository\n");
		return -1;
	}

	/*
	 * Check that repository index exists and not empty, otherwise bail out.
	 */
	repo = xbps_repo_open(xhp, repodir);
	if (repo == NULL) {
		rv = errno;
		xbps_error_printf("%s: cannot read repository data: %s\n",
		    _XBPS_RINDEX, strerror(errno));
		goto out;
	}
	if (xbps_dictionary_count(repo->idx) == 0) {
		xbps_error_printf("%s: invalid repository, exiting!\n", _XBPS_RINDEX);
		rv = EINVAL;
		goto out;
	}

	ssl_init();

	rsa = load_rsa_key(privkey);
	/*
	 * Check if repository index-meta contains changes compared to its
	 * current state.
	 */
	if ((buf = pubkey_from_privkey(rsa)) == NULL) {
		rv = EINVAL;
		goto out;
	}
	meta = xbps_dictionary_create();

	data = xbps_data_create_data(buf, strlen(buf));
	rpubkey = xbps_dictionary_get(repo->idxmeta, "public-key");
	if (!xbps_data_equals(rpubkey, data))
		flush = true;

	free(buf);

	pubkeysize = RSA_size(rsa) * 8;
	xbps_dictionary_get_uint16(repo->idxmeta, "public-key-size", &rpubkeysize);
	if (rpubkeysize != pubkeysize)
		flush = true;

	xbps_dictionary_get_cstring_nocopy(repo->idxmeta, "signature-by", &rsignedby);
	if (rsignedby == NULL || strcmp(rsignedby, signedby))
		flush = true;

	if (!flush)
		goto out;

	xbps_dictionary_set(meta, "public-key", data);
	xbps_dictionary_set_uint16(meta, "public-key-size", pubkeysize);
	xbps_dictionary_set_cstring_nocopy(meta, "signature-by", signedby);
	xbps_dictionary_set_cstring_nocopy(meta, "signature-type", "rsa");
	xbps_object_release(data);
	data = NULL;

	/* lock repository to write repodata file */
	if (!xbps_repo_lock(xhp, repodir, &rlockfd, &rlockfname)) {
		rv = errno;
		xbps_error_printf("%s: cannot lock repository: %s\n",
		    _XBPS_RINDEX, strerror(errno));
		goto out;
	}
	flush_failed = repodata_flush(xhp, repodir, "repodata", repo->idx, meta, compression);
	xbps_repo_unlock(rlockfd, rlockfname);
	if (!flush_failed) {
		xbps_error_printf("failed to write repodata: %s\n", strerror(errno));
		goto out;
	}
	printf("Initialized signed repository (%u package%s)\n",
	    xbps_dictionary_count(repo->idx),
	    xbps_dictionary_count(repo->idx) == 1 ? "" : "s");

out:
	if (rsa) {
		RSA_free(rsa);
		rsa = NULL;
	}
	if (repo)
		xbps_repo_release(repo);

	return rv ? -1 : 0;
}

static int
sign_pkg(struct xbps_handle *xhp, const char *binpkg, const char *privkey, bool force)
{
	RSA *rsa = NULL;
	unsigned char *sig = NULL;
	unsigned int siglen = 0;
	char *tname = NULL;
	int rv = 0, tmp_fd = -1;
	unsigned char buf[4096];
	uint32_t i = 0;
	off_t seek = 0;
	FILE *tmp_fp = NULL, *binpkg_fp = NULL;

	tname = xbps_xasprintf("%s.XXXXXXXXXX", binpkg);
	assert(tname);

	if ((binpkg_fp = fopen(binpkg, "r")) == NULL) {
		xbps_error_printf("failed to open %s: %s\n", binpkg, strerror(errno));
		rv = EINVAL;
		goto out;
	}

	// Read first 4 bytes of binpkg
	if (fread(&i, 1, sizeof i, binpkg_fp) != sizeof i) {
		if (feof(binpkg_fp))
			xbps_error_printf("failed to read binpkg: reached EOF\n");
		else if (ferror(binpkg_fp))
			xbps_error_printf("failed to read binpkg: %s\n", strerror(errno));
		rv = EINVAL;
		goto out;
	}
	// if it's our skippable frame magic, either seek past it (force) or skip the binpkg (!force)
	if (le32toh(i) == _FRAME_MAGIC) {
		if (force) {
			// read size header
			if (fread(&i, 1, sizeof i, binpkg_fp) != sizeof i) {
				if (feof(binpkg_fp))
					xbps_error_printf("failed to read binpkg: reached EOF\n");
				else if (ferror(binpkg_fp))
					xbps_error_printf("failed to read binpkg: %s\n", strerror(errno));
				rv = EINVAL;
				goto out;
			}
			// magic + header + contents
			seek = (off_t)i + 8;
		} else {
			// Skip pkg if signature exists
			if (xhp->flags & XBPS_FLAG_VERBOSE)
				fprintf(stderr, "skipping %s, signature found.\n", binpkg);
			goto out;
		}
	}
	if (fseeko(binpkg_fp, seek, SEEK_SET) == -1) {
		xbps_error_printf("failed to seek: %s\n", strerror(errno));
		rv = EINVAL;
		goto out;
	}
	// TODO: split into library function?
	// TODO: loop to be able to skip multiple skip frames?

	/*
	 * Generate pkg file signature.
	 */
	rsa = load_rsa_key(privkey);
	if (!rsa_sign_file(rsa, binpkg, &sig, &siglen)) {
		xbps_error_printf("failed to sign %s: %s\n", binpkg, strerror(errno));
		rv = EINVAL;
		goto out;
	}
	/*
	 * Write pkg file signature.
	 */
	if ((tmp_fd = mkstemp(tname)) == -1) {
		xbps_error_printf("failed to create temporary file: %s\n", strerror(errno));
		rv = EINVAL;
		goto out;
	}

	if ((tmp_fp = fdopen(tmp_fd, "w")) == NULL) {
		xbps_error_printf("failed to open %s: %s\n", binpkg, strerror(errno));
		rv = EINVAL;
		goto out;
	}

	i = htole32(_FRAME_MAGIC);
	if (fwrite(&i, 1, sizeof i, tmp_fp) != sizeof i) {
		xbps_error_printf("failed to write magic to temporary file: %s\n", strerror(errno));
		rv = EINVAL;
		goto out;
	}

	if (siglen > (UINT32_MAX - 4)) {
		xbps_error_printf("signature too long for skippable frame\n");
		rv = EINVAL;
		goto out;
	}
	i = htole32(siglen + 4);
	if (fwrite(&i, 1, sizeof i, tmp_fp) != sizeof i) {
		xbps_error_printf("failed to write length to temporary file: %s\n", strerror(errno));
		rv = EINVAL;
		goto out;
	}

	i = htole32(XBPS_META_SIG2);
	if (fwrite(&i, 1, sizeof i, tmp_fp) != sizeof i) {
		xbps_error_printf("failed to write type to temporary file: %s\n", strerror(errno));
		rv = EINVAL;
		goto out;
	}

	if (fwrite(sig, 1, siglen, tmp_fp) != siglen) {
		xbps_error_printf("failed to write signature to temporary file: %s\n", strerror(errno));
		rv = EINVAL;
		goto out;
	}
	fflush(tmp_fp);

	while (!feof(binpkg_fp)) {
		size_t bytes = fread(buf, 1, sizeof buf, binpkg_fp);
		if (bytes) {
			if (fwrite(buf, 1, bytes, tmp_fp) != bytes) {
				xbps_error_printf("failed to write binpkg to temporary file: %s\n", strerror(errno));
				rv = EINVAL;
				goto out;
			}
		}
	}
	fflush(tmp_fp);

	if (fchmod(tmp_fd, 0664) == -1) {
		xbps_error_printf("failed to chmod temporary file: %s\n", strerror(errno));
		fclose(tmp_fp);
		unlink(tname);
		rv = EINVAL;
		goto out;
	}
	fclose(tmp_fp);
	tmp_fp = NULL;
	if (rename(tname, binpkg) == -1) {
		xbps_error_printf("failed to rename temporary file: %s\n", strerror(errno));
		unlink(tname);
		rv = EINVAL;
		goto out;
	}

	printf("signed successfully %s\n", binpkg);

out:
	if (sig)
		free(sig);
	if (rsa) {
		RSA_free(rsa);
		rsa = NULL;
	}
	if (tname)
		free(tname);
	if (tmp_fp != NULL)
		fclose(tmp_fp);
	if (binpkg_fp != NULL)
		fclose(binpkg_fp);
	return rv;
}

int
sign_pkgs(struct xbps_handle *xhp, int args, int argmax, char **argv,
		const char *privkey, bool force)
{
	ssl_init();
	/*
	 * Process all packages specified in argv.
	 */
	for (int i = args; i < argmax; i++) {
		int rv;
		const char *binpkg = argv[i];
		rv = sign_pkg(xhp, binpkg, privkey, force);
		if (rv != 0)
			return rv;
	}
	return 0;
}
