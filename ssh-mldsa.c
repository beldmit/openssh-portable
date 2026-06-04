/*
 * Copyright (c) 2026 Dmitry Belyavskiy
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#if defined(WITH_OPENSSL) && defined(OPENSSL_HAS_MLDSA)

#include <sys/types.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/fips.h>

#include "log.h"
#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

#define FIPS_FALLBACK_PROPQ "provider=default,-fips"

struct mldsa_params {
	const char *alg_name;
	const char *evp_name;
	size_t pk_sz;
	size_t sig_sz;
};

static const struct mldsa_params *
mldsa_params_from_type(int type)
{
	static const struct mldsa_params params[] = {
		{ "ssh-mldsa-44", "ML-DSA-44", MLDSA44_PK_SZ, MLDSA44_SIG_SZ },
		{ "ssh-mldsa-65", "ML-DSA-65", MLDSA65_PK_SZ, MLDSA65_SIG_SZ },
		{ "ssh-mldsa-87", "ML-DSA-87", MLDSA87_PK_SZ, MLDSA87_SIG_SZ },
	};
	switch (sshkey_type_plain(type)) {
	case KEY_MLDSA44: return &params[0];
	case KEY_MLDSA65: return &params[1];
	case KEY_MLDSA87: return &params[2];
	default:          return NULL;
	}
}

static void
ssh_mldsa_cleanup(struct sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static int
ssh_mldsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->pkey == NULL || b->pkey == NULL)
		return 0;
	return EVP_PKEY_eq(a->pkey, b->pkey) == 1;
}

static int
ssh_mldsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	const struct mldsa_params *params;
	u_char *pk = NULL;
	size_t pklen = 0;
	int r;

	if (key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((params = mldsa_params_from_type(key->type)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	if (EVP_PKEY_get_raw_public_key(key->pkey, NULL, &pklen) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	if (pklen != params->pk_sz)
		return SSH_ERR_INVALID_FORMAT;
	if ((pk = malloc(pklen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (EVP_PKEY_get_raw_public_key(key->pkey, pk, &pklen) != 1) {
		free(pk);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}
	r = sshbuf_put_string(b, pk, pklen);
	free(pk);
	return r;
}

static int
ssh_mldsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	const struct mldsa_params *params;
	u_char *pk = NULL;
	size_t pklen = 0;
	int r;

	if ((params = mldsa_params_from_type(key->type)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	if ((r = sshbuf_get_string(b, &pk, &pklen)) != 0)
		return r;
	if (pklen != params->pk_sz) {
		freezero(pk, pklen);
		return SSH_ERR_INVALID_FORMAT;
	}

	EVP_PKEY_free(key->pkey);
	key->pkey = EVP_PKEY_new_raw_public_key_ex(NULL, params->evp_name,
	    NULL, pk, pklen);
	freezero(pk, pklen);
	if (key->pkey == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

static int
ssh_mldsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	const struct mldsa_params *params;
	u_char *pk = NULL, *sk = NULL;
	size_t pklen = 0, sklen = 0;
	int r;

	if (key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((params = mldsa_params_from_type(key->type)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	if (EVP_PKEY_get_raw_public_key(key->pkey, NULL, &pklen) != 1 ||
	    EVP_PKEY_get_raw_private_key(key->pkey, NULL, &sklen) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	if ((pk = malloc(pklen)) == NULL ||
	    (sk = malloc(sklen)) == NULL) {
		free(pk);
		return SSH_ERR_ALLOC_FAIL;
	}
	if (EVP_PKEY_get_raw_public_key(key->pkey, pk, &pklen) != 1 ||
	    EVP_PKEY_get_raw_private_key(key->pkey, sk, &sklen) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((r = sshbuf_put_string(b, pk, pklen)) != 0 ||
	    (r = sshbuf_put_string(b, sk, sklen)) != 0)
		goto out;
	r = 0;
 out:
	freezero(pk, pklen);
	freezero(sk, sklen);
	return r;
}

static int
ssh_mldsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	const struct mldsa_params *params;
	u_char *pk = NULL, *sk = NULL;
	u_char *check_pk = NULL;
	size_t pklen = 0, sklen = 0, check_pklen = 0;
	int r;

	if ((params = mldsa_params_from_type(key->type)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	if ((r = ssh_mldsa_deserialize_public(NULL, b, key)) != 0)
		goto out;
	if ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		goto out;

	EVP_PKEY_free(key->pkey);
	key->pkey = EVP_PKEY_new_raw_private_key_ex(NULL, params->evp_name,
	    NULL, sk, sklen);
	if (key->pkey == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* Verify the public key matches */
	if (EVP_PKEY_get_raw_public_key(key->pkey, NULL, &check_pklen) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((check_pk = malloc(check_pklen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_PKEY_get_raw_public_key(key->pkey, check_pk, &check_pklen) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	/* Extract the public key we deserialized earlier for comparison */
	if (EVP_PKEY_get_raw_public_key(key->pkey, NULL, &pklen) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	r = 0;
 out:
	freezero(pk, pklen);
	freezero(sk, sklen);
	freezero(check_pk, check_pklen);
	return r;
}

static int
ssh_mldsa_generate(struct sshkey *k, int bits)
{
	const struct mldsa_params *params;
	EVP_PKEY_CTX *ctx = NULL;
	EVP_PKEY *pkey = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if ((params = mldsa_params_from_type(k->type)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	ctx = EVP_PKEY_CTX_new_from_name(NULL, params->evp_name, NULL);
	if (ctx == NULL && FIPS_mode())
		ctx = EVP_PKEY_CTX_new_from_name(NULL, params->evp_name,
		    FIPS_FALLBACK_PROPQ);
	if (ctx == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_keygen(ctx, &pkey) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	k->pkey = pkey;
	pkey = NULL;
	ret = 0;
 out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

static int
ssh_mldsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	const struct mldsa_params *params;
	u_char *pk = NULL;
	size_t pklen = 0;

	if (from->pkey == NULL)
		return 0;
	if ((params = mldsa_params_from_type(from->type)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	if (EVP_PKEY_get_raw_public_key(from->pkey, NULL, &pklen) != 1)
		return SSH_ERR_LIBCRYPTO_ERROR;
	if ((pk = malloc(pklen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (EVP_PKEY_get_raw_public_key(from->pkey, pk, &pklen) != 1) {
		free(pk);
		return SSH_ERR_LIBCRYPTO_ERROR;
	}

	EVP_PKEY_free(to->pkey);
	to->pkey = EVP_PKEY_new_raw_public_key_ex(NULL, params->evp_name,
	    NULL, pk, pklen);
	free(pk);
	if (to->pkey == NULL)
		return SSH_ERR_LIBCRYPTO_ERROR;
	return 0;
}

static int
ssh_mldsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	const struct mldsa_params *params;
	EVP_MD_CTX *ctx = NULL;
	struct sshbuf *b = NULL;
	u_char *sig = NULL;
	size_t slen = 0, len;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->pkey == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((params = mldsa_params_from_type(key->type)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	slen = params->sig_sz;
	if ((sig = malloc(slen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, key->pkey) != 1 ||
	    EVP_DigestSign(ctx, sig, &slen, data, datalen) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if (slen != params->sig_sz) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, params->alg_name)) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	freezero(sig, slen);
	sshbuf_free(b);
	EVP_MD_CTX_free(ctx);
	return ret;
}

static int
ssh_mldsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	const struct mldsa_params *params;
	EVP_MD_CTX *ctx = NULL;
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	size_t slen;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (key == NULL || key->pkey == NULL ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((params = mldsa_params_from_type(key->type)) == NULL)
		return SSH_ERR_INTERNAL_ERROR;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((ret = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (ret = sshbuf_get_string_direct(b, &sigblob, &slen)) != 0)
		goto out;
	if (strcmp(params->alg_name, ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if (slen != params->sig_sz) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	if ((ctx = EVP_MD_CTX_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	switch (EVP_DigestVerify(ctx, sigblob, slen, data, dlen)) {
	case 1:
		ret = 0;
		break;
	case 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		break;
	default:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		break;
	}
 out:
	EVP_MD_CTX_free(ctx);
	sshbuf_free(b);
	free(ktype);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_mldsa_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_mldsa_cleanup,
	/* .equal = */		ssh_mldsa_equal,
	/* .ssh_serialize_public = */ ssh_mldsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_mldsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_mldsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_mldsa_deserialize_private,
	/* .generate = */	ssh_mldsa_generate,
	/* .copy_public = */	ssh_mldsa_copy_public,
	/* .sign = */		ssh_mldsa_sign,
	/* .verify = */		ssh_mldsa_verify,
};

const struct sshkey_impl sshkey_mldsa44_impl = {
	/* .name = */		"ssh-mldsa-44",
	/* .shortname = */	"MLDSA-44",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA44,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_mldsa_funcs,
};

const struct sshkey_impl sshkey_mldsa65_impl = {
	/* .name = */		"ssh-mldsa-65",
	/* .shortname = */	"MLDSA-65",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA65,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	384,
	/* .funcs = */		&sshkey_mldsa_funcs,
};

const struct sshkey_impl sshkey_mldsa87_impl = {
	/* .name = */		"ssh-mldsa-87",
	/* .shortname = */	"MLDSA-87",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA87,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512,
	/* .funcs = */		&sshkey_mldsa_funcs,
};

const struct sshkey_impl sshkey_mldsa44_cert_impl = {
	/* .name = */		"ssh-mldsa-44-cert-v01@openssh.com",
	/* .shortname = */	"MLDSA-44-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA44_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_mldsa_funcs,
};

const struct sshkey_impl sshkey_mldsa65_cert_impl = {
	/* .name = */		"ssh-mldsa-65-cert-v01@openssh.com",
	/* .shortname = */	"MLDSA-65-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA65_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	384,
	/* .funcs = */		&sshkey_mldsa_funcs,
};

const struct sshkey_impl sshkey_mldsa87_cert_impl = {
	/* .name = */		"ssh-mldsa-87-cert-v01@openssh.com",
	/* .shortname = */	"MLDSA-87-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_MLDSA87_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512,
	/* .funcs = */		&sshkey_mldsa_funcs,
};

#endif /* WITH_OPENSSL && OPENSSL_HAS_MLDSA */
