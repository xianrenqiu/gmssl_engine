#include "pkey.h"
#include "engine.h"

#define PKEY_NID_NUM 2
pkey_info_t info[PKEY_NID_NUM];

int pkey_nids[] = {
    EVP_PKEY_EC,
    EVP_PKEY_TLS1_PRF
};

int gmssl_engine_pkey_init(EVP_PKEY_CTX *ctx)
{
	pkey_init_func default_init;
	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_init(pmeth, &default_init);

	return (*default_init)(ctx);
}

int gmssl_engine_pkey_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
{
	pkey_copy_func default_copy;
	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_copy(pmeth, &default_copy);

	return (*default_copy)(dst, src);
}

void gmssl_engine_pkey_cleanup(EVP_PKEY_CTX *ctx)
{
	pkey_cleanup_func default_cleanup;
	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_cleanup(pmeth, &default_cleanup);

	(*default_cleanup)(ctx);
}

int gmssl_engine_pkey_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	pkey_paramgen_init_func default_paramgen_init;
	pkey_paramgen_func default_paramgen;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_paramgen(pmeth, &default_paramgen_init, &default_paramgen);

	return (*default_paramgen)(ctx, pkey);
}

int gmssl_engine_pkey_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey)
{
	pkey_keygen_init_func default_keygen_init;
	pkey_keygen_func default_keygen;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_keygen(pmeth, &default_keygen_init, &default_keygen);

	return (*default_keygen)(ctx, pkey);
}

int gmssl_engine_pkey_sign(EVP_PKEY_CTX *ctx, uint8_t *sig, 
					size_t *siglen, const uint8_t *tbs, size_t tbslen)
{
	pkey_sign_func default_sign;
	pkey_sign_func_init default_sign_init;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_sign(pmeth, &default_sign_init, &default_sign);
	return (*default_sign)(ctx, sig, siglen, tbs, tbslen);

	return 1;
}

int gmssl_engine_pkey_verify(EVP_PKEY_CTX *ctx,
					   const uint8_t *sig, size_t siglen,
					   const uint8_t *tbs, size_t tbslen)
{
	pkey_verify_func default_verify;
	pkey_verify_init_func default_verify_init;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_verify(pmeth,&default_verify_init,&default_verify);
	return (*default_verify)(ctx, sig, siglen, tbs, tbslen);

	return 1;
}

int gmssl_engine_pkey_encrypt(EVP_PKEY_CTX *ctx, uint8_t *out, 
						size_t *outlen, const uint8_t *in, size_t inlen)
{
	EC_KEY *ec_key = EVP_PKEY_get0_EC_KEY(EVP_PKEY_CTX_get0_pkey(ctx));

	pkey_encrypt_func default_encrypt;
	pkey_encrypt_init_func default_encrypt_init;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_encrypt(pmeth, &default_encrypt_init, &default_encrypt);
	return (*default_encrypt)(ctx, out, outlen, in, inlen);

	return 1;
}

int gmssl_engine_pkey_decrypt(EVP_PKEY_CTX *ctx, uint8_t *out, 
					size_t *outlen, const uint8_t *in, size_t inlen)
{
	pkey_decrypt_func default_decrypt;
	pkey_decrypt_init_func default_decrypt_init;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_decrypt(pmeth, &default_decrypt_init, &default_decrypt);
	return (*default_decrypt)(ctx, out, outlen, in, inlen);

	return 1;
}

int gmssl_engine_pkey_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	pkey_ctrl_func default_ctrl;
	pkey_ctrl_str_func default_ctrl_str;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_ctrl(pmeth, &default_ctrl, &default_ctrl_str);

	return (*default_ctrl)(ctx, type, p1, p2);
}

int gmssl_engine_pkey_derive(EVP_PKEY_CTX *ctx, uint8_t *key, size_t *keylen)
{
	pkey_derive_func default_derive;
	pkey_derive_init_func default_derive_init;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_EC);
	EVP_PKEY_meth_get_derive(pmeth, &default_derive_init, &default_derive);

	return (*default_derive)(ctx, key, keylen);
}

EVP_PKEY_METHOD *e_pkey_ec_pmeth(void)
{
	if ((info[0].pMethod = EVP_PKEY_meth_new(EVP_PKEY_EC, 0)) == NULL)
		return NULL;

	EVP_PKEY_meth_set_init(info[0].pMethod, gmssl_engine_pkey_init);
	EVP_PKEY_meth_set_copy(info[0].pMethod, gmssl_engine_pkey_copy);
	EVP_PKEY_meth_set_cleanup(info[0].pMethod, gmssl_engine_pkey_cleanup);
	EVP_PKEY_meth_set_paramgen(info[0].pMethod, NULL, gmssl_engine_pkey_paramgen);
	EVP_PKEY_meth_set_keygen(info[0].pMethod, NULL, gmssl_engine_pkey_keygen);
	EVP_PKEY_meth_set_sign(info[0].pMethod, NULL, gmssl_engine_pkey_sign);
	EVP_PKEY_meth_set_verify(info[0].pMethod, NULL, gmssl_engine_pkey_verify);
	EVP_PKEY_meth_set_encrypt(info[0].pMethod, NULL, gmssl_engine_pkey_encrypt);
	EVP_PKEY_meth_set_decrypt(info[0].pMethod, NULL, gmssl_engine_pkey_decrypt);
	EVP_PKEY_meth_set_derive(info[0].pMethod, NULL, gmssl_engine_pkey_derive);
	EVP_PKEY_meth_set_ctrl(info[0].pMethod, gmssl_engine_pkey_ctrl, NULL);

	return info[0].pMethod;
}

int gmssl_engine_pkey_tls1_prf_init(EVP_PKEY_CTX *ctx)
{
	pkey_init_func default_init;
	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_TLS1_PRF);
	EVP_PKEY_meth_get_init(pmeth, &default_init);

	return (*default_init)(ctx);
}

int gmssl_engine_pkey_tls1_prf_derive(EVP_PKEY_CTX *ctx, uint8_t *key, size_t *keylen)
{
	pkey_derive_func default_derive;
	pkey_derive_init_func default_derive_init;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_TLS1_PRF);
	EVP_PKEY_meth_get_derive(pmeth, &default_derive_init, &default_derive);

	return (*default_derive)(ctx, key, keylen);
}

int gmssl_engine_pkey_tls1_prf_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2)
{
	pkey_ctrl_func default_ctrl;
	pkey_ctrl_str_func default_ctrl_str;

	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_TLS1_PRF);
	EVP_PKEY_meth_get_ctrl(pmeth, &default_ctrl, &default_ctrl_str);

	return (*default_ctrl)(ctx, type, p1, p2);
}

void gmssl_engine_pkey_tls1_prf_cleanup(EVP_PKEY_CTX *ctx)
{
	pkey_cleanup_func default_cleanup;
	EVP_PKEY_METHOD *pmeth = EVP_PKEY_meth_find(EVP_PKEY_TLS1_PRF);
	EVP_PKEY_meth_get_cleanup(pmeth, &default_cleanup);

	(*default_cleanup)(ctx);
}

EVP_PKEY_METHOD *e_pkey_tls1_prf_pmeth(void)
{
	if ((info[1].pMethod = EVP_PKEY_meth_new(EVP_PKEY_TLS1_PRF, 0)) == NULL)
		return NULL;

	EVP_PKEY_meth_set_init(info[1].pMethod, gmssl_engine_pkey_tls1_prf_init);
	EVP_PKEY_meth_set_cleanup(info[1].pMethod, gmssl_engine_pkey_tls1_prf_cleanup);
	EVP_PKEY_meth_set_derive(info[1].pMethod, NULL, gmssl_engine_pkey_tls1_prf_derive);
	EVP_PKEY_meth_set_ctrl(info[1].pMethod, gmssl_engine_pkey_tls1_prf_ctrl, NULL);

	return info[1].pMethod;
}

int gmssl_engine_pkey(ENGINE *e, EVP_PKEY_METHOD **pmeth,
					 const int **nids, int nid)
{
	if (pmeth == NULL)
	{
		*nids = pkey_nids;
		return (sizeof(pkey_nids) / sizeof(pkey_nids[0]));
	}

	switch (nid)
	{
		case EVP_PKEY_EC:
			*pmeth = e_pkey_ec_pmeth();
			break;

		case EVP_PKEY_TLS1_PRF:
			*pmeth = e_pkey_tls1_prf_pmeth();
			break;

		default:
			break;
	}

	return 1;
}
