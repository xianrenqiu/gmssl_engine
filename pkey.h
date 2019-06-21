#ifndef __PKEY_H__
#define __PKEY_H__

#include <openssl/sm2.h>
#include <openssl/engine.h>

int gmssl_engine_pkey(ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid);

typedef int (*pkey_init_func)(EVP_PKEY_CTX *);
typedef int (*pkey_copy_func)(EVP_PKEY_CTX *, EVP_PKEY_CTX *);
typedef int (*pkey_paramgen_init_func)(EVP_PKEY_CTX *ctx);
typedef int (*pkey_paramgen_func)(EVP_PKEY_CTX *, EVP_PKEY *);
typedef int (*pkey_keygen_init_func)(EVP_PKEY_CTX *ctx);
typedef int (*pkey_keygen_func)(EVP_PKEY_CTX *, EVP_PKEY *);
typedef int (*pkey_sign_func_init)(EVP_PKEY_CTX *ctx);
typedef int (*pkey_sign_func)(EVP_PKEY_CTX *, uint8_t *, size_t *, const uint8_t *, size_t);
typedef int (*pkey_verify_init_func)(EVP_PKEY_CTX *ctx);
typedef int (*pkey_verify_func)(EVP_PKEY_CTX *, const uint8_t *, size_t, const uint8_t *, size_t);
typedef int (*pkey_encrypt_init_func)(EVP_PKEY_CTX *ctx);
typedef int (*pkey_encrypt_func)(EVP_PKEY_CTX *, uint8_t *, size_t *, const uint8_t *, size_t);
typedef int (*pkey_decrypt_init_func)(EVP_PKEY_CTX *ctx);
typedef int (*pkey_decrypt_func)(EVP_PKEY_CTX *, uint8_t *, size_t *, const uint8_t *, size_t);
typedef int (*pkey_derive_init_func)(EVP_PKEY_CTX *ctx);
typedef int (*pkey_derive_func)(EVP_PKEY_CTX *ctx, uint8_t *key, size_t *keylen);
typedef int (*pkey_ctrl_func)(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
typedef int (*pkey_ctrl_str_func)(EVP_PKEY_CTX *ctx, const char *type, const char *value);
typedef void (*pkey_cleanup_func)(EVP_PKEY_CTX *);

typedef struct pkey_info_
{
    EVP_PKEY_METHOD *pMethod;
} pkey_info_t;

#endif
