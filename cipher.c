#include <pthread.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <signal.h>

#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/async.h>
#include <openssl/obj_mac.h>

#include "engine.h"
#include "cipher.h"

typedef struct cipher_ctx_ {
    int nid;
    int ivsize;
    EVP_CIPHER *cipher;
} cipher_ctx_t;

int ciphers_nids[] = 
{                             
    NID_aes_128_ecb,
    NID_aes_128_cbc,
    NID_aes_128_ctr,
    NID_aes_192_ecb,
    NID_aes_192_cbc,
    NID_aes_192_ctr,
    NID_aes_256_ecb,
    NID_aes_256_cbc,
    NID_aes_256_ctr,
    NID_aes_128_gcm,
    NID_aes_256_gcm,
    NID_sms4_ecb,
    NID_sms4_cbc,
    NID_sms4_ctr
};

static cipher_ctx_t cipher_table[] = {
    // aes
    {NID_aes_128_ecb, 0, NULL},
    {NID_aes_128_cbc, 16, NULL},
    {NID_aes_128_ctr, 16, NULL},
    {NID_aes_192_ecb, 0, NULL},
    {NID_aes_192_cbc, 16, NULL},
    {NID_aes_192_ctr, 16, NULL},
    {NID_aes_256_ecb, 0, NULL},
    {NID_aes_256_cbc, 16, NULL},
    {NID_aes_256_ctr, 16, NULL},
    {NID_aes_128_gcm, 16, NULL},
    {NID_aes_256_gcm, 16, NULL},

    // sm4
    {NID_sms4_ecb, 0, NULL},
    {NID_sms4_cbc, 16, NULL},
    {NID_sms4_ctr, 16, NULL},
};

static inline const EVP_CIPHER *gmssl_engine_cipher_sw_impl(int nid)
{
    switch (nid) {
        case NID_aes_128_ecb:
            return EVP_aes_128_ecb();
        case NID_aes_128_cbc:
            return EVP_aes_128_cbc();
        case NID_aes_128_ctr:
            return EVP_aes_128_ctr();
        case NID_aes_192_ecb:
            return EVP_aes_192_ecb();
        case NID_aes_192_cbc:
            return EVP_aes_192_cbc();
        case NID_aes_192_ctr:
            return EVP_aes_192_ctr();
        case NID_aes_256_ecb:
            return EVP_aes_256_ecb();
        case NID_aes_256_cbc:
            return EVP_aes_256_cbc();
        case NID_aes_256_ctr:
            return EVP_aes_256_ctr();
        case NID_aes_128_gcm:
            return EVP_aes_128_gcm();
        case NID_aes_256_gcm:
            return EVP_aes_256_gcm();
        case NID_sms4_ecb:
            return EVP_sms4_ecb();
        case NID_sms4_cbc:
            return EVP_sms4_cbc();
        case NID_sms4_ctr:
            return EVP_sms4_ctr();
        default:
            printf("Invalid nid %d\n", nid);
            return NULL;
    }
}

#define GET_SW_CIPHER(ctx) \
            gmssl_engine_cipher_sw_impl(EVP_CIPHER_CTX_nid((ctx)))

int gmssl_engine_create_ciphers(void)
{
    uint32_t i;
    
    for (i = 0; i < sizeof(cipher_table)/sizeof(cipher_ctx_t); i++)
    {
        EVP_CIPHER *temp = gmssl_engine_cipher_sw_impl(cipher_table[i].nid);
        cipher_table[i].cipher = EVP_CIPHER_meth_dup(temp);

        if (!EVP_CIPHER_meth_set_do_cipher(cipher_table[i].cipher, gmssl_engine_ciphers_do_cipher))
            goto cipher_error;
    }
    
    return 1;
    
cipher_error:
    EVP_CIPHER_meth_free(cipher_table[i].cipher);
    cipher_table[i].cipher = NULL;

    return 0;
}

const EVP_CIPHER *gmssl_engine_get_cipher(int nid)
{
    for (int i = 0; i < sizeof(cipher_table)/sizeof(cipher_ctx_t); i++)
        if (cipher_table[i].nid == nid)
            return cipher_table[i].cipher;
    
    return NULL;
}

int gmssl_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{   
    if (!cipher) 
    {
        *nids = ciphers_nids;
        return (sizeof(ciphers_nids) / sizeof(ciphers_nids[0]));
    }

    *cipher = gmssl_engine_get_cipher(nid);

    return (*cipher != NULL);
}

int gmssl_engine_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
    DEBUG_FUNC_INFO();

    return EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))(ctx, out, in, len);
}
