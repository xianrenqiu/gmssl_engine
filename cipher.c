#include <stdio.h>
#include <stdlib.h>

#include "engine.h"
#include "cipher.h"

typedef struct cipher_ctx_ {
    int nid;
    EVP_CIPHER *cipher;
} cipher_info_t;

static int ciphers_nids[] = 
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

static cipher_info_t info[] = {
    // aes
    {NID_aes_128_ecb, NULL},
    {NID_aes_128_cbc, NULL},
    {NID_aes_128_ctr, NULL},
    {NID_aes_192_ecb, NULL},
    {NID_aes_192_cbc, NULL},
    {NID_aes_192_ctr, NULL},
    {NID_aes_256_ecb, NULL},
    {NID_aes_256_cbc, NULL},
    {NID_aes_256_ctr, NULL},
    {NID_aes_128_gcm, NULL},
    {NID_aes_256_gcm, NULL},

    // sm4
    {NID_sms4_ecb, NULL},
    {NID_sms4_cbc, NULL},
    {NID_sms4_ctr, NULL},
};

static const EVP_CIPHER *gmssl_engine_cipher_sw_impl(int nid)
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

static int gmssl_engine_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in, size_t len)
{
    return EVP_CIPHER_meth_get_do_cipher(GET_SW_CIPHER(ctx))(ctx, out, in, len);
}

static const EVP_CIPHER *gmssl_engine_get_cipher(int nid)
{
    for (int i = 0; i < sizeof(info)/sizeof(cipher_info_t); i++)
        if (info[i].nid == nid)
            return info[i].cipher;
    
    return NULL;
}

int gmssl_engine_create_ciphers(void)
{
    for (int i = 0; i < sizeof(info)/sizeof(cipher_info_t); i++)
    {
        EVP_CIPHER *temp = gmssl_engine_cipher_sw_impl(info[i].nid);
        info[i].cipher = EVP_CIPHER_meth_dup(temp);

        if (!EVP_CIPHER_meth_set_do_cipher(info[i].cipher, gmssl_engine_ciphers_do_cipher))
        {
            info[i].cipher = NULL;
            EVP_CIPHER_meth_free(info[i].cipher);
            return 0;
        }
    }
    
    return 1;
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
