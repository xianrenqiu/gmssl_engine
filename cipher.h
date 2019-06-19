#ifndef __CIPHER_H__
#define __CIPHER_H__

# include <openssl/aes.h>
# include <openssl/ssl.h>
# include <openssl/engine.h>
# include <openssl/crypto.h>

int gmssl_engine_create_ciphers(void);
int gmssl_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);
int gmssl_engine_ciphers_do_cipher(EVP_CIPHER_CTX *ctx, uint8_t *out, const uint8_t *in, size_t len);

#endif 
