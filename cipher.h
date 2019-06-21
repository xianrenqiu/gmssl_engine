#ifndef __CIPHER_H__
#define __CIPHER_H__

#include <openssl/engine.h>

int gmssl_engine_create_ciphers(void);
int gmssl_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid);

#endif 
