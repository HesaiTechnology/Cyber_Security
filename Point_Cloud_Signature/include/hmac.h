#ifndef _HMAC_H_
#define _HMAC_H_

#include <openssl/evp.h>

struct hmac_cipher_st{
    const EVP_MD *cipher;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    int keylen;
    int mdlen;
    int initial;
};
typedef struct hmac_cipher_st HMAC_CIPHER;

int hmac_key_init(const EVP_MD *evp_md,
                  const unsigned char *key, const int keyl, 
                  const int mdlen, HMAC_CIPHER *hmac_cipher);

int hmac_verify(const HMAC_CIPHER hmaccipher,
                const unsigned char *data, const int datalen, 
                char *out, int *outl);

#endif