#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <hmac.h>
#include <common.h>

int hmac_key_init(const EVP_MD *evp_md,
                  const unsigned char *key, const int keyl, 
                  const int mdlen, HMAC_CIPHER *hmac_cipher)
{
    if(evp_md == NULL || key == NULL || hmac_cipher == NULL || keyl <= 0 || mdlen <= 0)
        return 1;
    if(hmac_cipher->initial == 1)
    {
        printf("hmac cipher has been initialized!\n");
        return 0;
    }
    hmac_cipher->cipher = evp_md;
    memcpy(hmac_cipher->key, key, keyl);
    hmac_cipher->keylen = keyl;
    hmac_cipher->mdlen = mdlen;
    hmac_cipher->initial = 1;
    return 0;
}

static int hmac_campare(const unsigned char *md_src, const int srclen, 
                        const unsigned char *md_dst, const int dstlen)
{
    if(md_src == NULL || md_dst == NULL || srclen <= 0 || dstlen <= 0)
        handle_error("parameter error!!\n");

    if(srclen == dstlen)
    {
       if(memcmp(md_src, md_dst, srclen) == 0)
            return 0;
    }
    return 1;
}

int hmac_verify(const HMAC_CIPHER hmaccipher,
                const unsigned char *data, const int datalen, 
                char *out, int *outl)
{
    if(datalen < hmaccipher.mdlen || hmaccipher.cipher == NULL || data == NULL)
        handle_error("parameter error!!\n");

    unsigned char hamc[EVP_MAX_MD_SIZE] = {0};
    int hamclen = 0;

    if(HMAC(hmaccipher.cipher, hmaccipher.key, hmaccipher.keylen,
            data, datalen - hmaccipher.mdlen, hamc, &hamclen) == NULL)
        return 1;
    printf_cipher_message("VERIFY HMAC", hamc, hamclen);

    if( hmac_campare(data + (datalen - hmaccipher.mdlen), hmaccipher.mdlen, hamc, hamclen) == 0)
    {
        if(out != NULL && outl != NULL)
        {
            memcpy(out, data, datalen - hamclen);
            *outl = datalen - hamclen;
        }
        return 0;
    }

    return 1;
}
