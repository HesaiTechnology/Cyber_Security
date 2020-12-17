#ifndef HESAI_HKDF_H_
#define HESAI_HKDF_H_

#include <openssl/evp.h>
#define SECRET_IKM_MAX_LEN      EVP_MAX_KEY_LENGTH

int HKDF_salt_init(const unsigned char *random_c, const int random_cl, 
                   const unsigned char *random_s, const int random_sl, 
                   unsigned char *salt, size_t *salt_len);

int HKDF_get_ikm(unsigned char *ikm, size_t *ikm_len);

int HKDF_ikm_init(const char *ssk, const int ssk_len);

int HKDF(const EVP_MD *evp_md,
        const unsigned char *salt, size_t salt_len,
        const unsigned char *key, size_t key_len,
        const unsigned char *info, size_t info_len,
        unsigned char *okm, size_t okm_len);

#endif