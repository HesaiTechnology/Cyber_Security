#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <hkdf.h>
#include <string.h>
#include <common.h>

struct hkdf_ikm
{
    char ikm[SECRET_IKM_MAX_LEN];
    int len;
    int initial;
    char md[32];
};

static struct hkdf_ikm g_ikm;

int HKDF_salt_init(const unsigned char *random_c, const int random_cl, 
                   const unsigned char *random_s, const int random_sl, 
                   unsigned char *salt, size_t *salt_len)
{
    if(random_c == NULL || random_s == NULL || salt == NULL)
        return 1;
    if(random_cl <= 0 || random_sl <= 0)
        return 1;
    memcpy(salt ,random_c, random_cl);
    memcpy(salt+random_sl, random_s, random_sl);
    if(salt_len != NULL)
        *salt_len = random_cl + random_sl;
    return 0;
}

int HKDF_get_ikm(unsigned char *ikm, size_t *ikm_len)
{
    if(g_ikm.initial != 1)
        handle_error("shared secret key is not initial!");
    
    int ret = 0;
    char md[EVP_MAX_MD_SIZE] = {0};
    unsigned char *t_ikm = NULL;
    int t_ikm_len = 0;

    SHA256((unsigned char*)&g_ikm, sizeof(g_ikm)-sizeof(g_ikm.md), md);
    if(memcmp(md, g_ikm.md, sizeof(g_ikm.md)))
        handle_error("shared secret key may be broken!");

    memcpy(ikm, g_ikm.ikm, g_ikm.len);
    *ikm_len = g_ikm.len;
    printf_cipher_message("IKM", ikm, *ikm_len);
    return 0;
}

int HKDF_ikm_init(const char *ssk, const int ssk_len)
{
    if( !ssk || ssk_len <= 0 || ssk_len > sizeof(g_ikm.ikm) )
        handle_error("paremeter error");

    SET_ZERO(g_ikm);
    g_ikm.len = ssk_len;
    memcpy(g_ikm.ikm, ssk, ssk_len);
    g_ikm.initial = 1;
    if( NULL == SHA256((unsigned char*)&g_ikm, sizeof(g_ikm)-sizeof(g_ikm.md), g_ikm.md))
        handle_error("HASH256 Calculate failed!");

    return 0;
}

int HKDF(const EVP_MD *evp_md,
        const unsigned char *salt, size_t salt_len,
        const unsigned char *key, size_t key_len,
        const unsigned char *info, size_t info_len,
        unsigned char *okm, size_t okm_len)
{
    int ret = 0;
    EVP_PKEY_CTX *pctx;
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (EVP_PKEY_derive_init(pctx) <= 0) {
        printf("EVP_PKEY_derive_init");
        ret = 1;
    }
    else if (EVP_PKEY_CTX_set_hkdf_md(pctx, evp_md) <= 0) {
        printf("EVP_PKEY_CTX_set_hkdf_md");
        ret = 1;
    }
    else if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
        printf("EVP_PKEY_CTX_set1_hkdf_salt");
        ret = 1;
    }
    else if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
        printf("EVP_PKEY_CTX_set1_hkdf_key");
        ret = 1;
    }
    else if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
        printf("EVP_PKEY_CTX_set1_hkdf_info");
        ret = 1;
    }
    else if (EVP_PKEY_derive(pctx, okm, &okm_len) <= 0) {
        printf("EVP_PKEY_derive");
        ret = 1;
    }
    EVP_PKEY_CTX_free(pctx);
    return ret;
}
