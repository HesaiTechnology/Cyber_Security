#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <common.h>
#include <pointcloud_signature.h>
#include <hmac.h>
#include <hkdf.h>
#include <openssl/sha.h>

static struct session_hmac_key g_session_hmac_key;

static int generate_session_key(const unsigned char *random_c, const int random_cl, 
                                const unsigned char *random_s, const int random_sl,
                                unsigned char *sessionkey, int sessionkeyl)
{
    if(random_s == NULL || random_c == NULL || sessionkey == NULL)
        return 1;

    if(sessionkeyl < 32 || sessionkeyl > 60)
        return 1;
    char salt[100] = {0};
    size_t salt_len = 0;
    char ikm[SECRET_IKM_MAX_LEN];
    size_t ikm_len = 0;
    const char *info = "finish session key";

    if( HKDF_salt_init(random_c, random_cl, random_s, random_sl, salt, &salt_len) == 1)
        return 1;

    if( HKDF_get_ikm(ikm, &ikm_len) == 1)
        return 1;
    
    if( HKDF(EVP_sha256(), salt, salt_len, ikm, ikm_len, 
            info, strlen(info), sessionkey, sessionkeyl) )
        return 1;
    
    return 0;
}

int session_cal_session_key(const random_st random_lidar, 
                                   const random_st random_client, 
                                   session_key_st *sessionkey)
{
    sessionkey->datal = 32;
    printf_cipher_message("random from lidar", random_lidar.data, random_lidar.datal);
    printf_cipher_message("random from client", random_client.data, random_client.datal);
    return generate_session_key(random_lidar.data, random_lidar.datal, 
                                random_client.data, random_client.datal, 
                                sessionkey->data, sessionkey->datal);
}

int session_get_random_number(random_st *random)
{
    if(random == NULL)
        return 1;
    
    random->datal = 32;
    if(random_get(random->data, random->datal) == 1)
        return 1;
    return 0;
}

int ptcs_set_session_hmac_key(const session_key_st session_key)
{
    if(session_key.datal != 32)
    {
        handle_error("the input session key err!");
    }

    memcpy(&g_session_hmac_key.key, &session_key, sizeof(session_key));
    g_session_hmac_key.initial = 1;
    return 0;
}

static int session_hmac_verify(const session_key_st sessionkey,
                        const char *data, const int datalen, 
                        char *out, int *outl)
{
    HMAC_CIPHER hmac_key;
    memset(&hmac_key, 0, sizeof(hmac_key));
    if(hmac_key_init(EVP_sha256(), sessionkey.data, sessionkey.datal, 32, &hmac_key) == 1)
        return 1;
    
    return hmac_verify(hmac_key, data, datalen, out, outl);
}

int ptcs_pointcloud_hmac_verify(const char *signedpc, const int signedpc_len, 
                                char *pointcloud, int *pointcloud_len)
{
    if(g_session_hmac_key.initial != 1)
    {
        printf("session key is not initial!\n");
        return 1;
    }

    return session_hmac_verify(g_session_hmac_key.key, 
                               signedpc, signedpc_len, 
                               pointcloud, pointcloud_len);
}
