#ifndef HESAI_SECURITY_H_
#define HESAI_SECURITY_H_


struct data_block{
    unsigned char data[32];
    int datal;
};

struct cipher_block{
    unsigned char data[64];
    int datal;
};

struct message_block{
    unsigned char data[80];
    int datal;
};

typedef struct message_block    message_st;
typedef struct data_block       random_st;
typedef struct data_block       session_key_st;
typedef struct cipher_block     hmacblock_st;

typedef struct aes_cipher_st AES_CIPHER;
typedef struct hmac_cipher_st HMAC_CIPHER;
#endif
