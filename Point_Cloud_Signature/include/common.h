#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdlib.h>

#define handle_error(msg) \
    do { printf("Line:%d %s:%s\n",__LINE__, __FUNCTION__, #msg); return(EXIT_FAILURE); } while (0)

#define SET_ZERO(x)                 memset(&x, 0, sizeof(x))

int read_file(const char *filename, char *buff, int *len);

void printf_cipher_message(const char *description, 
                            const unsigned char *message, 
                            const int messagel);

int random_get(unsigned char *random, int randoml);
int read_file(const char *filename, char *buff, int *len);
#endif
