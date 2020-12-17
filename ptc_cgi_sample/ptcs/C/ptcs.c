#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <linux/sockios.h>
#include <net/if.h>
#include <pthread.h>
#include <sys/ioctl.h>
#ifndef DEBUG
#define DEBUG
#endif

#ifndef PACKED
#define PACKED __attribute__((packed))
#endif

#include "openssl/err.h"
#include "openssl/ssl.h"

typedef enum
{
    PTC_COMMAND_GET_LIDAR_CALIBRATION = 5,
} PTC_COMMAND;

typedef enum
{
    PTC_ERROR_NO_ERROR = 0,
    PTC_ERROR_BAD_PARAMETER,
    PTC_ERROR_CONNECT_SERVER_FAILED,
    PTC_ERROR_TRANSFER_FAILED,
    PTC_ERROR_NO_MEMORY,
    PTC_ERROR_NOT_SUPPORT,
    PTC_ERROR_FPGA_ERROR,
} PTC_ErrCode;

typedef struct TcpCommandHeader_s
{
    unsigned char cmd;
    unsigned char ret_code;
    unsigned int len;
} TcpCommandHeader;

typedef struct TC_Command_s
{
    TcpCommandHeader header;
    unsigned char *data;

    unsigned char *ret_data;
    unsigned int ret_size;
} PACKED TC_Command;

#define CLIENT_CRT "cert/client.crt"
#define CLIENT_RSA_PRIVATE "cert/client.key.pem"
#define CA_SERVER_CRT "cert/ca_client.crt"

typedef struct TcpCommandClient_s
{
    pthread_mutex_t lock;
    pthread_t tid;

    int exit;

    char ip[256];
    unsigned short port;

    int fd;
} TcpCommandClient;

int g_debug_print_on = 0;
static void print_mem(char *mem, int len)
{

    int i = 0;
    if (!g_debug_print_on)
        return;

    for (i = 0; i < len; ++i)
    {
        printf("%02x ", mem[i]);
    }
    printf("\n");
}

static int tcp_open(const char *ipaddr, int port)
{
    int sockfd;
    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        return -1;

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(port);
    if (inet_pton(AF_INET, ipaddr, &servaddr.sin_addr) <= 0)
    {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
    {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int sys_readn(SSL *ssl, void *vptr, int n)
{
    int nleft, nread;
    char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0)
    {
        if ((nread = SSL_read(ssl, ptr, nleft)) < 0)
        {
            if (errno == EINTR)
                nread = 0;
            else
                return -1;
        }
        else if (nread == 0)
            break;

        nleft -= nread;
        ptr += nread;
    }

    return n - nleft;
}

static int sys_writen(SSL *ssl, const void *vptr, int n)
{
    int nleft;
    int nwritten;
    const char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0)
    {
        if ((nwritten = SSL_write(ssl, ptr, nleft)) <= 0)
        {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0; /* and call write() again */
            else
                return (-1); /* error */
        }

        nleft -= nwritten;
        ptr += nwritten;
    }

    return n;
}

static int tcpCommandHeaderParser(unsigned char *buffer, int len, TcpCommandHeader *header)
{
    int index = 0;
    header->cmd = buffer[index++];
    header->ret_code = buffer[index++];
    header->len = ((buffer[index] & 0xff) << 24) | ((buffer[index + 1] & 0xff) << 16) |
                    ((buffer[index + 2] & 0xff) << 8) | ((buffer[index + 3] & 0xff) << 0);
    return 0;
}

static int tcpCommandReadCommand(SSL *ssl, TC_Command *cmd)
{
    int ret = 0;
    if (!cmd)
    {
        return -1;
    }
    memset(cmd, 0, sizeof(TC_Command));
    unsigned char buffer[1500];
    ret = sys_readn(ssl, buffer, 2);
    if (ret <= 0 || buffer[0] != 0x47 || buffer[1] != 0x74)
    {
        printf("Server Read failed!!!\n");
        return -1;
    }

    ret = sys_readn(ssl, buffer + 2, 6);
    if (ret != 6)
    {
        printf("Server Read failed\n");
        return -1;
    }

    if (g_debug_print_on)
        printf(" read response header size = 8:\n");
    print_mem(buffer, 8);
    tcpCommandHeaderParser(buffer + 2, 6, &cmd->header);

    if (cmd->header.len > 0)
    {
        cmd->data = malloc(cmd->header.len + 1);
        if (!cmd->data)
        {
            printf("malloc data error\n");
            return -1;
        }
        memset(cmd->data, 0, cmd->header.len + 1);
    }

    ret = sys_readn(ssl, cmd->data, cmd->header.len);
    if (ret != cmd->header.len)
    {
        free(cmd->data);
        printf("Server Read failed\n");
        return -1;
    }
    if (g_debug_print_on)
        printf(" read response data size = %d:\n", cmd->header.len);
    print_mem(cmd->data, cmd->header.len);

    cmd->ret_data = cmd->data;
    cmd->ret_size = cmd->header.len;

    return 0;
}

static int TcpCommand_buildHeader(char *buffer, TC_Command *cmd)
{
    if (!buffer)
    {
        return -1;
    }
    int index = 0;
    buffer[index++] = 0x47;
    buffer[index++] = 0x74;
    buffer[index++] = cmd->header.cmd;
    buffer[index++] = cmd->header.ret_code; // color or mono
    buffer[index++] = (cmd->header.len >> 24) & 0xff;
    buffer[index++] = (cmd->header.len >> 16) & 0xff;
    buffer[index++] = (cmd->header.len >> 8) & 0xff;
    buffer[index++] = (cmd->header.len >> 0) & 0xff;

    return index;
}

SSL_CTX *initial_client_ssl(const char *cert, const char *private_key, const char *ca)
{

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);

        printf("%s:%d, create SSL_CTX failed\n", __func__, __LINE__);
        return NULL;
    }

    if (ca)
    {

        if (SSL_CTX_load_verify_locations(ctx, ca, NULL) == 0)
        {
            ERR_print_errors_fp(stderr);

            printf("%s:%d, load ca failed\n", __func__, __LINE__);
            return NULL;
        }
    }

    if (cert && private_key)
    {

        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) == 0 ||
            SSL_CTX_use_PrivateKey_file(ctx, private_key, SSL_FILETYPE_PEM) == 0 ||
            SSL_CTX_check_private_key(ctx) == 0)
        {
            ERR_print_errors_fp(stderr);

            printf("%s:%d, load cert failed\n", __func__, __LINE__);
            return NULL;
        }
    }

    return ctx;
}

char *get_client_crt() { return CLIENT_CRT; }

char *get_client_rsa_private() { return CLIENT_RSA_PRIVATE; }

char *get_server_ca() { return CA_SERVER_CRT; }

static PTC_ErrCode tcpCommandClient_SendCmd(TcpCommandClient *client, TC_Command *cmd)
{
    if (!client || !cmd)
    {
        printf("Bad Parameter\n");
        return PTC_ERROR_BAD_PARAMETER;
    }

    if (cmd->header.len != 0 && cmd->data == NULL)
    {
        printf("Bad Parameter : payload is null\n");
        return PTC_ERROR_BAD_PARAMETER;
    }

    pthread_mutex_lock(&client->lock);

    int err_code = PTC_ERROR_NO_ERROR;

    SSL_CTX *ctx =
        initial_client_ssl(get_client_crt(), get_client_rsa_private(), get_server_ca());

    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        return PTC_ERROR_CONNECT_SERVER_FAILED;
    }

    int fd = tcp_open(client->ip, client->port);

    if (fd < 0)
    {
        printf("Connect to Server Failed!~!~\n");
        err_code = PTC_ERROR_CONNECT_SERVER_FAILED;

        goto end;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("%s:%d, create ssl failed\n", __func__, __LINE__);
        err_code = PTC_ERROR_CONNECT_SERVER_FAILED;

        goto end;
    }

    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) == 0)
    {
        printf("%s:%d, connect ssl failed\n", __func__, __LINE__);

        ERR_print_errors_fp(stderr);

        err_code = PTC_ERROR_CONNECT_SERVER_FAILED;

        goto end;
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        printf("%s:%d, verify ssl failed\n", __func__, __LINE__);

        ERR_print_errors_fp(stderr);

        err_code = PTC_ERROR_CONNECT_SERVER_FAILED;

        goto end;
    }

    unsigned char buffer[128];
    int size = TcpCommand_buildHeader(buffer, cmd);

    if (g_debug_print_on)
        printf(" cmd header to tx, size = %d: \n", size);
    print_mem(buffer, size);

    int ret = SSL_write(ssl, buffer, size);
    if (ret != size)
    {
        printf("Write header error, ret=%d, size=%d\n", ret, size);
        err_code = PTC_ERROR_TRANSFER_FAILED;

        goto end;
    }

    if (cmd->header.len > 0 && cmd->data)
    {
        if (g_debug_print_on)
            printf(" cmd data to tx size = %d: \n", cmd->header.len);
        print_mem(cmd->data, cmd->header.len);
        ret = SSL_write(ssl, cmd->data, cmd->header.len);
        if (ret != cmd->header.len)
        {
            printf("Write Payload error\n");
            err_code = PTC_ERROR_TRANSFER_FAILED;

            goto end;
        }
    }

    TC_Command feedBack;
    ret = tcpCommandReadCommand(ssl, &feedBack);
    if (ret != 0)
    {
        printf("Receive feed back failed!!!\n");

        err_code = PTC_ERROR_TRANSFER_FAILED;

        goto end;
    }
    if (g_debug_print_on)
        printf("feed back : %d %d %d \n", cmd->ret_size, cmd->header.ret_code, cmd->header.cmd);

    cmd->ret_data = feedBack.ret_data;
    cmd->ret_size = feedBack.ret_size;
    cmd->header.ret_code = feedBack.header.ret_code;

    printf("close ssl and fd\n");

end:

    if (ssl != NULL)
        SSL_shutdown(ssl);

    if (fd > 0)
        close(fd);

    if (ctx != NULL)
    {
        SSL_CTX_free(ctx);
        pthread_mutex_unlock(&client->lock);
    }

    return err_code;
}

void *TcpCommandClientNew(char *ip, unsigned short port)
{
    if (!ip)
    {
        printf("Bad Parameter\n");
        return NULL;
    }

    TcpCommandClient *client = (TcpCommandClient *)malloc(sizeof(TcpCommandClient));
    if (!client)
    {
        printf("No Memory!!!\n");
        return NULL;
    }
    memset(client, 0, sizeof(TcpCommandClient));
    client->fd = -1;
    strcpy(client->ip, ip);
    client->port = port;

    pthread_mutex_init(&client->lock, NULL);

    printf("TCP Command Client Init Success!!!\n");
    return (void *)client;
}

PTC_ErrCode TcpCommandGetLidarCalibration(void *handle, unsigned char **buffer,
                                            unsigned int *len)
{
    if (!handle || !buffer || !len)
    {
        printf("Bad Parameter!!!\n");
        return PTC_ERROR_BAD_PARAMETER;
    }
    TcpCommandClient *client = (TcpCommandClient *)handle;

    TC_Command cmd;
    memset(&cmd, 0, sizeof(TC_Command));
    cmd.header.cmd = PTC_COMMAND_GET_LIDAR_CALIBRATION;
    cmd.header.len = 0;
    cmd.data = NULL;

    PTC_ErrCode errorCode = tcpCommandClient_SendCmd(client, &cmd);
    if (errorCode != PTC_ERROR_NO_ERROR)
    {
        printf("Get Calibration Failed\n");
        return errorCode;
    }

    *buffer = cmd.ret_data;
    *len = cmd.ret_size;
    printf("\n");

    return cmd.header.ret_code;
}

int main(int argc, char **argv)
{
    void *handle = TcpCommandClientNew("192.168.1.201", 9347);
    if (!handle)
    {
        printf("TCP COMMAND new failed\n");
        return -1;
    }
    printf("\n\n\n");
    unsigned char *buffer = NULL;
    int len = 0;
    PTC_ErrCode errorCode = TcpCommandGetLidarCalibration(handle, &buffer, &len);
    if (errorCode != PTC_ERROR_NO_ERROR)
    {
        printf("TcpCommandGetLidarCalibration Failed\n");
    }
    if (buffer && len > 0)
    {
        printf("Lidar Calibration Data: \r\n");
        // print_mem(buffer , len);
        printf("%s\n", buffer);
        free(buffer);
    }
    return 0;
}

