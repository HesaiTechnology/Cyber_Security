#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <fcntl.h> 
#include <setjmp.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <pthread.h>
#include <inttypes.h>
#include <asm/byteorder.h>

#include <sys/stat.h>
#include <sys/mman.h>

#include <net/if.h>  
#include <linux/sockios.h>  
#include <sys/ioctl.h>  
#include <pthread.h>
#include "tcp_command_client.h"
#include "hesai_security.h"
#include "pointcloud_signature.h"
#include "common.h"

#ifndef DEBUG
#define DEBUG
#endif


#include "openssl/ssl.h"
#include "openssl/err.h"

/**
 * Specify the client certificate and the corresponding
 * private key for double-end authentication of PTCs. 
 * The certificate is sent to Lidar to verify the identity of the client.
*/
#define CLIENT_CRT "cert/client.test.cert.pem"
#define CLIENT_RSA_PRIVATE  "cert/client.test.key.pem"
/**
 * Specify the client certificate chain for 
 * single-ended verification of PTCs to verify 
 * the validity of the certificate sent by the server.
 */
#define CA_SERVER_CRT "cert/ca_client.pem"


typedef struct TcpCommandClient_s{
	pthread_mutex_t lock;
	pthread_t tid;

	int exit;

	char ip[256];
	unsigned short port;

	int fd;
}TcpCommandClient;

int g_debug_print_on = 0;
static void print_mem(char* mem , int len)
{
	
	int i =0;
	if( !g_debug_print_on ) return;
	
	for ( i = 0; i < len; ++i)
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
    if (inet_pton(AF_INET, ipaddr, &servaddr.sin_addr) <= 0) {
        close(sockfd);
        return -1;
    }

    if (connect(sockfd, (struct sockaddr *)&servaddr, 
                sizeof(servaddr)) == -1) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int tcpCommandHeaderParser(unsigned char* buffer , int len , TcpCommandHeader *header)
{
	int index = 0;
	header->cmd = buffer[index++];
	header->ret_code = buffer[index++];
	header->len = ((buffer[index] & 0xff)<<24) |
					((buffer[index + 1] & 0xff)<<16) |
					((buffer[index + 2] & 0xff)<<8) |
					((buffer[index + 3] & 0xff)<<0);
	return 0;
}

static int TcpCommand_buildHeader(char *buffer , TC_Command* cmd)
{
	if(!buffer)
	{
		return -1;
	}
	int index = 0;
	buffer[index++] = 0x47;
	buffer[index++] = 0x74;
	buffer[index++] = cmd->header.cmd;
	buffer[index++] = cmd->header.ret_code;  // color or mono
	buffer[index++] = (cmd->header.len >> 24) & 0xff;
	buffer[index++] = (cmd->header.len >> 16) & 0xff;
	buffer[index++] = (cmd->header.len >> 8)  & 0xff;
	buffer[index++] = (cmd->header.len >> 0)  & 0xff;

	return index;
}

#ifdef CONFIG_SSL
static int sys_readn(SSL *ssl, void *vptr, int n)
{
    int nleft, nread;
    char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ((nread = SSL_read(ssl, ptr, nleft)) < 0) {
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
    while (nleft > 0) {
        if ( (nwritten = SSL_write(ssl, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0;   /* and call write() again */
            else
                return (-1);    /* error */
        }

        nleft -= nwritten;
        ptr += nwritten;
    }

    return n;
}

static int tcpCommandReadCommand(SSL *ssl, TC_Command* cmd)
{
	int ret = 0;
	if(!cmd)
	{
		return -1;
	}
	memset(cmd , 0 , sizeof(TC_Command));
	unsigned char buffer [1500];
	ret = sys_readn(ssl, buffer , 2);
	if(ret <= 0 || buffer[0] != 0x47 || buffer [1] != 0x74)
	{
		printf("Server Read failed!!!\n");
		perror("read");
		printf("ret = %d , errno = %s\n", ret, strerror(errno));
		return -1;
	}

	ret = sys_readn(ssl, buffer + 2 , 6);
	if(ret != 6)
	{
		printf("Server Read failed\n");
		return -1;
	}
	
	if( g_debug_print_on )  printf(" read response header size = 8:\n");
	print_mem(buffer , 8);
	tcpCommandHeaderParser(buffer + 2 , 6 , &cmd->header);

	if(cmd->header.len > 0)
	{
		cmd->data = malloc(cmd->header.len + 1);
		if(!cmd->data)
		{
			printf("malloc data error\n");
			return -1;
		}
		memset(cmd->data, 0, cmd->header.len + 1);
	}

	ret = sys_readn(ssl, cmd->data , cmd->header.len);
	if(ret != cmd->header.len)
	{
		free(cmd->data);
		printf("Server Read failed\n");
		return -1;
	}
	if( g_debug_print_on )  printf(" read response data size = %d:\n", cmd->header.len);
	print_mem(cmd->data , cmd->header.len);
	
	cmd->ret_data = cmd->data;
	cmd->ret_size = cmd->header.len;

	return 0;
}

SSL_CTX* initial_client_ssl(const char* cert, const char* private_key, const char* ca)
{

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();



	SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());

	if(ctx == NULL)
	{
		ERR_print_errors_fp(stderr);

		printf("%s:%d, create SSL_CTX failed\n", __func__, __LINE__);
		return NULL;
	}



	if (ca)
	{

		if(	SSL_CTX_load_verify_locations(ctx, ca, NULL) == 0)
		{
			ERR_print_errors_fp(stderr);

			printf("%s:%d, load ca failed\n", __func__, __LINE__);
			return NULL;
		}

	}


	if (cert && private_key)
	{

		if(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 0 ||
			SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 0)
		{
			ERR_print_errors_fp( stderr );
			exit(1);
		}
		
		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

		if(	SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) == 0 ||
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

char* get_client_crt()
{
	return CLIENT_CRT;
}

char* get_client_rsa_private()
{
	return CLIENT_RSA_PRIVATE;
}

char* get_server_ca()
{
	return CA_SERVER_CRT;
}

static PTC_ErrCode tcpCommandClient_SendCmd(TcpCommandClient *client , TC_Command *cmd)
{
	if(!client && !cmd)
	{
		printf("Bad Parameter\n");
		return PTC_ERROR_BAD_PARAMETER;
	}

	if(cmd->header.len != 0 && cmd->data == NULL)
	{
		printf("Bad Parameter : payload is null\n");
		return PTC_ERROR_BAD_PARAMETER;
	}

	pthread_mutex_lock(&client->lock);

	int err_code = PTC_ERROR_NO_ERROR;


	SSL_CTX* ctx = initial_client_ssl(get_client_crt(), get_client_rsa_private(), get_server_ca());

	if(ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
		return PTC_ERROR_CONNECT_SERVER_FAILED;
	}

	int fd = tcp_open(client->ip , client->port);
	
	if(fd < 0)
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
	if(SSL_connect(ssl) == 0)
	{
		printf("%s:%d, connect ssl failed\n", __func__, __LINE__);

		ERR_print_errors_fp(stderr);

		err_code = PTC_ERROR_CONNECT_SERVER_FAILED;

		goto end;
	}


	if(SSL_get_verify_result(ssl) != X509_V_OK)
	{
		printf("%s:%d, verify ssl failed\n", __func__, __LINE__);

		ERR_print_errors_fp(stderr);

		err_code = PTC_ERROR_CONNECT_SERVER_FAILED;

		goto end;
	}

	unsigned char buffer[128];
	int size = TcpCommand_buildHeader(buffer , cmd);

	if( g_debug_print_on )  printf(" cmd header to tx, size = %d: \n",size);
	print_mem(buffer , size);


	int ret = SSL_write(ssl , buffer , size);
	if(ret != size)
	{
		printf("Write header error, ret=%d, size=%d\n", ret, size);
		err_code = PTC_ERROR_TRANSFER_FAILED;

		goto end;
	}

	if(cmd->header.len > 0 && cmd->data)
	{		
		if( g_debug_print_on )  printf(" cmd data to tx size = %d: \n", cmd->header.len);
		print_mem(cmd->data , cmd->header.len);
		ret = SSL_write(ssl, cmd->data , cmd->header.len);
		if(ret != cmd->header.len)
		{
			printf("Write Payload error\n");
			err_code = PTC_ERROR_TRANSFER_FAILED;

			goto end;
		}
	}

	TC_Command feedBack;
	ret = tcpCommandReadCommand(ssl, &feedBack);
	if(ret != 0)
	{
		printf("Receive feed back failed!!!\n");

		err_code = PTC_ERROR_TRANSFER_FAILED;

		goto end;

	}
	if( g_debug_print_on )  printf("feed back : %d %d %d \n", cmd->ret_size , cmd->header.ret_code , cmd->header.cmd);

	cmd->ret_data = feedBack.ret_data;
	cmd->ret_size = feedBack.ret_size;
	cmd->header.ret_code = feedBack.header.ret_code;

	printf("close ssl and fd\n");

	end:

	if (ssl != NULL) SSL_shutdown(ssl);


	if (fd > 0) close(fd);


	if (ctx != NULL)
	{
		SSL_CTX_free(ctx);
		pthread_mutex_unlock(&client->lock);
	}

	return err_code;
}

#else
static int sys_readn(int fd, void *vptr, int n)
{
    int nleft, nread;
    char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ((nread = read(fd, ptr, nleft)) < 0) {
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

static int sys_writen(int fd, const void *vptr, int n)
{
    int nleft;
    int nwritten;
    const char *ptr;

    ptr = vptr;
    nleft = n;
    while (nleft > 0) {
        if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR)
                nwritten = 0;   /* and call write() again */
            else
                return (-1);    /* error */
        }

        nleft -= nwritten;
        ptr += nwritten;
    }

    return n;
}

static int tcpCommandReadCommand(int connfd , TC_Command* cmd)
{
	int ret = 0;
	if(!cmd)
	{
		return -1;
	}
	memset(cmd , 0 , sizeof(TC_Command));
	unsigned char buffer [1500];
	ret = sys_readn(connfd , buffer , 2);
	if(ret <= 0 || buffer[0] != 0x47 || buffer [1] != 0x74)
	{
		printf("Server Read failed!!!\n");
		perror("read");
		printf("ret = %d , errno = %s\n", ret, strerror(errno));
		return -1;
	}

	ret = sys_readn(connfd , buffer + 2 , 6);
	if(ret != 6)
	{
		printf("Server Read failed\n");
		return -1;
	}
	
	if( g_debug_print_on )  printf(" read response header size = 8:\n");
	print_mem(buffer , 8);
	tcpCommandHeaderParser(buffer + 2 , 6 , &cmd->header);

	if(cmd->header.len > 0)
	{
		cmd->data = malloc(cmd->header.len + 1);
		if(!cmd->data)
		{
			printf("malloc data error\n");
			return -1;
		}
		memset(cmd->data, 0, cmd->header.len + 1);
	}

	ret = sys_readn(connfd , cmd->data , cmd->header.len);
	if(ret != cmd->header.len)
	{
		free(cmd->data);
		printf("Server Read failed\n");
		return -1;
	}
	if( g_debug_print_on )  printf(" read response data size = %d:\n", cmd->header.len);
	print_mem(cmd->data , cmd->header.len);
	
	cmd->ret_data = cmd->data;
	cmd->ret_size = cmd->header.len;

	return 0;
}

static PTC_ErrCode tcpCommandClient_SendCmd(TcpCommandClient *client , TC_Command *cmd)
{
	if(!client && !cmd)
	{
		printf("Bad Parameter\n");
		return PTC_ERROR_BAD_PARAMETER;
	}

	if(cmd->header.len != 0 && cmd->data == NULL)
	{
		printf("Bad Parameter : payload is null\n");
		return PTC_ERROR_BAD_PARAMETER;
	}

	pthread_mutex_lock(&client->lock);
	
	int fd = tcp_open(client->ip , client->port);
	
	if(fd < 0)
	{
		printf("Connect to Server Failed!~!~\n");
		pthread_mutex_unlock(&client->lock);
		return PTC_ERROR_CONNECT_SERVER_FAILED;
	}

	unsigned char buffer[128];
	int size = TcpCommand_buildHeader(buffer , cmd);

	if( g_debug_print_on )  printf(" cmd header to tx, size = %d: \n",size);
	print_mem(buffer , size);
	int ret = write(fd , buffer , size);
	if(ret != size)
	{
		close(fd);
		pthread_mutex_unlock(&client->lock);
		printf("Write header error\n");
		return PTC_ERROR_TRANSFER_FAILED;
	}

	if(cmd->header.len > 0 && cmd->data)
	{		
		if( g_debug_print_on )  printf(" cmd data to tx size = %d: \n", cmd->header.len);
		print_mem(cmd->data , cmd->header.len);
		ret = write(fd , cmd->data , cmd->header.len);
		if(ret != cmd->header.len)
		{
			printf("Write Payload error\n");
			close(fd);
			pthread_mutex_unlock(&client->lock);
			return PTC_ERROR_TRANSFER_FAILED;
		}
	}

	TC_Command feedBack;
	ret = tcpCommandReadCommand(fd , &feedBack);
	if(ret != 0)
	{
		printf("Receive feed back failed!!!\n");
		close(fd);
		pthread_mutex_unlock(&client->lock);
		return PTC_ERROR_TRANSFER_FAILED;
	}
	if( g_debug_print_on )  printf("feed back : %d %d %d \n", cmd->ret_size , cmd->header.ret_code , cmd->header.cmd);

	cmd->ret_data = feedBack.ret_data;
	cmd->ret_size = feedBack.ret_size;
	cmd->header.ret_code = feedBack.header.ret_code;

	close(fd);
	pthread_mutex_unlock(&client->lock);
	return PTC_ERROR_NO_ERROR;
}
#endif
void *TcpCommandClientNew(char* ip , unsigned short port)
{
	if(!ip)
	{
		printf("Bad Parameter\n");
		return NULL;
	}

	TcpCommandClient *client = (TcpCommandClient*)malloc(sizeof(TcpCommandClient));
	if(!client)
	{
		printf("No Memory!!!\n");
		return NULL;
	}
	memset(client , 0 , sizeof(TcpCommandClient));
	client->fd = -1;
	strcpy(client->ip, ip);
	client->port = port;

	pthread_mutex_init(&client->lock , NULL);


	printf("TCP Command Client Init Success!!!\n");
	return (void*)client;
}

PTC_ErrCode TcpCommandGetLidarCalibration(void* handle , unsigned char** buffer , unsigned int* len)
{
	if(!handle || !buffer || !len)
	{
		printf("Bad Parameter!!!\n");
		return PTC_ERROR_BAD_PARAMETER;
	}
	TcpCommandClient *client = (TcpCommandClient*)handle;

	TC_Command cmd;
	memset(&cmd , 0 , sizeof(TC_Command));
	cmd.header.cmd = PTC_COMMAND_GET_LIDAR_CALIBRATION;
	cmd.header.len = 0;
	cmd.data = NULL;
	

	PTC_ErrCode errorCode = tcpCommandClient_SendCmd(client , &cmd);
	if(errorCode != PTC_ERROR_NO_ERROR)
	{
		printf("Set Calibration Failed\n");
		return errorCode;
	}
	
	*buffer = cmd.ret_data;
	*len = cmd.ret_size;
	printf("\n");

	return cmd.header.ret_code;
}

PTC_ErrCode TcpSigStart(void * handle)
{
	if(!handle)
	{
		printf("Bad Parameter!!!!~\n");
		return PTC_ERROR_BAD_PARAMETER;
	}
	int ret = 0;
	session_key_st session_key;
	random_st client_random;
	memset(client_random.data, 0, sizeof(client_random.data));
	client_random.datal = 32;
	message_st msg;
	size_t session_len;
	ret = session_get_random_number(&client_random);
	if( ret != 0)
	{
		printf("generate random fail!\n");
		return -1;
	}
	memcpy(msg.data, client_random.data, client_random.datal);
	msg.datal = client_random.datal;
	
	printf_cipher_message("client random to server lidar", client_random.data, client_random.datal);

	TcpCommandClient *client = (TcpCommandClient *)handle;
	session_len = msg.datal;
	char * send_data = malloc( session_len );
	memcpy(send_data, msg.data, session_len );
	
	TC_Command cmd;
	memset(&cmd, 0, sizeof(TC_Command));
	cmd.header.cmd = PTC_COMMAND_DP_SIG_SESSION_START;
	cmd.header.len = session_len;
	cmd.data = send_data;

	PTC_ErrCode err_code = tcpCommandClient_SendCmd(client, &cmd);
	if(err_code != PTC_ERROR_NO_ERROR)
	{
		printf("%s:%d, fail to get ptp config\n", __func__, __LINE__);
		return err_code;
	}

	// deal with response
	if (cmd.ret_size != session_len)
	{
		printf("rsp size %d error\n", cmd.ret_size);
		return -1;
	}

	if (cmd.header.ret_code != 0)
	{
		printf("rsp retcode %u error\n", cmd.header.ret_code);
		return -1;
	}

	message_st rsp;
	memcpy(rsp.data, cmd.ret_data, cmd.ret_size);
	rsp.datal = session_len;

	printf("sig decrypt begin\n");

	random_st server_random;
	memcpy(server_random.data, rsp.data, rsp.datal);
	server_random.datal = rsp.datal;
	
	printf_cipher_message("server random form lidar", server_random.data, server_random.datal);

	memset(&session_key, 0, sizeof(session_key));
	if(session_cal_session_key(server_random, client_random, &session_key) == 1)
	{
		printf("cal session key error!!");
		return -1;
	}
	printf_cipher_message("session key", session_key.data, session_key.datal);

	if(ptcs_set_session_hmac_key(session_key) == 1)
	{
		printf("set session hmac key err!\n");
		return -1;
	}

	free(cmd.data);
	free(cmd.ret_data);
	return 0;
}

PTC_ErrCode TcpSigQuery(void * handle)
{
	if(!handle)
	{
		printf("Bad Parameter!!!!~\n");
		return PTC_ERROR_BAD_PARAMETER;
	}

	TcpCommandClient *client = (TcpCommandClient *)handle;
	TC_Command cmd;
	memset(&cmd, 0, sizeof(TC_Command));
	cmd.header.cmd = PTC_COMMAND_GET_DP_SIG_STATE;

	PTC_ErrCode err_code = tcpCommandClient_SendCmd(client, &cmd);
	if(err_code != PTC_ERROR_NO_ERROR)
	{
		printf("%s:%d, fail to get ptp config\n", __func__, __LINE__);
		return err_code;
	}

	// deal with response
	if (cmd.ret_size != 1)
	{
		printf("rsp size %d error\n", cmd.ret_size);
		return -1;
	}

	if (cmd.header.ret_code != 0)
	{
		printf("rsp retcode %u error\n", cmd.header.ret_code);
		return -1;
	}

	printf("get rsp from lidar: siguature flag [%s] \n", *cmd.ret_data == 0 ? "OFF" : "ON");

	free(cmd.data);
	free(cmd.ret_data);
	return 0;
}

PTC_ErrCode TcpSigStop(void * handle)
{
	if(!handle)
	{
		printf("Bad Parameter!!!!~\n");
		return PTC_ERROR_BAD_PARAMETER;
	}

	TcpCommandClient *client = (TcpCommandClient *)handle;
	TC_Command cmd;
	memset(&cmd, 0, sizeof(TC_Command));
	cmd.header.cmd = PTC_COMMAND_DP_SIG_SESSION_STOP;

	PTC_ErrCode err_code = tcpCommandClient_SendCmd(client, &cmd);
	if(err_code != PTC_ERROR_NO_ERROR)
	{
		printf("%s:%d, fail to get ptp config\n", __func__, __LINE__);
		return err_code;
	}

	if (cmd.header.ret_code != 0)
	{
		printf("rsp retcode %u error\n", cmd.header.ret_code);
		return -1;
	}

	printf("sig stop success\n");
	return 0;
}
