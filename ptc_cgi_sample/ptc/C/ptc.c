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
        printf("TcpCommandGetLidarCalibration Failed %d\n", errorCode);
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

