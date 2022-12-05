#include <stdio.h>  
#include <stdlib.h>   
#include <string.h>  
#include <sys/socket.h>  
#include <netinet/in.h>  
#include <arpa/inet.h>  
#include <netdb.h>  
#include <fcntl.h>
#include <unistd.h>
#include <hesai_security.h>
#include <tcp_command_client.h>
#include <pointcloud_signature.h>
#include <hkdf.h>
#include "common.h"

static void printf_msg(const char *description, 
                           const unsigned char *msg, 
                           const int msgl)
{
    printf("%s:\n", description);
    for (int i = 0; i < msgl; i++){
        if(i>0 && i % 32 == 0)
            printf("\n");
        printf("%02x", msg[i]);
    }
    printf("\n");
}

static int shared_secret_key_set( const char *ssk_path )
{
    char ssk_buf[256] = {0};
    int ssk_l = 0;
    if(read_file(ssk_path, ssk_buf, &ssk_l))
    {
        printf("reading ssk file failed!\n");
        return 1;
    }
    if(HKDF_ikm_init(ssk_buf, ssk_l))
    {
        printf("ssk setting failed\n");
        return 1;
    }
    return 0;
}

/**
 * process_signed_point_cloud() - Receive the point cloud data, 
 *           and verify the signature of the signed point cloud.
*/
static int process_signed_point_cloud( void *handle, int port)
{
    if(!handle || port <= 0)
        return 1;

    char recv_msg[2048] = {0};
    char pointcloud[2048] = {0};
    int ioptval = 1;
    int ufd;
    int ret = 0;
    int pclen, sig_addr_len, recvl = 0;

    struct sockaddr_in sig_addr;
    if ((ufd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
        printf("socket failed\n");
        return 1;
    }
    if (setsockopt(ufd, SOL_SOCKET, SO_REUSEADDR, &ioptval, sizeof(int)) < 0)
    {
        printf("setsockopt failed!\n");
        close(ufd);
        return 1;
    }
    memset(&sig_addr, 0, sizeof(struct sockaddr_in));  
    sig_addr.sin_family = AF_INET;
    sig_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    sig_addr.sin_port = port;
    sig_addr_len = sizeof(sig_addr);

    if (bind(ufd, (struct sockaddr *)&sig_addr, sizeof(sig_addr)) == -1)
    {
        printf("bind failed!\n");
        ret = 1;
    }
    while (!ret)  
    {  
        if ((recvl = recvfrom(ufd, recv_msg, sizeof(recv_msg), 0, (struct sockaddr *)&sig_addr, &sig_addr_len)) == -1)
        {
            printf("no data to be received!\n");
            ret = 1;
            break;
        }
        printf_msg("\npointcloud",recv_msg, recvl);
        if(ptcs_pointcloud_hmac_verify(recv_msg, recvl, pointcloud, &pclen))
        {
            printf("verification failed! num\n");
            ret = 1;
            break;
        }
    }
    close(ufd);
    return ret;
}

int main(int argc , char *argv[]) 
{  
    int recvl = 0;
    int port;
    int ret = 0;
    printf(" tcp client test\r\n");
	if(argc < 4)
	{
		printf("Ussage:\n\t %s <ip> <port> <cmd>\n" , argv[0]);
		printf("\t\t <ip> -- lidar ip address such as 192.168.1.201\n" );
		printf("\t\t <port> -- shall be 9347\n" );
        printf("\t\t <cmd> == signatureStop  - stop point cloud signature\n" );
		printf("\t\t <cmd> == signatureQuery - query whether the point cloud signature is ON or OFF.\n" );
		printf("\t\t <cmd> == signatureStart - point cloud signature start!\n" );
		return -1;
	}
	
	void * handle = TcpCommandClientNew(argv[1] , atoi(argv[2]));
	if(!handle)
	{
		printf("TCP COMMAND new failed\n");
		return -1;
	}
    
    if (strncmp(argv[3],"signatureQuery",strlen("signatureQuery")) == 0){
		PTC_ErrCode errorCode = TcpSigQuery(handle);
        free(handle);
		return errorCode;	
	}
	else if (strncmp(argv[3],"signatureStop",strlen("signatureStop")) == 0){
		PTC_ErrCode errorCode = TcpSigStop(handle);
        free(handle); 
		return errorCode;	
	}
    else if (strncmp(argv[3],"signatureStart",strlen("signatureStart")) == 0)
    {
        if(argc < 6)
        {
            printf("please input: <udp port> <ssk file path> <enc> \n");
            printf("\t\t<udp port> == shall be 2368 - read point cloud from this udp port!\n" );
            printf("\t\t<ssk file path> == path of the shared secret key! may be './ucs/ssk/ssk.nky'\n");
            return 1;
        }

        if(shared_secret_key_set(argv[5]))
        {
            printf("shared secret key setting failed!\n");
            free(handle);
            return 1;
        }

        PTC_ErrCode errorCode;
        errorCode = TcpSigStart(handle);
        if(errorCode != 0){
            printf("signature session key calculation failed!\n");
            free(handle); 
		    return errorCode;
        }
        
        uint16_t udp_port = htons((uint16_t)strtoul(argv[4], NULL, 10));
        ret = process_signed_point_cloud(handle, udp_port);

        free(handle);
        return ret;
    }

    free(handle);
    return 0;
}
