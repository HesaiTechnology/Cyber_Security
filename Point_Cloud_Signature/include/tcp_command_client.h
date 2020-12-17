#ifndef TCP_COMMAND_CLIENT_H
#define TCP_COMMAND_CLIENT_H
#define MAX_IPV4_STRING_LEN (32)

#define PTC_VERSION 010902

#ifdef __cplusplus
extern "C" {
#endif
#ifndef PACKED
#define PACKED __attribute__((packed))
#endif

typedef enum{
	PTC_COMMAND_GET_LIDAR_CALIBRATION = 5 ,
	PTC_COMMAND_GET_DP_SIG_STATE      = 45, 
	PTC_COMMAND_DP_SIG_SESSION_START  = 46,
	PTC_COMMAND_DP_SIG_SESSION_STOP   = 47,

}PTC_COMMAND;


typedef enum{
	PTC_ERROR_NO_ERROR = 0,
	PTC_ERROR_BAD_PARAMETER,
	PTC_ERROR_CONNECT_SERVER_FAILED,
	PTC_ERROR_TRANSFER_FAILED,
	PTC_ERROR_NO_MEMORY,
	PTC_ERROR_NOT_SUPPORT,
	PTC_ERROR_FPGA_ERROR,
}PTC_ErrCode;

typedef struct TcpCommandHeader_s{
	unsigned char cmd;
	unsigned char ret_code;
	unsigned int len;
}TcpCommandHeader;

typedef struct TC_Command_s
{
	TcpCommandHeader header;
	unsigned char * data;

	unsigned char * ret_data;
	unsigned int ret_size;
}PACKED TC_Command;

PTC_ErrCode TcpSigStart(void * handle);
PTC_ErrCode TcpSigQuery(void * handle);
PTC_ErrCode TcpSigStop(void * handle);

void *TcpCommandClientNew(char* ip , unsigned short port);
#ifdef __cplusplus
}
#endif

#endif
