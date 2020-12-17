
#CC=arm-linux-gnueabihf-gcc
#CC=gcc
CFLAGE=-lssl -lcrypto -L./libs/lib -I./include -I./libs/include -Wl,-rpath="./libs/lib" 
#stack protection enable
CFLAGE += -fstack-protector
#RELORO NOW
CFLAGE += -z relro -z now
#Executable code
CFLAGE += -fPIE

ifeq ($(SSL),on)
	CFLAGE += -DCONFIG_SSL
endif
all:
	$(CC) tcp_command_client.c ptcs_sig_test.c common.c  hkdf.c pointcloud_signature.c hmac.c -o ptcs_sig $(CFLAGE)
clear:
	$(RM) -rf ptcs_sig
