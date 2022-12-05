#include <common.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <errno.h>
#include <signal.h>

int read_file(const char *filename, char *buff, int *len)
{
    int fd;
    struct stat sb;
    off_t offset, pa_offset;
    size_t length;
    ssize_t s;
    char *addr;
    fd = open(filename, O_RDONLY);
    if (fd == -1)
        handle_error("open failed!");

    if (fstat(fd, &sb) == -1)           /* To obtain file size */
        handle_error("fstat failed!");

    offset = 0;
    pa_offset = offset & ~(sysconf(_SC_PAGE_SIZE) - 1);
        /* offset for mmap() must be page aligned */
        
    length = sb.st_size - offset;

    addr = mmap(NULL, length + offset - pa_offset, PROT_READ,
                MAP_PRIVATE, fd, pa_offset);
    if (addr == MAP_FAILED)
        handle_error("mmap failed");

    memcpy(buff, addr + offset - pa_offset, length);
    *len = sb.st_size;
    munmap(addr, length + offset - pa_offset);
    close(fd);
    return 0;
}

static void printf_data(const char *description, 
                 const unsigned char *data, 
                 const int datal)
{
    printf("%s:\n", description);
    for (int i = 0; i < datal; i++){
        if(i%32 == 0 && i > 0)
            printf("\n");
        printf("%02x", (unsigned char)data[i]);
    }
    printf("\n");
}

#define CONFIG_KEY_MSG_PRINT
void printf_cipher_message(const char *description, 
                           const unsigned char *message, 
                           const int messagel)
{
#ifdef CONFIG_KEY_MSG_PRINT
    printf_data(description, message, messagel);
#endif
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

int random_get(unsigned char *random, int randoml)
{
    if(randoml <= 0 || random == NULL)
    {
        printf("parameter error!");
        return 1;
    }
    int fd;
    int rdlen = 0;
    if((fd = open("/dev/urandom", O_RDONLY)) <= 0)
        return 1;

    if((rdlen = sys_readn(fd, random, randoml)) != randoml) {
        close(fd);
        return 1;
    }
    close(fd);
    return 0;
}