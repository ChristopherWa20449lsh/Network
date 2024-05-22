#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/socket.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define BUFFSIZE 2048
#define SERVER_IP "127.0.0.1" // 指定服务端的IP，记得修改为你的服务端所在的ip
#define SERVER_PORT 16555     // 指定服务端的port
int main()
{
    struct sockaddr_in servaddr;
    char buff[BUFFSIZE];
    int sockfd;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd)
    {
        printf("Create socket error(%d): %s\n", errno, strerror(errno));
        return -1;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    // inet_pton函数用于将点分十进制的IP地址转换为网络字节序的二进制值
    inet_pton(AF_INET, SERVER_IP, &servaddr.sin_addr);
    // htons函数用于将主机字节序的端口号转换为网络字节序的端口号
    // 在网络通讯中，为了保证数据的正确传输，我们需要将数据转换为网络字节序（大端字节序）
    // htons的全名是host to network short
    servaddr.sin_port = htons(SERVER_PORT);
    if (-1 == connect(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)))
    {
        printf("Connect error(%d): %s\n", errno, strerror(errno));
        close(sockfd);
        return -1;
    }
    printf("Please input: ");
    scanf("%s", buff);
    send(sockfd, buff, strlen(buff), 0);
    bzero(buff, sizeof(buff));
    recv(sockfd, buff, BUFFSIZE - 1, 0);
    printf("Recv: %s\n", buff);
    close(sockfd);
    return 0;
}