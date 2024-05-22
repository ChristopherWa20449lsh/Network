#include <unistd.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <arpa/inet.h> // inet_ntoa函数：将网络字节序的ip地址转换为点分十进制的ip地址
#include <sys/socket.h>
#include <sys/unistd.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <netinet/in.h>
#include <signal.h>

#define BUFFSIZE 2048      // 缓冲区大小
#define DEFAULT_PORT 16555 // 指定端口为16555
#define MAXLINK 2048       // 最大连接数

int sockfd, connfd; // 定义监听套接字（用于监听客户端连接）和连接套接字（用于进行数据交换）

void stopServerRunning(int p)
{
    close(sockfd);
    printf("Close Server\n");
    exit(0);
}

void output_sockaddr_in(sockaddr_in *addr)
{
    printf("sin_family: %d\n", addr->sin_family);
    printf("Port(未转化): %d\n", addr->sin_port);
    printf("Port(转化): %d\n", ntohs(addr->sin_port));
    printf("IP: %s\n", inet_ntoa(addr->sin_addr));
}

void set_response(char *buff)
{
    bzero(buff, BUFFSIZE);
    strcat(buff, "HTTP/1.1 200 OK\r\n");
    strcat(buff, "Connection: close\r\n");
    strcat(buff, "\r\n");
    strcat(buff, "Hello\n");
}

int main()
{
    struct sockaddr_in servaddr; // 用于存放ip和端口的结构
    struct sockaddr clientaddr;
    socklen_t clientaddr_len; // 用于存放clientaddr的长度
    char buff[BUFFSIZE];      // 用于收发数据
    // 对应伪代码中的sockfd = socket();
    // AF_INET表示使用ipv4协议，SOCK_STREAM表示使用TCP协议，0表示使用默认协议
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (-1 == sockfd) // 如果socket创建失败
    {
        // 通常一个内核函数运行出错的时候，它会定义全局变量errno并赋值（通过strerror(errno)可以输出具体错误信息）
        printf("Create socket error(%d): %s\n", errno, strerror(errno));
        return -1;
    }
    // 对应伪代码中的bind(sockfd, ip::port和一些配置);
    bzero(&servaddr, sizeof(servaddr));                                     // clear servaddr(servaddr被用作bind函数的参数)
    servaddr.sin_family = AF_INET;                                          // 使用ipv4协议
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);                           // 服务器允许任何ip连接
    servaddr.sin_port = htons(DEFAULT_PORT);                                // 设置提供服务的端口
    if (-1 == bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) // 绑定ip和端口
    {
        printf("Bind error(%d): %s\n", errno, strerror(errno));
        return -1;
    }
    // 对应伪代码中的listen(sockfd);
    if (-1 == listen(sockfd, MAXLINK)) // MAXLINK指定了最佳连接请求队列的长度（超出的请求会被忽略）
    {
        // listen函数本身并不处理连接请求，它只是设置套接字为监听模式，并指定了最大的连接请求队列长度。当客户端向服务器发送连接请求时，这些请求会被放入一个队列中，队列的最大长度由listen函数的第二个参数MAXLINK指定。
        // 真正接受并处理这些连接请求的是accept函数。当accept函数被调用时，它会从队列中取出一个连接请求来处理，如果队列为空（即没有客户端发送连接请求），accept函数会阻塞，直到有新的连接请求到来。
        // 如果想要并发处理多个连接请求，需要自己在服务端实现多线程或者多进程
        printf("Listen error(%d): %s\n", errno, strerror(errno));
        return -1;
    }
    // END
    while (true)
    {
        printf("Listening...\n");
        signal(SIGINT, stopServerRunning); // 这句用于在输入Ctrl+C的时候关闭服务器
        bzero(&clientaddr, sizeof(clientaddr));
        // 对应伪代码中的connfd = accept(sockfd);
        // 当accept函数被调用时，它会从队列中取出一个连接请求来处理
        // 如果队列为空（即没有客户端发送连接请求），accept函数会阻塞，直到有新的连接请求到来。
        connfd = accept(sockfd, (struct sockaddr *)&clientaddr, &clientaddr_len);
        /* 这里简单介绍一下accept函数
        int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        sockfd：是一个监听套接字，用于接收客户端的连接请求
        addr：是一个指向sockaddr_in结构体的指针，用于存放客户端的ip和端口（如果你不关心客户端的地址信息的话，直接置NULL即可）
        addrlen：是一个指向整型变量的指针，用于存放addr的长度（同理，如果addr置NULL，此项也必须是NULL）
        */
        if (-1 == connfd)
        {
            printf("Accept error(%d): %s\n", errno, strerror(errno));
            return -1;
        }
        bzero(buff, BUFFSIZE);
        // 对应伪代码中的recv(connfd, buff);
        recv(connfd, buff, BUFFSIZE - 1, 0);
        // END
        printf("Recv: %s\n", buff);
        // output_sockaddr_in((sockaddr_in *)&clientaddr);
        // 对应伪代码中的send(connfd, buff);
        set_response(buff);
        send(connfd, buff, strlen(buff), 0);
        // 对应伪代码中的close(connfd);
        close(connfd);
        // 如果不close直接调用connfd = accept(...);，而没有先关闭connfd，那么你就会丢失对原来套接字的引用
        // 无法再关闭它，这就造成了资源泄漏（类比free操作）
    }
    return 0;
}