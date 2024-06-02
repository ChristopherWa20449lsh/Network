#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXBUF 1024
#define SERVER_IP "127.0.0.1" // 指定服务端的IP，记得修改为你的服务端所在的ip
#define SERVER_PORT 16555     // 指定服务端的port

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL)
    {
        printf("数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("无证书信息！\n");
}
int main()
{
    int sockfd, len;
    struct sockaddr_in dest; // server 的地址信息
    char buffer[MAXBUF + 1];

    /* SSL_CTX介绍
    SSL_CTX 是一个 SSL 上下文对象，它包含了 SSL 连接的很多设置和选项。
    例如，你可以在 SSL_CTX 中设置证书、私钥、密码回调函数、选项标志等。
    当你创建一个 SSL_CTX 对象时，这些设置和选项会被用于新的 SSL 连接。
    你可以把 SSL_CTX 看作是 SSL 连接的模板
    */
    SSL_CTX *ctx;
    /* SSL介绍
    SSL 是一个代表 SSL 连接的对象。
    当你创建一个新的 SSL 连接时，你需要从一个 SSL_CTX 对象创建一个 SSL 对象。
    SSL 对象包含了 SSL 连接的所有状态信息，例如握手状态、加密参数、应用数据等。
    你可以使用 SSL 对象的函数来进行读写操作，进行握手，获取连接状态等
    */
    SSL *ssl;

    SSL_library_init();                         // 初始化 SSL 库
    OpenSSL_add_all_algorithms();               // 加载所有算法
    SSL_load_error_strings();                   // 加载所有错误信息
    ctx = SSL_CTX_new(TLSv1_1_client_method()); // 创建 SSL_CTX 对象(选择会话协议，比如这里选择SSLv2/v3)
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4") != 1)
    {
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    // 启用心跳机制
    SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Create socket error(%d): %s\n", errno, strerror(errno));
        exit(errno);
    }
    printf("socket created\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, SERVER_IP, &dest.sin_addr);
    dest.sin_port = htons(SERVER_PORT);

    printf("address settled\n");

    /* 尝试建立TCP连接，连接建立成功返回0 */
    if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0)
    {
        printf("Connect error(%d): %s\n", errno, strerror(errno));
        exit(errno);
    }
    printf("server connected\n");

    /* 基于 ctx 产生一个新的 SSL */
    ssl = SSL_new(ctx);      // 创建一个新的SSL连接
    SSL_set_fd(ssl, sockfd); // 将ssl和套接字关联，这样就可以使用openssl对套接字进行加密和解密操作了
    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1) // 尝试建立SSL连接（使用一个ssl对象作为参数）
        ERR_print_errors_fp(stderr);
    else
    {
        // 打印SSL连接使用的加密算法
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        // 打印SSL连接的证书信息
        ShowCerts(ssl);
    }

    /* 接收对方发过来的消息，最多接收 MAXBUF 个字节 */
    bzero(buffer, MAXBUF + 1);
    /* 接收服务器来的消息 */
    len = SSL_read(ssl, buffer, MAXBUF);
    if (len > 0)
        printf("接收消息成功:'%s'，共%d个字节的数据\n",
               buffer, len);
    else
    {
        printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",
               errno, strerror(errno));
        goto finish;
    }
    bzero(buffer, MAXBUF + 1);
    printf("请输入消息：");
    scanf("%s", buffer);
    /* 发消息给服务器 */
    len = SSL_write(ssl, buffer, strlen(buffer));
    if (len < 0)
        printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",
               buffer, errno, strerror(errno));
    else
        printf("消息'%s'发送成功，共发送了%d个字节！\n",
               buffer, len);

finish:
    /* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}