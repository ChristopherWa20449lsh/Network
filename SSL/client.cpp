#include <stdio.h>
#include <string.h>
#include <string>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define ROOTCERTPEM "ca.crt"
#define ROOTKEYPEM "ca_rsa_private.pem"
#define SERVERPEM "server.crt"
#define SERVERKEYPEM "server_rsa_private.pem"
#define CLIENTPEM "client.crt"
#define CLIENTKEYPEM "client_rsa_private.pem"

#define MAXBUF 1024
#define PASSWORD "client"

using namespace std;

char *SERVER_IP = "127.0.0.1";
int SERVER_PORT = 8000;
const SSL_METHOD *meth = TLSv1_2_client_method();

void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
    // 如果验证不通过，那么程序抛出异常中止连接
    if (SSL_get_verify_result(ssl) == X509_V_OK)
    {
        printf("证书验证通过\n");
    }
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

int password_cb(char *buf, int num, int rwflag, void *userdata)
{
    char *pass = PASSWORD;
    if ((unsigned int)num < strlen(pass) + 1)
    {
        return (0);
    }

    strcpy(buf, pass);
    return (strlen(pass));
}

// 双重认证
// SSL_CTX *initialize_ctx()
// {
//     /* SSL 库初始化，参看 ssl-server.c 代码 */
//     SSL_library_init();
//     OpenSSL_add_all_algorithms();
//     SSL_load_error_strings();
//     SSL_CTX *ctx = SSL_CTX_new(TLSv1_2_client_method());
//     if (ctx == NULL)
//     {
//         ERR_print_errors_fp(stdout);
//         exit(1);
//     }
//     // 双向验证
//     // SSL_VERIFY_PEER---要求对证书进行认证，没有证书也会放行
//     // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---要求客户端需要提供证书，但验证发现单独使用没有证书也会放行
//     SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
//     // 设置信任根证书
//     if (SSL_CTX_load_verify_locations(ctx, ROOTCERTPEM, NULL) <= 0)
//     {
//         ERR_print_errors_fp(stdout);
//         exit(1);
//     }

//     SSL_CTX_set_default_passwd_cb(ctx, password_cb);

//     /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
//     if (SSL_CTX_use_certificate_file(ctx, CLIENTPEM, SSL_FILETYPE_PEM) <= 0)
//     {
//         ERR_print_errors_fp(stdout);
//         exit(1);
//     }
//     /* 载入用户私钥 */
//     if (SSL_CTX_use_PrivateKey_file(ctx, CLIENTKEYPEM, SSL_FILETYPE_PEM) <= 0)
//     {
//         ERR_print_errors_fp(stdout);
//         exit(1);
//     }
//     /* 检查用户私钥是否正确 */
//     if (!SSL_CTX_check_private_key(ctx))
//     {
//         ERR_print_errors_fp(stdout);
//         exit(1);
//     }
//     printf("SSL_CTX initialized\n");
//     return ctx;
// }

void HEAD_RE(SSL *ssl, BIO *io)
{
    const char *request = "HEAD / HTTP/1.1\r\n"
                          "Host: example.com\r\n"
                          "Connection: close\r\n"
                          "\r\n";
    int request_len = strlen(request);
    int bytes_sent = SSL_write(ssl, request, request_len);
    if (bytes_sent <= 0)
    {
        printf("Failed to send HEAD request\n");
        return;
    }
    printf("HEAD request sent successfully\n");

    char response[MAXBUF + 1];
    int bytes_received = SSL_read(ssl, response, MAXBUF);
    if (bytes_received <= 0)
    {
        printf("Failed to receive response\n");
        return;
    }
    response[bytes_received] = '\0';
    printf("Received response:\n%s\n", response);
}

void GET_RE(SSL *ssl, BIO *io, char *filename)
{
    char request[MAXBUF] = {};

    sprintf(request, "GET %s HTTP/1.1\r\n"
                     "Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/vnd.ms-excel, application/vnd.ms-powerpoint\r\n"
                     "Host: %s\r\n"
                     "Connection: close\r\n"
                     "\r\n",
            filename, SERVER_IP);

    if (BIO_write(io, request, strlen(request)) <= 0)
    {
        printf("Failed to send GET request\n");
        return;
    }
    BIO_flush(io);
    printf("GET request sent successfully\n");

    char buf[MAXBUF], Header[4096];
    int r, length = 0;

    memset(buf, 0, MAXBUF);  // 清空缓冲区
    memset(Header, 0, 4096); // 清空缓冲区
    while (1)
    {
        // 从io中读取一行数据，存放到buf中
        r = BIO_gets(io, buf, MAXBUF - 1);
        // printf("r = %d\r\n",r);
        switch (SSL_get_error(ssl, r))
        {
        case SSL_ERROR_NONE:
            memcpy(&Header[length], buf, r);
            length += r;
            // printf("Case 1... \r\n");
            break;
        default:
            // printf("Case 2... \r\n");
            break;
        }
        // 在 HTTP 协议中，头部和主体之间的分隔符是一个空行
        // 这里读取到说明对于HTTP头部的读取已经完成
        if (!strcmp(buf, "\r\n") || !strcmp(buf, "\n"))
        {
            printf("IF...\r\n");
            break;
        }
    }
    Header[length] = '\0';

    printf("Received response:\n%s\n", Header);

    // 读取主体
    memset(buf, 0, MAXBUF);
    FILE *file = fopen(filename + 1, "wb");
    if (file == NULL)
    {
        printf("Failed to open file\n");
        return;
    }
    while (1)
    {
        r = BIO_read(io, buf, MAXBUF - 1);
        if (r <= 0)
        {
            break;
        }
        fwrite(buf, sizeof(char), r, file);
    }
    fclose(file);
}

void POST_RE(SSL *ssl, BIO *io)
{
    const char *request = "POST / HTTP/1.1\r\n"
                          "Host: example.com\r\n"
                          "Connection: close\r\n"
                          "\r\n";
    int request_len = strlen(request);
    int bytes_sent = SSL_write(ssl, request, request_len);
    if (bytes_sent <= 0)
    {
        printf("Failed to send POST request\n");
        return;
    }
    printf("POST request sent successfully\n");

    char response[MAXBUF + 1];
    int bytes_received = SSL_read(ssl, response, MAXBUF);
    if (bytes_received <= 0)
    {
        printf("Failed to receive response\n");
        return;
    }
    response[bytes_received] = '\0';
    printf("Received response:\n%s\n", response);
}

void DELETE_RE(SSL *ssl, BIO *io, char *filename)
{
    char request[MAXBUF] = {};

    sprintf(request, "DELETE %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Connection: close\r\n"
                     "\r\n",
            filename, SERVER_IP);
    int request_len = strlen(request);
    int bytes_sent = SSL_write(ssl, request, request_len);
    if (bytes_sent <= 0)
    {
        printf("Failed to send DELETE request\n");
        return;
    }
    printf("DELETE request sent successfully\n");

    char response[MAXBUF + 1];
    int bytes_received = SSL_read(ssl, response, MAXBUF);
    if (bytes_received <= 0)
    {
        printf("Failed to receive response\n");
        return;
    }
    response[bytes_received] = '\0';
    printf("Received response:\n%s\n", response);
}

int main(int argc, char *argv[])
{

    if (argc >= 2)
    {
        SERVER_IP = argv[1];
    }

    if (argc >= 3)
    {
        SERVER_PORT = stoi(argv[2]);
    }

    if (argc >= 4)
    {
        switch (atoi(argv[3]))
        {
        case 1:
            meth = TLSv1_1_client_method();
            break;
        case 2:
            meth = TLSv1_2_client_method();
            break;
        default:
            meth = TLSv1_2_client_method();
            break;
        }
    }

    cout << "SSL Version: " << (meth == TLSv1_1_client_method() ? "TLSv1.1" : "TLSv1.2") << endl;
    cout << "Server IP: " << SERVER_IP << endl;
    cout << "Server Port: " << SERVER_PORT << endl;

    int sockfd, len;
    struct sockaddr_in dest;
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *sbio, *io, *ssl_bio;

    /* SSL 库初始化，参看 ssl-server.c 代码 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    // ctx = initialize_ctx();
    ctx = SSL_CTX_new(meth);

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &dest.sin_addr);

    while (true)
    {
        /* 创建一个 socket 用于 tcp 通信 */
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            perror("Socket");
            exit(errno);
        }
        /* 连接服务器 */
        if (connect(sockfd, (struct sockaddr *)&dest, sizeof(dest)) != 0)
        {
            perror("Connect ");
            exit(errno);
        }
        /* 基于 ctx 产生一个新的 SSL */
        ssl = SSL_new(ctx);

        sbio = BIO_new_socket(sockfd, BIO_NOCLOSE);
        SSL_set_bio(ssl, sbio, sbio);

        /* 建立 SSL 连接 */
        if (SSL_connect(ssl) == -1)
        {
            printf("ssl connect failed\n");
            ERR_print_errors_fp(stderr);
        }
        else
        {
            printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
            ShowCerts(ssl);
        }

        io = BIO_new(BIO_f_buffer());
        ssl_bio = BIO_new(BIO_f_ssl());
        BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
        BIO_push(io, ssl_bio);
        // 接下来，我们可以使用 io 来读写数据，而不用直接使用 sockfd

        printf("Enter message type to send: HEAD, GET, POST\n");

        char message_type[10];
        char filename[100];
        scanf("%s", message_type);

        if (strcmp(message_type, "GET") == 0)
        {
            printf("Enter filename to GET\n");
            scanf("%s", filename);
            GET_RE(ssl, io, filename);
        }
        else if (strcmp(message_type, "HEAD") == 0)
            HEAD_RE(ssl, io);
        else if (strcmp(message_type, "DELETE") == 0)
        {
            printf("Enter filename to GET\n");
            scanf("%s", filename);
            DELETE_RE(ssl, io, filename);
        }
        else
            printf("Invalid message type\n");

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sockfd);
    }

    // finish:
    /* 关闭连接 */
    // SSL_shutdown(ssl);
    // SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 0;
}