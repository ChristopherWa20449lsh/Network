#ifndef _common_h
#define _common_h

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define HTTPSPORT 8000
#define METHOD_GET 0
#define METHOD_HEAD 1

#define BUFSIZZ 1024
#define ROOTCERTPEM "root-cert.pem"
#define ROOTKEYPEM "root-key.pem"
#define SERVERKEYPEM "server-key.pem"
#define SERVERPEM "server.pem"
#define PASSWORD "OPENSSL"

#define HTTP_STATUS_OK "200 OK"
#define HTTP_STATUS_CREATED "201 Created"
#define HTTP_STATUS_ACCEPTED "202 Accepted"
#define HTTP_STATUS_NOCONTENT "204 No Content"
#define HTTP_STATUS_MOVEDPERM "301 Moved Permanently"
#define HTTP_STATUS_MOVEDTEMP "302 Moved Temporarily"
#define HTTP_STATUS_NOTMODIFIED "304 Not Modified"
#define HTTP_STATUS_BADREQUEST "400 Bad Request"
#define HTTP_STATUS_UNAUTHORIZED "401 Unauthorized"
#define HTTP_STATUS_FORBIDDEN "403 Forbidden"
#define HTTP_STATUS_NOTFOUND "404 File can not fonund!"
#define HTTP_STATUS_SERVERERROR "500 Internal Server Error"
#define HTTP_STATUS_NOTIMPLEMENTED "501 Not Implemented"
#define HTTP_STATUS_BADGATEWAY "502 Bad Gateway"
#define HTTP_STATUS_UNAVAILABLE "503 Service Unavailable"

typedef int INT;
typedef unsigned int UINT;
typedef unsigned int *PUINT;
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef UINT SOCKET;
typedef unsigned long DWORD;
typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef float FLOAT;
typedef FLOAT *PFLOAT;
typedef BOOL *PBOOL;
typedef BOOL *LPBOOL;
typedef BYTE *PBYTE;
typedef BYTE *LPBYTE;
typedef int *PINT;
typedef int *LPINT;
typedef WORD *PWORD;
typedef WORD *LPWORD;
typedef long *LPLONG;
typedef DWORD *PDWORD;
typedef DWORD *LPDWORD;
typedef void *LPVOID;
typedef char *LPSTR;
typedef struct sockaddr *LPSOCKADDR;
typedef void *HANDLE;
#define INVALID_HANDLE_VALUE (HANDLE) - 1
#define INVALID_FILE_SIZE (DWORD)0xFFFFFFFF
#define INVALID_SOCKET (SOCKET)(~0)
#define SOCKET_ERROR (-1)
typedef struct REQUEST
{
	HANDLE hExit;
	SOCKET Socket;			   // �����socket
	int nMethod;			   // �����ʹ�÷�����GET��HEAD
	DWORD dwRecv;			   // �յ����ֽ���
	DWORD dwSend;			   // ���͵��ֽ���
	int hFile;				   // �������ӵ��ļ�
	char szFileName[256];	   // �ļ������·��
	char postfix[10];		   // �洢��չ��
	char StatuCodeReason[100]; // ͷ����status cod�Լ�reason-phrase
	bool permitted;			   // �û�Ȩ���ж�
	char *authority;		   // �û��ṩ����֤��Ϣ
	char key[1024];			   // ��ȷ��֤��Ϣ
	SSL_CTX *ssl_ctx;
	void *pHttpProtocol; // ָ����CHttpProtocol��ָ��
} REQUEST, *PREQUEST;

typedef struct HTTPSTATS
{
	DWORD dwRecv; // �յ��ֽ���
	DWORD dwSend; // �����ֽ���
} HTTPSTATS, *PHTTPSTATS;

#endif
