#include "common.h"
#include "HttpProtocol.h"

int main(int argc, char *argv[])
{
	int v;
	if (argc != 2)
	{
		printf("Usage: %s <1|2> to choose the TLS version,setting TLSv1.2 as default\n", argv[0]);
		v = 2;
	}
	else
	{
		v = atoi(argv[1]);
	}
	CHttpProtocol MyHttpObj(v); // 创建一个CHttpProtocol对象
	printf("Setting SSL Version to %s\n", (v == 1) ? "TLSv1.1" : "TLSv1.2");
	MyHttpObj.StartHttpSrv(); // 调用StartHttpSrv()

	while (true)
	{
	}
	// SSL *ssl;		// 创建一个SSL对象
	// BYTE buf[4096]; // 创建一个缓冲区
	// BIO *io;		// 创建一个BIO对象
	// bool bRet;
	// // 主次进程同步的问题：主进程应该在此处等待才对
	// bRet = MyHttpObj.SSLRecvRequest(ssl, io, buf, sizeof(buf)); // 调用SSLRecvRequest()函数接收请求
	// if (!bRet)
	// {
	// 	MyHttpObj.err_exit("Receiving request error! \n");
	// }
	// else
	// {
	// 	printf("Request received!! \n");
	// 	printf("%s \n", buf);
	// }
	// sleep(1000);
	return 0;
}
