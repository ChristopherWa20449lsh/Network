#include "common.h"
#include "HttpProtocol.h"

int main()
{
	CHttpProtocol MyHttpObj;  // 创建一个CHttpProtocol对象
	MyHttpObj.StartHttpSrv(); // 调用StartHttpSrv()函数启动HTTP服务
	SSL *ssl;				  // 创建一个SSL对象
	BYTE buf[4096];			  // 创建一个缓冲区
	BIO *io;				  // 创建一个BIO对象
	bool bRet;
	bRet = MyHttpObj.SSLRecvRequest(ssl, io, buf, sizeof(buf)); // 调用SSLRecvRequest()函数接收请求
	if (!bRet)
	{
		MyHttpObj.err_exit("Receiving request error! \n");
	}
	else
	{
		printf("Request received!! \n");
		printf("%s \n", buf);
	}
	sleep(1000);
	return 0;
}
