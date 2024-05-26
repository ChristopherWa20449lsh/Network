#include "common.h"
#include "HttpProtocol.h"

int main()
{
	CHttpProtocol MyHttpObj;  // 创建一个CHttpProtocol对象
	MyHttpObj.StartHttpSrv(); // 调用StartHttpSrv()函数启动HTTP服务
	SSL *ssl;
	BYTE buf[4096];
	BIO *io;
	bool bRet;
	bRet = MyHttpObj.SSLRecvRequest(ssl, io, buf, sizeof(buf));
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
