#include "common.h"
#include <sys/stat.h>
#include "HttpProtocol.h"

#include "json.hpp"

using json = nlohmann::json;

using namespace std;

#define MAXLINK 5

char *CHttpProtocol::pass = PASSWORD;

// 构造函数，初始化SSL_CTX对象
CHttpProtocol::CHttpProtocol(void)
{
	CreateTypeMap();
	printf("初始化SSL_CTX对象... \n");
	printf("OpenSSL version: %s %s\n", OPENSSL_VERSION_TEXT, OpenSSL_version(OPENSSL_DIR));
	bio_err = 0;
	m_strRootDir = "./WebServer"; // web根目录
	ErrorMsg = "";
	// 初始化SSL_CTX对象
	ErrorMsg = initialize_ctx();
	if (ErrorMsg == "")
	{
		ErrorMsg = load_dh_params(ctx, ROOTKEYPEM);
	}
	else
		printf("%s \n", ErrorMsg);
}
// 释放SSL_CTX对象包含的所有资源（直接类比free函数即可）
CHttpProtocol::~CHttpProtocol(void)
{
	SSL_CTX_free(ctx);
}

char *CHttpProtocol::initialize_ctx()
{
	if (!bio_err)
	{
		// OpenSSL库初始化
		SSL_library_init();
		// 载入所有SSL算法
		OpenSSL_add_all_algorithms();
		// 载入所有 SSL 错误消息
		SSL_load_error_strings();
		// 设置一个错误输出接口，用于将OpenSSL的错误消息输出到标准错误
		bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	}
	else
	{
		return "initialize_ctx() error!";
	}

	// 创建SSL_CTX对象
	ctx = SSL_CTX_new(TLSv1_2_server_method());

	// 双向验证
	// SSL_VERIFY_PEER---要求对证书进行认证，没有证书也会放行
	// SSL_VERIFY_FAIL_IF_NO_PEER_CERT---要求客户端需要提供证书，但验证发现单独使用没有证书也会放行
	// SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	// 设置SSL会话的密码回调函数（用于加密解密私钥文件）
	SSL_CTX_set_default_passwd_cb(ctx, password_cb);

	// 设置信任根证书
	if (SSL_CTX_load_verify_locations(ctx, ROOTCERTPEM, NULL) <= 0)
	{
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	/* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
	if (SSL_CTX_use_certificate_file(ctx, SERVERPEM, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* 载入用户私钥 */
	if (SSL_CTX_use_PrivateKey_file(ctx, SERVERKEYPEM, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* 检查用户私钥是否正确 */
	if (!SSL_CTX_check_private_key(ctx))
	{
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	return "";
}

char *CHttpProtocol::load_dh_params(SSL_CTX *ctx, char *file)
{
	DH *ret = 0;
	BIO *bio;

	if ((bio = BIO_new_file(file, "r")) == NULL)
	{
		char *Str = "BIO_new_file error!";
		return Str;
	}

	ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (SSL_CTX_set_tmp_dh(ctx, ret) < 0)
	{
		char *Str = "SSL_CTX_set_tmp_dh error!";
		return Str;
	}
	return "";
}

int CHttpProtocol::password_cb(char *buf, int num, int rwflag, void *userdata)
{
	if ((unsigned int)num < strlen(pass) + 1)
	{
		return (0);
	}

	strcpy(buf, pass);
	return (strlen(pass));
}

void CHttpProtocol::err_exit(char *str)
{
	printf("%s \n", str);
	exit(1);
}

void CHttpProtocol::Disconnect(PREQUEST pReq)
{
	// ????????????????§Ö????
	int nRet;
	printf("Closing socket! \r\n");

	nRet = close(pReq->Socket);
	if (nRet == SOCKET_ERROR)
	{
		// ????????
		printf("Closing socket error! \r\n");
	}

	//	HTTPSTATS	stats;
	//	stats.dwRecv = pReq->dwRecv;
	//	stats.dwSend = pReq->dwSend;
	//	SendMessage(m_hwndDlg, DATA_MSG, (UINT)&stats, NULL);
}
// 创建文件拓展名映射表（用于设置响应头中的Content-Type字段）
void CHttpProtocol::CreateTypeMap()
{
	m_typeMap[".doc"] = "application/msword";
	m_typeMap[".bin"] = "application/octet-stream";
	m_typeMap[".dll"] = "application/octet-stream";
	m_typeMap[".exe"] = "application/octet-stream";
	m_typeMap[".pdf"] = "application/pdf";
	m_typeMap[".ai"] = "application/postscript";
	m_typeMap[".eps"] = "application/postscript";
	m_typeMap[".ps"] = "application/postscript";
	m_typeMap[".rtf"] = "application/rtf";
	m_typeMap[".fdf"] = "application/vnd.fdf";
	m_typeMap[".arj"] = "application/x-arj";
	m_typeMap[".gz"] = "application/x-gzip";
	m_typeMap[".class"] = "application/x-java-class";
	m_typeMap[".js"] = "application/x-javascript";
	m_typeMap[".lzh"] = "application/x-lzh";
	m_typeMap[".lnk"] = "application/x-ms-shortcut";
	m_typeMap[".tar"] = "application/x-tar";
	m_typeMap[".hlp"] = "application/x-winhelp";
	m_typeMap[".cert"] = "application/x-x509-ca-cert";
	m_typeMap[".zip"] = "application/zip";
	m_typeMap[".cab"] = "application/x-compressed";
	m_typeMap[".arj"] = "application/x-compressed";
	m_typeMap[".aif"] = "audio/aiff";
	m_typeMap[".aifc"] = "audio/aiff";
	m_typeMap[".aiff"] = "audio/aiff";
	m_typeMap[".au"] = "audio/basic";
	m_typeMap[".snd"] = "audio/basic";
	m_typeMap[".mid"] = "audio/midi";
	m_typeMap[".rmi"] = "audio/midi";
	m_typeMap[".mp3"] = "audio/mpeg";
	m_typeMap[".vox"] = "audio/voxware";
	m_typeMap[".wav"] = "audio/wav";
	m_typeMap[".ra"] = "audio/x-pn-realaudio";
	m_typeMap[".ram"] = "audio/x-pn-realaudio";
	m_typeMap[".bmp"] = "image/bmp";
	m_typeMap[".gif"] = "image/gif";
	m_typeMap[".jpeg"] = "image/jpeg";
	m_typeMap[".jpg"] = "image/jpeg";
	m_typeMap[".tif"] = "image/tiff";
	m_typeMap[".tiff"] = "image/tiff";
	m_typeMap[".xbm"] = "image/xbm";
	m_typeMap[".wrl"] = "model/vrml";
	m_typeMap[".htm"] = "text/html";
	m_typeMap[".html"] = "text/html";
	m_typeMap[".c"] = "text/plain";
	m_typeMap[".cpp"] = "text/plain";
	m_typeMap[".def"] = "text/plain";
	m_typeMap[".h"] = "text/plain";
	m_typeMap[".txt"] = "text/plain";
	m_typeMap[".rtx"] = "text/richtext";
	m_typeMap[".rtf"] = "text/richtext";
	m_typeMap[".java"] = "text/x-java-source";
	m_typeMap[".css"] = "text/css";
	m_typeMap[".mpeg"] = "video/mpeg";
	m_typeMap[".mpg"] = "video/mpeg";
	m_typeMap[".mpe"] = "video/mpeg";
	m_typeMap[".avi"] = "video/msvideo";
	m_typeMap[".mov"] = "video/quicktime";
	m_typeMap[".qt"] = "video/quicktime";
	m_typeMap[".shtml"] = "wwwserver/html-ssi";
	m_typeMap[".asa"] = "wwwserver/isapi";
	m_typeMap[".asp"] = "wwwserver/isapi";
	m_typeMap[".cfm"] = "wwwserver/isapi";
	m_typeMap[".dbm"] = "wwwserver/isapi";
	m_typeMap[".isa"] = "wwwserver/isapi";
	m_typeMap[".plx"] = "wwwserver/isapi";
	m_typeMap[".url"] = "wwwserver/isapi";
	m_typeMap[".cgi"] = "wwwserver/isapi";
	m_typeMap[".php"] = "wwwserver/isapi";
	m_typeMap[".wcgi"] = "wwwserver/isapi";
}

int CHttpProtocol::TcpListen()
{
	int sock;
	struct sockaddr_in sin; // 用于存放ip和端口的数据结构

	// PF_INET：ipv4协议，SOCK_STREAM：TCP协议
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) // 创建socket失败直接退出
		err_exit("Couldn't make socket");

	memset(&sin, 0, sizeof(sin));
	sin.sin_addr.s_addr = htonl(INADDR_ANY); // 允许任意ip地址建立TCP连接(htonl转换为网络字节序)
	sin.sin_family = PF_INET;				 // ipv4协议
	sin.sin_port = htons(HTTPSPORT);		 // 8000端口

	// ::bind(sock, (struct sockaddr *)&sin, sizeof(sin));
	// 设置端口复用
	int reuse = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
	{
		err_exit("setsockopt(SO_REUSEADDR) failed");
	}
	if (::bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0)
	{

		err_exit("Couldn't bind");
	}

	// 使用全局bind而不是std::下的bind函数！！！！！！！！！
	// if (::bind(sock, (struct sockaddr *)&sin, sizeof(sin)) < 0) // 绑定ip和端口
	// err_exit("Couldn't bind");
	// listen函数本身并不处理连接请求，它只是设置套接字为监听模式，并指定了最大的连接请求队列长度。当客户端向服务器发送连接请求时，这些请求会被放入一个队列中，队列的最大长度由listen函数的第二个参数MAXLINK指定。
	// 真正接受并处理这些连接请求的是accept函数。当accept函数被调用时，它会从队列中取出一个连接请求来处理，如果队列为空（即没有客户端发送连接请求），accept函数会阻塞，直到有新的连接请求到来。
	if (-1 == listen(sock, MAXLINK))
		err_exit("TcpListen error!");
	printf("TcpListen Ok\n");

	return sock;
}
// SSL请求接收函数（只能处理get请求，因为只读取了头部数据）
// 一个典型的HTTP请求如下：
/* GET请求范例
GET /index.html HTTP/1.1
Host: www.example.com
User-Agent: Mozilla/5.0
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

主体内容为空（上面是\r\n）
*/
bool CHttpProtocol::SSLRecvRequest(SSL *ssl, BIO *io, LPBYTE pBuf, DWORD dwBufSize)
{
	// printf("SSLRecvRequest \n");
	char buf[BUFSIZZ];
	int r, length = 0;

	memset(buf, 0, BUFSIZZ); // 清空缓冲区
	while (1)
	{
		// 从io中读取一行数据，存放到buf中
		r = BIO_gets(io, buf, BUFSIZZ - 1);
		// printf("r = %d\r\n",r);
		switch (SSL_get_error(ssl, r))
		{
		case SSL_ERROR_NONE:
			memcpy(&pBuf[length], buf, r);
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
	pBuf[length] = '\0';
	return true;
}
bool CHttpProtocol::StartHttpSrv()
{
	CreateTypeMap();

	printf("*******************Server starts************************ \n");

	pid_t pid;
	m_listenSocket = TcpListen(); // 创建TCP监听套接字，监听8000端口

	pthread_t listen_tid;
	pthread_create(&listen_tid, NULL, &ListenThread, this);
}

void *CHttpProtocol::ListenThread(LPVOID param)
{
	printf("Starting ListenThread... \n");

	CHttpProtocol *pHttpProtocol = (CHttpProtocol *)param;

	SOCKET socketClient; // 用于和客户端通信的socket
	pthread_t client_tid;
	struct sockaddr_in SockAddr;
	PREQUEST pReq;
	socklen_t nLen;
	DWORD dwRet;

	while (1) // 循环调用accept接受新连接，并为每个新的连接创建一个新的线程来处理客户端请求
	{
		// printf("while!\n");
		nLen = sizeof(SockAddr);
		// 创建客户数据接收套接字（SockAddr用于接收客户端的相关信息）
		// accept就是从listen的队列中取出一个连接请求，如果队列为空（即没有客户端发送连接请求），accept函数会阻塞，直到有新的连接请求到来。
		// printf("%d\n", nLen);
		if ((socketClient = accept(pHttpProtocol->m_listenSocket, (LPSOCKADDR)&SockAddr, &nLen)) == -1)
		{
			printf("accept error(%d): %s\n", errno, strerror(errno));
			break;
		}
		printf("client ip: %s\nclient port: %d\n", inet_ntoa(SockAddr.sin_addr), ntohs(SockAddr.sin_port)); // 输出客户端连接ip

		if (socketClient == INVALID_SOCKET)
		{
			printf("INVALID_SOCKET !\n");
			break;
		}
		pReq = new REQUEST;
		// pReq->hExit  = pHttpProtocol->m_hExit;
		pReq->Socket = socketClient;
		pReq->hFile = -1;
		pReq->dwRecv = 0;
		pReq->dwSend = 0;
		pReq->pHttpProtocol = pHttpProtocol;
		pReq->ssl_ctx = pHttpProtocol->ctx;

		// 对每个新的连接创建一个新的线程（处理函数为ClientThread,传递参数为pReq）
		// printf("New request");
		pthread_create(&client_tid, NULL, &ClientThread, pReq);
	} // while

	return NULL;
}

void *CHttpProtocol::ClientThread(LPVOID param)
{
	printf("Starting ClientThread... \n");
	int nRet;
	SSL *ssl;
	BYTE buf[4096]; // 缓冲区
	BIO *sbio, *io, *ssl_bio;
	PREQUEST pReq = (PREQUEST)param;
	CHttpProtocol *pHttpProtocol = (CHttpProtocol *)pReq->pHttpProtocol;
	// pHttpProtocol->CountUp();
	SOCKET s = pReq->Socket; // 和客户端的通信socket

	// 这里就是给SSL_read和SSL_write套了个娃
	sbio = BIO_new_socket(s, BIO_NOCLOSE); // sbio是和客户端的通信接口
	ssl = SSL_new(pReq->ssl_ctx);		   // 基于ctx创建一个新的SSL对象
	SSL_set_bio(ssl, sbio, sbio);		   // 将sbio和ssl关联起来，这样当ssl对象读写数据时，就会通过sbio来读写数据

	nRet = SSL_accept(ssl); // SSL握手，建立安全连接

	if (nRet <= 0)
	{
		pHttpProtocol->err_exit("SSL_accept()error! \r\n");
	}
	else
	{
		printf("SSL连接建立... \n");
	}

	// 安全连接建立成功，开始处理客户端请求
	// 设置缓冲读取，可以大大提高读取效率
	io = BIO_new(BIO_f_buffer());
	ssl_bio = BIO_new(BIO_f_ssl());
	BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE); // ssl_bio和ssl关联
	BIO_push(io, ssl_bio);				  // 缓冲区和ssl_bio关联

	// 开始获取客户端请求数据
	printf("****************\r\n");

	// Rest of the code goes here...
	if (!pHttpProtocol->SSLRecvRequest(ssl, io, buf, sizeof(buf)))
	{
		pHttpProtocol->err_exit("Receiving SSLRequest error!! \r\n");
	}
	else
	{
		printf("Request received!! \n");
		printf("%s \n", buf);
		// return 0;
	}
	// 开始分析客户端请求
	nRet = pHttpProtocol->Analyze(pReq, buf);
	if (nRet)
	{
		// 分析请求失败，直接断开连接
		pHttpProtocol->Disconnect(pReq);
		delete pReq;
		pHttpProtocol->err_exit("Analyzing request from client error!!\r\n");
	}

	// 读取请求body
	if (pReq->contentLength > 0)
	{
		char temp[256];
		// 读取body内容
		nRet = BIO_read(io, temp, pReq->contentLength);
		if (nRet <= 0)
		{
			pHttpProtocol->Disconnect(pReq);
			delete pReq;
			pHttpProtocol->err_exit("Reading body error!!\r\n");
		}
		temp[pReq->contentLength] = '\0';
		sprintf(pReq->content, "%s", urlDecode(temp).c_str());
		printf("Body: %s \n", pReq->content);
	}

	printf("Ready to send Response!!\n");

	if (!pHttpProtocol->SSLSendResponse(pReq, io))
	{
		printf("Sending response error!!\n");
		pHttpProtocol->err_exit("Sending fileheader error!\r\n");
	}
	BIO_flush(io);
	printf("Response sent!!\n");
	// pHttpProtocol->Test(pReq);
	pHttpProtocol->Disconnect(pReq);
	delete pReq;
	SSL_free(ssl);
	return NULL;
}
// HTTP请求分析函数(就是构造PREQUEST结构体)
int CHttpProtocol::Analyze(PREQUEST pReq, LPBYTE pBuf)
{
	char szSeps[] = " \n"; // 用于分割的字符串，包括空格和换行符(是有空格就分割，有换行符就分割)
	char *cpToken;		   // 用于存放分割后的字符串
	// ..是请求访问父级目录，这是安全风险，直接返回400 Bad Request，拒绝请求
	if (strstr((const char *)pBuf, "..") != NULL)
	{
		strcpy(pReq->StatuCodeReason, HTTP_STATUS_BADREQUEST);
		return 1;
	}

	cpToken = strtok((char *)pBuf, szSeps); // 将获取到的请求头分割成一个个字符串，存放在cpToken中（这里是分割第一次，也就是说cpToken中的内容是GET）
	if (!strcmp(cpToken, "GET"))			// GET请求
	{
		pReq->nMethod = METHOD_GET;
	}
	else if (!strcmp(cpToken, "HEAD")) // 也是HTTP请求方法，只是不返回实体主体
	{
		pReq->nMethod = METHOD_HEAD;
	}
	else if (!strcmp(cpToken, "POST"))
	{
		pReq->nMethod = METHOD_POST;
	}
	else if (!strcmp(cpToken, "DELETE"))
	{
		pReq->nMethod = METHOD_DELETE;
	}
	else
	{
		// 未实现的协议内容
		strcpy(pReq->StatuCodeReason, HTTP_STATUS_NOTIMPLEMENTED);
		return 1;
	}

	// 获取文件路径
	cpToken = strtok(NULL, szSeps);
	if (cpToken == NULL)
	{
		strcpy(pReq->StatuCodeReason, HTTP_STATUS_BADREQUEST);
		return 1;
	}
	// 首先设置根目录 /home/WebServer
	strcpy(pReq->szFileName, m_strRootDir);
	if (strlen(cpToken) > 1)
	{
		strcat(pReq->szFileName, cpToken); // 拼接得到完整文件路径
	}
	else
	{
		strcat(pReq->szFileName, "/index.html");
	}

	// 接下来需要获取得到Body长度
	while (1)
	{
		cpToken = strtok(NULL, szSeps);
		if (cpToken == NULL)
		{
			break;
		}
		if (!strcmp(cpToken, "Content-Length:"))
		{
			cpToken = strtok(NULL, szSeps);
			pReq->contentLength = atoi(cpToken);
			break;
		}
	}

	return 0;
}

int CHttpProtocol::FileExist(PREQUEST pReq)
{
	pReq->hFile = open(pReq->szFileName, O_RDONLY);
	// 文件不存在
	if (pReq->hFile == -1)
	{
		strcpy(pReq->StatuCodeReason, HTTP_STATUS_NOTFOUND);
		printf("open %s error\n", pReq->szFileName);
		return 0;
	}
	else
	{
		// printf("hFile\n");
		return 1;
	}
}
void CHttpProtocol::Test(PREQUEST pReq)
{
	struct stat buf;
	long fl;
	if (stat(pReq->szFileName, &buf) < 0)
	{
		err_exit("Getting filesize error!!\r\n");
	}
	fl = buf.st_size;
	printf("Filesize = %d \r\n", fl);
}
// 获取系统当前时间（转换为字符串？）
void CHttpProtocol::GetCurrentTime(LPSTR lpszString)
{
	char *week[] = {
		"Sun,",
		"Mon,",
		"Tue,",
		"Wed,",
		"Thu,",
		"Fri,",
		"Sat,",
	};
	char *month[] = {
		"Jan",
		"Feb",
		"Mar",
		"Apr",
		"May",
		"Jun",
		"Jul",
		"Aug",
		"Sep",
		"Oct",
		"Nov",
		"Dec",
	};
	struct tm *st;
	long ct;
	ct = time(&ct);
	st = (struct tm *)localtime(&ct);
	sprintf(lpszString, "%s %02d %s %d %02d:%02d:%02d GMT", week[st->tm_wday], st->tm_mday, month[st->tm_mon],
			1900 + st->tm_year, st->tm_hour, st->tm_min, st->tm_sec);
}
// 获取文件类型
bool CHttpProtocol::GetContentType(PREQUEST pReq, LPSTR type)
{
	// 文件后缀根据HTTP协议设置Content-Type字段
	map<string, const char *>::iterator it = m_typeMap.find(pReq->postfix);
	if (it != m_typeMap.end())
	{
		sprintf(type, "%s", (*it).second);
	}
	return 1;
}

// 发送HTTP头部（接受一个PREQUEST类型的指针，其中PREQUEST的内容在Analyze函数中分析得到）
bool CHttpProtocol::SSLSendResponse(PREQUEST pReq, BIO *io)
{
	char Header[2048] = " ";
	// HTTP状态码
	char *STATUS = HTTP_STATUS_OK;
	long length;
	struct stat buf;

	char curTime[50];
	GetCurrentTime(curTime); // 反正就是获取到了字符串形式的当前时间

	if (pReq->nMethod == METHOD_HEAD || pReq->nMethod == METHOD_GET)
	{
		// stat 结构体通常用于存储文件或文件系统的信息
		// 可以使用 stat 函数来获取文件的信息，并将信息存储在 stat 结构体中

		if (FileExist(pReq))
		{
			if (stat(pReq->szFileName, &buf) < 0)
			{
				err_exit("Getting filesize error!!\r\n");
			}
			length = buf.st_size;
		}
		else
		{
			// 文件不存在
			STATUS = HTTP_STATUS_NOTFOUND;
			length = 0;
		}

		// 获取文件类型和Content-Type字段
		char ContentType[50] = " ";

		char *postfix = strstr(pReq->szFileName, ".");
		strcpy(pReq->postfix, postfix);

		GetContentType(pReq, (char *)ContentType);

		sprintf((char *)Header, "HTTP/1.1 %s\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
				STATUS,
				curTime,						// Date
				"Villa Server 192.168.176.139", // Server"My Https Server"
				ContentType,					// Content-Type
				length);						// Content-length

		if (BIO_write(io, Header, strlen(Header)) <= 0)
		{
			return false;
		}
		BIO_flush(io); // 只是确保所有的IO操作都已经完成了
		printf("SSLSendHeader successfully!\n");

		// 对于HEAD请求来说，只需要发送头部即可，接下来处理GET请求的主体内容
		if (pReq->nMethod == METHOD_GET && strcmp(STATUS, HTTP_STATUS_OK) == 0)
		{
			static char buf[2048];
			DWORD dwRead;		// 读取文件的字节数
			BOOL fRet;			// 读取文件的返回值
			int flag = 1, nReq; // flag用于标记是否读取完文件，nReq用于记录BIO_write的返回值
			while (1)
			{
				// 读取文件内容到缓冲区（一次读取最多2048个字节）
				fRet = read(pReq->hFile, buf, sizeof(buf));
				// printf("%d,%d\n",fRet,pReq->hFile);
				// 文件不存在或者读取失败
				if (fRet < 0)
				{
					// printf("!fRet\n");
					static char szMsg[512];
					sprintf(szMsg, "%s", HTTP_STATUS_SERVERERROR);
					if ((nReq = BIO_write(io, szMsg, strlen(szMsg))) <= 0)
					{
						err_exit("BIO_write() error!\n");
					}
					BIO_flush(io);
					break;
				}

				// 读取完文件
				if (fRet == 0)
				{
					printf("complete \n");
					break;
				}
				// 通过BIO接口发送文件内容
				if (BIO_write(io, buf, fRet) <= 0)
				{
					if (!BIO_should_retry(io))
					{
						printf("BIO_write() error!\r\n");
						break;
					}
				}
				BIO_flush(io);
				pReq->dwSend += fRet;
			}
			// 关闭文件
			if (close(pReq->hFile) == 0)
			{
				pReq->hFile = -1;
				return true;
			}
			else
			{
				err_exit("Closing file error!");
			}
		}
	}
	else if (pReq->nMethod == METHOD_POST)
	{
		json postData;
		char *body = pReq->content;
		char szSeps[] = "&=";
		char *cpToken = strtok((char *)body, szSeps);
		while (cpToken != NULL)
		{
			string key = cpToken;
			cpToken = strtok(NULL, szSeps);
			string value = cpToken;
			postData[key] = value;
			cpToken = strtok(NULL, szSeps);
		}
		printf("PostData: %s\n", postData.dump().c_str());
		// POST请求
		char ContentType[50] = "application/json";
		long length = 0;
		json res;
		res["stataus"] = "success";
		res["message"] = "Form submitted successfully";
		string json_string = res.dump();
		length = json_string.length();
		sprintf((char *)Header, "HTTP/1.1 %s\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
				STATUS,
				curTime,						// Date
				"Villa Server 192.168.176.139", // Server"My Https Server"
				ContentType,					// Content-Type
				length);						// Content-length

		if (BIO_write(io, Header, strlen(Header)) <= 0)
		{
			return false;
		}
		BIO_flush(io); // 只是确保所有的IO操作都已经完成了
		printf("SSLSendHeader successfully!\n");

		// 接下来，只要发送json字符串即可
		if (BIO_write(io, json_string.c_str(), length) <= 0)
		{
			return false;
		}
		BIO_flush(io);
	}
	else if (pReq->nMethod == METHOD_DELETE)
	{
		char ContentType[50] = "text/plain";

		if (FileExist(pReq))
		{
			if (stat(pReq->szFileName, &buf) < 0)
			{
				err_exit("Getting filesize error!!\r\n");
			}
			length = buf.st_size;
			// 删除文件
			if (remove(pReq->szFileName) == 0)
			{
				STATUS = HTTP_STATUS_OK;
			}
			else
			{
				STATUS = HTTP_STATUS_SERVERERROR;
				length = 0;
			}
		}
		else
		{
			// 文件不存在
			STATUS = HTTP_STATUS_NOTFOUND;
			length = 0;
		}
		// DELETE请求
		sprintf((char *)Header, "HTTP/1.1 %s\r\nDate: %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n",
				STATUS,
				curTime,						// Date
				"Villa Server 192.168.176.139", // Server"My Https Server"
				ContentType,					// Content-Type
				length);						// Content-length
		if (BIO_write(io, Header, strlen(Header)) <= 0)
		{
			return false;
		}
		BIO_flush(io); // 只是确保所有的IO操作都已经完成了
		printf("SSLSendHeader successfully!\n");
	}

	return true;
}
