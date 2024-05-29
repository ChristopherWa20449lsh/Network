#include "common.h"
#include "HttpProtocol.h"

int main()
{
    CHttpProtocol MyHttpObj;  // 创建一个CHttpProtocol对象
    MyHttpObj.StartHttpSrv(); // 调用StartHttpSrv()
    while (true)
    {
    }
}
