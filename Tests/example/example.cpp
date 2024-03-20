#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <string>
#include<winsock2.h>
#pragma comment(lib,"ws2_32.lib")//加载网络编程静态库
using namespace std;


//解析URL
void ParseURL(string url, string& host, string& res)
{
    //这里只是简单解析本例题的URL
    if (url.find("http://") != url.npos)
    {
        url = url.substr(7);//删除字符串中的http://
    }
    else if (url.find("https://") != url.npos)
    {
        url = url.substr(8);//删除字符串中的https://
    }
    //获取域名 删除URL协议头后的studentwebsite.cn/index.html，找到第一个"/"的位置 返回下标
    int pos = url.find_first_of("/");
    host = url.substr(0, pos);
    //获取资源地址
    res = url.substr(pos);
    cout << "域名：" << host << endl;
    cout << "资源：" << res << endl;
}


int main() {
    // MessageBox示例
    MessageBoxA(NULL, "Text1", "Caption1", 0);
    MessageBoxW(NULL, L"Text2", L"Caption2", 0);

    // 文件操作示例
    FILE* f = fopen("test.txt", "wt");
    if (f != NULL)
    {
        printf("file opened\n");
        fputs("1234567890", f);
        fclose(f);
    }
    f = fopen("test.txt", "rt");
    if (f != NULL)
    {
        char buffer[0x100];
        fread(buffer, 1, 0x100, f);
        printf("read file: %s\n", buffer);
        fclose(f);
    }
    if (DeleteFileW(L"test.txt"))
    {
        printf("file deleted\n");
    }

    // 堆操作示例
    HANDLE hHeap = HeapCreate(0, 0x100, 0x1000);
    if (hHeap != NULL)
    {
        printf("Create Heap\n");
        LPVOID p = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 0x200);
        if (p != NULL)
        {
            printf("Heap Alloc\n");
            if (HeapFree(hHeap, HEAP_NO_SERIALIZE, p))
            {
                printf("Heap Free\n");
            }
        }
        if (HeapDestroy(hHeap))
        {
            printf("Destory Heap\n");
        }
    }

    // 注册表操作示例
    HKEY hKey;
    LONG openResult = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
    if (openResult == ERROR_SUCCESS) {
        LONG deleteResult = RegDeleteValueW(hKey, L"TestProgram");
        if (deleteResult == ERROR_FILE_NOT_FOUND) {
            // 如果键值对不存在，则创建它
            printf("creat\n");
            RegSetValueExW(hKey, L"TestProgram", 0, REG_SZ, (BYTE*)L"E:/code/C++/me/czh/1.exe", wcslen(L"E:/code/C++/me/czh/1.exe") * sizeof(wchar_t));
        }
        else printf("delete\n");
        RegCloseKey(hKey);
    }
 

    // 网络操作示例
    WSADATA wsdata;
    WSAStartup(MAKEWORD(2, 2), &wsdata);
    SOCKET skt = socket(AF_INET, SOCK_STREAM, 0);
    if (skt == SOCKET_ERROR)
    {
        return 0;
    }
    string host_url = "https://www.vcg.com/creative/";//URL
    string host;//域名
    string res;//资源地址

    int t = 1;
    while (t < 100) {
        host_url += to_string(t++) + ".html";
        cout << host_url << '\n';
        //解析URL，即将URL才分为域名+域名后面的资源地址，比如上面的拆分之后是：域名：studentwebsite.cn；资源地址：/index.html
        ParseURL(host_url, host, res);

        //设置要连接的服务器地址
        HOSTENT* ip = gethostbyname(host.c_str());//获取主机信息，里面包含IP地址

        //将IP地址绑定到套接字
        sockaddr_in address;
        memset(&address, 0, sizeof(sockaddr_in));//将结构体对象的所有变量初始化为0
        address.sin_family = AF_INET;//遵循的协议族
        address.sin_port = htons(80);//上面的URL端口是80,一般http端口号是80，htons作用是将端口号主机字节序转换为网络字节序
        memcpy(&address.sin_addr, ip->h_addr, 4);//转换为4个字节的正规IP地址

        //连接服务器
        int cflag = connect(skt, (SOCKADDR*)&address, sizeof(SOCKADDR));
        if (cflag == SOCKET_ERROR)
        {
            cout << "连接服务器失败.." << endl;
            return 0;
        }
        else
        {
            cout << "连接服务器成功.." << endl;
        }
        //准备发送给服务器，客户端需要的信息请求
        string req = "";
        req += "GET " + res + " HTTP/1.1\r\n";
        req += "Host: " + host + "\r\n";
        req += "User-Agent:*\r\n";
        req += "Connection:Keep-Alive\r\n";
        req += "\r\n";

        //给服务器发送信息
        int clen = send(skt, req.c_str(), req.length(), 0);

        //接受服务器返回的信息
        string info;//接受的信息
        char ch;//每次接受的信息
        int rlength = 0;//接受数据的总大小

        int rlen = recv(skt, &ch, 1, 0);//每次接受的数据大小
        rlength += rlen;
        if (rlen == SOCKET_ERROR) {
            printf("接收错误\n");
            continue;
        }

        while (rlen != 0 && rlen != SOCKET_ERROR)
        {
            info += ch;
            rlen = recv(skt, &ch, 1, 0);//每次接受的数据大小
            cout << ch;
            Sleep(100);
            rlength += rlen;
        }

        //编码转换 防止在控制台显示乱码
        char* pszBuffer = new char[info.length() + 1];
        wchar_t* pszWideBuffer = new wchar_t[(info.length() + 1) * 2];
        memset(pszWideBuffer, 0, (info.length() + 1) * 2);
        memset(pszBuffer, 0, info.length() + 1);
        MultiByteToWideChar(CP_UTF8, 0, info.c_str(), info.length(), pszWideBuffer, (info.length() + 1) * 2);//将unicode编码，转换为宽字节
        WideCharToMultiByte(CP_ACP, 0, pszWideBuffer, wcslen(pszWideBuffer), pszBuffer, info.length() + 1, NULL, NULL);//将宽字节,转换为控制台编码

        //cout << pszBuffer;
        info = pszBuffer;
        delete[] pszBuffer;
        delete[] pszWideBuffer;

        //显示
        cout << "客户端给服务器发送了：" << req.length() << "个字节" << endl;
        cout << "服务器返回给客户端了：" << rlength << "个字节" << endl;
        cout << info << endl;//在控制台打印从服务器请求到信息

        Sleep(rand() % 1000 + 1000);
    }
    system("pause");
    return 0;
}
