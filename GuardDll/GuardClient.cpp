// GuardClient.cpp
// API HOOK客户端
// 创建socket与分析程序通信


#include "pch.h"

#ifndef _GUARD_CLIENT_H
#include "GuardClient.h"
#endif

#ifndef _MESSAGE_DEFINE_H
#include"MessageDefine.h"
#endif

#ifndef _DETOURS_HOOK_H
#include "DetoursHook.h"
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>

#pragma comment(lib, "Ws2_32.lib")

SOCKET sock = INVALID_SOCKET;
struct sockaddr_in serverAddr;

char udpBuffer[UDP_BUFFER_SIZE];

// Socket通信线程，接收server数据
extern "C" __declspec(dllexport) void ClientSocketThread(LPVOID serverPortP)
{
    uint16_t serverPort = (uintptr_t)serverPortP & 0xFFFF;
    printf("ServerPort: %d\n", serverPort);
    int retryTimes = 0;
    uint16_t randPort;
    srand((uint32_t)time(0));
    // 设置服务器地址和端口
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, SERVER_IP, &(serverAddr.sin_addr));

    // 初始化socket
    while (retryTimes++ < RETRY_TIMES)
    {
        randPort = rand() % 0x10000;
        if (randPort < 1024) randPort += 1024;
        if (InitClientSocket(randPort) == 0)
        {
            retryTimes = 0;
            break;
        }
    }
    if (retryTimes != 0)
    {
        return;
    }

    // 向服务端发送hello 报告端口信息
    struct hello_msg* helloMsg = (struct hello_msg*)udpBuffer;
    helloMsg->msg_type = MSG_HELLO;
    helloMsg->data_length = sizeof(struct hello_msg);
    helloMsg->process_pid = dwPid;

    retryTimes = 0;
    while (retryTimes++ < RETRY_TIMES)
    {
        SocketSend((const char*)helloMsg, (size_t)helloMsg->data_length);
        memset(udpBuffer, 0, UDP_BUFFER_SIZE);
        int recvBytes = recvfrom(sock, udpBuffer, UDP_BUFFER_SIZE, 0, NULL, NULL);
        if (recvBytes != SOCKET_ERROR)
        {
            // 接收到服务端hello
            if (helloMsg->msg_type == MSG_HELLO && helloMsg->data_length == sizeof(struct hello_msg))
            {
                retryTimes = 0;
                break;
            }
        }
    }
    if (retryTimes != 0)
    {
        // 未接收到服务端hello
        CloseClientSocket();
    }

    // 设置hook(临时代码)
    HookAttach();

    while (1)
    {
        int recvBytes = recvfrom(sock, udpBuffer, UDP_BUFFER_SIZE, 0, NULL, NULL);
        if (recvBytes == SOCKET_ERROR)
        {
            continue;
        }
        struct udp_msg* msg = (struct udp_msg*)udpBuffer;
        switch (msg->msg_type)
        {
        case MSG_HELLO:
            printf("hello from server\n");
            break;
        case MSG_STOP:
            printf("stop\n");
            // 关闭socket
            CloseClientSocket();
            // 关闭所有Hook
            HookDetachAll();
            return;
        default:
            break;
        }
    }
}

extern "C" __declspec(dllexport) int InitClientSocket(uint16_t port)
{
    WSADATA wsaData;
    struct sockaddr_in clientAddr;
    int iResult;
    int retryTimes = 0;
    
    // 初始化 Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        return -1;
    }

    // 创建UDP套接字
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    // 设置接收超时
    DWORD timeoutValue = RECV_TIMEOUT;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutValue, sizeof(timeoutValue)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    // 设置客户端地址和端口
    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = INADDR_ANY; // 接收来自任何地址的数据

    clientAddr.sin_port = htons(port); // 设置端口号

    iResult = bind(sock, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
    if (iResult == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }
    return 0;
}

extern "C" __declspec(dllexport) void CloseClientSocket()
{
    // 关闭套接字和清理 Winsock
    closesocket(sock);
    WSACleanup();
}

extern "C" __declspec(dllexport) void SocketSend(const char * data, int dataLen)
{
    int retryTimes = 0;
    while (retryTimes++ < RETRY_TIMES)
    {
        if (sendto(sock, data, dataLen, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR)
        {
            break;
        }
    }
}