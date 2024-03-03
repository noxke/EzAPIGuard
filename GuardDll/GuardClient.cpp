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


struct sockaddr_in serverAddr;

uint16_t serverPort = 0;    // 注入前patch为真实端口

char udpBuffer[UDP_BUFFER_SIZE];

// Socket通信线程，接收server数据
void ClientSocketThread()
{
    // printf("ServerPort: %d\n", serverPort);
    int retryTimes = 0;
    uint16_t randPort;
    SOCKET sock = INVALID_SOCKET;

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
        if (InitUdpSocket(&sock, randPort) == 0)
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
        UdpSocketSend(&sock, (const char*)helloMsg, (size_t)helloMsg->data_length);
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
        // 关闭socket
        // 关闭所有Hook
        // 卸载DLL
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
            break;
        case MSG_STOP:
            // 关闭socket
            // 关闭所有Hook
            // 卸载DLL
            return;
        default:
            break;
        }
    }
}

int InitUdpSocket(SOCKET* sock, uint16_t port)
{
    // 不能使用WSACleanup，在多线程环境中， WSACleanup 终止所有线程的 Windows 套接字操作。
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
    *sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (*sock == INVALID_SOCKET) {
        return -1;
    }

    // 设置接收超时
    DWORD timeoutValue = RECV_TIMEOUT;
    if (setsockopt(*sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutValue, sizeof(timeoutValue)) == SOCKET_ERROR) {
        closesocket(*sock);
        return -1;
    }

    // 设置客户端地址和端口
    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = INADDR_ANY; // 接收来自任何地址的数据

    clientAddr.sin_port = htons(port); // 设置端口号

    iResult = bind(*sock, (struct sockaddr*)&clientAddr, sizeof(clientAddr));
    if (iResult == SOCKET_ERROR) {
        closesocket(*sock);
        return -1;
    }
    return 0;
}

void CloseUdpSocket(SOCKET* sock)
{
    // 关闭套接字
    closesocket(*sock);
}

void UdpSocketSend(SOCKET* sock, const char * data, int dataLen)
{
    int retryTimes = 0;
    while (retryTimes++ < RETRY_TIMES)
    {
        if (sendto(*sock, data, dataLen, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR)
        {
            break;
        }
    }
}