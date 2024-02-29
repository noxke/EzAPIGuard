// GuardServer.cpp
// API HOOK服务端
// 创建socket与api hook进行通信

#include "pch.h"

#ifndef _GUARD_SERVER_H
#include "GuardServer.h"
#endif

#ifndef _LOG_H
#include "Log.h"
#endif

#ifndef _MESSAGE_DEFINE_H
#include"MessageDefine.h"
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
char udpBuffer[UDP_BUFFER_SIZE];

extern "C" __declspec(dllexport) void ServerSocketThread(uint16_t *serverPortP)
{
    int retryTimes = 0;
    uint16_t serverPort = *serverPortP;
    uint16_t randPort = serverPort;
    struct sockaddr_in clientAddr;
    char clientIP[INET_ADDRSTRLEN];
    uint16_t clientPort;
    int clientAddrLen = sizeof(clientAddr);
    srand((uint32_t)time(0));

    // 初始化socket
    while (retryTimes++ < RETRY_TIMES)
    {
        if (serverPort == 0)
        {
            randPort = rand() % 0x10000;
            if (randPort < 1024) randPort += 1024;
        }
        if (InitServerSocket(randPort) == 0)
        {
            retryTimes = 0;
            break;
        }
    }
    *serverPortP = randPort;
    LOG_PRINTF("ServerPort: %d", randPort);
    if (retryTimes != 0)
    {
        return;
    }

    while (1)
    {
        int recvBytes = recvfrom(sock, udpBuffer, UDP_BUFFER_SIZE, 0, (sockaddr *)& clientAddr, &clientAddrLen);
        if (recvBytes == SOCKET_ERROR)
        {
            continue;
        }
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        clientPort = ntohs(clientAddr.sin_port);
        struct udp_msg* msg = (struct udp_msg*)udpBuffer;
        struct api_hooked_msg* api_msg = (struct api_hooked_msg*)udpBuffer;
        struct hello_msg* helloMsg = (struct hello_msg*)udpBuffer;
        switch (msg->msg_type)
        {
        case MSG_HELLO:
            LOG_PRINTF("Received hello from %s:%d", clientIP, clientPort);
            // 向客户端发送hello 报告端口信息
            helloMsg->msg_type = MSG_HELLO;
            helloMsg->data_length = sizeof(struct hello_msg);
            helloMsg->process_pid = GetCurrentProcessId();
            SocketSend(&clientAddr, (const char*)helloMsg, (size_t)helloMsg->data_length);
            break;
        case MSG_HOOKED:
            LOG_PRINTF("Received api hooked from %s:%d", clientIP, clientPort);
            LOG_PRINTF("PID: %d, API id: %d, API arg num: %d", api_msg->process_pid, api_msg->api_id, api_msg->arg_num);
            break;
        default:
            break;
        }
    }

}

extern "C" __declspec(dllexport) int InitServerSocket(uint16_t port)
{
    WSADATA wsaData;
    struct sockaddr_in serverAddr;
    int iResult;
    int retryTimes = 0;

    // 初始化 Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        LOG_PRINTF("WSAStartup failed: %d", iResult);
        return -1;
    }

    // 创建UDP套接字
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == INVALID_SOCKET) {
        LOG_PRINTF("Error at socket() : % ld", WSAGetLastError());
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

    // 设置服务器地址和端口
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // 接收来自任何地址的数据
    
    serverAddr.sin_port = htons(port); // 设置端口号

    iResult = bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (iResult == SOCKET_ERROR) {
            LOG_PRINTF("bind failed with error: %d", WSAGetLastError());
            closesocket(sock);
            WSACleanup();
            return -1;
    }
    return 0;
}

extern "C" __declspec(dllexport) void CloseServerSocket()
{
    // 关闭套接字和清理 Winsock
    closesocket(sock);
    WSACleanup();
}

extern "C" __declspec(dllexport) void SocketSend(struct sockaddr_in *clientAddr, const char* data, int dataLen)
{
    int retryTimes = 0;
    while (retryTimes++ < RETRY_TIMES)
    {
        if (sendto(sock, data, dataLen, 0, (sockaddr *)clientAddr, sizeof(struct sockaddr_in)) != SOCKET_ERROR)
        {
            break;
        }
    }
}