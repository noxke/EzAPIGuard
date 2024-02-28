// GuardServer.cpp
// API HOOK服务端
// 创建socket与api hook进行通信

//! TODO

#include "pch.h"

#ifndef _GUARD_SERVER_H
#include "GuardServer.h"
#endif

#ifndef _LOG_H
#include "Log.h"
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

extern "C" __declspec(dllexport) uint16_t InitServerSocket(uint16_t port)
{
    WSADATA wsaData;
    struct sockaddr_in serverAddr;
    uint16_t randPort = port;
    int iResult;
    int retryTimes = 0;

    srand(time(0));

    // 初始化 Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        LOGPRINTF("WSAStartup failed: %d", iResult);
        return 0;
    }

    // 创建UDP套接字
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    if (sock == INVALID_SOCKET) {
        LOGPRINTF("Error at socket() : % ld", WSAGetLastError());
        WSACleanup();
        return 0;
    }

    // 设置服务器地址和端口
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY; // 接收来自任何地址的数据
    while (retryTimes++ < RETRY_TIMES)
    {
        if (port == 0)
        {
            randPort = rand() % 0x10000;
            if (randPort < 1024) randPort += 1024;
        }
        serverAddr.sin_port = htons(randPort); // 设置端口号

        iResult = bind(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        if (iResult == SOCKET_ERROR) {
            if (port != 0)
            {
                LOGPRINTF("bind failed with error: %d", WSAGetLastError());
                closesocket(sock);
                WSACleanup();
                return 0;
            }
            randPort = 0;
            continue;
        }
        break;
    }
    return randPort;
}

extern "C" __declspec(dllexport) void CloseServerSocket()
{
    // 关闭套接字和清理 Winsock
    closesocket(sock);
    WSACleanup();
}

void SocketRecv()
{
    struct sockaddr_in clientAddr;
    int clientAddrLen = sizeof(clientAddr);
    // 接收数据
    memset(udpBuffer, 0, UDP_BUFFER_SIZE);
    if (recvfrom(sock, udpBuffer, UDP_BUFFER_SIZE, 0, (struct sockaddr*)&clientAddr, &clientAddrLen) == SOCKET_ERROR) {
        LOGPRINTF("Failed to receive data.");
        closesocket(sock);
        WSACleanup();
    }

    LOGPRINTF("Received message from %s:%d: %s", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), udpBuffer);
}