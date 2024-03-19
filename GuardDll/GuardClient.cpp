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

#ifndef _API_HOOK_H
#include "APIHook.h"
#endif


#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#pragma comment(lib, "Ws2_32.lib")

struct sockaddr_in serverAddr;

uint16_t serverPort = 1145;    // 注入前patch为真实端口
char udpBuffer[UDP_BUFFER_SIZE];

// Socket通信线程，接收server数据
void ClientSocketThread()
{
    int retryTimes = 0;
    SOCKET sock = INVALID_SOCKET;
    struct udp_msg* msg = (struct udp_msg*)udpBuffer;
    struct api_config_msg* config_msg = NULL;

    // 设置服务器地址和端口
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, SERVER_IP, &(serverAddr.sin_addr));

    // 初始化socket 随机端口
    while (retryTimes++ < RETRY_TIMES)
    {
        if (InitUdpSocket(&sock, 0, RECV_TIMEOUT) == 0)
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
    retryTimes = 0;
    while (retryTimes++ < RETRY_TIMES)
    {
        msg->msg_type = MSG_HELLO;
        msg->data_length = sizeof(struct empty_msg);
        msg->process_pid = dwPid;
        msg->time = time(0);
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        memset(udpBuffer, 0, UDP_BUFFER_SIZE);
        if (UdpSocketRecv(&sock, udpBuffer, UDP_BUFFER_SIZE) == 0)
        {
            // 接收到服务端ack
            if (msg->msg_type == MSG_ACK && msg->data_length == sizeof(struct empty_msg))
            {
                retryTimes = 0;
                break;
            }
        }
    }
    if (retryTimes != 0)
    {
        // 未接收到服务端ack
        // 关闭socket
        // 卸载DLL
        CloseUdpSocket(&sock);
        UnloadInjectedDll();
    }

    // 设置hook
    HookAttach();

    while (1)
    {
        memset(udpBuffer, 0, UDP_BUFFER_SIZE);
        if (UdpSocketRecv(&sock, udpBuffer, UDP_BUFFER_SIZE) != 0)
        {
            continue;
        }
        switch (msg->msg_type)
        {
        case MSG_HELLO:
            // 收到hello后回复 确认存活
            msg->msg_type = MSG_ACK;
            msg->data_length = sizeof(struct empty_msg);
            msg->process_pid = dwPid;
            msg->time = time(0);
            UdpSocketSend(&sock, (const char*)msg, msg->data_length);
            break;
        case MSG_CONFIG:
            config_msg = (struct api_config_msg*)msg;
            msg->msg_type = MSG_CONFIG;
            msg->data_length = sizeof(struct api_config_msg);
            msg->process_pid = dwPid;
            msg->time = time(0);
            for (int i = 0; i < HOOK_API_NUM; i++)
            {
                api_config[i] = config_msg->config[i];
            }
            UdpSocketSend(&sock, (const char*)msg, msg->data_length);
            break;
        case MSG_ENABLE:
            HookAttach();
            msg->msg_type = MSG_ENABLE;
            msg->data_length = sizeof(struct empty_msg);
            msg->process_pid = dwPid;
            msg->time = time(0);
            UdpSocketSend(&sock, (const char*)msg, msg->data_length);
            break;
        case MSG_DISABLE:
            HookDetach();
            msg->msg_type = MSG_DISABLE;
            msg->data_length = sizeof(struct empty_msg);
            msg->process_pid = dwPid;
            msg->time = time(0);
            UdpSocketSend(&sock, (const char*)msg, msg->data_length);
            break;
        case MSG_UNLOAD:
            // 卸载dll
            HookDetach();
            msg->msg_type = MSG_UNLOAD;
            msg->data_length = sizeof(struct empty_msg);
            msg->process_pid = dwPid;
            msg->time = time(0);
            UdpSocketSend(&sock, (const char*)msg, msg->data_length);
            UnloadInjectedDll();
            break;
        case MSG_KILL:
            // 结束进程
            HookDetach();
            msg->msg_type = MSG_KILL;
            msg->data_length = sizeof(struct empty_msg);
            msg->process_pid = dwPid;
            msg->time = time(0);
            UdpSocketSend(&sock, (const char*)msg, msg->data_length);
            CloseUdpSocket(&sock);
            TerminateProcess(hProcess, 0);
            break;
        default:
            break;
        }
    }
}

int InitUdpSocket(SOCKET* sock, uint16_t port, uint32_t timeout)
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
    *sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (*sock == INVALID_SOCKET) {
        return -1;
    }

    // 设置接收超时
    if (setsockopt(*sock, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) == SOCKET_ERROR) {
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

int UdpSocketSend(SOCKET* sock, const char * data, int dataLen)
{
    int retryTimes = 0;
    while (retryTimes++ < RETRY_TIMES)
    {
        if (Oldsendto(*sock, data, dataLen, 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR)
        {
            return 0;
        }
    }
    return -1;
}

int UdpSocketRecv(SOCKET* sock, char* data, int dataLen)
{
    int retryTimes = 0;
    struct sockaddr_in from;
    int fromLen = sizeof(from);
    while (retryTimes++ < RETRY_TIMES)
    {
        if (Oldrecvfrom(*sock, data, dataLen, 0, (sockaddr *) & from, &fromLen) != SOCKET_ERROR)
        {
            return 0;
        }
    }
    return -1;
}

// 用于发送并接收一次
int UdpSendRecv(char* buffer, int bufferLen, bool recv)
{
    int retryTimes = 0;
    SOCKET sock = INVALID_SOCKET;
    // 多发几次避免失败 实际上应该不可能失败
    while (retryTimes++ < RETRY_TIMES)
    {
        if (InitUdpSocket(&sock, 0, REQUEST_TIMEOUT) != 0)
        {
            continue;
        }
        if (UdpSocketSend(&sock, buffer, bufferLen) != 0)
        {
            CloseUdpSocket(&sock);
            continue;
        }
        if (recv == TRUE)
        {
            if (UdpSocketRecv(&sock, buffer, bufferLen) != 0)
            {
                CloseUdpSocket(&sock);
                continue;
            }
        }
        CloseUdpSocket(&sock);
        return 0;
    }
    return -1;

}