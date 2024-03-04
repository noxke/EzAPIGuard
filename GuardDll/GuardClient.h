#pragma once
#define _GUARD_CLIENT_H

#include <stdint.h>
#include <Windows.h>
#include <winsock2.h>

#define DLL_EXPORT extern "C" __declspec(dllexport)

#define SERVER_IP "127.0.0.1"
#define CLIENT_IP "127.0.0.1"

#define RETRY_TIMES 3
#define RECV_TIMEOUT 1000

// 导出端口，注入前将serverPort patch为真实端口
DLL_EXPORT uint16_t serverPort;

void ClientSocketThread();

int InitUdpSocket(SOCKET *sock, uint16_t port);

void CloseUdpSocket(SOCKET* sock);

int UdpSocketSend(SOCKET* sock, const char* data, int dataLen);

int UdpSocketRecv(SOCKET* sock, char* data, int dataLen);

// 用于发送并接收一次 recvBuffer为NULL时不接收
// 这里的sendBuffer和recvBuffer可以且建议用同一个
int UdpSendRecv(const char *sendBuffer, char *recvBuffer);