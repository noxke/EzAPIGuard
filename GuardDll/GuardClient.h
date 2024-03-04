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
extern SOCKET serverSock;
void ClientSocketThread();

int InitUdpSocket(SOCKET *sock, uint16_t port);

void CloseUdpSocket(SOCKET* sock);

void UdpSocketSend(SOCKET* sock, const char* data, int dataLen);

void UdpSocketRecv(SOCKET* sock, char* data, int dataLen);