#pragma once
#define _GUARD_CLIENT_H

#include <stdint.h>
#include <Windows.h>
#include <winsock2.h>

#define DLL_EXPORT extern "C" __declspec(dllexport)

#define SERVER_IP "127.0.0.1"
#define CLIENT_IP "127.0.0.1"

#define RETRY_TIMES 3
#define RECV_TIMEOUT 3000

// 导出端口，注入前将serverPort patch为真实端口
DLL_EXPORT extern uint16_t serverPort;

void ClientSocketThread();

int InitUdpSocket(SOCKET *sock, uint16_t port);

void CloseUdpSocket(SOCKET* sock);

int UdpSocketSend(SOCKET* sock, const char* data, int dataLen);

int UdpSocketRecv(SOCKET* sock, char* data, int dataLen);

// 用于发送并接收一次 recv为FALSE时不接收
// 这里的buffer即用于发送又用于接收
int UdpSendRecv(char *buffer, int bufferLen, bool recv);