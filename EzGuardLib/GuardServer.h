#pragma once
#define _GUARD_SERVER_H

#define SERVER_IP "127.0.0.1"

#define RETRY_TIMES 3
#define RECV_TIMEOUT 1000

#include <stdint.h>

extern "C" __declspec(dllexport) void ServerSocketThread(uint16_t serverPort);

extern "C" __declspec(dllexport) int InitServerSocket(uint16_t port);

extern "C" __declspec(dllexport) void CloseServerSocket();

extern "C" __declspec(dllexport) void SocketSend(struct sockaddr_in* clientAddr, const char* data, int dataLen);