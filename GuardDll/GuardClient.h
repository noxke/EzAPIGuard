#pragma once
#define _GUARD_CLIENT_H

#include <stdint.h>

#define SERVER_IP "127.0.0.1"
#define CLIENT_IP "127.0.0.1"

#define RETRY_TIMES 3
#define RECV_TIMEOUT 1000

extern "C" __declspec(dllexport) void ClientSocketThread(LPVOID serverPortP);

extern "C" __declspec(dllexport) int InitClientSocket(uint16_t port);

extern "C" __declspec(dllexport) void CloseClientSocket();

extern "C" __declspec(dllexport) void SocketSend(const char* data, int dataLen);
