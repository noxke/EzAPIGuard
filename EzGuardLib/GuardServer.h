#pragma once
#define _GUARD_SERVER_H

#define SERVER_IP "127.0.0.1"

#define UDP_BUFFER_SIZE 0x1000

#define RETRY_TIMES 3
#define RECV_TIMEOUT 1000

#include <stdint.h>

extern "C" __declspec(dllexport) uint16_t InitServerSocket(uint16_t port);

extern "C" __declspec(dllexport) void CloseServerSocket();

void SocketRecv();