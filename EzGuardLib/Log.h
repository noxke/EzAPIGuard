#pragma once
#define _LOG_H

#include <string.h>

#define LOGPRINTF(...) memset(logBuffer, 0, LOG_BUFFER_SIZE);\
    snprintf(logBuffer, LOG_BUFFER_SIZE, __VA_ARGS__);\
    LogStrMsg(logBuffer);


#define LOG_BUFFER_SIZE 0x100

char logBuffer[LOG_BUFFER_SIZE];

extern "C" __declspec(dllexport) int LogStrMsg(const char *msg);