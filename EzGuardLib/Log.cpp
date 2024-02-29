// Log.cpp
// 日志模块

#include "pch.h"

#ifndef _LOG_H
#include "Log.h"
#endif

#include <stdio.h>

char logBuffer[LOG_BUFFER_SIZE];

extern "C" __declspec(dllexport) int LogStrMsg(const char* msg)
{
    puts(msg);
    return 0;
}