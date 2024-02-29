#pragma once
#define _INJECTOR_H

#define GUARD_DLL "GuardDll.dll"

#include <Windows.h>
#include <stdint.h>

// 通过进程名获取pid
extern "C" __declspec(dllexport) DWORD GetDwPidByName(const char* procName);

// 注入dll到目标进程
extern "C" __declspec(dllexport) BOOL InjectByPID(DWORD dwPID, LPCSTR dllPath);

// 在目标进程中创建远程线程运行ClientSocketThread
extern "C" __declspec(dllexport) BOOL RunClientThreadByPID(DWORD dwPID, LPCSTR dllPath, uint16_t serverPort);