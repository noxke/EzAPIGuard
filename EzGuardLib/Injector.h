#pragma once
#define _INJECTOR_H

#define GUARD_DLL "GuardDll.dll"

#include <Windows.h>
#include <stdint.h>

#define DLL_EXPORT extern "C" __declspec(dllexport)

// 两种架构下LoadLibraryW在kernel32.dll中的偏移
DLL_EXPORT extern uint64_t LoadLibraryAoff86;
DLL_EXPORT extern uint64_t LoadLibraryAoff64;

// 注入dll到目标进程
DLL_EXPORT BOOL InjectByPID(uint32_t dwPID, const char *dllPath);

// 启动目标程序并注入dll
DLL_EXPORT BOOL RunInject(const char *exePath, char *cmdLine, const char *dllPath);