// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <stdio.h>
#include <Windows.h>

#ifndef _DETOURS_HOOK_H
#include "DetoursHook.h"
#endif

#ifndef _GUARD_CLIENT_H
#include "GuardClient.h"
#endif

HMODULE handleModule;
DWORD dwPid;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        handleModule = hModule;
        dwPid = GetCurrentProcessId();
        // 开启Client线程连接server
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ClientSocketThread, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

