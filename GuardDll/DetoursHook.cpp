// DetoursHook.cpp
// GuardDll主功能函数 使用Detours进行api hook

#include "pch.h"
#include <Windows.h>

#ifndef _LOCAL_API_H
#include "LocalAPI.h"
#endif

#ifndef _DETOURS_HOOK_H
#include "DetoursHook.h"
#endif

#ifndef _API_HOOK_H
#include "APIHook.h"
#endif

#include "detours.h"

#pragma comment(lib, "detours.lib")

#define DLL_EXPORT extern "C" __declspec(dllexport)

void HookAttach()
{
    DisableThreadLibraryCalls(handleModule);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OldMessageBoxA, NewMessageBoxA);
    DetourTransactionCommit();
}

void HookDetach()
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)OldMessageBoxA, NewMessageBoxA);
    DetourTransactionCommit();
}

void HookDetachAll()
{
    HookDetach();
}

void UnloadInjectedDll()
{
    Sleep(100);
    FreeLibraryAndExitThread(handleModule, 0);
}