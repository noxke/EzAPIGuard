// DetoursHook.cpp
// GuardDll主功能函数 使用Detours进行api hook

#include "pch.h"

#ifndef _DETOURS_HOOK_H
#include "DetoursHook.h"
#endif

#ifndef _API_HOOK_H
#include "APIHook.h"
#endif

#include "detours.h"

#pragma comment(lib, "detours.lib")


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

extern "C" __declspec(dllexport) void HookDetachAll()
{
    HookDetach();
}