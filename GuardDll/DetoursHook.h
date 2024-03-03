#pragma once
#define _DETOURS_HOOK_H

extern HMODULE handleModule;
extern DWORD dwPid;

void HookAttach();

void HookDetach();

extern "C" __declspec(dllexport) void HookDetachAll();

// 从进程中卸载注入的dll
extern "C" __declspec(dllexport) void UnloadInjectedDll();
