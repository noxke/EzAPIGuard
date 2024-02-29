#pragma once
#define _DETOURS_HOOK_H

extern HMODULE handleModule;
extern DWORD dwPid;

void HookAttach();

void HookDetach();

extern "C" __declspec(dllexport) void HookDetachAll();
