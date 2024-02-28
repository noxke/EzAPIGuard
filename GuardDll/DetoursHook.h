#pragma once
#define _DETOURS_HOOK_H

extern HMODULE handleModule;
extern DWORD pid;

void HookAttach();

void HookDetach();

extern "C" __declspec(dllexport) void HookDetachAll();
