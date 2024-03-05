#pragma once
#define _DETOURS_HOOK_H

extern HMODULE handleModule;
extern DWORD dwPid;
extern HANDLE hProcess;


void HookAttach();

void HookDetach();


// 从进程中卸载注入的dll
void UnloadInjectedDll();
