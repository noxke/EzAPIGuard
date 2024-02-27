// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "stdio.h"
#include "detours.h"
#include "Windows.h"

#pragma comment(lib, "detours.lib")

static int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;

extern "C" __declspec(dllexport) int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
    printf("\n\n******************************************\n");
    printf("MessageBoxA Hooked!\n");
    printf("lpText: %s\n", lpText);
    printf("lpCaption: %s\n", lpCaption);
    printf("\n\n******************************************\n");
    return OldMessageBoxA(NULL, "new MessageBoxA", "Hooked", MB_OK);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OldMessageBoxA, NewMessageBoxA);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OldMessageBoxA, NewMessageBoxA);
        DetourTransactionCommit();
        break;
    }
    return TRUE;
}

