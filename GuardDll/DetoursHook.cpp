// DetoursHook.cpp
// GuardDll主功能函数 使用Detours进行api hook

#include "pch.h"
#include <Windows.h>


#ifndef _DETOURS_HOOK_H
#include "DetoursHook.h"
#endif

#ifndef _API_HOOK_H
#include "APIHook.h"
#endif


#include "detours.h"

#pragma comment(lib, "detours.lib")

BOOL attaching = FALSE;

void HookAttach()
{
    if (attaching == TRUE) return;
    attaching = TRUE;
    DisableThreadLibraryCalls(handleModule);
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourAttach(&OldMessageBoxA, NewMessageBoxA);
    DetourAttach(&OldMessageBoxW, NewMessageBoxW);

    DetourAttach(&OldCreateFile, NewCreateFile);
    DetourAttach(&OldReadFile, NewReadFile);
    DetourAttach(&OldWriteFile, NewWriteFile);
    DetourAttach(&OldDeleteFile, NewDeleteFile);

    DetourAttach(&OldHeapCreate, NewHeapCreate);
    DetourAttach(&OldHeapDestroy, NewHeapDestroy);
    DetourAttach(&OldHeapFree, NewHeapFree);
    // HeapAlloc几乎无法hook
    // DetourAttach(&OldHeapAlloc, NewHeapAlloc);

    DetourAttach(&OldRegCreateKeyEx, NewRegCreateKeyEx);
    DetourAttach(&OldRegSetValueEx, NewRegSetValueEx);
    DetourAttach(&OldRegCloseKey, NewRegCloseKey);
    DetourAttach(&OldRegOpenKeyEx, NewRegOpenKeyEx);
    DetourAttach(&OldRegDeleteValue, NewRegDeleteValue);

    DetourAttach(&Oldsend, Newsend);
    DetourAttach(&Oldrecv, Newrecv);
    DetourAttach(&Oldsendto, Newsendto);
    DetourAttach(&Oldrecvfrom, Newrecvfrom);
    DetourAttach(&Oldconnect, Newconnect);

    DetourTransactionCommit();
}

void HookDetach()
{
    if (attaching == FALSE) return;
    attaching = FALSE;
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&OldMessageBoxA, NewMessageBoxA);
    DetourDetach(&OldMessageBoxW, NewMessageBoxW);

    DetourDetach(&OldCreateFile, NewCreateFile);
    DetourDetach(&OldReadFile, NewReadFile);
    DetourDetach(&OldWriteFile, NewWriteFile);
    DetourDetach(&OldDeleteFile, NewDeleteFile);

    DetourDetach(&OldHeapCreate, NewHeapCreate);
    DetourDetach(&OldHeapDestroy, NewHeapDestroy);
    DetourDetach(&OldHeapFree, NewHeapFree);
    // DetourDetach(&OldHeapAlloc, NewHeapAlloc);

    DetourDetach(&OldRegCreateKeyEx, NewRegCreateKeyEx);
    DetourDetach(&OldRegSetValueEx, NewRegSetValueEx);
    DetourDetach(&OldRegCloseKey, NewRegCloseKey);
    DetourDetach(&OldRegOpenKeyEx, NewRegOpenKeyEx);
    DetourDetach(&OldRegDeleteValue, NewRegDeleteValue);

    DetourDetach(&Oldsend, Newsend);
    DetourDetach(&Oldrecv, Newrecv);
    DetourDetach(&Oldsendto, Newsendto);
    DetourDetach(&Oldrecvfrom, Newrecvfrom);
    DetourDetach(&Oldconnect, Newconnect);

    DetourTransactionCommit();
}


void UnloadInjectedDll()
{
    Sleep(100);
    FreeLibraryAndExitThread(handleModule, 0);
}