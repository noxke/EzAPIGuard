// APIHook.cpp
// api hook功能实现

#include "pch.h"

#ifndef _API_HOOK_H
#include "APIHook.h"
#endif

#ifndef _MESSAGE_DEFINE_H
#include"MessageDefine.h"
#endif

#ifndef _GUARD_CLIENT_H
#include "GuardClient.h"
#endif

#ifndef _DETOURS_HOOK_H
#include "DetoursHook.h"
#endif

#include <stdio.h>
#include <stdlib.h>

int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;

extern "C" __declspec(dllexport) int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
    printf("MessageBoxA hooked\n");
    // 以MessageBoxA为例，封装数据包
    // 字符串需要注意缓冲区长度

    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;   // uType参数不重要
        msg->process_pid = dwPid;

        msg->api_id = API_MESSAGEBOXA;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(hWnd);
        p1 += 2;
        *(HWND*)((uint8_t*)msg + p2) = hWnd;
        p2 += sizeof(hWnd);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpText);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpText);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg2:
        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpCaption);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpCaption);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldMessageBoxA(NULL, "new MessageBoxA", "Hooked", MB_OK);
}

int (WINAPI* OldMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxW;

extern "C" __declspec(dllexport) int WINAPI NewMessageBoxW(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
    printf("MessageBoxA hooked\n");
    // 以MessageBoxA为例，封装数据包
    // 字符串需要注意缓冲区长度

    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;   // uType参数不重要
        msg->process_pid = dwPid;

        msg->api_id = API_MESSAGEBOXW;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(hWnd);
        p1 += 2;
        *(HWND*)((uint8_t*)msg + p2) = hWnd;
        p2 += sizeof(hWnd);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpText);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpText);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg2:
        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpCaption);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpCaption);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldMessageBoxW(NULL, "new MessageBoxW", "Hooked", MB_OK);
}

HANDLE(WINAPI* OldCreateFile)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    ) = CreateFile;

extern "C" __declspec(dllexport)HANDLE WINAPI NewCreateFile(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
){
    printf("CreateFile Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if(msg!=NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 2;   // uType参数不重要
        msg->process_pid = dwPid;
        msg->api_id = API_CreateFile;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(lpFileName);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpFileName);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwDesiredAccess;
        p2 += 4;
        if (p2 >= sizeof(udp_msg)) goto arg_end;


    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE(WINAPI* OldHeapCreate)(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) = HeapCreate;

extern "C" __declspec(dllexport)HANDLE WINAPI NewHeapCreate(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    printf("HeapCreate Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;  
        msg->process_pid = dwPid;
        msg->api_id = API_HeapCreate;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = fIOoptions;
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(SIZE_T);
        p1 += 2;
        *(SIZE_T*)((uint8_t*)msg + p2) = dwInitialSize;
        p2 += sizeof(SIZE_T);
        if (p2 >= sizeof(udp_msg)) goto arg_end;


    arg2:
        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(SIZE_T);
        p1 += 2;
        *(SIZE_T*)((uint8_t*)msg + p2) = dwMaximumSize;
        p2 += sizeof(SIZE_T);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg3:
        // arg3
        *(uint16_t*)((uint8_t*)msg + p1) = p3;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HANDLE);
        p1 += 2;
        //调用OldCreateFile
        HANDLE hHeap = OldCreateFile(fIOoptions, dwInitialSize, dwMaximumSize);
        *(HANDLE*)((uint8_t*)msg + p2) = hHeap;
        p2 += sizeof(HANDLE);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return hHeap;
}

BOOL(WINAPI* OldHeapDestory)(HANDLE heap) = HeapDestroy;

extern "C" __declspec(dllexport) BOOL WINAPI NewHeapDestory(HANDLE hHeap)
{
    printf("HeapDestroy Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 1;   
        msg->process_pid = dwPid;
        msg->api_id = API_HeapDestroy;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HANDLE);
        p1 += 2;
        *(HANDLE*)((uint8_t*)msg + p2) = hHeap;
        p2 += sizeof(hHeap);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldHeapDestory(hHeap);
}

BOOL(WINAPI* OldHeapFree)(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem) = HeapFree;

extern "C" __declspec(dllexport) BOOL WINAPI NewHeapFree(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem)
{
    printf("HeapFree Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;
        msg->process_pid = dwPid;
        msg->api_id = API_HeapFree;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HANDLE);
        p1 += 2;
        *(HANDLE*)((uint8_t*)msg + p2) = hHeap;
        p2 += sizeof(hHeap);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) =dwFlags;
        p2 += sizeof(DWORD);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg2：
        // arg2
        * (uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(lpMem);
        p1 += 2;
        memcpy((uint8_t*)msg+p2,&lpMem,sizeof(lpMem));
        p2 += sizeof(lpMem);

    if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldHeapFree(hHeap, dwFlags, lpMem);
}

LPVOID(WINAPI* OldHeapAlloc)(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes) = HeapAlloc;

extern "C" __declspec(dllexport) LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes)
{
    printf("HeapAlloc Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;
        msg->process_pid = dwPid;
        msg->api_id = API_HeapAlloc;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HANDLE);
        p1 += 2;
        *(HANDLE*)((uint8_t*)msg + p2) = hHeap;
        p2 += sizeof(hHeap);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwFlags;
        p2 += sizeof(DWORD);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg2：
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(SIZE_T);
        p1 += 2;
        *(SIZE_T*)((uint8_t*)msg + p2) = dwBytes;
        p2 += sizeof(SIZE_T);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldHeapAlloc(hHeap,dwFlags,dwBytes);
}

extern LSTATUS(WINAPI* OldRegCreateKeyEx)(
    HKEY                        hKey,
    LPCTSTR                     lpSubKey,
    DWORD                       Reserved,
    LPTSTR                      lpClass,
    DWORD                       dwOptions,
    REGSAM                      samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY                       phkResult,
    LPDWORD                     lpdwDisposition
    ) = RegCreateKeyEx;

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegCreateKeyEx(
    HKEY                        hKey,
    LPCWSTR                     lpSubKey,
    DWORD                       Reserved,
    LPWSTR                      lpClass,
    DWORD                       dwOptions,
    REGSAM                      samDesired,
    const LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    PHKEY                       phkResult,
    LPDWORD                     lpdwDisposition
)
{
    printf("RegCreateKeyEx Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 4;
        msg->process_pid = dwPid;
        msg->api_id = API_RegCreateKeyEx;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpSubKey);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpSubKey);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg2：
        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(REGSAM);
        p1 += 2;
        *(REGSAM*)((uint8_t*)msg + p2) = samDesired;
        p2 += sizeof(REGSAM);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg3:
        //arg3
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(PHKEY);
        p1 += 2;
        *(PHKEY*)((uint8_t*)msg + p2) = phkResult;
        p2 += sizeof(PHKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldRegCreateKeyEx(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
}

LSTATUS(WINAPI* OldRegSetValueEx)(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
    ) = RegSetValueEx;

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegSetValueEx(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE * lpData,
    DWORD      cbData
)
{
    printf("RegSetValueEx Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 5;
        msg->process_pid = dwPid;
        msg->api_id = API_RegSetValueEx;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpValueName);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpValueName);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg2：
        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwType;
        p2 += sizeof(DWORD);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg3:
        //arg3
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(const BYTE);
        p1 += 2;
        *(const BYTE*)((uint8_t*)msg + p2) = lpData;
        p2 += sizeof(const BYTE);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg4
        //arg4
        * (uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = cbData;
        p2 += sizeof(DWORD);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldRegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, cbData);
}

LSTATUS(WINAPI* OldRegCloseKey)(HKEY hKey)=RegCloseKey；

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegCloseKey(HKEY hKey)
{
    printf("RegCloseKey Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 1;
        msg->process_pid = dwPid;
        msg->api_id = API_RegCloseKey;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldRegCloseKey(hKey);
}

LSTATUS(WINAPI* OldRegOpenKeyEx)(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
    )= RegOpenKeyEx;

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegOpenKeyEx(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
)
{
    printf("RegOpenKeyEx Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 5;
        msg->process_pid = dwPid;
        msg->api_id = API_RegOpenKeyEx;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpValueName);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpValueName);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
     arg2：
        // arg2
        * (uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = ulOptions;
        p2 += sizeof(DWORD);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg3：
        // arg3
        * (uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(REGSAM);
        p1 += 2;
        *(REGSAM*)((uint8_t*)msg + p2) = samDesired;
        p2 += sizeof(REGSAM);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg4:
        //arg4
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(PHKEY);
        p1 += 2;
        *(PHKEY*)((uint8_t*)msg + p2) = phkResult;
        p2 += sizeof(PHKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldRegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

extern LSTATUS(WINAPI* OldRegDeleteValue)(HKEY hKey, LPCWSTR lpValueName) = RegDeleteValue;

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegDeleteValue(
    HKEY    hKey,
    LPCWSTR lpValueName
)
{
    printf("RegDeleteValue Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    if (msg != NUll)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 5;
        msg->process_pid = dwPid;
        msg->api_id = API_RegDeleteValue;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
    arg0:
        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpValueName);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpValueName);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        SocketSend((const char*)msg, (size_t)msg->data_length);
        free(msg);
    }
    msg = NULL;
    return OldRegDeleteValue(hKey,lpValueName);
}







