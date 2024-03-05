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
#include <time.h>


// 定义宏用于处理API操作
#define API_HOOK_BEGIN_MACRO(_api_id)\
struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(UDP_BUFFER_SIZE);\
BOOL allow = TRUE;\
if (api_config[_api_id] == HOOK_DISABLE) allow = FALSE;\
if (allow && msg != NULL)\
{\
    msg->msg_type = MSG_HOOKED;\
    msg->process_pid = dwPid;\
    msg->time = time(0);\
    msg->api_id = _api_id;\
    uint16_t p1 = 0;\
    uint16_t p2 = 0;\

/*
    中间是参数处理 在函数内完成
*/

#define API_HOOK_END_MACRO(_api_id)\
arg_end:\
    msg->data_length = p2;\
    switch (api_config[_api_id])\
    {\
    case HOOK_DISABLE:\
        allow = TRUE;\
        break;\
    case HOOK_ALLOW:\
        UdpSendRecv((char*)msg, msg->data_length, FALSE);\
        allow = TRUE;\
        break;\
    case HOOK_REJECT:\
        UdpSendRecv((char*)msg, msg->data_length, FALSE);\
        allow = FALSE;\
        break;\
    case HOOK_REQUEST:\
        UdpSendRecv((char*)msg, msg->data_length, TRUE);\
        if (((struct api_config_msg*)msg)->msg_type == MSG_REPLY && ((struct api_config_msg*)msg)->access == TRUE)\
        {\
            allow = TRUE;\
        }\
        else\
        {\
            allow = FALSE;\
        }\
        break;\
    }\
}\
free(msg);\

// 末尾是原函数执行或绕过


int api_config[HOOK_API_NUM] = {HOOK_ALLOW,};


int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;

DLL_EXPORT int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
    API_HOOK_BEGIN_MACRO(API_MessageBoxA);
        msg->arg_num = 3;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(hWnd);
        p1 += 2;
        *(HWND*)((uint8_t*)msg + p2) = hWnd;
        p2 += sizeof(hWnd);
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpText);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, lpText);
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpCaption);
        p1 += 2;

        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, lpCaption);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    API_HOOK_END_MACRO(API_MessageBoxA);

    if (allow)
    {
        return OldMessageBoxA(hWnd, lpText, lpCaption, uType);
    }
    else
    {
        return IDCANCEL; // 返回窗口取消值
    }
}

int (WINAPI* OldMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType) = MessageBoxW;

DLL_EXPORT int WINAPI NewMessageBoxW(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType)
{
    API_HOOK_BEGIN_MACRO(API_MessageBoxW);
        msg->arg_num = 3;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(hWnd);
        p1 += 2;
        *(HWND*)((uint8_t*)msg + p2) = hWnd;
        p2 += sizeof(hWnd);
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg1
        char buffer[100];//用来转换宽字符
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        WideCharToMultiByte(CP_ACP, 0, lpText, -1, buffer, sizeof(buffer), NULL, NULL);
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(buffer);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, buffer);
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        WideCharToMultiByte(CP_ACP, 0, lpCaption, -1, buffer, sizeof(buffer), NULL, NULL);
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(buffer);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, buffer);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    API_HOOK_END_MACRO(API_MessageBoxW);

    if (allow)
    {
        return OldMessageBoxW(hWnd, lpText, lpCaption, uType);
    }
    else
    {
        return IDCANCEL; // 返回窗口取消值
    }
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

DLL_EXPORT HANDLE WINAPI NewCreateFile(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
) {
    API_HOOK_BEGIN_MACRO(API_CreateFile);
        msg->arg_num = 6;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        char buffer[100];
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, buffer, sizeof(buffer), NULL, NULL);
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(buffer);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, buffer);
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwDesiredAccess;
        p2 += 4;
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwShareMode;
        p2 += 4;
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg3
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwCreationDisposition;
        p2 += 4;
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg4
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwFlagsAndAttributes;
        p2 += 4;
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg5
        HANDLE heap;
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HANDLE);
        p1 += 2;
        heap = OldCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        *(HANDLE*)((uint8_t*)msg + p2) = heap;
        p2 += 4;
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    API_HOOK_END_MACRO(API_CreateFile);

    if (allow)
    {
        return OldCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    else
    {
        return INVALID_HANDLE_VALUE;
    }
}

BOOL(WINAPI* OldReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    ) = ReadFile;

DLL_EXPORT BOOL WINAPI NewReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
) {
    API_HOOK_BEGIN_MACRO(API_ReadFile);
        msg->arg_num = 3;
    API_HOOK_END_MACRO(API_ReadFile);

    if (allow)
    {
        return OldReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    }
    else
    {
        return FALSE;
    }
}

BOOL(WINAPI* OldWriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    ) = WriteFile;

DLL_EXPORT BOOL WINAPI NewWriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    API_HOOK_BEGIN_MACRO(API_WriteFile);
        msg->arg_num = 3;
    API_HOOK_END_MACRO(API_WriteFile);

    if (allow)
    {
        return OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }
    else
    {
        return FALSE;
    }
}

HANDLE(WINAPI* OldHeapCreate)(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) = HeapCreate;

DLL_EXPORT HANDLE WINAPI NewHeapCreate(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    API_HOOK_BEGIN_MACRO(API_HeapCreate);
        msg->arg_num = 4;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);
        HANDLE _hHeap = NULL;

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = fIOoptions;
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(SIZE_T);
        p1 += 2;
        *(SIZE_T*)((uint8_t*)msg + p2) = dwInitialSize;
        p2 += sizeof(SIZE_T);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(SIZE_T);
        p1 += 2;
        *(SIZE_T*)((uint8_t*)msg + p2) = dwMaximumSize;
        p2 += sizeof(SIZE_T);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg3
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HANDLE);
        p1 += 2;
        //调用OldHeapCreate
        _hHeap = OldHeapCreate(fIOoptions, dwInitialSize, dwMaximumSize);
        *(HANDLE*)((uint8_t*)msg + p2) = _hHeap;
        p2 += sizeof(HANDLE);
    API_HOOK_END_MACRO(API_HeapCreate);

    if (allow)
    {
        return OldHeapCreate(fIOoptions, dwInitialSize, dwMaximumSize);
    }
    else
    {
        return NULL;
    }
}

BOOL(WINAPI* OldHeapDestroy)(HANDLE heap) = HeapDestroy;

DLL_EXPORT BOOL WINAPI NewHeapDestroy(HANDLE hHeap)
{
    API_HOOK_BEGIN_MACRO(API_HeapDestroy);
        msg->arg_num = 1;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HANDLE);
        p1 += 2;
        *(HANDLE*)((uint8_t*)msg + p2) = hHeap;
        p2 += sizeof(hHeap);
    API_HOOK_END_MACRO(API_HeapDestroy);

    if (allow)
    {
        return OldHeapDestroy(hHeap);
    }
    else
    {
        return 0;
    }
}

BOOL(WINAPI* OldHeapFree)(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem) = HeapFree;

DLL_EXPORT BOOL WINAPI NewHeapFree(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem)
{
    API_HOOK_BEGIN_MACRO(API_HeapFree);
        msg->arg_num = 3;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HANDLE);
        p1 += 2;
        *(HANDLE*)((uint8_t*)msg + p2) = hHeap;
        p2 += sizeof(hHeap);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwFlags;
        p2 += sizeof(DWORD);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(lpMem);
        p1 += 2;
        memcpy((uint8_t*)msg + p2, &lpMem, sizeof(lpMem));
        p2 += sizeof(lpMem);

        if (p2 >= sizeof(udp_msg)) goto arg_end;
    API_HOOK_END_MACRO(API_HeapFree);

    if (allow)
    {
        return OldHeapFree(hHeap, dwFlags, lpMem);
    }
    else
    {
        return 0;
    }
}

LPVOID(WINAPI* OldHeapAlloc)(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes) = HeapAlloc;

DLL_EXPORT LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes)
{
    API_HOOK_BEGIN_MACRO(API_HeapAlloc);
        // 不hook该函数
        // never here
    API_HOOK_END_MACRO(API_HeapAlloc);

    if (allow)
    {
        return OldHeapAlloc(hHeap, dwFlags, dwBytes);
    }
    else
    {
        return NULL;
    }
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

DLL_EXPORT LSTATUS WINAPI NewRegCreateKeyEx(
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
    API_HOOK_BEGIN_MACRO(API_RegCreateKeyEx);
        msg->arg_num = 4;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg1
        char buffer[100];
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        WideCharToMultiByte(CP_ACP, 0, lpSubKey, -1, buffer, sizeof(buffer), NULL, NULL);
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(buffer);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, buffer);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(REGSAM);
        p1 += 2;
        *(REGSAM*)((uint8_t*)msg + p2) = samDesired;
        p2 += sizeof(REGSAM);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        //arg3
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(PHKEY);
        p1 += 2;
        *(PHKEY*)((uint8_t*)msg + p2) = phkResult;
        p2 += sizeof(PHKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    API_HOOK_END_MACRO(API_RegCreateKeyEx);

    if (allow)
    {
        return OldRegCreateKeyEx(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
    }
    else
    {
        return ERROR_SUCCESS;
    }
}

LSTATUS(WINAPI* OldRegSetValueEx)(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
    ) = RegSetValueEx;

DLL_EXPORT LSTATUS WINAPI NewRegSetValueEx(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE * lpData,
    DWORD      cbData
)
{
    API_HOOK_BEGIN_MACRO(API_RegSetValueEx);
        msg->arg_num = 4;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg1
        char buffer[100];
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        WideCharToMultiByte(CP_ACP, 0, lpValueName, -1, buffer, sizeof(buffer), NULL, NULL);
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(buffer);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, buffer);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = dwType;
        p2 += sizeof(DWORD);
        if (p2 >= sizeof(udp_msg)) goto arg_end;


        //arg4
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = cbData;
        p2 += sizeof(DWORD);
    API_HOOK_END_MACRO(API_RegSetValueEx);

    if (allow)
    {
        return OldRegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    }
    else
    {
        return ERROR_SUCCESS;
    }
}

LSTATUS(WINAPI* OldRegCloseKey)(HKEY hKey) = RegCloseKey;

DLL_EXPORT LSTATUS WINAPI NewRegCloseKey(HKEY hKey)
{
    API_HOOK_BEGIN_MACRO(API_RegCloseKey);
        msg->arg_num = 1;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
    API_HOOK_END_MACRO(API_RegCloseKey);

    if (allow)
    {
        return OldRegCloseKey(hKey);
    }
    else
    {
        return ERROR_SUCCESS;
    }
}

LSTATUS(WINAPI* OldRegOpenKeyEx)(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
    ) = RegOpenKeyEx;

DLL_EXPORT LSTATUS WINAPI NewRegOpenKeyEx(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
)
{
    API_HOOK_BEGIN_MACRO(API_RegOpenKeyEx);
        msg->arg_num = 5;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg1
        char buffer[100];
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        WideCharToMultiByte(CP_ACP, 0, lpSubKey, -1, buffer, sizeof(buffer), NULL, NULL);
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(buffer);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, buffer);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(DWORD);
        p1 += 2;
        *(DWORD*)((uint8_t*)msg + p2) = ulOptions;
        p2 += sizeof(DWORD);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg3
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(REGSAM);
        p1 += 2;
        *(REGSAM*)((uint8_t*)msg + p2) = samDesired;
        p2 += sizeof(REGSAM);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        //arg4
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(PHKEY);
        p1 += 2;
        *(PHKEY*)((uint8_t*)msg + p2) = phkResult;
        p2 += sizeof(PHKEY);
    API_HOOK_END_MACRO(API_RegOpenKeyEx);

    if (allow)
    {
        return OldRegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, phkResult);
    }
    else
    {
        return ERROR_SUCCESS;
    }
}

extern LSTATUS(WINAPI* OldRegDeleteValue)(HKEY hKey, LPCWSTR lpValueName) = RegDeleteValue;

DLL_EXPORT LSTATUS WINAPI NewRegDeleteValue(
    HKEY    hKey,
    LPCWSTR lpValueName
)
{
    API_HOOK_BEGIN_MACRO(API_RegDeleteValue);
        msg->arg_num = 2;

        // p1指向参数列表
        // p2指向参数
        p1 = sizeof(struct api_hooked_msg);
        p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

        // arg0
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = sizeof(HKEY);
        p1 += 2;
        *(HKEY*)((uint8_t*)msg + p2) = hKey;
        p2 += sizeof(HKEY);
        if (p2 >= sizeof(udp_msg)) goto arg_end;

        // arg1
        char buffer[100];
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        WideCharToMultiByte(CP_ACP, 0, lpValueName, -1, buffer, sizeof(buffer), NULL, NULL);
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(buffer);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(udp_msg) - p2, buffer);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    API_HOOK_END_MACRO(API_RegDeleteValue);

    if (allow)
    {
        return OldRegDeleteValue(hKey, lpValueName);
    }
    else
    {
        // 假装成功
        return ERROR_SUCCESS;
    }
}


int (WSAAPI* Oldsend)(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
    ) = send;

DLL_EXPORT int WSAAPI Newsend(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
) {
    API_HOOK_BEGIN_MACRO(API_send);
        msg->arg_num = 3;
    API_HOOK_END_MACRO(API_send);

    if (allow)
    {
        return Oldsend(s, buf, len, flags);
    }
    else
    {
        return SOCKET_ERROR;
    }
}

int (WSAAPI* Oldrecv)(
    SOCKET s,
    char* buf,
    int    len,
    int    flags
    ) = recv;

DLL_EXPORT int WSAAPI Newrecv(
    SOCKET s,
    char* buf,
    int    len,
    int    flags
) {
    API_HOOK_BEGIN_MACRO(API_recv);
        msg->arg_num = 3;
    API_HOOK_END_MACRO(API_recv);

    if (allow)
    {
        return Oldrecv(s, buf, len, flags);
    }
    else
    {
        return SOCKET_ERROR;
    }
}

int (WSAAPI* Oldsendto)(
    SOCKET         s,
    const char* buf,
    int            len,
    int            flags,
    const sockaddr* to,
    int            tolen
    ) = sendto;

DLL_EXPORT int WSAAPI Newsendto(
    SOCKET         s,
    const char* buf,
    int            len,
    int            flags,
    const sockaddr* to,
    int            tolen
) {
    API_HOOK_BEGIN_MACRO(API_sendto);
        msg->arg_num = 3;
    API_HOOK_END_MACRO(API_sendto);

    if (allow)
    {
        return Oldsendto(s, buf, len, flags, to, tolen);
    }
    else
    {
        return SOCKET_ERROR;
    }
}

int (WSAAPI* Oldrecvfrom)(
    SOCKET   s,
    char* buf,
    int      len,
    int      flags,
    sockaddr* from,
    int* fromlen
    ) = recvfrom;

DLL_EXPORT int WSAAPI Newrecvfrom(
    SOCKET   s,
    char* buf,
    int      len,
    int      flags,
    sockaddr* from,
    int* fromlen
) {
    API_HOOK_BEGIN_MACRO(API_recvfrom);
        msg->arg_num = 3;
    API_HOOK_END_MACRO(API_recvfrom);

    if (allow)
    {
        return Oldrecvfrom(s, buf, len, flags, from, fromlen);
    }
    else
    {
        return SOCKET_ERROR;
    }
}

int (WSAAPI* Oldconnect)(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
    ) = connect;

DLL_EXPORT int WSAAPI Newconnect(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
) {
    API_HOOK_BEGIN_MACRO(API_connect);
        msg->arg_num = 3;
    API_HOOK_END_MACRO(API_connect);

    if (allow)
    {
        return Oldconnect(s, name, namelen);
    }
    else
    {
        return SOCKET_ERROR;
    }
}