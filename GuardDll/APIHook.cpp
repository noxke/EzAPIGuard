// APIHook.cpp
// api hook功能实现

#include "pch.h"

#ifndef _LOCAL_API_H
#include "LocalAPI.h"
#endif

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


int api_config[HOOK_API_NUM] = {HOOK_DISABLE,};

struct api_hooked_msg* msg_HeapCreate = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
struct api_hooked_msg* msg_HeapDestroy = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
struct api_hooked_msg* msg_HeapFree = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
struct api_hooked_msg* msg_HeapAlloc = (struct api_hooked_msg*)malloc(sizeof(udp_msg));

int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;


extern "C" __declspec(dllexport) int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
    printf("MessageBoxA hooked\n");
    // 以MessageBoxA为例，封装数据包
    // 字符串需要注意缓冲区长度

    struct api_hooked_msg* msg = (struct api_hooked_msg*)local_malloc();
    BOOL allow = TRUE;

    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;   // uType参数不重要
        msg->process_pid = dwPid;

        msg->api_id = API_MessageBoxA;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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

    arg_end:
        msg->data_length = p2;

        switch (api_config[API_MessageBoxA])
        {
        case HOOK_DISABLE:
            allow = TRUE;
            break;
        case HOOK_ALLOW:
            UdpSendRecv((const char *)msg, NULL);
            allow = TRUE;
            break;
        case HOOK_REJECT:
            UdpSendRecv((const char*)msg, NULL);
            allow = FALSE;
            break;
        case HOOK_REQUEST:
            UdpSendRecv((const char*)msg, (char*)msg);
            if (((struct api_config_msg*)msg)->msg_type == MSG_REPLY \
                && ((struct api_config_msg*)msg)->access == TRUE)
            {
                allow = TRUE;
            }
            else
            {
                allow = FALSE;
            }
            break;
        }
        local_free(msg);
    }
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

extern "C" __declspec(dllexport) int WINAPI NewMessageBoxW(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType)
{
    printf("MessageBoxW hooked\n");
    // 字符串需要注意缓冲区长度

    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    struct api_config_msg* msg_config = (struct api_config_msg*)malloc(sizeof(api_config_msg));
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;   // uType参数不重要
        msg->process_pid = dwPid;

        msg->api_id = API_MessageBoxW;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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

    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldMessageBoxW(hWnd, lpText, lpCaption, uType);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }
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

extern "C" __declspec(dllexport)HANDLE WINAPI NewCreateFile(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
) {
    printf("CreateFile Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    struct api_config_msg* msg_config = (struct api_config_msg*)malloc(sizeof(api_config_msg));

    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 6;
        msg->process_pid = dwPid;
        msg->api_id = API_CreateFile;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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

    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldCreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }
    }
}

HANDLE(WINAPI* OldHeapCreate)(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) = HeapCreate;

extern "C" __declspec(dllexport)HANDLE WINAPI NewHeapCreate(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    printf("HeapCreate Hooked!\n");
    HANDLE hHeap;
    struct api_hooked_msg* msg = msg_HeapCreate;
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 4;
        msg->process_pid = dwPid;
        msg->api_id = API_HeapCreate;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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
        //调用OldCreateFile
        hHeap = OldHeapCreate(fIOoptions, dwInitialSize, dwMaximumSize);
        *(HANDLE*)((uint8_t*)msg + p2) = hHeap;
        p2 += sizeof(HANDLE);
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return hHeap;
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }
        ;
    }
}

BOOL(WINAPI* OldHeapDestroy)(HANDLE heap) = HeapDestroy;

extern "C" __declspec(dllexport) BOOL WINAPI NewHeapDestory(HANDLE hHeap)
{
    printf("HeapDestroy Hooked!\n");
    struct api_hooked_msg* msg = msg_HeapDestroy;
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 1;
        msg->process_pid = dwPid;
        msg->api_id = API_HeapDestroy;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldHeapDestroy(hHeap);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }
    }

}

BOOL(WINAPI* OldHeapFree)(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem) = HeapFree;

extern "C" __declspec(dllexport) BOOL WINAPI NewHeapFree(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem)
{
    printf("HeapFree Hooked!\n");
    struct api_hooked_msg* msg = msg_HeapFree;
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;
        msg->process_pid = dwPid;
        msg->api_id = API_HeapFree;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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

    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldHeapFree(hHeap, dwFlags, lpMem);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }

    }
}

LPVOID(WINAPI* OldHeapAlloc)(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes) = HeapAlloc;

extern "C" __declspec(dllexport) LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes)
{
    printf("HeapAlloc Hooked!\n");
    struct api_hooked_msg* msg = msg_HeapAlloc;
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;
        msg->process_pid = dwPid;
        msg->api_id = API_HeapAlloc;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldHeapAlloc(hHeap, dwFlags, dwBytes);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }

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
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 4;
        msg->process_pid = dwPid;
        msg->api_id = API_RegCreateKeyEx;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldRegCreateKeyEx(hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }
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
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 4;
        msg->process_pid = dwPid;
        msg->api_id = API_RegSetValueEx;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldRegSetValueEx(hKey, lpValueName, Reserved, dwType, lpData, cbData);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }

    }


}

LSTATUS(WINAPI* OldRegCloseKey)(HKEY hKey) = RegCloseKey;

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegCloseKey(HKEY hKey)
{
    printf("RegCloseKey Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 1;
        msg->process_pid = dwPid;
        msg->api_id = API_RegCloseKey;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(msg_config));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldRegCloseKey(hKey);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }


    }


}

LSTATUS(WINAPI* OldRegOpenKeyEx)(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
    ) = RegOpenKeyEx;

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
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 5;
        msg->process_pid = dwPid;
        msg->api_id = API_RegOpenKeyEx;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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
        if (p2 >= sizeof(udp_msg)) goto arg_end;
    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldRegOpenKeyEx(hKey, lpSubKey, ulOptions, samDesired, phkResult);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }

    }

}

extern LSTATUS(WINAPI* OldRegDeleteValue)(HKEY hKey, LPCWSTR lpValueName) = RegDeleteValue;

extern "C" __declspec(dllexport)LSTATUS WINAPI NewRegDeleteValue(
    HKEY    hKey,
    LPCWSTR lpValueName
)
{
    printf("RegDeleteValue Hooked!\n");
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(udp_msg));
    struct api_config_msg* msg_config;
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 2;
        msg->process_pid = dwPid;
        msg->api_id = API_RegDeleteValue;

        // p1指向参数列表
        // p2指向参数
        uint16_t p1 = sizeof(struct api_hooked_msg);
        uint16_t p2 = p1 + msg->arg_num * (sizeof(uint16_t) * 2);

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

    arg_end:
        msg->data_length = p2;
        // 使用socket发送api信息
        UdpSocketSend(&sock, (const char*)msg, (size_t)msg->data_length);
        // 使用socket接受
        UdpSocketRecv(&sock, (char*)msg_config, sizeof(api_config_msg));
        if (msg_config->access == TRUE)
        {
            free(msg);
            msg = NULL;
            return OldRegDeleteValue(hKey, lpValueName);
        }
        else
        {
            free(msg);
            msg = NULL;
            //这里的返回值后期可以宏定义一下错误内容，目前暂时用ERROR代替；
            return ERROR;
        }

    }

}