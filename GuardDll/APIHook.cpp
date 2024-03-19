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
#include <ws2tcpip.h>


uint8_t api_config[HOOK_API_NUM] = { HOOK_ALLOW, };


// 定义宏用于处理API操作
#define API_HOOK_BEGIN_MACRO(_api_id, _arg_num)\
struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(UDP_BUFFER_SIZE);\
memset(msg, 0, UDP_BUFFER_SIZE);\
BOOL allow = TRUE;\
if (api_config[_api_id] == HOOK_UNHOOK) goto _nosend;\
if (allow && msg != NULL)\
{\
    msg->msg_type = MSG_HOOKED;\
    msg->process_pid = dwPid;\
    msg->time = time(0);\
    msg->api_id = _api_id;\
    msg->arg_num = _arg_num;\
    msg->name_off = sizeof(struct api_hooked_msg) + msg->arg_num * sizeof(struct api_arg_struct);\
    msg->name_len = snprintf((char*)msg + msg->name_off, MAX_NAME_LEN, #_api_id);\
    struct api_arg_struct *p1 = (struct api_arg_struct *)((uint8_t *)msg + sizeof(struct api_hooked_msg));\
    uint8_t* p2 = (uint8_t *)msg + msg->name_off + msg->name_len;

// API参数的宏定义
#define API_ARG_BEGIN_MACRO(_arg_type, _arg) \
    p1->arg_name_off = (uint16_t)(p2 - (uint8_t*)msg); \
    p1->arg_name_len = snprintf((char*)p2, MAX_NAME_LEN, #_arg); \
    p2 += p1->arg_name_len; \
    p1->arg_off = (uint16_t)(p2 - (uint8_t*)msg);

// 中间只需要将处理后的值写入p2 长度写入p1->arg_len

#define API_ARG_END_MACRO(_arg_type, _arg) \
    p2 += p1->arg_len; \
    p1 = (struct api_arg_struct*)((uint8_t*)p1 + sizeof(struct api_arg_struct));


// 数值类型参数宏定义
#define API_ARG_INT_MACRO(_arg_type, _arg) \
    API_ARG_BEGIN_MACRO(_arg_type, _arg); \
    *(_arg_type*)p2 = _arg; \
    p1->arg_len = 8; \
    API_ARG_END_MACRO(_arg_type, _arg);

// 字符串类型参数宏定义
#define API_ARG_STR_MACRO(_arg_type, _arg) \
    API_ARG_BEGIN_MACRO(_arg_type, _arg); \
    p1->arg_len = snprintf((char *)p2, MAX_ARG_LEN, _arg); \
    API_ARG_END_MACRO(_arg_type, _arg);

// 宽字符串类型参数宏定义
#define API_ARG_WSTR_MACRO(_arg_type, _arg) \
    API_ARG_BEGIN_MACRO(_arg_type, _arg); \
    p1->arg_off = (uint16_t)(p2 - (uint8_t*)msg); \
    p1->arg_len = WideCharToMultiByte(CP_ACP, 0, _arg, -1, (LPSTR)p2, MAX_ARG_LEN, NULL, NULL); \
    API_ARG_END_MACRO(_arg_type, _arg);

// 通用类型 转换为指针之后给出指针和长度
#define API_ARG_MACRO(_arg_type, _arg, _p, _len) \
    API_ARG_BEGIN_MACRO(_arg_type, _arg); \
    { \
    int copy_len = (_len) > MAX_ARG_LEN ? MAX_ARG_LEN : (_len); \
    memcpy((char*)p2, (char *)(_p), copy_len); \
    p1->arg_len = (copy_len); \
    } \
    API_ARG_END_MACRO(_arg_type, _arg);


/*
    中间是参数处理 在函数内完成
*/

#define API_HOOK_END_MACRO(_api_id)\
    msg->data_length = p2 - (uint8_t*)msg;\
    switch (api_config[_api_id])\
    {\
    case HOOK_UNHOOK:\
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
        if (((struct api_reply_msg*)msg)->msg_type == MSG_REPLY && ((struct api_reply_msg*)msg)->access == TRUE)\
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
_nosend:\
free(msg);

// 末尾是原函数执行或绕过



int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType) = MessageBoxA;

DLL_EXPORT int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
    // uType参数省略
    API_HOOK_BEGIN_MACRO(API_MessageBoxA, 3);
        
        //将hWnd转换为窗口名
        char buffer[MAX_ARG_LEN];
        GetWindowTextA(hWnd, (LPSTR)buffer, MAX_ARG_LEN);
        API_ARG_MACRO(HWND, hWnd, buffer, strlen(buffer));
        API_ARG_STR_MACRO(LPCSTR, lpText);
        API_ARG_STR_MACRO(LPCSTR, lpCaption);
        
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
    API_HOOK_BEGIN_MACRO(API_MessageBoxW, 3);

        //将hWnd转换为窗口名
        char buffer[MAX_ARG_LEN];
        GetWindowTextA(hWnd, (LPSTR)buffer, MAX_ARG_LEN);
        API_ARG_MACRO(HWND, hWnd, buffer, strlen(buffer));
        API_ARG_WSTR_MACRO(LPCWSTR, lpText);
        API_ARG_WSTR_MACRO(LPCWSTR, lpCaption);

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
    API_HOOK_BEGIN_MACRO(API_CreateFile, 5);
        
        API_ARG_WSTR_MACRO(LPCWSTR, lpFileName);
        API_ARG_INT_MACRO(DWORD, dwDesiredAccess);
        API_ARG_INT_MACRO(DWORD, dwShareMode);
        API_ARG_INT_MACRO(DWORD, dwCreationDisposition);
        API_ARG_INT_MACRO(DWORD, dwFlagsAndAttributes);

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
    DWORD NumberOfBytesRead = 0;
    BOOL ret = FALSE;
    API_HOOK_BEGIN_MACRO(API_ReadFile, 3);

        // 获取文件名
        char buffer[UDP_BUFFER_SIZE];
        // 获取文件名需要关掉CreateFile的hook
        uint8_t old_config = api_config[API_CreateFile];
        api_config[API_CreateFile] = HOOK_UNHOOK;
        if (GetFinalPathNameByHandleA(hFile, (LPSTR)buffer, UDP_BUFFER_SIZE, FILE_NAME_NORMALIZED) == 0)
        {
            goto _nosend;
        }
        api_config[API_CreateFile] = old_config;
        API_ARG_MACRO(HANDLE, hFile, buffer, strlen(buffer));

        // 提前读取内容
        ret = OldReadFile(hFile, lpBuffer, nNumberOfBytesToRead, &NumberOfBytesRead, lpOverlapped);
        API_ARG_MACRO(LPVOID, lpBuffer, lpBuffer, nNumberOfBytesToRead);
        API_ARG_INT_MACRO(DWORD, nNumberOfBytesToRead);

    API_HOOK_END_MACRO(API_ReadFile);

    if (allow)
    {
        if (lpNumberOfBytesRead != NULL) *lpNumberOfBytesRead = NumberOfBytesRead;
        return ret;
    }
    else
    {
        // 清空文件读取记录
        SetFilePointer(hFile, -(LONG)NumberOfBytesRead, NULL, FILE_CURRENT);
        memset(lpBuffer, 0, nNumberOfBytesToRead);
        if (lpNumberOfBytesRead != NULL) *lpNumberOfBytesRead = 0;
        if (lpOverlapped != NULL)
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
    API_HOOK_BEGIN_MACRO(API_WriteFile, 3);

        // 获取文件名
        char buffer[UDP_BUFFER_SIZE];
        memset(buffer, 0, UDP_BUFFER_SIZE);
        // 获取文件名需要关掉CreateFile的hook
        uint8_t old_config = api_config[API_CreateFile];
        api_config[API_CreateFile] = HOOK_UNHOOK;
        if (GetFinalPathNameByHandleA(hFile, (LPSTR)buffer, UDP_BUFFER_SIZE, FILE_NAME_NORMALIZED) == 0)
        {
            goto _nosend;
        }
        api_config[API_CreateFile] = old_config;
        API_ARG_MACRO(HANDLE, hFile, buffer, strlen(buffer));
        // 这里直接传写入的内容
        API_ARG_MACRO(LPCVOID, lpBuffer, lpBuffer, nNumberOfBytesToWrite);
        API_ARG_INT_MACRO(DWORD, nNumberOfBytesToWrite);

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


BOOL(WINAPI* OldDeleteFile)(LPCWSTR lpFileName) = DeleteFileW;


DLL_EXPORT BOOL WINAPI NewDeleteFile(LPCWSTR lpFileName)
{
    API_HOOK_BEGIN_MACRO(API_DeleteFile, 1);

        API_ARG_WSTR_MACRO(LPCWSTR, lpFileName);

    API_HOOK_END_MACRO(API_DeleteFile);
    if (allow)
    {
        return OldDeleteFile(lpFileName);
    }
    else
    {
        return FALSE;
    }
}


HANDLE(WINAPI* OldHeapCreate)(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize) = HeapCreate;

DLL_EXPORT HANDLE WINAPI NewHeapCreate(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    HANDLE retHandle = NULL;

    API_HOOK_BEGIN_MACRO(API_HeapCreate, 3);

        API_ARG_INT_MACRO(DWORD, fIOoptions);
        API_ARG_INT_MACRO(SIZE_T, dwInitialSize);
        API_ARG_INT_MACRO(SIZE_T, dwMaximumSize);

        // 获取堆句柄
        retHandle = OldHeapCreate(fIOoptions, dwInitialSize, dwMaximumSize);

        API_ARG_INT_MACRO(HANDLE, retHandle);

    API_HOOK_END_MACRO(API_HeapCreate);

    if (allow)
    {
        return retHandle;
    }
    else
    {
        OldHeapDestroy(retHandle);
        return NULL;
    }
}

BOOL(WINAPI* OldHeapDestroy)(HANDLE heap) = HeapDestroy;

DLL_EXPORT BOOL WINAPI NewHeapDestroy(HANDLE hHeap)
{
    API_HOOK_BEGIN_MACRO(API_HeapDestroy, 1);

        API_ARG_INT_MACRO(HANDLE, hHeap);

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
    API_HOOK_BEGIN_MACRO(API_HeapFree, 3);
 
        API_ARG_INT_MACRO(HANDLE, hHeap);
        API_ARG_INT_MACRO(DWORD, dwFlags);
        API_ARG_INT_MACRO(LPVOID, lpMem);

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
    API_HOOK_BEGIN_MACRO(API_HeapAlloc, 3);
        // 不hook该函数
        API_ARG_INT_MACRO(HANDLE, hHeap);
        API_ARG_INT_MACRO(DWORD, dwFlags);
        API_ARG_INT_MACRO(SIZE_T, dwBytes);

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
    API_HOOK_BEGIN_MACRO(API_RegCreateKeyEx, 2);

        API_ARG_INT_MACRO(HKEY, hKey);
        API_ARG_WSTR_MACRO(LPWSTR, lpSubKey);

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
    API_HOOK_BEGIN_MACRO(API_RegSetValueEx, 5);

        API_ARG_INT_MACRO(HKEY, hKey);
        API_ARG_WSTR_MACRO(LPCWSTR, lpValueName);
        API_ARG_INT_MACRO(DWORD, dwType);
        API_ARG_MACRO(BYTE*, lpData, lpData, cbData);
        API_ARG_INT_MACRO(DWORD, cbData);

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
    API_HOOK_BEGIN_MACRO(API_RegCloseKey, 1);

        API_ARG_INT_MACRO(HKEY, hKey);

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
    API_HOOK_BEGIN_MACRO(API_RegOpenKeyEx, 2);

        API_ARG_INT_MACRO(HKEY, hKey);
        API_ARG_WSTR_MACRO(LPWSTR, lpSubKey);

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
    API_HOOK_BEGIN_MACRO(API_RegDeleteValue, 2);

        API_ARG_INT_MACRO(HKEY, hKey);
        API_ARG_WSTR_MACRO(LPWSTR, lpValueName);

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
    API_HOOK_BEGIN_MACRO(API_send, 4);

        int sock_type;
        int type_len = sizeof(sock_type);
        getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &type_len);
        API_ARG_INT_MACRO(int, sock_type);

        char hostname[NI_MAXHOST];
        char servInfo[NI_MAXSERV];
        char buffer[UDP_BUFFER_SIZE];
        // socket转换为本地的地址和端口
        sockaddr local_sockaddr;
        int local_sockaddr_len = sizeof(sockaddr);
        getsockname(s, &local_sockaddr, &local_sockaddr_len);
        getnameinfo(&local_sockaddr,
            local_sockaddr_len, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* local = buffer;
        API_ARG_STR_MACRO(char, local);
        // 发送到的数据
        API_ARG_MACRO(char, buf, buf, len);

        // 远程的地址和端口
        sockaddr name;
        int namelen = sizeof(sockaddr);
        getpeername(s, &name, &namelen);
        getnameinfo(&name,
            namelen, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* remote = buffer;
        API_ARG_STR_MACRO(char, remote);

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
    int ret = SOCKET_ERROR;
    API_HOOK_BEGIN_MACRO(API_recv, 4);

        // 先指向recv接收数据
        ret = Oldrecv(s, buf, len, flags);

        int sock_type;
        int type_len = sizeof(sock_type);
        getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &type_len);
        API_ARG_INT_MACRO(int, sock_type);

        char hostname[NI_MAXHOST];
        char servInfo[NI_MAXSERV];
        char buffer[UDP_BUFFER_SIZE];
        // socket转换为本地的地址和端口
        sockaddr local_sockaddr;
        int local_sockaddr_len = sizeof(sockaddr);
        getsockname(s, &local_sockaddr, &local_sockaddr_len);
        getnameinfo(&local_sockaddr,
            local_sockaddr_len, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* local = buffer;
        API_ARG_STR_MACRO(char, local);

        // 发送到的数据
        API_ARG_MACRO(char, buf, buf, len);

        // 远程的地址和端口
        sockaddr name;
        int namelen = sizeof(sockaddr);
        getpeername(s, &name, &namelen);
        getnameinfo(&name,
            namelen, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* remote = buffer;
        API_ARG_STR_MACRO(char, remote);

    API_HOOK_END_MACRO(API_recv);

    if (allow)
    {
        return ret;
    }
    else
    {
        // 清空接收的数据
        memset(buf, 0, len);
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
    API_HOOK_BEGIN_MACRO(API_sendto, 4);

        int sock_type;
        int type_len = sizeof(sock_type);
        getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &type_len);
        API_ARG_INT_MACRO(int, sock_type);
        
        char hostname[NI_MAXHOST];
        char servInfo[NI_MAXSERV];
        char buffer[UDP_BUFFER_SIZE];
        // socket转换为本地的地址和端口
        sockaddr local_sockaddr;
        int local_sockaddr_len = sizeof(sockaddr);
        getsockname(s, &local_sockaddr, &local_sockaddr_len);
        getnameinfo(&local_sockaddr,
            local_sockaddr_len, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* local = buffer;
        API_ARG_STR_MACRO(char, local);

        // 发送到的数据
        API_ARG_MACRO(char, buf, buf, len);

        // to转换为远程的地址和端口
        getnameinfo(to,
            tolen, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* remote = buffer;
        API_ARG_STR_MACRO(char, remote);

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
    int ret = SOCKET_ERROR;
    API_HOOK_BEGIN_MACRO(API_recvfrom, 4);

        // 先执行原recvfrom接收数据
        ret = Oldrecvfrom(s, buf, len, flags, from, fromlen);

        int sock_type;
        int type_len = sizeof(sock_type);
        getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &type_len);
        API_ARG_INT_MACRO(int, sock_type);

        char hostname[NI_MAXHOST];
        char servInfo[NI_MAXSERV];
        char buffer[UDP_BUFFER_SIZE];
        // socket转换为本地的地址和端口
        sockaddr local_sockaddr;
        int local_sockaddr_len = sizeof(sockaddr);
        getsockname(s, &local_sockaddr, &local_sockaddr_len);
        getnameinfo(&local_sockaddr,
            local_sockaddr_len, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* local = buffer;
        API_ARG_STR_MACRO(char, local);

        // 接收到的数据
        API_ARG_MACRO(char, buf, buf, ret);

        // from转换为远程的地址和端口
        getnameinfo(from,
            *fromlen, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* remote = buffer;
        API_ARG_STR_MACRO(char, remote);

    API_HOOK_END_MACRO(API_recvfrom);

    if (allow)
    {
        return ret;
    }
    else
    {
        // 失败则清空接收到的数据
        memset(buf, 0, len);
        memset(from, 0, *fromlen);
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
    API_HOOK_BEGIN_MACRO(API_connect, 3);

        int sock_type;
        int type_len = sizeof(sock_type);
        getsockopt(s, SOL_SOCKET, SO_TYPE, (char*)&sock_type, &type_len);
        API_ARG_INT_MACRO(int, sock_type);

        char hostname[NI_MAXHOST];
        char servInfo[NI_MAXSERV];
        char buffer[UDP_BUFFER_SIZE];
        // socket转换为本地的地址和端口
        sockaddr local_sockaddr;
        int local_sockaddr_len = sizeof(sockaddr);
        if (getsockname(s, &local_sockaddr, &local_sockaddr_len) == 0)
        {
            getnameinfo(&local_sockaddr,
                local_sockaddr_len, hostname,
                NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        }
        else
        {
            // 由于connect前不需要显示绑定地址，因此可能无法获取到正确的地址
            if (name->sa_family == AF_INET6)
            {
                snprintf(hostname, NI_MAXHOST, "0:0:0:0:0:0:0:0");
                snprintf(servInfo, NI_MAXSERV, "0");
            }
            else
            {
                snprintf(hostname, NI_MAXHOST, "0.0.0.0");
                snprintf(servInfo, NI_MAXSERV, "0");
            }
        }
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* local = buffer;
        API_ARG_STR_MACRO(char, local);

        // name转换为远程的地址和端口
        getnameinfo(name,
            namelen, hostname,
            NI_MAXHOST, servInfo, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);
        snprintf(buffer, UDP_BUFFER_SIZE, "(%s, %s)", hostname, servInfo);
        char* remote = buffer;
        API_ARG_STR_MACRO(char, remote);

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