#pragma once
#include "pch.h"

#include <stdint.h>
#include <Windows.h>
#include <winsock2.h>

#define _API_HOOK_H
#define DLL_EXPORT extern "C" __declspec(dllexport)

#ifndef _MESSAGE_DEFINE_H
#include"MessageDefine.h"
#endif

// api hook配置
#define HOOK_ALLOW 0
#define HOOK_REJECT 1
#define HOOK_REQUEST 2
#define HOOK_UNHOOK 3

// api config
extern uint8_t api_config[HOOK_API_NUM];


//hook的api有 MessageBoxA MessageBoxW
// CreateFile ReadFile WriteFile DeleteFile
// HeapCreate HeapDestroy HeapFree HeapAlloc
// RegCreateKeyEx RegSetValueEx RegCloseKey RegOpenKeyEx RegDeleteValue
// send recv sento recvfrom


//消息框MessageBox操作的hook定义
extern int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

DLL_EXPORT int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

extern int (WINAPI* OldMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);

DLL_EXPORT int WINAPI NewMessageBoxW(_In_opt_ HWND hwnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);



//文件操作API的hook定义
extern HANDLE (WINAPI* OldCreateFile)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

DLL_EXPORT HANDLE WINAPI NewCreateFile(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
    );

extern BOOL(WINAPI* OldReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    );

DLL_EXPORT BOOL WINAPI NewReadFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    );

extern BOOL (WINAPI* OldWriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );

DLL_EXPORT BOOL WINAPI NewWriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );

extern BOOL (WINAPI *OldDeleteFile)(LPCTSTR lpFileName);


DLL_EXPORT BOOL WINAPI NewDeleteFile(LPCTSTR lpFileName);

//堆操作API的hook定义
extern HANDLE(WINAPI* OldHeapCreate)(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);

DLL_EXPORT HANDLE WINAPI NewHeapCreate(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);

extern BOOL(WINAPI* OldHeapDestroy)(HANDLE heap);

DLL_EXPORT BOOL WINAPI NewHeapDestroy(HANDLE hHeap);

extern BOOL(WINAPI* OldHeapFree)(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem);

DLL_EXPORT BOOL WINAPI NewHeapFree(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem);

extern LPVOID(WINAPI* OldHeapAlloc)(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes);

DLL_EXPORT LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes);


//注册表API的hook定义

//创建或打开注册表键
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
    );

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
);

//用于在注册表中设置键值的函数
extern LSTATUS(WINAPI* OldRegSetValueEx)(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE* lpData,
    DWORD      cbData
    );

DLL_EXPORT LSTATUS WINAPI NewRegSetValueEx(
    HKEY       hKey,
    LPCWSTR    lpValueName,
    DWORD      Reserved,
    DWORD      dwType,
    const BYTE * lpData,
    DWORD      cbData
);


//关闭一个打开的注册表键的
extern LSTATUS(WINAPI* OldRegCloseKey)(HKEY hKey);

DLL_EXPORT LSTATUS WINAPI NewRegCloseKey(HKEY hKey);

//用于打开注册表中的一个子键
extern LSTATUS(WINAPI* OldRegOpenKeyEx)(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
    );

DLL_EXPORT LSTATUS WINAPI NewRegOpenKeyEx(
    HKEY    hKey,
    LPCWSTR lpSubKey,
    DWORD   ulOptions,
    REGSAM  samDesired,
    PHKEY   phkResult
);

//删除键值
extern LSTATUS(WINAPI* OldRegDeleteValue)(
    HKEY    hKey,
    LPCWSTR lpValueName
    );

DLL_EXPORT LSTATUS WINAPI NewRegDeleteValue(
    HKEY    hKey,
    LPCWSTR lpValueName
);



// 网络API hook定义

// send
extern int (WSAAPI *Oldsend)(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
    );

DLL_EXPORT int WSAAPI Newsend(
    SOCKET     s,
    const char* buf,
    int        len,
    int        flags
    );

// recv
extern int (WSAAPI *Oldrecv)(
    SOCKET s,
    char* buf,
    int    len,
    int    flags
    );

DLL_EXPORT int WSAAPI Newrecv(
    SOCKET s,
    char* buf,
    int    len,
    int    flags
    );

// sendto
extern int (WSAAPI *Oldsendto)(
    SOCKET         s,
    const char* buf,
    int            len,
    int            flags,
    const sockaddr* to,
    int            tolen
    );

DLL_EXPORT int WSAAPI Newsendto(
    SOCKET         s,
    const char* buf,
    int            len,
    int            flags,
    const sockaddr* to,
    int            tolen
    );

// recvfrom
extern int (WSAAPI *Oldrecvfrom)(
    SOCKET   s,
    char* buf,
    int      len,
    int      flags,
    sockaddr* from,
    int* fromlen
    );

DLL_EXPORT int WSAAPI Newrecvfrom(
    SOCKET   s,
    char* buf,
    int      len,
    int      flags,
    sockaddr* from,
    int* fromlen
    );

// connect
extern int (WSAAPI *Oldconnect)(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
    );

DLL_EXPORT int WSAAPI Newconnect(
    SOCKET         s,
    const sockaddr* name,
    int            namelen
);