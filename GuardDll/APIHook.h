#pragma once
#include "pch.h"

#include <Windows.h>

#define _API_HOOK_H
#define DLL_EXPORT extern "C" __declspec(dllexport)

// 定义API ID
#define HOOK_API_NUM 19

#define API_NONE 0  // 空定义 不需要实现
#define API_MessageBoxA 1
#define API_MessageBoxW 2
#define API_CreateFile 3
#define API_ReadFile 4
#define API_WriteFile 5
#define API_HeapCreate 6
#define API_HeapDestroy 7
#define API_HeapFree 8
#define API_HeapAlloc 9
#define API_RegCreateKeyEx 10
#define API_RegSetValueEx 11
#define API_RegCloseKey 12
#define API_RegOpenKeyEx 13
#define API_RegDeleteValue 14
#define API_send 15
#define API_recv 16
#define API_sendto 17
#define API_recvfrom 18

// api hook配置
#define HOOK_DISABLE 0
#define HOOK_ALLOW 1
#define HOOK_REJECT 2
#define HOOK_REQUEST 3

// api config
extern int api_config[HOOK_API_NUM];

//hook的api有 MessageBoxA MessageBoxW CreateFile ReadFile HeapCreate HeapDestroy HeapFree HeapAlloc RegCreateKeyEx
// RegSetValueEx RegCloseKey RegOpenKeyEx RegDeleteValue


//消息框MessageBox操作的hook定义
extern int (WINAPI* OldMessageBoxA)(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

DLL_EXPORT int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType);

extern int  MessageBoxA_config;

extern int (WINAPI* OldMessageBoxW)(_In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);

DLL_EXPORT int WINAPI NewMessageBoxW(_In_opt_ HWND hwnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);

extern int MessageBoxW_config;


//文件操作API的hook定义
extern  HANDLE(WINAPI* OldCreateFile)(
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

extern int CreateFile_config;

// ReadFile
extern int ReadFile_config;

extern BOOL(WINAPI* OldWriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );

DLL_EXPORT BOOL WINAPI NewWriteFile(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

extern int WriteFile_config;


//堆操作API的hook定义
extern HANDLE(WINAPI* OldHeapCreate)(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);

DLL_EXPORT HANDLE WINAPI NewHeapCreate(DWORD fIOoptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);

extern int HeapCreate_config;

extern BOOL(WINAPI* OldHeapDestory)(HANDLE heap);

DLL_EXPORT BOOL WINAPI NewHeapDestroy(HANDLE hHeap);

extern int HeapDestroy_config;

extern BOOL(WINAPI* OldHeapFree)(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem);

DLL_EXPORT BOOL WINAPI NewHeapFree(HANDLE hHeap, DWORD dwFlags, _Frees_ptr_opt_ LPVOID lpMem);

extern int HeapFree_config;

extern LPVOID(WINAPI* OldHeapAlloc)(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes);

DLL_EXPORT LPVOID WINAPI NewHeapAlloc(HANDLE hHeap, DWORD  dwFlags, SIZE_T dwBytes);

extern int HeapAlloc_config;


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

extern int RegCreateKey_config;

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

extern int RegSetValue_config;

//关闭一个打开的注册表键的
extern LSTATUS(WINAPI* OldRegCloseKey)(HKEY hKey);

DLL_EXPORT LSTATUS WINAPI NewRegCloseKey(HKEY hKey);

extern int RegCloseKey_config;

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

extern int RegOpenKey_config;

//删除键值
extern LSTATUS(WINAPI* OldRegDeleteValue)(
    HKEY    hKey,
    LPCWSTR lpValueName
    );

DLL_EXPORT LSTATUS WINAPI NewRegDeleteValue(
    HKEY    hKey,
    LPCWSTR lpValueName
);

extern int RegDeleteValue_config;


// 网络API hook定义

// send
extern int send_config;

// recv
extern int recv_config;

// sendto
extern int sendto_config;

// recvfrom
extern int recvfrom_config;