// Injector.cpp
// dll注入器 注入已存在进程或创建新进程
// 与注入进程进行初始通信

#include "pch.h"

#ifndef _INJECTOR_H
#include "Injector.h"
#endif

#ifndef _GUARD_SERVER_H
#include "GuardServer.h"
#endif

#ifndef _LOG_H
#include "Log.h"
#endif

#include <Windows.h>
#include <psapi.h>
#include <processthreadsapi.h>
#include <WinUser.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <stdlib.h>

extern "C" __declspec(dllexport) DWORD GetDwPidByName(const char *procName)
{
    // 将进程名转换为宽字符
    LPWSTR procNameW = (LPWSTR)malloc(sizeof(WCHAR) * (strlen(procName) + 1));
    MultiByteToWideChar(CP_ACP,
        MB_PRECOMPOSED,
        (LPCCH)procName,
        strlen(procName) + 1,
        procNameW,
        (int)((strlen(procName) + 1) * sizeof(WCHAR)));
    // 使用tlhelp32获取进程PID
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, (DWORD)0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return 0;
    }
    LPWSTR fileNameBuf = (LPWSTR)malloc(sizeof(WCHAR) * MAX_PATH);
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnapshot, &pe32);
    do
    {
        DWORD dwPID = pe32.th32ProcessID;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
        if (hProcess == NULL)
        {
            continue;
        }
        GetProcessImageFileName(hProcess, fileNameBuf, (DWORD)MAX_PATH);
        // 提取进程名
        WCHAR* pFileName = wcsrchr(fileNameBuf, L'\\');
        pFileName++;
        if (!wcscmp(procNameW, pFileName))
        {
            free((void*)fileNameBuf);
            return dwPID;
        }
    } while (Process32Next(hSnapshot, &pe32));
    free((void*)fileNameBuf);
    return 0;
}

extern "C" __declspec(dllexport) BOOL InjectByPID(DWORD dwPID, LPCSTR dllPath)
{
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HMODULE hMod = NULL;
    LPVOID pRemoteBuf = NULL;
    DWORD dwBufSize = (DWORD)strlen(dllPath) * sizeof(char) + 1;
    LPTHREAD_START_ROUTINE pThreadProc;
    // 获取进程句柄
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        LOG_PRINTF("open process %d failed", dwPID);
        return FALSE;
    }
    LOG_PRINTF("open process succeed");
    // 远程分配内存
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf == NULL)
    {
        LOG_PRINTF("alloc memory failed");
        return FALSE;
    }
    LOG_PRINTF("memory alloced at 0x%llx", (DWORD_PTR)pRemoteBuf);
    // 写入LoadLibraryA参数
    if (WriteProcessMemory(hProcess, pRemoteBuf, dllPath, dwBufSize, NULL) == FALSE)
    {
        LOG_PRINTF("write dllPath to process failed");
        return FALSE;
    }
    LOG_PRINTF("write dllPath succeed");
    // 获取LoadLibraryA地址
    hMod = GetModuleHandleA((LPCSTR)"kernel32.dll");
    pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
    if (pThreadProc == NULL)
    {
        LOG_PRINTF("get LoadLibraryA address failed");
        return FALSE;
    }
    LOG_PRINTF("LoadLibraA at 0x%llx", (DWORD_PTR)pThreadProc);
    // 创建远程线程执行LoadLibraryA
    hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE)
    {
        LOG_PRINTF("create remote thread failed");
    }
    LOG_PRINTF("inject succeed");
    return TRUE;
}

extern "C" __declspec(dllexport) BOOL RunClientThreadByPID(DWORD dwPID, LPCSTR dllPath, uint16_t serverPort)
{
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HMODULE hMod = NULL;
    DWORD_PTR threadProcOff;
    DWORD_PTR pThreadProc;
    // 获取进程句柄
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        LOG_PRINTF("open process %d failed", dwPID);
        return FALSE;
    }
    LOG_PRINTF("open process succeed");
    
    // 获取ClientSocketThread地址
    hMod = LoadLibraryA(dllPath);
    if (hMod == NULL)
    {
        LOG_PRINTF("load %s failed", dllPath);
        return FALSE;
    }
    LOG_PRINTF("%s address: 0x%llx", dllPath, (DWORD_PTR)hMod);
    pThreadProc = (DWORD_PTR)GetProcAddress(hMod, "ClientSocketThread");
    if (pThreadProc == NULL)
    {
        LOG_PRINTF("get ClientSocketThread address failed");
        return FALSE;
    }
    LOG_PRINTF("ClientSocketThread at 0x%llx", (DWORD_PTR)pThreadProc);
    threadProcOff = (DWORD_PTR)pThreadProc - (DWORD_PTR)hMod;
    LOG_PRINTF("ClientSocketThread offset 0x%llx", threadProcOff);

    HMODULE hModules[1024];
    DWORD cbNeeded;
    hMod = NULL;
    char dllFullPath[MAX_PATH];
    GetFullPathNameA(dllPath, sizeof(dllFullPath), dllFullPath, NULL);
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        int moduleCount = cbNeeded / sizeof(HMODULE);
        for (int i = 0; i < moduleCount; i++) {
            CHAR szModuleName[MAX_PATH];
            if (GetModuleFileNameA(hModules[i], szModuleName, sizeof(szModuleName))) {
                if (strcmp(dllFullPath, szModuleName) == 0)
                {
                    hMod = hModules[i];
                    break;
                }
            }
        }
    }
    if (hMod == NULL)
    {
        LOG_PRINTF("%s not found in %d", dllPath, dwPID);
        return FALSE;
    }
    LOG_PRINTF("%s in %d at %llx", dllPath, dwPID, (DWORD_PTR)hMod);
    pThreadProc = (DWORD_PTR)hMod + threadProcOff;
    LOG_PRINTF("ClientSocketThread in %d at %llx", dwPID, pThreadProc);

    // 创建远程线程执行ClientSocketThread
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadProc, (LPVOID)serverPort, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE)
    {
        LOG_PRINTF("create remote thread failed");
    }
    LOG_PRINTF("Run client thread succeed");
    return TRUE;
}
