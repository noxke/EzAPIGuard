// Injector.cpp
// dll注入器 注入已存在进程或创建新进程
// 与注入进程进行初始通信

#include "pch.h"

#ifndef _INJECTOR_H
#include "Injector.h"
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


uint64_t LoadLibraryArva86 = 0x1234;
uint64_t LoadLibraryArva64 = 0x5678;

DLL_EXPORT BOOL InjectByPID(uint32_t dwPID, const char* dllPath)
{
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    HMODULE hMod = NULL;
    BOOL isWow64;
    LPVOID pRemoteBuf = NULL;
    DWORD dwBufSize = strlen(dllPath) + 1;
    uint64_t pThreadProc;

    // 获取进程句柄
    if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
    {
        return FALSE;
    }

    // 获取LoadLibraryA地址 由于兼容x86 不能直接获取本进程内的kernel32.dll
    // 创建快照
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, dwPID);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 枚举模块
    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hSnapshot, &moduleEntry)) {
        do {
            // wprintf(L"%s\n", moduleEntry.szExePath);
            WCHAR* modName = wcsrchr(moduleEntry.szExePath, L'\\');
            modName++;
            if (lstrcmpiW(modName, L"kernel32.dll") == 0) {
                hMod = moduleEntry.hModule;
            }
        } while (Module32Next(hSnapshot, &moduleEntry));
    }
    else {
    }

    if (hMod == NULL)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 确定目标进程架构
    if (IsWow64Process(hProcess, &isWow64))
    {
        if (isWow64)
        {
            // 32位程序
            pThreadProc = (uint64_t)hMod + LoadLibraryArva86;
        }
        else
        {
            // 64位程序
            pThreadProc = (uint64_t)hMod + LoadLibraryArva64;
        }
    }
    else
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    if (pThreadProc == NULL)
    {
        CloseHandle(hProcess);
        return FALSE;
    }

    // 远程分配内存
    pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuf == NULL)
    {
        CloseHandle(hProcess);
        return FALSE;
    }
    // 写入LoadLibraryA参数
    if (WriteProcessMemory(hProcess, pRemoteBuf, dllPath, dwBufSize, NULL) == FALSE)
    {
        CloseHandle(hProcess);
        return FALSE;
    }
    // 创建远程线程执行LoadLibraryA
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pThreadProc, pRemoteBuf, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hProcess);
    }
    CloseHandle(hProcess);
    return TRUE;
}

DLL_EXPORT uint32_t RunInject(const char* exePath, char* cmdLine, const char* dllPath)
{
    DWORD dwPID = 0;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    // 启动目标进程 以调试模式启动
    BOOL success = CreateProcessA(
        exePath,            // 目标可执行文件路径
        cmdLine,            // 命令行参数
        NULL,               // 进程安全描述符
        NULL,               // 线程安全描述符
        FALSE,              // 是否继承句柄
        DEBUG_ONLY_THIS_PROCESS,      // 创建调试进程的标志
        NULL,               // 环境变量
        NULL,               // 当前目录
        &si,                // 启动信息
        &pi                 // 进程信息
    );
    if (success == FALSE)
    {
        return FALSE;
    }
    dwPID = pi.dwProcessId;

    // 创建后已经附加 不需要再附加到进程

    success = FALSE;
    // 等待调试事件 10s
    DEBUG_EVENT debugEvent;
    uint64_t bpAddr = 0;
    uint32_t bpOriData = 0;
    while (WaitForDebugEvent(&debugEvent, 10000))
    {
        if (debugEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT)
        {
            // 目标进程已创建
        }
        else if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            // 32位会报0xC0000005异常 而不是软件断点
            if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT ||
                debugEvent.u.Exception.ExceptionRecord.ExceptionCode == 0xC0000005)
            {

                // 第一次在ntdll中断下 一般此时kernel32.dl没有加载
                // printf("break at 0x%llx\n", debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
                if (bpAddr == 0)
                {
                    HMODULE hMod;
                    DWORD needed;
                    if (EnumProcessModules(pi.hProcess, &hMod, sizeof(HMODULE), &needed))
                    {
                        char name[MAX_PATH];
                        GetModuleBaseNameA(pi.hProcess, hMod, name, MAX_PATH);
                    }
                    else
                    {
                        break;
                    }
                    // 读取pe文件获取文件入口信息
                    uint8_t* fileBuffer = (uint8_t*)malloc(0x1000);
                    if (fileBuffer == NULL)
                    {
                        continue;
                    }
                    FILE* exeFile = NULL;
                    fopen_s(&exeFile, exePath, "rb");
                    fread(fileBuffer, 1, 0x1000, exeFile);
                    fclose(exeFile);
                    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)fileBuffer;
                    // 确定目标进程架构
                    BOOL isWow64;
                    if (IsWow64Process(pi.hProcess, &isWow64))
                    {
                        if (isWow64)
                        {
                            // 32位程序
                            IMAGE_NT_HEADERS32* pNtHeader = (IMAGE_NT_HEADERS32*)(pDosHeader->e_lfanew + fileBuffer);
                            IMAGE_OPTIONAL_HEADER32* pOptHeader = &(pNtHeader->OptionalHeader);
                            // 程序入口点
                            bpAddr = (uint64_t)hMod + (uint64_t)pOptHeader->AddressOfEntryPoint;
                        }
                        else
                        {
                            // 64位程序
                            IMAGE_NT_HEADERS64* pNtHeader = (IMAGE_NT_HEADERS64*)(pDosHeader->e_lfanew + fileBuffer);
                            IMAGE_OPTIONAL_HEADER64* pOptHeader = &(pNtHeader->OptionalHeader);
                            // 程序入口点
                            bpAddr = (uint64_t)hMod + (uint64_t)pOptHeader->AddressOfEntryPoint;
                        }
                        if (!ReadProcessMemory(pi.hProcess, (LPVOID)bpAddr, (LPVOID)&bpOriData, 4, NULL))
                        {
                            break;
                        }
                        DWORD oldProtect1;
                        DWORD oldProtect2;
                        if (!VirtualProtectEx(pi.hProcess, (LPVOID)bpAddr, 0x1000, PAGE_READWRITE, &oldProtect1))
                        {
                            break;
                        }
                        uint32_t bpCC = 0xCCCCCCCC;
                        WriteProcessMemory(pi.hProcess, (LPVOID)bpAddr, (LPVOID)&bpCC, 4, NULL);
                        if (!VirtualProtectEx(pi.hProcess, (LPVOID)bpAddr, 0x1000, oldProtect1, &oldProtect2))
                        {
                            break;
                        }
                    }
                    else
                    {
                        free(fileBuffer);
                        continue;
                    }
                    free(fileBuffer);
                }
                else
                {
                    CONTEXT context;
                    context.ContextFlags = CONTEXT_FULL;
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, debugEvent.dwThreadId);
                    GetThreadContext(hThread, &context);
                    // printf("break at 0x%llx\n", context.Rip);
                    context.Rip = bpAddr;
                    SetThreadContext(hThread, &context);
                    CloseHandle(hThread);
                    // 在入口点断下 恢复断点数据 注入DLL
                    DWORD oldProtect1;
                    DWORD oldProtect2;
                    if (!VirtualProtectEx(pi.hProcess, (LPVOID)bpAddr, 0x1000, PAGE_READWRITE, &oldProtect1))
                    {
                        break;
                    }
                    WriteProcessMemory(pi.hProcess, (LPVOID)bpAddr, (LPVOID)&bpOriData, 4, NULL);
                    if (!VirtualProtectEx(pi.hProcess, (LPVOID)bpAddr, 0x1000, oldProtect1, &oldProtect2))
                    {
                        break;
                    }
                    success = InjectByPID(dwPID, dllPath);
                    break;
                }
            }
        }
        else if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        {
            // 目标进程已退出
            break;
        }
        // 继续处理下一个调试事件
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    }
    // 将主线程休眠 回复运行使注入远程线程先运行
    SuspendThread(pi.hThread);
    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
    // 分离目标进程
    DebugActiveProcessStop(pi.dwProcessId);
    // 延迟启动启动 确保hook成功后再运行程序
    Sleep(1000);
    ResumeThread(pi.hThread);
    // 关闭进程和线程句柄
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return success ? dwPID : 0;
}