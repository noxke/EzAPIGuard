// EzAPIGuard.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

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
#include <stdio.h>
#include <stdlib.h>

#define SERVER_PORT 0 // random

int main(int argc, const char* argv[])
{

    if (argc != 3)
    {
        printf("usage: %s process_name dll_path", argv[0]);
    }
    else
    {
        DWORD dwPID = GetDwPidByName(argv[1]);
        if (dwPID == 0)
        {
            return 0;
        }
        LPCSTR dllPath = argv[2];
        uint16_t serverPort = SERVER_PORT;

        // 启动ServerThread线程
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ServerSocketThread, (LPVOID)&serverPort, 0, NULL);
        Sleep(1000);

        // 将dll注入进程
        if (InjectByPID(dwPID, dllPath) == FALSE)
        {
            return 0;
        }
        Sleep(1000);

        // 启动进程内的ClientThread
        if (RunClientThreadByPID(dwPID, dllPath, serverPort) == FALSE)
        {
            return TRUE;
        }

        while (1)
        {
            Sleep(5000);
        }
    }
    return 0;
}
