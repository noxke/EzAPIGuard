// EzAPIGuard.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <Windows.h>
#include <stdio.h>
#include <string.h>

BOOL inject(DWORD dwPID, LPCSTR dllPath)
{
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)strlen(dllPath) * sizeof(char) + 1;
	LPTHREAD_START_ROUTINE pThreadProc;
	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		printf("open process %d failed\n", dwPID);
		return FALSE;
	}
	printf("open process success\n");
	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL)
	{
		printf("alloc memory failed\n");
		return FALSE;
	}
	printf("memory alloced at 0x%x\n", pRemoteBuf);
	if (WriteProcessMemory(hProcess, pRemoteBuf, dllPath, dwBufSize, NULL) == FALSE)
	{
		printf("write dllPath to process failed\n");
		return FALSE;
	}
	printf("write dllPath success\n");
	hMod = GetModuleHandleA((LPCSTR)"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryA");
	if (pThreadProc == NULL)
	{
		printf("get LoadLibraryA address failed\n");
		return FALSE;
	}
	printf("LoadLibraA at 0x%x\n", pThreadProc);
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE)
	{
		printf("create remote thread failed\n");
	}
	printf("inject success\n");
	return TRUE;
}

int main(int argc, const char* argv[])
{
	if (argc != 3)
	{
		printf("usage: %s process_pid dll_path", argv[0]);
	}
	else
	{
		DWORD dwPID;
		LPCSTR dllPath = argv[2];
		sscanf_s(argv[1], "%d", &dwPID);
		inject(dwPID, dllPath);
	}
	return 0;
}
