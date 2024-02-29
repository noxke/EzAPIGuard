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

#include <stdio.h>
#include <stdlib.h>


extern "C" __declspec(dllexport) int WINAPI NewMessageBoxA(_In_opt_ HWND hWnd, _In_opt_ LPCSTR lpText, _In_opt_ LPCSTR lpCaption, _In_ UINT uType)
{
    // 以MessageBoxA为例，封装数据包
    // 字符串需要注意缓冲区长度
    struct api_hooked_msg* msg = (struct api_hooked_msg*)malloc(sizeof(api_hooked_msg));
    if (msg != NULL)
    {
        msg->msg_type = MSG_HOOKED;
        msg->arg_num = 3;   // uType参数不重要

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
        if (p2 >= sizeof(api_hooked_msg)) goto arg_end;

    arg1:
        // arg1
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpText);
        p1 += 2;
        p2 += snprintf((char *)msg + p2, sizeof(api_hooked_msg) - p2, lpText);
        if (p2 >= sizeof(api_hooked_msg)) goto arg_end;

    arg2:
        // arg2
        *(uint16_t*)((uint8_t*)msg + p1) = p2;
        p1 += 2;
        *(uint16_t*)((uint8_t*)msg + p1) = strlen(lpCaption);
        p1 += 2;
        p2 += snprintf((char*)msg + p2, sizeof(api_hooked_msg) - p2, lpCaption);
        if (p2 >= sizeof(api_hooked_msg)) goto arg_end;

    arg_end:
        // 使用socket发送api信息
        SocketSend((const char *)msg, (size_t)msg->data_length);
        free(msg);
    }
    return OldMessageBoxA(NULL, "new MessageBoxA", "Hooked", MB_OK);
}