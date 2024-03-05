// MessageDefine.h
// 定义通信消息封装格式

#pragma once
#define _MESSAGE_DEFINE_H

#define UDP_BUFFER_SIZE 1024

#include <stdint.h>

// 定义消息类型
#define MSG_NONE 0  // 空数据包
#define MSG_HELLO 1 // hello数据包 传输端口信息
#define MSG_ACK 2   // 确认数据包
#define MSG_HOOKED 10   // api hook数据包
#define MSG_REPLY 11    // hooked回复包
#define MSG_ATTACH 20   // 配置hook指定api
#define MSG_DETACH 21   // 配置取消hook指定api
#define MSG_CONFIG 22   // api配置包来判断是否放行或者拦截api
#define MSG_ENABLE 250    // 启用hook
#define MSG_DISABLE 251   // 禁用hook
#define MSG_UNLOAD 252    // 卸载dll
#define MSG_KILL 255      // 关闭进程

// 定义API ID
#define HOOK_API_NUM 20

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
#define API_connect 19


// 基础数据包
struct udp_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint32_t process_pid;//进程PID信息
    uint64_t time;
    uint8_t data[UDP_BUFFER_SIZE - 16];
};

// 空数据包
struct empty_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint32_t process_pid;//进程PID信息
    uint64_t time;
};

// api hook数据包 包含api参数信息
struct api_hooked_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint32_t process_pid;//进程PID信息
    uint64_t time;
    uint16_t api_id;  // api id
    uint16_t arg_num;   // api参数个数(传递重要参数即可)
    // 紧接着为参数偏移表
    // 参数列表格式如下
    // uint16_t arg0_off;
    // uint16_t arg0_len;
    // uint16_t arg1_off;
    // uint16_t arg1_len;
    // uint16_t arg2_off;
    // uint16_t arg2_len;
    // ...
    // uint8_t arg0[arg0_len];
    // uint8_t arg1[arg1_len];
    // uint8_t arg2[arg2_len];
    // ...
};


//config数据包
struct api_config_msg
{
    uint16_t msg_type;
    uint16_t api_id;
    uint32_t process_pid;//进程PID信息
    uint64_t time;
    bool access;//是否放行
};