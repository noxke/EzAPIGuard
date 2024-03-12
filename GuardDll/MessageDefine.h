// MessageDefine.h
// 定义通信消息封装格式

#pragma once
#define _MESSAGE_DEFINE_H

#define UDP_BUFFER_SIZE 1024

#include <stdint.h>

// 定义消息类型
#define MSG_NONE    0xC000      // 空数据包
#define MSG_HELLO   0xC001      // hello数据包 传输端口信息
#define MSG_ACK     0xC002      // 确认数据包
#define MSG_HOOKED  0xC010      // api hook数据包
#define MSG_REPLY   0xC011      // hooked回复包
#define MSG_ATTACH  0xC020      // 配置hook指定api
#define MSG_DETACH  0xC021      // 配置取消hook指定api
#define MSG_CONFIG  0xC022      // config配置api hook行为
#define MSG_ENABLE  0xC0F0      // 启用hook
#define MSG_DISABLE 0xC0F1      // 禁用hook
#define MSG_UNLOAD  0xC0F2      // 卸载dll
#define MSG_KILL    0xC0FF      // 关闭进程

// 定义API ID
#define HOOK_API_NUM 0x50

#define API_NONE            0x00  // 空定义 不需要实现
#define API_MessageBoxA     0x01
#define API_MessageBoxW     0x02
#define API_CreateFile      0x10
#define API_ReadFile        0x11
#define API_WriteFile       0x12
#define API_DeleteFile      0x13
#define API_HeapCreate      0x20
#define API_HeapDestroy     0x21
#define API_HeapFree        0x22
#define API_HeapAlloc       0x23
#define API_RegCreateKeyEx  0x30
#define API_RegSetValueEx   0x31
#define API_RegCloseKey     0x32
#define API_RegOpenKeyEx    0x33
#define API_RegDeleteValue  0x34
#define API_send            0x40
#define API_recv            0x41
#define API_sendto          0x42
#define API_recvfrom        0x43
#define API_connect         0x44

// 名称长度限制32 参数长度限制128
#define MAX_NAME_LEN 32
#define MAX_ARG_LEN 128

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

struct api_arg_struct
{
    uint16_t arg_name_off;
    uint16_t arg_name_len;
    uint16_t arg_off;
    uint16_t arg_len;
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
    uint16_t name_off;
    uint16_t name_len;
    // 紧接着为参数偏移表
    // 参数列表格式如下
    // uint16_t arg0_name_off;
    // uint16_t arg0_name_len;
    // uint16_t arg0_off;
    // uint16_t arg0_len;
    // uint16_t arg1_name_off;
    // uint16_t arg1_name_len;
    // uint16_t arg1_off;
    // uint16_t arg1_len;
    // uint16_t arg2_name_off;
    // uint16_t arg2_name_len;
    // uint16_t arg2_off;
    // uint16_t arg2_len;
    // ...
    // uint8_t api_name[name_len];
    // uint8_t arg0_name[arg0_name_len];
    // uint8_t arg0[arg0_len];
    // uint8_t arg1_name[arg1_name_len];
    // uint8_t arg1[arg1_len];
    // uint8_t arg2_name[arg2_name_len];
    // uint8_t arg2[arg2_len];
    // ...
};

// config数据包
struct api_config_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint32_t process_pid;//进程PID信息
    uint64_t time;
    uint8_t config[HOOK_API_NUM];   // 每个api的配置信息
};


// reply数据包
struct api_reply_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint32_t process_pid;//进程PID信息
    uint64_t time;
    bool access;//是否放行
};