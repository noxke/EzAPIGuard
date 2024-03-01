// MessageDefine.h
// 定义通信消息封装格式

#pragma once
#define _MESSAGE_DEFINE_H

#define UDP_BUFFER_SIZE 1024

#include <stdint.h>

// 定义消息类型
#define MSG_NONE 0  // 空数据包
#define MSG_HELLO 1 // hello数据包 传输pid信息
#define MSG_HOOKED 10   // api hook数据包
#define MSG_ATTACH 11   // 配置hook指定api
#define MSG_DETACH 12   // 配置取消hook指定api
#define MSG_STOP 255    // 停止所有hook并退出

// 定义API ID
#define API_MESSAGEBOXA 1
#define API_MESSAGEBOXW 2
#define API_CreateFile 3
#define API_HeapCreate 4
#define API_HeapDestroy 5
#define API_HeapFree 6
#define API_HeapAlloc 7
#define API_RegCreateKeyEx 8
#define API_RegSetValueEx 9
#define API_RegCloseKey 10
#define API_RegOpenKeyEx 11
#define API_RegDeleteValue 12
 

// 基础数据包
struct udp_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint8_t data[UDP_BUFFER_SIZE-4];
};

// api hook数据包 包含api参数信息
struct api_hooked_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint32_t process_pid;   // 进程PID信息
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

// hello数据包
struct hello_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint32_t process_pid;   // 进程PID信息
};