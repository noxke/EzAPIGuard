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
#define MSG_REPLY 11    // hooked回复包
#define MSG_ATTACH 20   // 配置hook指定api
#define MSG_DETACH 21   // 配置取消hook指定api
#define MSG_CONFIG 22   // api配置包来判断是否放行或者拦截api
#define MSG_ENABLE 250    // 启用hook
#define MSG_DISABLE 251   // 禁用hook
#define MSG_UNLOAD 252    // 卸载dll
#define MSG_KILL 255      // 关闭进程


// 基础数据包
struct udp_msg
{
    uint16_t msg_type;
    uint16_t data_length;
    uint8_t data[UDP_BUFFER_SIZE - 4];
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

//config数据包
struct api_config_msg
{
    uint16_t msg_type;
    uint16_t api_id;
    uint32_t process_pid;//进程PID信息
    bool access;//是否放行
};