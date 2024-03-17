#include "pch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <algorithm>
#include <winsock2.h> // 包含网络通信的头文件
#include <ws2tcpip.h> // 包含IP地址处理的头文件
#include <unordered_map> // 引入无序映射容器
#include <unordered_set> // 引入无序集合容器
#include <set> // 引入集合容器
#include <string> // 引入字符串处理库

#ifndef _MESSAGE_DEFINE_H
#include"MessageDefine.h"
#endif

#pragma comment(lib, "Ws2_32.lib") // 链接Winsock库，用于网络通信
// 定义各种API操作的宏，用于简化代码中的判断逻辑

// 定义UDP消息结构体
struct udp_msg_t
{
    uint16_t msg_type; // 消息类型
    uint16_t data_length; // 数据长度
    uint32_t process_pid;   // 进程PID信息
    uint64_t time; // 时间戳
    uint16_t api_id;  // API标识符
    uint16_t arg_num; // 参数数量
    uint16_t data[(UDP_BUFFER_SIZE>>1)-8]; // 消息数据，减去前面字段的长度
};

// 定义API信息结构体
struct info{
    uint16_t type; // API类型
    uint16_t data_length; // 数据长度
    uint32_t process_pid; // 进程PID
    uint64_t time; // 时间戳
    uint16_t api_id; // API标识符
    uint16_t arg_num; // 参数数量
    char arg_Value[10][100]; // 参数值，最多10个参数，每个参数最大长度为100
};
#define WARN_DATA_SIZE 0x100
struct back_warns{
    bool is_warn;
    char warn_level_data[WARN_DATA_SIZE];
};
// 定义网络信息结构体
struct networkInfo {
    char protocol[10]; // 协议类型
    char ip[INET6_ADDRSTRLEN]; // IP地址
    int port; // 端口号
};

// 定义进程状态记录结构体
struct processState {
    std::unordered_set<int> HeapSave;
    std::set<std::string> foldernameSave;
    std::string source_filepath;
    std::unordered_map<int, networkInfo> networkConnections;
    std::unordered_set<std::string> registerSave;
};

back_warns back_warn;

#define DLL_EXPORT extern "C" __declspec(dllexport)
extern "C" {
    // 声明外部C接口，以便在C++中调用C函数
    void checkAPIheap(struct info* checkAPIarg, std::unordered_set<int>* HeapSave, std::unordered_set<int>* HeapMemerySave);
    void checkAPIcreatefile(struct info* checkAPIarg, std::set<std::string>* foldernameSave, std::string* source_filepath);
    void checkAPIregistry(struct info* checkAPIarg, std::unordered_set<std::string>* registerSave);
    void checkAPInetwork(struct info* checkAPIarg, std::unordered_map<int, networkInfo>* networkConnections);
    void checkAPI(struct info* checkAPIarg, struct udp_msg_t* msg, processState& state);
}
DLL_EXPORT void checker(char *inBuffer,char *outbuffer,uint16_t inbufferlen,uint16_t outbufferlen);
// 初始化info结构体，将udp_msg_t的数据转换为info结构体
void init_changeto(struct info *checkAPIarg,udp_msg_t*msg){
    checkAPIarg->type = msg->msg_type;
    checkAPIarg->data_length = msg->data_length;
    checkAPIarg->process_pid = msg->process_pid; // 进程PID信息
    checkAPIarg->time = msg->time; // 时间戳
    checkAPIarg->api_id = msg->api_id; // API标识符
    checkAPIarg->arg_num = msg->arg_num; // 参数数量
    int cnt=0;
    for(int sit=4;sit<msg->arg_num*4+2;sit+=4){
        // 确保正确处理msg->data
        int data_index = msg->data[sit];
        int data_length = msg->data[sit+1];
        if(data_index + data_length <= UDP_BUFFER_SIZE-12) { // 确保没有缓冲区溢出
            memcpy(checkAPIarg->arg_Value[cnt], &msg->data[data_index], data_length);
            checkAPIarg->arg_Value[cnt][data_length] = '\0'; // 字符串结束符
            cnt++;
        }
    }
}

// 检查堆操作API
void checkAPIheap(struct info* checkAPIarg, std::unordered_set<int>* HeapSave) {
    unsigned handle_int;
    switch (checkAPIarg->type) {
        case API_HeapCreate: {
            handle_int = atoi(checkAPIarg->arg_Value[3]); // 修正API_HeapCreate的索引
            HeapSave->insert(handle_int); // 插入堆操作
            break;
        }
        case API_HeapDestroy:
        case API_HeapFree: {
            handle_int = atoi(checkAPIarg->arg_Value[0]);
            if (checkAPIarg->type == API_HeapDestroy || checkAPIarg->type == API_HeapFree) {
                auto it = HeapSave->find(handle_int);
                if (it != HeapSave->end()||checkAPIarg->type == API_HeapDestroy) {
                    HeapSave->erase(it); // 统一处理API_HeapDestroy和API_HeapFree
                } else {
                    back_warn.is_warn=true;
                    sprintf_s(back_warn.warn_level_data,"[High]Attempt to destroy or free invalid heap\n");
                    //SocketAPI_send((const char*)&back_warn,(size_t)(sizeof(back_warn)));
                    //printf("Attempt to destroy or free invalid heap\n"); // 统一错误消息
                }
            }
            break;
        }
    }
}

// 检查文件操作API
void checkAPIcreatefile(struct info* checkAPIarg, std::set<std::string>* foldernameSave, std::string* source_filepath) {
    std::string lpfilename = checkAPIarg->arg_Value[0]; // 获取文件名
    int dwDesireadAccess = atoi(checkAPIarg->arg_Value[1]); // 获取访问权限

    // 简化文件路径提取
    std::string folderpath = lpfilename.substr(0, lpfilename.find_last_of("\\/")); // 提取文件夹路径
    std::string foldername = lpfilename.substr(lpfilename.find_last_of("\\/") + 1); // 提取最近文件夹

    // 检测是否存在操作范围有多个文件夹
    foldernameSave->insert(foldername); // 插入文件夹名
    if (foldernameSave->size() >= 2) {
        back_warn.is_warn=false;
        sprintf_s(back_warn.warn_level_data,"[Info]The program operated on multiple folders\n");
        //SocketAPI_send((const char*)&back_warn,(size_t)(sizeof(back_warn)));
        //printf("The program operated on multiple folders\n"); // 如果操作了多个文件夹，打印警告
    }

    // 简化自我复制和可执行文件修改检查
    bool isSelfReplication = (dwDesireadAccess & GENERIC_READ) && (lpfilename == *source_filepath); // 检查是否自我复制
    std::string lpfilename_lower = lpfilename;
    std::transform(lpfilename_lower.begin(), lpfilename_lower.end(), lpfilename_lower.begin(), ::tolower);//大小写转化
    bool isExecutableModification = (lpfilename_lower.find(".exe") != std::string::npos || lpfilename_lower.find(".dll") != std::string::npos || lpfilename_lower.find(".ocx") != std::string::npos) && (dwDesireadAccess & GENERIC_WRITE);
    if (isSelfReplication) {
        back_warn.is_warn=true;
        sprintf_s(back_warn.warn_level_data,"[High]The program has replicated itself\n");
        //SocketAPI_send((const char*)&back_warn,(size_t)(sizeof(back_warn)));
    }
    if (isExecutableModification) {
        back_warn.is_warn=true;
        sprintf_s(back_warn.warn_level_data,"[Medium]The program modified other executable code\n");
        //SocketAPI_send((const char*)&back_warn,(size_t)(sizeof(back_warn)));
    }
}

// 检查注册表操作API
void checkAPIregistry(struct info* checkAPIarg, std::unordered_set<std::string>* registerSave) {
    std::string regPath = checkAPIarg->arg_Value[1]; // 获取注册表路径
    registerSave->insert(regPath);
    bool isAutostartModification = (checkAPIarg->type == API_RegCreateKeyEx || checkAPIarg->type == API_RegSetValueEx) && (regPath.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos); // 检查是否修改了自启动项

    if (isAutostartModification) {
        back_warn.is_warn=true;
        sprintf_s(back_warn.warn_level_data,"[High]The program added or modified an autostart registry entry\n");
        //SocketAPI_send((const char*)&back_warn,(size_t)(sizeof(back_warn)));
    }
    bool isRegistryModification = (checkAPIarg->type == API_RegCreateKeyEx || checkAPIarg->type == API_RegSetValueEx || checkAPIarg->type == API_RegDeleteValue) && (regPath.find("Software\\") != std::string::npos); // 检查是否修改了注册表项

    if (isRegistryModification) {
        back_warn.is_warn=true;
        sprintf_s(back_warn.warn_level_data,"[Medium]The program modified a registry entry\n");
        //SocketAPI_send((const char*)&back_warn,(size_t)(sizeof(back_warn)));
    }
}

// 检查网络通信API
void checkAPInetwork(struct info* checkAPIarg, std::unordered_map<int, networkInfo>* networkConnections) {
    std::string local, remote, buffer;
    int type;
    switch (checkAPIarg->type) {
        case API_send:
        case API_recv:
        case API_sendto:
        case API_recvfrom: {
            // 解析API调用的参数
            type = atoi(checkAPIarg->arg_Value[0]); // 获取网络操作类型
            local = checkAPIarg->arg_Value[1]; // 本地地址和端口
            if (checkAPIarg->type != API_connect) {
                buffer = checkAPIarg->arg_Value[2]; // 数据缓冲区
                remote = checkAPIarg->arg_Value[3]; // 远程地址和端口
            } else {
                remote = checkAPIarg->arg_Value[2]; // 连接操作的远程地址和端口
            }
            std::string typestr = (type == SOCK_STREAM) ? "TCP" : (type == SOCK_DGRAM) ? "UDP" : "";

            // 函数提取IP和端口信息
            auto extractIPandPort = [](const std::string& str) -> std::pair<std::string, int> {
                size_t pos = str.find(','); // 查找分隔符
                if (pos != std::string::npos) {
                    // 如果找到分隔符，提取IP和端口
                    return {str.substr(0, pos), std::stoi(str.substr(pos + 1))};
                }
                // 如果没有找到分隔符，返回空IP和无效端口
                return {"", -1}; 
            };

            // 提取本地和远程IP及端口
            auto localIPandPort = extractIPandPort(local);
            auto remoteIPandPort = extractIPandPort(remote);

            // 将连接详情保存到back_warn中
            sprintf_s(back_warn.warn_level_data, "连接类型: %s, 本地: %s:%d, 远程: %s:%d\n", 
                    typestr.c_str(), localIPandPort.first.c_str(), localIPandPort.second, 
                    remoteIPandPort.first.c_str(), remoteIPandPort.second);

            // 检查缓冲区是否包含明文HTTP通信
            if (!buffer.empty() && buffer.find("HTTP") != std::string::npos) {
                // 如果检测到明文HTTP通信，追加警告消息
                snprintf(back_warn.warn_level_data +strlen(back_warn.warn_level_data),
                        WARN_DATA_SIZE,
                        "[Warning] Potential plaintext HTTP communication detected.\n");
            }
            break;
        }
    }
}

// 根据API类型调用相应的检查函数
void checkAPI(struct info* checkAPIarg, struct udp_msg_t *msg, processState& state) {
    init_changeto(checkAPIarg,msg); // 初始化info结构体
    switch (checkAPIarg->type) {
        case API_HeapCreate:
        case API_HeapDestroy:
        case API_HeapAlloc:
        case API_HeapFree:
            checkAPIheap(checkAPIarg, &state.HeapSave); // 检查堆操作API
            break;
        case API_CreateFile:
            checkAPIcreatefile(checkAPIarg, &state.foldernameSave, &state.source_filepath); // 检查文件操作API
            break;
        case API_ReadFile:
            //checkAPIreadfile(checkAPIarg, &state.foldernameSave, &state.source_filepath);
            break;
        case API_RegCreateKeyEx:
        case API_RegSetValueEx:
        case API_RegCloseKey:
        case API_RegOpenKeyEx:
        case API_RegDeleteValue:
            checkAPIregistry(checkAPIarg, &state.registerSave); // 检查注册表操作API
            break;
        case API_connect:
        case API_send:
        case API_recv:
            checkAPInetwork(checkAPIarg, &state.networkConnections); // 检查网络通信API
            break;
    }
}


DLL_EXPORT void checker(char *inBuffer,char *outbuffer,uint16_t inbufferlen,uint16_t outbufferlen){
    // udp_msg_t udpMsgBuffer; // 修改为udpMsgBuffer，避免与类型名称冲突
    // 假设SocketAPI_recv是一个已定义的函数，用于接收数据
    processState state; // 假设有一个state对象
    struct info checkAPIarg; // 假设有一个info对象
    checkAPI(&checkAPIarg, (udp_msg_t*)inBuffer, state); // 调用checkAPI函数处理输入缓冲区的数据
    if(back_warn.is_warn) {
        memcpy(outbuffer, back_warn.warn_level_data, strlen(back_warn.warn_level_data)); // 将警告信息复制到输出缓冲区
        // outbuffer[outbufferlen - 1] = '\0'; // 确保字符串结束
    }
}

