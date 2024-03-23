#include "pch.h"
#include<psapi.h>
#include<iostream>
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
#include <vector>
#define ll unsigned long long
#ifndef _MESSAGE_DEFINE_H
#include"MessageDefine.h"
#endif

#pragma comment(lib, "Ws2_32.lib") // 链接Winsock库，用于网络通信
// 定义各种API操作的宏，用于简化代码中的判断逻辑
// 日志函数，支持各种类型的参数写入，采用printf相同的方式选择写入类型

// 定义UDP消息结构体
struct udp_msg_t
{
    uint16_t msg_type; // 消息类型
    uint16_t data_length; // 数据长度
    uint32_t process_pid;   // 进程PID信息
    uint64_t time; // 时间戳
    uint16_t api_id;  // API标识符
    uint16_t arg_num; // 参数数量
    uint16_t name_off;
    uint16_t name_len;
    uint8_t data[UDP_BUFFER_SIZE - 24]; // 消息数据，减去前面字段的长度
};

// 定义API信息结构体
struct info {
    uint16_t type; // API类型
    uint16_t data_length; // 数据长度
    uint32_t process_pid; // 进程PID
    uint64_t time; // 时间戳
    uint16_t api_id; // API标识符
    uint16_t arg_num; // 参数数量
    uint16_t name_off;
    uint16_t name_len;
    uint8_t arg_Value[10][100] = { 0 }; // 参数值，最多10个参数，每个参数最大长度为100
};
#define WARN_DATA_SIZE 0x100
struct back_warns {
    bool is_warn;
    char warn_level_data[WARN_DATA_SIZE];
};
// 定义网络信息结构体
struct networkInfo {
    char protocol[10]; // 协议类型
    char ip[INET6_ADDRSTRLEN]; // IP地址
    uint32_t port; // 端口号
};

// 定义进程状态记录结构体
struct processState {
    std::unordered_set<uint32_t> HeapSave;
    std::unordered_set<uint32_t> HeapBlockSave;
    std::set<std::string> foldernameSave;
    std::string source_filepath;
    std::unordered_map<uint32_t, networkInfo> networkConnections;
    std::unordered_set<std::string> registerSave;
};
processState state; // 假设有一个state对象
back_warns back_warn;

#define DLL_EXPORT extern "C" __declspec(dllexport)
extern "C" {
    // 声明外部C接口，以便在C++中调用C函数
    void checkAPIheap(struct info* checkAPIarg, std::unordered_set<uint32_t>* HeapSave, std::unordered_set<uint32_t>* HeapMemerySave);
    void checkAPIcreatefile(struct info* checkAPIarg, std::set<std::string>* foldernameSave, std::string* source_filepath);
    void checkAPIregistry(struct info* checkAPIarg, std::unordered_set<std::string>* registerSave);
    void checkAPInetwork(struct info* checkAPIarg, std::unordered_map<uint32_t, networkInfo>* networkConnections);
    void checkAPI(struct info* checkAPIarg, struct udp_msg_t* msg, processState& state);
}
DLL_EXPORT void checker(char* inBuffer, uint16_t inbufferlen, char* outbuffer, uint16_t outbufferlen);
// 初始化info结构体，将udp_msg_t的数据转换为info结构体
void init_changeto(struct info* checkAPIarg, udp_msg_t* msg) {
    checkAPIarg->type = msg->msg_type;
    checkAPIarg->data_length = msg->data_length;
    checkAPIarg->process_pid = msg->process_pid; // 进程PID信息
    checkAPIarg->time = msg->time; // 时间戳
    checkAPIarg->api_id = msg->api_id; // API标识符
    checkAPIarg->arg_num = msg->arg_num; // 参数数量
    checkAPIarg->name_off = msg->name_off;
    checkAPIarg->name_len = msg->name_len;
    uint32_t cnt = 0;
    for (uint32_t sit = 4; cnt < (uint32_t)checkAPIarg->arg_num; sit += 8) {
        // 确保正确处理msg->data
        uint32_t data_index = (((uint32_t)msg->data[sit + 1]) << 8) + (uint32_t)msg->data[sit];
        uint32_t data_length = ((uint32_t)msg->data[sit + 2]) + ((uint32_t)(msg->data[sit + 3]) << 8);
        if (data_index + data_length <= UDP_BUFFER_SIZE) { // 确保没有缓冲区溢出
            memcpy(checkAPIarg->arg_Value[cnt], (&msg->data[data_index - 24]), data_length);
            checkAPIarg->arg_Value[cnt][data_length] = '\0'; // 字符串结束符
            cnt++;
        }
    }
}

// 检查堆操作API
void checkAPIheap(struct info* checkAPIarg, std::unordered_set<uint32_t>* HeapSave, std::unordered_set<uint32_t>* HeapBlockSave) {
    uint32_t handle_int = 0;
    uint32_t handle_block_int = 0;
    switch (checkAPIarg->api_id) {
    case API_HeapCreate: {
        handle_int = *(reinterpret_cast<uint32_t*>(checkAPIarg->arg_Value[3])); // 更安全的转换方式
        HeapSave->insert(handle_int); // 插入堆操作
        break;
    }
    case API_HeapDestroy:
    case API_HeapFree: {
        handle_int = *(reinterpret_cast<uint32_t*>(checkAPIarg->arg_Value[0]));
        handle_block_int = *(reinterpret_cast<uint32_t*>(checkAPIarg->arg_Value[2]));
        auto it = HeapSave->find(handle_int);
        auto its = HeapBlockSave->find(handle_block_int);
        if (it != HeapSave->end()) {
            if (checkAPIarg->api_id == API_HeapDestroy) {
                HeapSave->erase(it); // 堆释放
            }
            else if (checkAPIarg->api_id == API_HeapFree) {
                if (its == HeapBlockSave->end()) {
                    HeapBlockSave->insert(handle_block_int); // 用于检测是否存在double free
                }
                else {
                    // free掉已经被free的堆
                    back_warn.is_warn = true;
                    strcat_s(back_warn.warn_level_data, "[High]Attempt to double free heap\n");
                }
            }
        }
        else {
            // Destory/free 不存在的堆
            back_warn.is_warn = true;
            strcat_s(back_warn.warn_level_data, "[High]Attempt to destroy or free invalid heap\n");
        }
        break;
    }
    }
}
// 检查文件操作API
void checkAPIfile(struct info* checkAPIarg, std::set<std::string>* foldernameSave, std::string* source_filepath) {
    std::string lpfilename = std::string(reinterpret_cast<char*>(checkAPIarg->arg_Value[0])); // 安全地转换并获取文件名
    // 规范化并简化文件路径提取
    std::replace(lpfilename.begin(), lpfilename.end(), '\\', '/');
    std::replace(source_filepath->begin(), source_filepath->end(), '\\', '/'); // 将source_filepath路径分隔符也规范化为 '/'
    size_t lastSlashPos = lpfilename.find_last_of('/');
    std::string folderName; // 用于存储最近的文件夹名称
    if (lastSlashPos != std::string::npos) {
        size_t prevSlashPos = lpfilename.rfind('/', lastSlashPos - 1); // 查找倒数第二个斜杠的位置
        if (prevSlashPos != std::string::npos) {
            folderName = lpfilename.substr(prevSlashPos + 1, lastSlashPos - prevSlashPos - 1); // 提取最近的文件夹名称
        }
        else {
            folderName = lpfilename.substr(0, lastSlashPos); // 当文件路径中只有一个斜杠时，提取该斜杠前的所有内容作为文件夹名称
        }
    }
    if (folderName.empty()) { // 当没有提供文件路径时
        size_t sourceLastSlashPos = (*source_filepath).find_last_of('/');
        size_t sourcePrevSlashPos = (*source_filepath).rfind('/', sourceLastSlashPos - 1); // 查找source_filepath中倒数第二个斜杠的位置
        if (sourcePrevSlashPos != std::string::npos) {
            folderName = (*source_filepath).substr(sourcePrevSlashPos + 1, sourceLastSlashPos - sourcePrevSlashPos - 1); // 采用source_filepath中最近的文件夹名称
        }
        else {
            folderName = (*source_filepath).substr(0, sourceLastSlashPos); // 当source_filepath中只有一个斜杠时，提取该斜杠前的所有内容作为文件夹名称
        }
    }
    // 插入并检查唯一的文件夹名称以检测跨多个文件夹的操作
    auto insertResult = foldernameSave->insert(folderName); // 插入文件夹名称
    if (insertResult.second && foldernameSave->size() > 1) { // 如果插入了一个新的文件夹名称且存在多个唯一的文件夹
        back_warn.is_warn = true;
        strcat_s(back_warn.warn_level_data, "[Info]The program operated on multiple folders\n");
    }
    // 自我复制和可执行文件修改检查
    if (checkAPIarg->api_id == API_CreateFile) {
        std::string lpfilenameiner = lpfilename.substr(lpfilename.find_last_of('/') + 1);
        uint32_t dwDesiredAccess = *reinterpret_cast<uint32_t*>(checkAPIarg->arg_Value[1]); // 获取访问权限
        bool isSelfReplication = (dwDesiredAccess & GENERIC_READ) && (source_filepath->find(lpfilenameiner) != std::string::npos); // 检查是否自我复制
        if (isSelfReplication) {
            back_warn.is_warn = true;
            strcat_s(back_warn.warn_level_data, "[High]The program has replicated itself\n");
        }
    }
    std::string lpfilename_lower = lpfilename;
    std::transform(lpfilename_lower.begin(), lpfilename_lower.end(), lpfilename_lower.begin(), ::tolower);//大小写转化
    std::vector<std::string> executableExtensions = { ".exe", ".dll", ".ocx","com","msi","ini" };
    bool isExecutableModification = std::any_of(executableExtensions.begin(), executableExtensions.end(), [&](const std::string& ext) {
        return lpfilename_lower.find(ext) != std::string::npos;
        }) && (checkAPIarg->api_id != API_ReadFile);
        if (isExecutableModification) {
            back_warn.is_warn = true;
            strcat_s(back_warn.warn_level_data, "[Medium]The program modified other executable code\n");
        }
}

// 检查注册表操作API
void checkAPIregistry(struct info* checkAPIarg, std::unordered_set<std::string>* registerSave) {
    std::string regPath;
    if (checkAPIarg->api_id == API_RegCloseKey) {
        regPath = (char*)checkAPIarg->arg_Value[0]; // For API_RegCloseKey, the registry path is in arg_Value[0]
    }
    else {
        std::string potentialRegPath1 = (char*)checkAPIarg->arg_Value[0];
        std::string potentialRegPath2 = (char*)checkAPIarg->arg_Value[1];
        if (potentialRegPath1.find("Software") != std::string::npos || potentialRegPath1.find("HKEY") != std::string::npos) {
            regPath = potentialRegPath1;
        }
        else if (potentialRegPath2.find("Software") != std::string::npos || potentialRegPath2.find("HKEY") != std::string::npos) {
            regPath = potentialRegPath2;
        }
        else {
            regPath = potentialRegPath2; // Default to arg_Value[1] if no key indicators are found
        }
    }
    registerSave->insert(regPath);
    bool isnewcreateModification = checkAPIarg->api_id == API_RegCreateKeyEx;
    if (isnewcreateModification) {
        back_warn.is_warn = true;
        sprintf_s(back_warn.warn_level_data, "[Medium]The program adds a new registry key at %s\n", regPath.c_str());
    }
    bool isAutostartModification = (checkAPIarg->api_id == API_RegCreateKeyEx || checkAPIarg->api_id == API_RegSetValueEx) && (regPath.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos); // 检查是否修改了自启动项

    if (isAutostartModification) {
        back_warn.is_warn = true;
        strcat_s(back_warn.warn_level_data, "[High]The program added or modified an autostart registry entry\n");
    }
    bool isRegistryModification = (checkAPIarg->api_id == API_RegCreateKeyEx || checkAPIarg->api_id == API_RegSetValueEx || checkAPIarg->api_id == API_RegDeleteValue) && (regPath.find("Software") != std::string::npos); // 检查是否修改了注册表项

    if (isRegistryModification) {
        back_warn.is_warn = true;
        strcat_s(back_warn.warn_level_data, "[Medium]The program modified a registry entry\n");
    }
}

// Check network communication APIs
void checkAPInetwork(struct info* checkAPIarg, std::unordered_map<uint32_t, networkInfo>* networkConnections) {
    std::string local, remote, buffer;
    uint32_t type;
    switch (checkAPIarg->api_id) {
    case API_send:
    case API_recv:
    case API_sendto:
    case API_recvfrom:
    case API_connect: {
        // Parse the arguments of the API call
        type = (checkAPIarg->arg_Value[0][0]) + (checkAPIarg->arg_Value[0][1] << 8) + (checkAPIarg->arg_Value[0][2] << 16) + (checkAPIarg->arg_Value[0][3] << 24); ; // Get the type of network operation
        local = (char*)checkAPIarg->arg_Value[1]; // Local address and port
        if (checkAPIarg->api_id != API_connect) {
            buffer = (char*)checkAPIarg->arg_Value[2]; // Data buffer
            remote = (char*)checkAPIarg->arg_Value[3]; // Remote address and port
        }
        else {
            remote = (char*)checkAPIarg->arg_Value[2]; // Remote address and port for connect operation
        }
        std::string typestr = (type == SOCK_STREAM) ? "TCP" : (type == SOCK_DGRAM) ? "UDP" : "";

        // Function to extract IP and port information
        auto extractIPandPort = [](const std::string& str) -> std::pair<std::string, uint32_t> {
            size_t pos = str.find(','); // Find the delimiter
            if (pos != std::string::npos) {
                // If delimiter is found, extract IP and port
                return { str.substr(0, pos), std::stoi(str.substr(pos + 1)) };
            }
            // If no delimiter is found, return empty IP and invalid port
            return { "", -1 };
            };

        // Extract local and remote IP and port
        auto localIPandPort = extractIPandPort(local);
        auto remoteIPandPort = extractIPandPort(remote);

        // Save connection details to back_warn
        back_warn.is_warn = true;
        sprintf_s(back_warn.warn_level_data, "Connection type: %s\n, Local: %s:%d)\n, Remote: %s:%d)\n",
            typestr.c_str(), localIPandPort.first.c_str(), localIPandPort.second,
            remoteIPandPort.first.c_str(), remoteIPandPort.second);

        // Check if the buffer contains plaintext HTTP communication
        if (!buffer.empty() && buffer.find("HTTP") != std::string::npos) {
            // If plaintext HTTP communication is detected, append a warning message
            back_warn.is_warn = true;
            snprintf(back_warn.warn_level_data + strlen(back_warn.warn_level_data),
                WARN_DATA_SIZE,
                "[Warning] Potential plaintext HTTP communication detected.\n");
        }
        break;
    }
    }
}

// 根据API类型调用相应的检查函数
void checkAPI(struct info* checkAPIarg, struct udp_msg_t* msg, processState& state) {
    init_changeto(checkAPIarg, msg); // 初始化info结构体
    char filename[MAX_PATH];
    if (GetProcessImageFileNameA(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, checkAPIarg->process_pid), filename, MAX_PATH)) {
        state.source_filepath = std::string(filename);
    }
    switch (checkAPIarg->api_id) {
    case API_HeapCreate:
    case API_HeapDestroy:
    case API_HeapAlloc:
    case API_HeapFree:
        checkAPIheap(checkAPIarg, &state.HeapSave, &state.HeapBlockSave); // 检查堆操作API
        break;
    case API_CreateFile:
    case API_ReadFile:
    case API_WriteFile:
    case API_DeleteFile:
        checkAPIfile(checkAPIarg, &state.foldernameSave, &state.source_filepath); // 检查文件操作API
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
    case API_sendto:
    case API_recvfrom:
        checkAPInetwork(checkAPIarg, &state.networkConnections); // 检查网络通信API
        break;
    }
}


DLL_EXPORT void checker(char* inBuffer, uint16_t inbufferlen, char* outbuffer, uint16_t outbufferlen) {
    struct info checkAPIarg; // 假设有一个info对象
    memset(&back_warn, 0, sizeof(back_warn));
    checkAPI(&checkAPIarg, (udp_msg_t*)inBuffer, state); // 调用checkAPI函数处理输入缓冲区的数据
    snprintf(outbuffer, sizeof(back_warn.warn_level_data), back_warn.warn_level_data);
    if (back_warn.is_warn) {
        memcpy(outbuffer, back_warn.warn_level_data, strlen(back_warn.warn_level_data)); // 将警告信息复制到输出缓冲区
        outbuffer[strlen(back_warn.warn_level_data)] = '\0'; // 确保字符串结束，替换注释掉的行以确保不会超出outbuffer的界限
    }
}


