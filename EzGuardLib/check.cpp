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
    for (uint32_t sit = 4; cnt <(uint32_t)checkAPIarg->arg_num; sit += 8) {
        // 确保正确处理msg->data
        uint32_t data_index = (((uint32_t)msg->data[sit + 1]) << 8) + (uint32_t)msg->data[sit];
        uint32_t data_length = ((uint32_t)msg->data[sit + 2]) + ((uint32_t)(msg->data[sit + 3]) << 8);
        //if (cnt == 1) {
            //std::string s = std::to_string(data_length);
            //snprintf(back_warn.warn_level_data, s.size()+1, s.c_str());
        //}
        if (data_index + data_length <= UDP_BUFFER_SIZE) { // 确保没有缓冲区溢出
            //memcpy(checkAPIarg->arg_Value[cnt], &msg->data[data_index], data_length);
            memcpy(checkAPIarg->arg_Value[cnt], (&msg->data[data_index - 24]),data_length);
            checkAPIarg->arg_Value[cnt][data_length] ='\0'; // 字符串结束符
            cnt++;
        }
    }
}

// 检查堆操作API
void checkAPIheap(struct info* checkAPIarg, std::unordered_set<uint32_t>* HeapSave,std::unordered_set<uint32_t>* HeapBlockSave) {
    uint32_t handle_int;
    switch (checkAPIarg->api_id) {
    case API_HeapCreate: {
        handle_int = (checkAPIarg->arg_Value[3][0]) + (checkAPIarg->arg_Value[3][1] << 8) + (checkAPIarg->arg_Value[3][2] << 16) + (checkAPIarg->arg_Value[3][3] << 24);; // 修正API_HeapCreate的索引
        HeapSave->insert(handle_int); // 插入堆操作
        break;
    }
    case API_HeapDestroy:
    case API_HeapFree: {
        handle_int = (checkAPIarg->arg_Value[0][0]) + (checkAPIarg->arg_Value[0][1] << 8) + (checkAPIarg->arg_Value[0][2] << 16) + (checkAPIarg->arg_Value[0][3] << 24);;
        uint32_t handle_block_int= (checkAPIarg->arg_Value[2][0]) + (checkAPIarg->arg_Value[2][1] << 8) + (checkAPIarg->arg_Value[2][2] << 16) + (checkAPIarg->arg_Value[2][3] << 24);
        if (checkAPIarg->api_id == API_HeapDestroy || checkAPIarg->api_id == API_HeapFree) {
            auto it = HeapSave->find(handle_int);
            auto its = HeapBlockSave->find(handle_block_int);
            if (it != HeapSave->end() && checkAPIarg->api_id == API_HeapDestroy) {
                HeapSave->erase(it); //堆释放
            }
            else if (it != HeapSave->end() && its == HeapBlockSave->end()&&checkAPIarg->api_id==API_HeapFree) {
                HeapBlockSave->insert(handle_block_int);//用于检测是否存在double free
            }
            else if(it==HeapSave->end()||(its!= HeapBlockSave->end()&& checkAPIarg->api_id == API_HeapFree)){
                //两种情况存在异常：1.Destory/free 不存在的堆 2.free掉已经被free的堆
                back_warn.is_warn = true;
                strcat_s(back_warn.warn_level_data, "[High]Attempt to destroy or free invalid heap\n");
            }
        }
        break;
    }
    }
}

// 检查文件操作API
void checkAPIfile(struct info* checkAPIarg, std::set<std::string>* foldernameSave, std::string* source_filepath) {
    std::string lpfilename =(char*) checkAPIarg->arg_Value[0]; // 获取文件名
    // 简化文件路径提取
    std::string folderpath = lpfilename.substr(0, lpfilename.find_last_of("\\/")); // 提取文件夹路径
    std::string foldername = folderpath.substr(folderpath.find_last_of("\\/") + 1); // 提取最近文件夹
    std::string filepathfolderpath = ( * source_filepath).substr(0, ( * source_filepath).find_last_of("\\/")); // 提取文件夹路径
    std::string filepathfoldername = filepathfolderpath.substr(filepathfolderpath.find_last_of("\\/") + 1); // 提取最近文件夹
    if (folderpath == ".") {
        folderpath = filepathfolderpath;
        foldername = filepathfoldername;
        lpfilename= lpfilename.substr(lpfilename.find_last_of("\\/") + 1);
    }
    //snprintf(back_warn.warn_level_data, folderpath.size() + 1, folderpath.c_str());
    // 检测是否存在操作范围有多个文件夹
    foldernameSave->insert(foldername); // 插入文件夹名
    if (foldernameSave->size() >= 2) {
        back_warn.is_warn = true;
        strcat_s(back_warn.warn_level_data, "[Info]The program operated on multiple folders/n");
    }
    // 自我复制和可执行文件修改检查
    if (checkAPIarg->api_id == API_CreateFile) {
        uint32_t dwDesireadAccess = (checkAPIarg->arg_Value[1][0]) + (checkAPIarg->arg_Value[1][1] << 8) + (checkAPIarg->arg_Value[1][2] << 16) + (checkAPIarg->arg_Value[1][3] << 24); // 获取访问权限
        bool isSelfReplication = (dwDesireadAccess & GENERIC_READ) && ((*source_filepath).find(lpfilename) != std::string::npos); // 检查是否自我复制
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
        })&&(checkAPIarg->api_id!=API_ReadFile) ;
        if (isExecutableModification) {
            back_warn.is_warn = true;
            strcat_s(back_warn.warn_level_data, "[Medium]The program modified other executable code\n");
        }
}

// 检查注册表操作API
void checkAPIregistry(struct info* checkAPIarg, std::unordered_set<std::string>* registerSave) {
    std::string regPath = (char*)checkAPIarg->arg_Value[0]; // 获取注册表路径
    registerSave->insert(regPath);
    FILE* logFile;
    errno_t err = fopen_s(&logFile, "api_log.txt", "a"); // 使用fopen_s打开或创建日志文件进行追加
    if (err == 0) {
        fprintf(logFile, "%d", checkAPIarg->api_id);
        fprintf(logFile, "regPath: %s\n", regPath.c_str()); // 将结果输出到日志文件中
        fclose(logFile); // 关闭文件
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
        local =(char*) checkAPIarg->arg_Value[1]; // Local address and port
        if (checkAPIarg->api_id != API_connect) {
            buffer = (char*)checkAPIarg->arg_Value[2]; // Data buffer
            remote =(char*) checkAPIarg->arg_Value[3]; // Remote address and port
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
        sprintf_s(back_warn.warn_level_data, "Connection type: %s, Local: %s:%d, Remote: %s:%d\n",
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
    processState state; // 假设有一个state对象
    struct info checkAPIarg; // 假设有一个info对象
    memset(&back_warn, 0, sizeof(back_warn));
    checkAPI(&checkAPIarg, (udp_msg_t*)inBuffer, state); // 调用checkAPI函数处理输入缓冲区的数据
    snprintf(outbuffer, sizeof(back_warn.warn_level_data), back_warn.warn_level_data);
    if (back_warn.is_warn) {
        memcpy(outbuffer, back_warn.warn_level_data, strlen(back_warn.warn_level_data)); // 将警告信息复制到输出缓冲区
        outbuffer[strlen(back_warn.warn_level_data)] = '\0'; // 确保字符串结束，替换注释掉的行以确保不会超出outbuffer的界限
    }
}


