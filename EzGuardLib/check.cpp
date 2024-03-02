#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h> // 包含网络通信的头文件
#include <ws2tcpip.h> // 包含IP地址处理的头文件
#include <unordered_map> // 引入无序映射容器
#include <unordered_set> // 引入无序集合容器
#include <set> // 引入集合容器
#include <string> // 引入字符串处理库
#pragma comment(lib, "Ws2_32.lib") // 链接Winsock库，用于网络通信

// 定义各种API操作的宏，用于简化代码中的判断逻辑
#define MESSAGEBOXA 1
#define MESSAGEBOXW 2
//文件操作系统调用截获
#define CREATEFILE 3
//堆操作API截获
#define HEAPCREATE 4
#define HEAPDESTROY 5
#define HEAPALLOC 6
#define HEAPFREE 7
//注册表操作API截获
#define REGCREATEKEYEX 8
#define REGSETVALUEEX 9
#define REGCLOSEKEY 10
#define REGOPENKEYEX 11
#define REGDELETEVALUE 12
//网络通信API截获
#define THESOCKET 13
#define BIND 14
#define SEND 15
#define CONNECT 16
#define RECV 17

struct info{
    uint16_t type; // API类型
    uint16_t data_length;
    uint32_t process_pid;
    uint16_t api_id;
    uint16_t arg_num; // 参数数量
    char arg_Name[10][20]; // 参数名
    char arg_Value[10][20]; // 参数值
};
struct networkInfo {
    char protocol[10];
    char ip[20];
    int port;
};

extern "C" {
    void checkAPIheap(struct info* checkAPIarg, std::unordered_set<int>* HeapSave, std::unordered_set<int>* HeapMemerySave);
    void checkAPIfile(struct info* checkAPIarg, std::set<std::string>* foldernameSave, std::string* source_filepath);
    void checkAPIregistry(struct info* checkAPIarg);
    void checkAPInetwork(struct info* checkAPIarg, std::unordered_map<int, networkInfo>* networkConnections);
    void checkAPI(struct info* checkAPIarg, std::unordered_set<int>* HeapSave, std::unordered_set<int>* HeapMemerySave, std::set<std::string>* foldernameSave, std::string* source_filepath, std::unordered_map<int, networkInfo>* networkConnections);
}

void checkAPIheap(struct info* checkAPIarg, std::unordered_set<int>* HeapSave, std::unordered_set<int>* HeapMemerySave) {
    unsigned handle_int;
    switch (checkAPIarg->type) {
        case HEAPCREATE: {
            handle_int = atoi(checkAPIarg->arg_Value[3]);
            HeapSave->insert(handle_int); // 插入堆操作
            break;
        }
        case HEAPDESTROY: {
            handle_int = atoi(checkAPIarg->arg_Value[0]);
            if (HeapSave->find(handle_int) != HeapSave->end()) {
                HeapSave->erase(handle_int); // 如果找到则删除
            } else {
                printf("Heap maliciously destroyed\n"); // Error if not found
            }
            break;
        }
        case HEAPALLOC: {
            handle_int = atoi(checkAPIarg->arg_Value[0]);
            HeapMemerySave->insert(handle_int); // 插入堆内存操作
            break;
        }
        case HEAPFREE: {
            handle_int = atoi(checkAPIarg->arg_Value[0]);
            if (HeapMemerySave->find(handle_int) != HeapMemerySave->end()) {
                HeapMemerySave->erase(handle_int); // 如果找到则删除
            } else {
                printf("Multiple abnormal releases of the same dynamically allocated memory block\n"); // Error if not found
            }
            break;
        }
    }
}

void checkAPIfile(struct info* checkAPIarg, std::set<std::string>* foldernameSave, std::string* source_filepath) {
    std::string foldername;
    std::string folderpath;
    std::string lpfilename = checkAPIarg->arg_Value[0];
    int dwDesireadAccess = atoi(checkAPIarg->arg_Value[1]);

    // 获取文件所在文件夹路径
    size_t pos = lpfilename.find_last_of("\\/");
    if (pos != std::string::npos) {
        folderpath = lpfilename.substr(0, pos);
        foldername = lpfilename.substr(pos + 1);
    }

    // 检测是否存在操作范围有多个文件夹
    foldernameSave->insert(foldername);
    if (foldernameSave->size() >= 2) {
        printf("The program operated on multiple folders\n");
    }

    // 检测是否存在自我复制的情况
    if ((dwDesireadAccess & GENERIC_READ) && lpfilename == *source_filepath) {
        printf("The program has replicated itself\n");
    }

    // 检测是否存在对其它可执行代码的操作
    if (lpfilename.find(".exe") != std::string::npos || lpfilename.find(".dll") != std::string::npos || lpfilename.find(".ocx") != std::string::npos) {
        if (dwDesireadAccess & GENERIC_WRITE) {
            printf("The program modified other executable code\n");
        }
    }
}

void checkAPIregistry(struct info* checkAPIarg) {
    std::string regPath = checkAPIarg->arg_Value[0];

    // 判断是否新增注册表项并判断是否为自启动执行文件项
    if (checkAPIarg->type == REGCREATEKEYEX || checkAPIarg->type == REGSETVALUEEX) {
        if (regPath.find("Software\\Microsoft\\Windows\\CurrentVersion\\Run") != std::string::npos) {
            printf("The program added or modified an autostart registry entry\n");
        }
    }

    // 输出所有的注册表操作项
    printf("Registry operation: %s\n", regPath.c_str());
}

void checkAPInetwork(struct info* checkAPIarg, std::unordered_map<int, networkInfo>* networkConnections) {
    switch (checkAPIarg->type) {
        case CONNECT: {
            // 假设arg_Value[1]是IP地址，arg_Value[2]是端口
// 假设arg_Value[1]是IP地址，arg_Value[2]是端口
        networkInfo info;
        strcpy(info.protocol, "TCP");
        strcpy(info.ip, checkAPIarg->arg_Value[1]);
        info.port = atoi(checkAPIarg->arg_Value[2]);
        networkConnections->insert({ atoi(checkAPIarg->arg_Value[0]), info });
        printf("TCP connection to %s:%d\n", info.ip, info.port);
            break;
        }
        case SEND: {
            // 假设arg_Value[0]是句柄，arg_Value[1]是发送的数据
            if (networkConnections->find(atoi(checkAPIarg->arg_Value[0])) != networkConnections->end()) {
                printf("Sending data through socket: %s\n", checkAPIarg->arg_Value[1]);
                // 这里可以添加对数据内容的进一步分析，例如是否为明文
            }
            break;
        }
        case RECV: {
            // 假设arg_Value[0]是句柄
            if (networkConnections->find(atoi(checkAPIarg->arg_Value[0])) != networkConnections->end()) {
                printf("Receiving data through socket\n");
                // 这里可以添加对接收数据的进一步分析
            }
            break;
        }
    }
}

void checkAPI(struct info* checkAPIarg, std::unordered_set<int>* HeapSave, std::unordered_set<int>* HeapMemerySave, std::set<std::string>* foldernameSave, std::string* source_filepath, std::unordered_map<int, networkInfo>* networkConnections) {
    switch (checkAPIarg->type) {
        case HEAPCREATE:
        case HEAPDESTROY:
        case HEAPALLOC:
        case HEAPFREE:
            checkAPIheap(checkAPIarg, HeapSave, HeapMemerySave);
            break;
        case CREATEFILE:
            checkAPIfile(checkAPIarg, foldernameSave, source_filepath);
            break;
        case REGCREATEKEYEX:
        case REGSETVALUEEX:
        case REGCLOSEKEY:
        case REGOPENKEYEX:
        case REGDELETEVALUE:
            checkAPIregistry(checkAPIarg);
            break;
        case CONNECT:
        case SEND:
        case RECV:
            checkAPInetwork(checkAPIarg, networkConnections);
            break;
    }
}
