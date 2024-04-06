#include<iostream>
#include<string>
#include <Windows.h>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include<vector>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

#define SERVER_IP "127.0.0.1"
int TCP_PORT;
int UDP_PORT;
#define BUFFER_SIZE 1024
using namespace std;
enum input {
    example_normal_Heapoperate = '1',// 正常堆操作
    example_doublefree_Heapoperate,// 双重释放堆操作
    example_normal_fileoperate,// 正常文件操作
    example_operatemanyfile_fileoperate,// 操作多个文件
    example_selfcopy_fileoperate,// 自我复制操作
    example_changeexefile_fileoperate,// 修改可执行文件操作
    example_normal_registry,// 正常注册表操作
    example_createnewselfrun_registry, // 创建自启动注册表项
    example_changeregistry_registry,// 修改注册表项
    example_normalTCP_connect = 'a',// 正常TCP连接
    example_normalUDP_connect,// 正常UDP连接
    example_sendHTTP_connecet,// 发送HTTP请求
    example_exit = 'e'
};

void init() {// 初始化提示信息
    std::cout << "This is an executable program that autonomously chooses the malicious actions it wants" << std::endl;
    std::cout << "Please select what you want the program to do:" << std::endl;
    std::cout << "------------------------------------------------------------------------------------------------" << std::endl;
    std::cout << "Input 1 :the program will perform normal heap operations" << std::endl;
    std::cout << "Input 2 :the program will perform an exception operation to release the heap multiple times" << std::endl;

    std::cout << "Input 3 :the program will perform normal file operations" << std::endl;
    std::cout << "Input 4 :the program will operate on multiple folders" << std::endl;
    std::cout << "Input 5 :The program will attempt to replicate itself" << std::endl;
    std::cout << "Input 6 :The program will attempt to make modifications to some executable programs" << std::endl;

    std::cout << "Input 7 :The program will perform some normal registry operations" << std::endl;
    std::cout << "Input 8 :The program will add a self-starting registry key" << std::endl;
    std::cout << "Input 9 :The program will attempt to make modifications to some registry keys" << std::endl;

    std::cout << "Input a :The program will send a TCP packet" << std::endl;
    std::cout << "Input b :The program will send a UDP packet" << std::endl;
    std::cout << "Input c :The program will send HTTP plaintext packets to transmit the content" << std::endl;
    // std::cout << "Input d :The program will send an HTTPS ciphertext packet to transmit the content" << std::endl;
    std::cout << "Input e :The program will exit" << std::endl;
    std::cout << "------------------------------------------------------------------------------------------------" << std::endl;
}
// Normal heap operation function
void normal_Heapoperate() {
    // Create a heap
    HANDLE heap = HeapCreate(0, 0, 0);
    if (heap == NULL) {
        std::cout << "Failed to create heap" << std::endl;
        return;
    }
    // Allocate memory in the heap
    int* arr = (int*)HeapAlloc(heap, 0, sizeof(int) * 5);
    if (arr == NULL) {
        std::cout << "Failed to allocate heap memory" << std::endl;
        HeapDestroy(heap);
        return;
    }
    // Free allocated heap memory
    if (!HeapFree(heap, 0, arr)) {
        std::cout << "Failed to free heap memory" << std::endl;
        HeapDestroy(heap);
        return;
    }
    // Destroy the heap
    if (!HeapDestroy(heap)) {
        std::cout << "Failed to destroy heap" << std::endl;
        return;
    }
}
// Function declarations
void doublefree_Heapoperate() {
    // Allocate heap memory
    LPVOID heapMemory = HeapAlloc(GetProcessHeap(), 0, 100);
    if (heapMemory == nullptr) {
        std::cout << "Heap memory allocation failed!" << std::endl;
        return;
    }
    std::cout << "Heap memory allocated successfully, address: " << heapMemory << std::endl;

    // First heap memory release
    if (!HeapFree(GetProcessHeap(), 0, heapMemory)) {
        std::cout << "Heap memory release failed!" << std::endl;
        return;
    }
    std::cout << "Heap memory released successfully!" << std::endl;
    // Second release of the same heap memory
    if (!HeapFree(GetProcessHeap(), 0, heapMemory)) {
        std::cout << "Second heap memory release failed!" << std::endl;
        return;
    }
    std::cout << "Heap memory released successfully for the second time!" << std::endl;
}
void CreateFileExample(const std::string& filename) {
    HANDLE hFile = CreateFileA(filename.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cout << "File creation failed!" << std::endl;
        return;
    }

    std::cout << "File created successfully!" << std::endl;

    CloseHandle(hFile);
}
void DeleteFileExample(const std::wstring& filename) {
    if (DeleteFileW(filename.c_str()) == 0) {
        std::wcout << L"File deletion failed!" << std::endl;
        return;
    }

    std::wcout << L"File deleted successfully!" << std::endl;
}
void ReadFileExample(const std::wstring& filename) {
    HANDLE hFile = CreateFileW(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"File opening failed!" << std::endl;
        return;
    }

    DWORD dwRead;
    CHAR buffer[1024];
    while (ReadFile(hFile, buffer, sizeof(buffer), &dwRead, NULL) && dwRead > 0) {
        std::cout.write(buffer, dwRead);
        std::cout << std::endl;
    }

    CloseHandle(hFile);
}
void WriteFileExample(const std::wstring& filename) {
    HANDLE hFile = CreateFileW(filename.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << L"File opening failed!" << std::endl;
        return;
    }
    std::wstring data;
    std::wcout << L"Please enter the content to be written into the file:" << std::endl;
    std::getline(std::wcin, data);

    DWORD dwWritten;
    WriteFile(hFile, data.c_str(), data.length() * sizeof(wchar_t), &dwWritten, NULL);

    CloseHandle(hFile);
    std::wcout << L"File written successfully!" << std::endl;
}
// Basic file operations demonstration
void normal_fileoperate() {
    std::wstring filename = L"example.txt";
    CreateFileExample(std::string(filename.begin(), filename.end()));
    ReadFileExample(filename);
    WriteFileExample(filename);
    DeleteFileExample(filename);
}

// Operate on multiple files within directories
void operatemanyfile_fileoperate() {
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(L"*.*", &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcout << L"No files or folders found." << std::endl;
        return;
    }
    else {
        do {
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                std::wstring folderName = findFileData.cFileName;
                // Ignore the '.' and '..' directories
                if (folderName != L"." && folderName != L"..") {
                    std::wcout << L"Accessing folder: " << folderName << std::endl;
                    // Creating a file in the discovered directory
                    std::wstring filePath = folderName + L"\\example.txt";
                    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile == INVALID_HANDLE_VALUE) {
                        std::wcout << L"Failed to create file in folder: " << folderName << std::endl;
                    }
                    else {
                        std::wcout << L"File created successfully in folder: " << folderName << std::endl;
                        CloseHandle(hFile);
                        // Deleting the file that was just created
                        // Example of deleting the created file
                        if (DeleteFileW(filePath.c_str()) != 0) {
                            std::wcout << L"File deleted successfully in folder: " << folderName << std::endl;
                        }
                        else {
                            std::wcout << L"Failed to delete file in folder: " << folderName << std::endl;
                        }
                    }
                }
            }
        } while (FindNextFileW(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
}
void selfcopy_fileoperate() {
    WCHAR szFilePath[MAX_PATH];
    WCHAR szNewFilePath[MAX_PATH];
    GetModuleFileNameW(NULL, szFilePath, MAX_PATH);

    // Open the current executable file
    HANDLE hFile = CreateFileW(szFilePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"Unable to open file" << std::endl;
        return;
    }

    // Get file size
    DWORD dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE)
    {
        std::wcout << L"Unable to get file size" << std::endl;
        CloseHandle(hFile);
        return;
    }

    // Read file content
    BYTE* pBuffer = new BYTE[dwFileSize];
    DWORD dwBytesRead;
    if (!ReadFile(hFile, pBuffer, dwFileSize, &dwBytesRead, NULL))
    {
        std::wcout << L"Unable to read file content" << std::endl;
        CloseHandle(hFile);
        delete[] pBuffer;
        return;
    }

    // Close file handle
    CloseHandle(hFile);

    // Create a copy of the file
    GetModuleFileNameW(NULL, szNewFilePath, MAX_PATH);
    lstrcatW(szNewFilePath, L".copy");

    HANDLE hNewFile = CreateFileW(szNewFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hNewFile == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"Unable to create copy file" << std::endl;
        delete[] pBuffer;
        return;
    }

    // Write file content to the copy
    DWORD dwBytesWritten;
    if (!WriteFile(hNewFile, pBuffer, dwBytesRead, &dwBytesWritten, NULL))
    {
        std::wcout << L"Unable to write to copy file" << std::endl;
        CloseHandle(hNewFile);
        delete[] pBuffer;
        return;
    }

    // Close copy file handle
    CloseHandle(hNewFile);

    std::wcout << L"Successfully created copy file: " << szNewFilePath << std::endl;

    delete[] pBuffer;

    return;
}
void changeexefile_fileoperate() {
    // Create file
    HANDLE hFile = CreateFile(TEXT("./example.exe"), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "Unable to create file" << std::endl;
        return;
    }

    // Write content to file
    const char* pData = "This is a sample file";
    DWORD dwBytesWritten;
    if (!WriteFile(hFile, pData, strlen(pData), &dwBytesWritten, NULL))
    {
        std::cout << "Unable to write file content" << std::endl;
        CloseHandle(hFile);
        return;
    }

    // Close file handle
    CloseHandle(hFile);

    std::cout << "Successfully created and written to file" << std::endl;

    // Delete file
    if (!DeleteFile(TEXT("./example.exe")))
    {
        std::cout << "Unable to delete file" << std::endl;
        return;
    }

    std::cout << "Successfully deleted file" << std::endl;

    return;
}


void normal_registry() {
    HKEY hKey;
    DWORD dwDisposition;
    // Create registry key
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Example", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS)
    {
        std::wcout << L"Unable to create registry key" << std::endl;
        return;
    }
    std::wcout << L"Successfully created registry key" << std::endl;
    // Set registry key value
    DWORD dwValue = 123;
    if (RegSetValueExW(hKey, L"Value", 0, REG_DWORD, reinterpret_cast<BYTE*>(&dwValue), sizeof(DWORD)) != ERROR_SUCCESS)
    {
        std::wcout << L"Unable to set registry key value" << std::endl;
        RegCloseKey(hKey);
        return;
    }
    std::wcout << L"Successfully set registry key value" << std::endl;
    // Delete registry key
    if (RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Example") != ERROR_SUCCESS)
    {
        std::wcout << L"Unable to delete registry key" << std::endl;
        return;
    }
    std::wcout << L"Successfully deleted registry key" << std::endl;
    // Open registry key
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Example", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
    {
        std::wcout << L"Unable to open registry key" << std::endl;
        return;
    }
    std::wcout << L"Successfully opened registry key" << std::endl;
    // Close registry key
    RegCloseKey(hKey);
    std::wcout << L"Successfully closed registry key" << std::endl;
    return;
}
void createnewselfrun_registry() {
    HKEY hKey;
    DWORD dwDisposition;
    // Create or open the auto-start entry
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS)
    {
        std::wcout << L"Failed to create or open the auto-start entry" << std::endl;
        return;
    }
    // Set the value of the auto-start entry
    const wchar_t* szValueName = L"MyApp";
    const wchar_t* szValueData = L"C:\\Path\\To\\MyApp.exe";
    if (RegSetValueExW(hKey, L"MyApp", 0, REG_SZ, reinterpret_cast<const BYTE*>(szValueData), (wcslen(szValueData) + 1) * sizeof(wchar_t)) != ERROR_SUCCESS)
    {
        std::wcout << L"Failed to set the auto-start entry value" << std::endl;
        RegCloseKey(hKey);
        return;
    }
    std::wcout << L"Successfully set the auto-start entry" << std::endl;

    // Delete the auto-start entry
    if (RegDeleteValueW(hKey, L"MyApp") != ERROR_SUCCESS)
    {
        std::wcout << L"Failed to delete the auto-start entry" << std::endl;
        RegCloseKey(hKey);
        return;
    }
    std::wcout << L"Successfully deleted the auto-start entry" << std::endl;
    // Close the registry key handle
    RegCloseKey(hKey);
    return;
}
void changeregistry_registry() {
    HKEY hKey;
    DWORD dwDisposition;
    // Create or open the registry key
    if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Example", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS)
    {
        std::wcout << L"Failed to create or open the registry key" << std::endl;
        return;
    }
    // Set the value of the registry key
    const wchar_t* szValueName = L"Value";
    const wchar_t* szValueData = L"Hello, Registry!";
    if (RegSetValueExW(hKey, L"Value", 0, REG_SZ, reinterpret_cast<const BYTE*>(szValueData), (wcslen(szValueData) + 1) * sizeof(wchar_t)) != ERROR_SUCCESS)
    {
        std::wcout << L"Failed to set the registry key value" << std::endl;
        RegCloseKey(hKey);
        return;
    }
    std::wcout << L"Successfully set the registry key value" << std::endl;
    // Delete the registry key
    if (RegDeleteKeyW(HKEY_CURRENT_USER, L"Software\\Example") != ERROR_SUCCESS)
    {
        std::wcout << L"Failed to delete the registry key" << std::endl;
        return;
    }
    std::wcout << L"Successfully deleted the registry key" << std::endl;
    // Close the registry key handle
    RegCloseKey(hKey);
    return;
}

void startServer() {
    WSADATA wsaData;
    SOCKET serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int addrLen = sizeof(clientAddr);
    char buffer[BUFFER_SIZE];

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return;
    }

    // Create server socket
    if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        return;
    }

    // Setup server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(0);

    // Bind socket to server address and port
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Bind failed\n");
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    // Start listening for incoming connections
    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed\n");
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    printf("Server is listening...\n");
    sockaddr_in sin;
    int addrlen = sizeof(sin);
    if (getsockname(serverSocket, (struct sockaddr*)&sin, &addrlen) == 0 && sin.sin_family == AF_INET && addrlen == sizeof(sin)) {
        InterlockedExchange((LONG*)&TCP_PORT, (LONG)ntohs(sin.sin_port));
    }
    // Accept connection
    if ((clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen)) == INVALID_SOCKET) {
        printf("Accept failed\n");
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    printf("Connected to client\n");
        while (1) {
            // Receive data
            int bytesReceived = recv(clientSocket, buffer, BUFFER_SIZE, 0);
            if (bytesReceived > 0) {
                buffer[bytesReceived] = '\0';
                printf("Message from client: %s\n", buffer);
            }
            else if (bytesReceived == 0) {
                printf("Connection closed\n");
                break;
            }
            else {
                printf("Error receiving data\n");
                break;
            }
        }

        // Close sockets
        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();
}

void normalTCP_connect() {
    WSADATA wsaData;
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;
    char buffer[BUFFER_SIZE];

    // 初始化 Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return;
    }

    // 创建客户端套接字
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return;
    }

    // 设置服务器地址结构
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serverAddr.sin_port = htons(TCP_PORT);

    // Connected to the server
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Connection failed\n");
        closesocket(clientSocket);
        WSACleanup();
        return;
    }

    printf("Connected to the server\n");

    // Send a message
    while (1)
    {
        char message[1000];
        scanf_s("%s", message, 1000);
        if (strcmp(message, "exit") == 0)break;
        printf("Send a message: %s\n", message);
        send(clientSocket, message, strlen(message), 0);
        Sleep(1000);
    }

    // 关闭套接字
    closesocket(clientSocket);
    WSACleanup();

    return;
};
void startServerUDP() {
    WSADATA wsaData;
    SOCKET serverSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int addrLen = sizeof(clientAddr);
    char buffer[BUFFER_SIZE];

    // 初始化 Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return;
    }

    // 创建服务器端套接字
    if ((serverSocket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup(); // Ensure WSACleanup is called before returning
        return;
    }

    // 设置服务器地址结构
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(0);

    // 绑定套接字到服务器地址和端口
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("Bind failed\n");
        closesocket(serverSocket);
        WSACleanup();
        return;
    }

    printf("The server is listening...\n");
    sockaddr_in sin;
    int addrlen = sizeof(sin);
    if (getsockname(serverSocket, (struct sockaddr*)&sin, &addrlen) == 0 && sin.sin_family == AF_INET && addrlen == sizeof(sin)) {
        InterlockedExchange((LONG*)&UDP_PORT, (LONG)ntohs(sin.sin_port));
    }
    while (1) {
        // 接收数据
        int bytesReceived = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0, (struct sockaddr*)&clientAddr, &addrLen);
        if (bytesReceived > 0) { // Check if bytesReceived is greater than 0 instead of not equal to SOCKET_ERROR
            buffer[bytesReceived] = '\0'; // Ensure buffer is null-terminated
            printf("client %s:%d Messages sent: %s\n", inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port), buffer);
        }
        else {
            printf("There was an error receiving data or the connection was closed\n");
            break; // Break only on error or no data received to allow for continuous operation
        }
    }

    // 关闭套接字
    closesocket(serverSocket);
    WSACleanup();

    return;
}

void normalUDP_connect() {
    WSADATA wsaData;
    SOCKET clientSocket;
    struct sockaddr_in serverAddr;
    char buffer[BUFFER_SIZE];

    // 初始化 Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return;
    }

    // 创建客户端套接字
    if ((clientSocket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return;
    }

    // 设置服务器地址结构
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serverAddr.sin_port = htons(UDP_PORT);

    // 发送消息
    while (1) {
        char message[1000];
        scanf_s("%s", message, 1000);
        if (strcmp(message, "exit") == 0) break;
        printf("Send a message: %s\n", message);
        sendto(clientSocket, message, strlen(message), 0, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    }

    // 关闭套接字
    closesocket(clientSocket);
    WSACleanup();

    return;
};
void sendHTTP_connecet() {
    WSADATA wsdata;
    WSAStartup(MAKEWORD(2, 2), &wsdata);
    SOCKET skt = socket(AF_INET, SOCK_STREAM, 0);
    if (skt == SOCKET_ERROR)
    {
        return;
    }
    string host_url = "https://cs144.keithw.org/hello";//URL
    string host = "cs144.keithw.org";//域名
    string res = "/hello";//资源地址

    int t = 1;
    cout << host_url << '\n';
    //解析URL，即将URL才分为域名+域名后面的资源地址，比如上面的拆分之后是：域名：studentwebsite.cn；资源地址：/index.html

    //设置要连接的服务器地址
    HOSTENT* ip = gethostbyname(host.c_str());//获取主机信息，里面包含IP地址

    //将IP地址绑定到套接字
    sockaddr_in address;
    memset(&address, 0, sizeof(sockaddr_in));//将结构体对象的所有变量初始化为0
    address.sin_family = AF_INET;//遵循的协议族
    address.sin_port = htons(80);//上面的URL端口是80,一般http端口号是80，htons作用是将端口号主机字节序转换为网络字节序
    memcpy(&address.sin_addr, ip->h_addr, 4);//转换为4个字节的正规IP地址

    //连接服务器
    int cflag = connect(skt, (SOCKADDR*)&address, sizeof(SOCKADDR));
    if (cflag == SOCKET_ERROR)
    {
        cout << "连接服务器失败.." << endl;
        return;
    }
    else
    {
        cout << "连接服务器成功.." << endl;
    }
    //准备发送给服务器，客户端需要的信息请求
    string req = "";
    req += "GET " + res + " HTTP/1.1\r\n";
    req += "Host: " + host + "\r\n";
    req += "User-Agent:*\r\n";
    req += "Connection: close\r\n";
    req += "\r\n";

    //给服务器发送信息
    int clen = send(skt, req.c_str(), req.length(), 0);

    //接受服务器返回的信息
    string info;//接受的信息
    char ch[50];//每次接受的信息
    int rlength = 0;//接受数据的总大小

    int rlen = recv(skt, ch, 50, 0);//每次接受的数据大小
    rlength += rlen;
    if (rlen == SOCKET_ERROR) {
        printf("接收错误\n");
        return;
    }

    while (rlen != 0 && rlen != SOCKET_ERROR)
    {
        info += ch;
        rlen = recv(skt, ch, 50, 0);//每次接受的数据大小
        cout << ch;
        Sleep(100);
        rlength += rlen;
    }

    //编码转换 防止在控制台显示乱码
    char* pszBuffer = new char[info.length() + 1];
    wchar_t* pszWideBuffer = new wchar_t[(info.length() + 1) * 2];
    memset(pszWideBuffer, 0, (info.length() + 1) * 2);
    memset(pszBuffer, 0, info.length() + 1);
    MultiByteToWideChar(CP_UTF8, 0, info.c_str(), info.length(), pszWideBuffer, (info.length() + 1) * 2);//将unicode编码，转换为宽字节
    WideCharToMultiByte(CP_ACP, 0, pszWideBuffer, wcslen(pszWideBuffer), pszBuffer, info.length() + 1, NULL, NULL);//将宽字节,转换为控制台编码

    //cout << pszBuffer;
    info = pszBuffer;
    delete[] pszBuffer;
    delete[] pszWideBuffer;

    //显示
    cout << "客户端给服务器发送了：" << req.length() << "个字节" << endl;
    cout << "服务器返回给客户端了：" << rlength << "个字节" << endl;
    cout << info << endl;//在控制台打印从服务器请求到信息

    //Sleep(rand() % 1000 + 1000);
};
void  sendHTTPS_connect() {};

void beginprocess() {
    while (1) {
        std::string operate;
        std::cin >> operate;
        for (int i = 0; i < operate.size(); i++) {
            switch (operate[i]) {
            case example_normal_Heapoperate:
                normal_Heapoperate();
                break;
            case example_doublefree_Heapoperate:
                doublefree_Heapoperate();
                break;
            case example_normal_fileoperate:
                normal_fileoperate();
                break;
            case example_operatemanyfile_fileoperate:
                operatemanyfile_fileoperate();
                break;
            case example_selfcopy_fileoperate:
                selfcopy_fileoperate();
                break;
            case example_changeexefile_fileoperate:
                changeexefile_fileoperate();
                break;
            case example_normal_registry:
                normal_registry();
                break;
            case example_createnewselfrun_registry:
                createnewselfrun_registry();
                break;
            case example_changeregistry_registry:
                changeregistry_registry();
                break;
            case example_normalTCP_connect:
            {
                normalTCP_connect();
                break;
            }
            case example_normalUDP_connect:
            {
                normalUDP_connect();
                break;
            }
            case example_sendHTTP_connecet:
            {
                sendHTTP_connecet();
                break;
            }
            /*case example_sendHTTPS_connect:
                sendHTTPS_connect();
                break;*/
            case example_exit:
                return;
            default:
                std::cout << "You entered an action symbol that does not exist" << std::endl;
            }
        }
    }
}
int main() {
    std::thread serverThread(startServer);
    serverThread.detach();
    std::thread serverThreadUDP(startServerUDP);
    serverThreadUDP.detach();
    init();
    beginprocess();
    return 0;
}


