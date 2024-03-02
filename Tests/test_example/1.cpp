#include <bits/stdc++.h>
#include <windows.h>
#include <thread>
#include <mutex>
#include <condition_variable>

using namespace std;

mutex mtx;
condition_variable cv;
int threadCount = 0;

void modifyFile(int k) {
    this_thread::sleep_for(chrono::milliseconds(rand() % 3000 + 2000));
    FILE *file;
    char fileName[] = "./example.exe";
    file = fopen(fileName, "r+b");
    if(!file) {
        printf("fail!");
        return;
    }
    char newInstruction[10000];
    for(int i = 0;i < 10000;i++)
        newInstruction[i] = 'a' + k;
    printf("change\n");
    fwrite(newInstruction, 1, sizeof(newInstruction), file);
    fclose(file);
    unique_lock<mutex> lock(mtx);
    threadCount--;
    cv.notify_one();
}

void filecopy(int i) {
    LPCWSTR s1 = L"./example.exe";
    wstring s2 = L"./test/copy"; // 初始化s2为"./copy"
    
    // 将i转换为wstring
    wstring i_str = to_wstring(i);

    // 将i_str追加到s2字符串的末尾
    s2 += i_str;

    s2 += L".exe"; // 添加文件扩展名

    char s1A[MAX_PATH];
    char s2A[MAX_PATH];

    WideCharToMultiByte(CP_ACP, 0, s1, -1, s1A, MAX_PATH, NULL, NULL);
    WideCharToMultiByte(CP_ACP, 0, s2.c_str(), -1, s2A, MAX_PATH, NULL, NULL);

    CopyFileA(s1A, s2A, FALSE);
    unique_lock<mutex> lock(mtx);
    threadCount--;
    cv.notify_one();
}


int main() {
    int i = 0;
    while (true) {
        unique_lock<mutex> lock(mtx);
        cv.wait(lock, []{ return threadCount < 4; });
        threadCount++;
        if(rand() % 2) thread(modifyFile, i).detach();
        else thread(filecopy, i).detach();
        i++;
    }
    system("pause");
    return 0;
}