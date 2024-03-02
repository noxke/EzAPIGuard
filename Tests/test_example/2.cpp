#include <bits/stdc++.h>
#include <Windows.h>
#include <thread>
#include <mutex>
#include <condition_variable>

using namespace std;

mutex mtx;
condition_variable cv;
int threadCount = 0;

void messagePrint() {
    int i = 3;
    while(i-- > 0) MessageBoxA(NULL, "Hello, World!", "Message", MB_OK);
    unique_lock<mutex> lock(mtx);
    threadCount--;
    cv.notify_one();
}

int main()
{
    int i = 0;
    while (true) {
        unique_lock<mutex> lock(mtx);
        cv.wait(lock, []{ return threadCount < 4; });
        threadCount++;
        thread(messagePrint).detach();
        i++;
    }
    system("pause");
    return 0;
}