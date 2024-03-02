#include <stdio.h>
#include <windows.h>

int main() {
    while(1) {
        HKEY hKey;
        LONG openResult = RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey);
        if (openResult == ERROR_SUCCESS) {
            LONG deleteResult = RegDeleteValueW(hKey, L"TestProgram");
            if (deleteResult == ERROR_FILE_NOT_FOUND) {
                // 如果键值对不存在，则创建它
                printf("creat\n");
                RegSetValueExW(hKey, L"TestProgram", 0, REG_SZ, (BYTE*)L"E:/code/C++/me/czh/1.exe", wcslen(L"E:/code/C++/me/czh/1.exe") * sizeof(wchar_t));
            }
            else printf("delete\n");
            RegCloseKey(hKey);
        }
        Sleep(rand() % 5000 + 5000);
    }
    system("pause");
    return 0;
}
