#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <windows.h>

int main() {
    while(1) {
        char folderPath[] = "./test";
        wchar_t folderPathW[MAX_PATH];
        mbstowcs(folderPathW, folderPath, MAX_PATH);
        wchar_t searchPath[MAX_PATH];
        swprintf(searchPath, MAX_PATH, L"%s\\*", folderPathW);
        wchar_t filePath[MAX_PATH];
        WIN32_FIND_DATAW findFileData;
        HANDLE hFind = FindFirstFileW(searchPath, &findFileData);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (wcscmp(findFileData.cFileName, L".") != 0 && wcscmp(findFileData.cFileName, L"..") != 0) {
                    swprintf(filePath, MAX_PATH, L"%s/%s", folderPathW, findFileData.cFileName);
                    wprintf(L"%s\n", filePath);
                    FILE *file = _wfopen(filePath, L"r+b");
                    if (file != NULL) {
                        fseek(file, 0, SEEK_END); // 移动文件指针到文件末尾
                        fwprintf(file, L"%s\n", filePath); // 写入文件名
                        printf("change\n");
                        fclose(file);
                    }
                }
            } while (FindNextFileW(hFind, &findFileData) != 0);
        }
        FindClose(hFind);
        Sleep(rand() % 5000 + 10000);
    }
    system("pause");
    return 0;
}
