#include "WeChatHelper.h"
#include <Windows.h>
#include <string>
#include <strstream>
#pragma comment(lib, "Version.lib")
using namespace std;

long weChatWinDllAddr = 0;
std::string weChatWinDllVersion = "";

void sendText(wchar_t* wxid, wchar_t* msg) {

}

long getWeChatWinAddr() {
    if (weChatWinDllAddr == 0) {
        weChatWinDllAddr = (long)LoadLibrary(L"WeChatWin.dll");
    }
    return weChatWinDllAddr;
}

std::string getWeChatWinDllVersion() {

    if (weChatWinDllVersion != "") {
        return weChatWinDllVersion;
    }

    DWORD weChatWinAddr = getWeChatWinAddr();

    WCHAR versionFilePath[MAX_PATH];
    if (GetModuleFileName((HMODULE)weChatWinAddr, versionFilePath, MAX_PATH) == 0) {
        return "";
    }

    string asVer = "";
    VS_FIXEDFILEINFO* vsInfo;
    unsigned int fileInfoSize = sizeof(VS_FIXEDFILEINFO);
    int verInfoSize = GetFileVersionInfoSize(versionFilePath, NULL);
    if (verInfoSize != 0) {
        char* buff = new char[verInfoSize];
        if (GetFileVersionInfo(versionFilePath, 0, verInfoSize, buff)) {
            if (VerQueryValue(buff, TEXT("\\"), (void**)&vsInfo, &fileInfoSize)) {
                int major_ver = (vsInfo->dwFileVersionMS >> 16) & 0x0000FFFF;
                int minor_ver = vsInfo->dwFileVersionMS & 0x0000FFFF;
                int build_num = (vsInfo->dwFileVersionLS >> 16) & 0x0000FFFF;
                int revision_num = vsInfo->dwFileVersionLS & 0x0000FFFF;
                strstream wxVer;
                wxVer << major_ver << "." << minor_ver << "." << build_num << "." << revision_num;
                wxVer >> asVer;
            }
        }
        delete[] buff;
    }
    weChatWinDllVersion = asVer;
    return asVer;
}
