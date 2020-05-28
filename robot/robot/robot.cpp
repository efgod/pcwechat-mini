// robot.cpp : 定义应用程序的入口点。
//

#include "robot.h"
#include "resource.h"
#include <Windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <direct.h>
#include <io.h>
#include <string>
using namespace std;

const wchar_t* DLL_NAME = L"helper.dll";
const wchar_t* WECHAT_PROCESS_NAME = L"WeChat.exe";

INT_PTR CALLBACK Dlgproc(
	HWND hWnd,
	UINT uMsg,
	WPARAM wParam,
	LPARAM lParam
);
void injectPid(long pid);
string getDllPath();

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
	DialogBox(hInstance, MAKEINTRESOURCE(ROBOT_MAIN), NULL, &Dlgproc);
	return 0;
}

INT_PTR CALLBACK Dlgproc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	if (uMsg == WM_INITDIALOG) {
	}
	else if (uMsg == WM_CLOSE) {
		EndDialog(hWnd, 0);
	}
	else if (uMsg == WM_COMMAND) {
		if (wParam == BTN_INJECT_PID) {
			int pid = GetDlgItemInt(hWnd, EDIT_PID, NULL, true);
			if (pid > 0) {
				injectPid(pid);
				MessageBox(NULL, L"注入成功", L"INFO", 0);
			}
			else {
				MessageBox(NULL, L"请输入进程ID", L"ERROR", 0);
			}
		}
	}
	return FALSE;
}

void injectPid(long pid) {
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (process == NULL) {
		MessageBox(NULL, L"打开微信进程失败", L"错误", 0);
		return;
	}

	string dllPath = getDllPath();
	if (dllPath == "") {
		MessageBox(NULL, L"helper.dll不存在", L"ERROR", 0);
		return;
	}

	LPVOID dllBuffer = VirtualAllocEx(process, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
	BOOL bWp = WriteProcessMemory(process, dllBuffer, dllPath.c_str(), MAX_PATH, NULL);
	if (bWp == 0) {
		MessageBox(NULL, L"写入dll路径失败", L"错误", 0);
		return;
	}

	FARPROC proc = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	HANDLE hThread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)proc, dllBuffer, 0, NULL);

	if (hThread == NULL) {
		MessageBox(NULL, L"创建线程失败", L"错误", MB_OK);
		return;
	}

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(process);
}

string getDllPath() {
	char dllPath[0x1000] = { 0 };
	sprintf_s(dllPath, "%s\\%ws", _getcwd(NULL, 0), DLL_NAME);
	if (_access(dllPath, 0) == -1) {
		return "";
	}
	return string(dllPath);
}
