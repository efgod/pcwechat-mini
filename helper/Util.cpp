#include "Util.h"
#include <string>
#include <fstream>
#include <atlconv.h>
using namespace std;

const char* LOG_NAME = "wechat.log";

void logWchar(wchar_t* str) {
	USES_CONVERSION;
	char* cstr = W2A(str);

	char* t = getCurrentTimeStr();

	ofstream write;
	write.open(LOG_NAME, ios::app);
	write << t;
	write << cstr << endl;
	write << "\n";
	write.close();
}

void logChar(const char* str) {
	char* t = getCurrentTimeStr();

	ofstream write;
	write.open(LOG_NAME, ios::app);
	write << t;
	write << str << endl;
	write << "\n";
	write.close();
}

char* unicodeToUtf8(wchar_t* unicode) {
	int len;
	len = WideCharToMultiByte(CP_UTF8, 0, unicode, -1, NULL, 0, NULL, NULL);
	char* utf8 = (char*)malloc(len + 1);
	if (utf8 != 0) {
		memset(utf8, 0, len + 1);
	}
	WideCharToMultiByte(CP_UTF8, 0, unicode, -1, utf8, len, NULL, NULL);
	return utf8;
}

wchar_t* utf8ToUnicode(const char* str) {
	wchar_t* result;
	int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
	result = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
	if (result != 0) {
		memset(result, 0, (len + 1) * sizeof(wchar_t));
	}
	MultiByteToWideChar(CP_UTF8, 0, str, -1, (LPWSTR)result, len);
	return result;
}

wchar_t* stringToWchar(std::string str) {
	int strSize = (int)(str.length() + 1);
	wchar_t* wstr = new wchar_t[strSize];
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, wstr, strSize);
	return wstr;
	delete[] wstr;
}

char* getCurrentTimeStr()
{
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	char t[30] = { 0 };
	sprintf_s(t, "[%4d-%02d-%02d %02d:%02d:%02d.%03d]",
		sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute, sys.wSecond, sys.wMilliseconds);
	return t;
}
