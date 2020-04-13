#pragma once
#include <string>

void logWchar(wchar_t* str);

void logChar(const char* str);

char* unicodeToUtf8(wchar_t* unicode);

wchar_t* utf8ToUnicode(const char* str);

wchar_t* stringToWchar(std::string str);

char* getCurrentTimeStr();

