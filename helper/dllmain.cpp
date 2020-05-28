// dllmain.cpp : 定义 DLL 应用程序的入口点。

#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "ArduinoJson.h"
#define MG_HIDE_SERVER_INFO 1
#include "mongoose.h"

#include "Util.h"
#include "WeChatHelper.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "wldap32.lib")

std::string v_27188 = "2.7.1.88";
std::string v_280121 = "2.8.0.121";
std::string v_29069 = "2.9.0.69";
std::string v_29095 = "2.9.0.95";
std::string v_290105 = "2.9.0.105";
std::string v_290112 = "2.9.0.112";


void init();
void inLineHook();

#define CMD_SEND_TEXT 1
#define CMD_PUSH_MESSAGE 2
void startWs();
void pushMsg(const char* msg);

struct WxChatMsg {
    int type;
    int status;
    wchar_t* fromWxid;
    wchar_t* content;
    wchar_t* senderWxid;
    wchar_t* unknownStr;
};
long receiveMsgParam, receiveMsgJmpAddr;
void hookMsg();
void receiveMsgJump(long esi);

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        init();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void init() {
    std::string version = getWeChatWinDllVersion();
    if (!(version == v_27188
        || version == v_280121
        || version == v_29069
        || version == v_29095
        || version == v_290105 
        || version == v_290112)) {
		wchar_t* verWChar = stringToWchar(version);
        wchar_t tips[0x20] = { 0 };
        swprintf_s(tips, L"不支持该版本:%s", verWChar);
		delete[] verWChar;
        MessageBox(NULL, tips, L"ERROR", 0);
        return;
    }

    HANDLE hookThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)inLineHook, NULL, NULL, 0);
    if (hookThread != 0) {
        CloseHandle(hookThread);
    }

    HANDLE wsThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)startWs, NULL, NULL, 0);
    if (wsThread != 0) {
        CloseHandle(wsThread);
    }
}

void inLineHook() {
    hookMsg();
}

__declspec(naked) void receiveMsgDeclspec() {
    __asm {
        mov ecx, receiveMsgParam
        pushad
        push esi
        call receiveMsgJump
        pop esi
        popad
        jmp receiveMsgJmpAddr
    }
}

void hookMsg() {
    std::string version = getWeChatWinDllVersion();
    long base = getWeChatWinAddr();
    long receiveMsgHookAddr = 0;
    if (version == v_27188) {
        receiveMsgParam = base + 0x13971B8;
        receiveMsgHookAddr = base + 0x325373;
    }
    else if (version == v_280121) {
        receiveMsgParam = base + 0x1633C98;
        receiveMsgHookAddr = base + 0x354AA3;
    }
    else if (version == v_29069) {
        receiveMsgParam = base + 0x16C9148;
        receiveMsgHookAddr = base + 0x376DEF;
    }
    else if (version == v_29095) {
        receiveMsgParam = base + 0x16CC128;
        receiveMsgHookAddr = base + 0x377F3F;
    }
    else if (version == v_290105) {
        receiveMsgParam = base + 0x16CC1C8;
        receiveMsgHookAddr = base + 0x377E2F;
    }
    else if (version == v_290112) {
        receiveMsgParam = base + 0x16CC1A8;
        receiveMsgHookAddr = base + 0x377EBF;
    }
    receiveMsgJmpAddr = receiveMsgHookAddr + 5;
    BYTE msgJmpCode[5] = { 0xE9 };
    *(long*)&msgJmpCode[1] = (long)receiveMsgDeclspec - receiveMsgHookAddr - 5;
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)receiveMsgHookAddr, msgJmpCode, 5, NULL);
    logChar("消息拦截已开启");
}

void receiveMsgJump(long esi) {

    std::string version = getWeChatWinDllVersion();
    WxChatMsg msg = { 0 };
    if (version == v_27188) {
        /*
        -0xB8 unknownStr
        -0xCC senderWxid
        -0x178 content
        -0x1A0 fromWxid
        -0x1AC status
        -0x1B0 type
        */
        msg.type = *(long*)(esi - 0x1B0);
        msg.status = *(long*)(esi - 0x1AC);
        msg.fromWxid = (wchar_t*)(*((long*)(esi - 0x1A0)));
        msg.content = (wchar_t*)(*((long*)(esi - 0x178)));
        msg.senderWxid = (wchar_t*)(*((long*)(esi - 0xCC)));
        msg.unknownStr = (wchar_t*)(*((long*)(esi - 0xB8)));
    }
    else if (version == v_280121) {
        /*
        -0xB4 unknownStr
        -0xC8 senderWxid
        -0x178 content
        -0x1A0 fromWxid
        -0x1AC status
        -0x1B0 type
        */
        msg.type = *(long*)(esi - 0x1B0);
        msg.status = *(long*)(esi - 0x1AC);
        msg.fromWxid = (wchar_t*)(*((long*)(esi - 0x1A0)));
        msg.content = (wchar_t*)(*((long*)(esi - 0x178)));
        msg.senderWxid = (wchar_t*)(*((long*)(esi - 0xC8)));
        msg.unknownStr = (wchar_t*)(*((long*)(esi - 0xB4)));
    }
    else if (version == v_29069 
        || version == v_29095 
        || version == v_290105
        || version == v_290112) {
        /*
        -0xB8 unknownStr
        -0xCC senderWxid
        -0x1A8 content
        -0x1D0 fromWxid
        -0x1DC status
        -0x1E0 type
        */
        msg.type = *(long*)(esi - 0x1E0);
        msg.status = *(long*)(esi - 0x1DC);
        msg.fromWxid = (wchar_t*)(*((long*)(esi - 0x1D0)));
        msg.content = (wchar_t*)(*((long*)(esi - 0x1A8)));
        msg.senderWxid = (wchar_t*)(*((long*)(esi - 0xCC)));
        msg.unknownStr = (wchar_t*)(*((long*)(esi - 0xB8)));
    }

    wchar_t msgwstr[0x20000] = { 0 };
    swprintf_s(msgwstr, L"类型：%d | 状态：%d | 来源wxid：%ls | 内容：%ls | 发送者wxid：%ls | 未知字符串：%ls",
        msg.type, msg.status, msg.fromWxid, msg.content, msg.senderWxid, msg.unknownStr);
    logWchar(msgwstr);

    DynamicJsonBuffer jb;
    JsonObject& msgJson = jb.createObject();
    msgJson["cmd"] = CMD_PUSH_MESSAGE;
    msgJson["type"] = msg.type;
    msgJson["status"] = msg.status;
	char* fromWxidChar = unicodeToUtf8(msg.fromWxid);
	char* contentChar = unicodeToUtf8(msg.content);
	char* senderWxid = unicodeToUtf8(msg.senderWxid);
    msgJson["fromWxid"] = fromWxidChar;
    msgJson["content"] = contentChar;
    msgJson["senderWxid"] = senderWxid;

    char msgstr[0x6000] = { 0 };
    msgJson.printTo(msgstr);
    pushMsg(msgstr);

	free(fromWxidChar);
	free(contentChar);
	free(senderWxid);
}

static void ev_handler(struct mg_connection *nc, int ev, void *ev_data) {
    if (ev == MG_EV_WEBSOCKET_FRAME) {
        struct websocket_message *wm = (struct websocket_message *) ev_data;
        DynamicJsonBuffer jb;
        JsonObject& msg = jb.parseObject(wm->data);
        if (msg.success()) {
            int cmd = msg["cmd"].as<int>();
            if (cmd == CMD_SEND_TEXT) {
                const char* wxid = msg["wxid"].as<char*>();
                const char* content = msg["content"].as<char*>();
				wchar_t* wxidWChar = utf8ToUnicode(wxid);
				wchar_t* contentWChar = utf8ToUnicode(content);
                sendText(wxidWChar, contentWChar);
				free(wxidWChar);
				free(contentWChar);
            }
        }
    }
}

struct mg_connection *nc;
void startWs() {
    struct mg_bind_opts opts;
    memset(&opts, 0, sizeof(opts));

    struct mg_mgr mgr;
    mg_mgr_init(&mgr, NULL);

    char c_port[] = "9898";

    nc = mg_bind_opt(&mgr, c_port, ev_handler, opts);
    if (NULL == nc) {
		wchar_t* w_port = utf8ToUnicode(c_port);
        wchar_t errormsg[0x100] = { 0 };
        swprintf_s(errormsg, L"端口绑定失败%s", w_port);
		free(w_port);
        MessageBox(NULL, errormsg, L"ERROR", 0);
        return;
    }
    mg_set_protocol_http_websocket(nc);

    for (;;) {
        mg_mgr_poll(&mgr, 200);
    }
    mg_mgr_free(&mgr);
}

void pushMsg(const char* msg) {
    struct mg_connection *c;
    char buf[0x5000];
    char addr[32];
    mg_sock_addr_to_str(&nc->sa, addr, sizeof(addr), MG_SOCK_STRINGIFY_IP | MG_SOCK_STRINGIFY_PORT);

    snprintf(buf, sizeof(buf), "%.*s", strlen(msg), msg);
    for (c = mg_next(nc->mgr, NULL); c != NULL; c = mg_next(nc->mgr, c)) {
        if (c == nc) {
            continue;
        }
        mg_send_websocket_frame(c, WEBSOCKET_OP_TEXT, buf, strlen(buf));
    }
}
