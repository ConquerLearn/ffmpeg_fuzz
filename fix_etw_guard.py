#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fix etw_guard.cpp: 3 empty path constants + FileLog thread safety"""
import os

f = os.path.join(r'C:\Users\Administrator\Desktop\2026_8_19_1和4', '04_ETW注入方案', 'etw_guard.cpp')
content = open(f, 'r', encoding='utf-8').read()

# Fix 1: kHeartbeatFile
content = content.replace(
    'static const WCHAR* kHeartbeatFile = L"";',
    'static const WCHAR* kHeartbeatFile = L"C:\\ProgramData\\GlobalHookLoader.heartbeat";'
)

# Fix 2: FileLog CreateFileW path - use g_logPath instead of L""
content = content.replace(
    'HANDLE f = CreateFileW(L"", FILE_APPEND_DATA,',
    'HANDLE f = CreateFileW(g_logPath, FILE_APPEND_DATA,'
)

# Fix 3: g_logPath
content = content.replace(
    'static const WCHAR* g_logPath   = L"";',
    'static const WCHAR* g_logPath   = L"C:\\ProgramData\\etw_guard.log";'
)

# Fix 4: FileLog thread safety - add CS protection
old_filelog = '''static void FileLog(const wchar_t* fmt, ...) {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t hdr[64];
    swprintf_s(hdr, _countof(hdr), L"[%04d-%02d-%02d %02d:%02d:%02d] ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    wchar_t msg[1024];
    va_list ap; va_start(ap, fmt);
    vswprintf_s(msg, _countof(msg), fmt, ap);
    va_end(ap);
    HANDLE f = CreateFileW(g_logPath, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD wr;
        WriteFile(f, hdr, (DWORD)(wcslen(hdr) * sizeof(wchar_t)), &wr, NULL);
        WriteFile(f, msg, (DWORD)(wcslen(msg) * sizeof(wchar_t)), &wr, NULL);
        WriteFile(f, L"\\r\\n", 4, &wr, NULL);
        CloseHandle(f);
    }
}'''

new_filelog = '''static void FileLog(const wchar_t* fmt, ...) {
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t hdr[64];
    swprintf_s(hdr, _countof(hdr), L"[%04d-%02d-%02d %02d:%02d:%02d] ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    wchar_t msg[1024];
    va_list ap; va_start(ap, fmt);
    vswprintf_s(msg, _countof(msg), fmt, ap);
    va_end(ap);
    EnterCriticalSection(&g_logCs);
    HANDLE f = CreateFileW(g_logPath, FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        DWORD wr;
        WriteFile(f, hdr, (DWORD)(wcslen(hdr) * sizeof(wchar_t)), &wr, NULL);
        WriteFile(f, msg, (DWORD)(wcslen(msg) * sizeof(wchar_t)), &wr, NULL);
        WriteFile(f, L"\\r\\n", 4, &wr, NULL);
        CloseHandle(f);
    }
    LeaveCriticalSection(&g_logCs);
}'''

content = content.replace(old_filelog, new_filelog)

open(f, 'w', encoding='utf-8').write(content)
print('Fixed: 3 empty path constants + FileLog thread safety in etw_guard.cpp')