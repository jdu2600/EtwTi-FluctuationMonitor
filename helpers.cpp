#include "stdafx.h"


const char* ProtectionString(DWORD Protection) {
    switch (Protection) {
    case PAGE_NOACCESS:
        return "---";
    case PAGE_READONLY:
        return "R--";
    case PAGE_READWRITE:
        return "RW-";
    case PAGE_WRITECOPY:
        return "RC-";
    case PAGE_EXECUTE:
        return "--X";
    case PAGE_EXECUTE_READ:
        return "R-X";
    case PAGE_EXECUTE_READWRITE:
        return "RWX";
    case PAGE_EXECUTE_WRITECOPY:
        return "RCX";
    }
    return "???";
}

std::wstring ProcessName(DWORD processId) {
    std::wstring buffer;
    buffer.resize(32768);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (hProcess) {
        DWORD dwSize = (DWORD)buffer.size();
        if (QueryFullProcessImageNameW(hProcess, 0, &buffer[0], &dwSize))
        {
            buffer = std::filesystem::path(buffer).filename();
        }
        CloseHandle(hProcess);
    }

    if (buffer.empty()) {
        wsprintf(&buffer[0], L"pid:%d", processId);
    }

    return buffer;
}