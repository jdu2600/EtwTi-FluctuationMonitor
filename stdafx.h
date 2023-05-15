#pragma once

#include <winsock2.h>
#include <Windows.h>
#define _WS2DEF_
#include <aclapi.h>
#include <processthreadsapi.h>
#include <Psapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <Shlobj.h>
#include <Shlobj_core.h>
#include <strsafe.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <stdio.h>

#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string_view>

#include "krabs.hpp"
#include "resource.h"

constexpr auto RED = 12;

constexpr auto PAGE_EXECUTE_ANY = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
constexpr auto IsExecutable = [](DWORD Protection) { return 0 != (Protection & PAGE_EXECUTE_ANY); };

constexpr auto PAGE_WRITE_ANY = PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
constexpr auto IsWritable = [](DWORD Protection) { return 0 != (Protection & PAGE_WRITE_ANY); };

// helpers.cpp
const char* ProtectionString(DWORD Protection);
std::wstring ProcessName(DWORD processId);

// enableppl.cpp
VOID InstallVulnerableDriver();
VOID EnablePPL();
VOID DisablePPL();