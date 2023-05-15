#include "stdafx.h"

// The set of all of the code pages in a process that have transitions from writable to non-writable, 
// or from executable to non-executable. In both cases, these code pages should never be modified again.
// Proper JIT: Allocate(RW) -> memcpy(code) -> Protect(RX) -> execute [-> Free]
// YOLO JIT: Allocate(RWX) -> memcpy(code) -> execute
// Bad JIT: Allocate(RW) -> memcpy(code) -> Protect(RX) -> execute -> Protect(RW) -> re-use for new code
// Fluctuation: ... -> Protect(RX) -> execute -> Protect(~X) [-> encrypt] -> Protect(RX) -> ...
std::unordered_map <DWORD, std::set<PVOID>> g_ImmutableCodePages;

krabs::user_trace g_trace(L"EtwTi-FluctuationMonitor");

DWORD WINAPI EtwEventThread(LPVOID) {
    g_trace.start();
    return 0;
}

int wmain(int, wchar_t**) {
    printf("[*] Enabling Microsoft-Windows-Threat-Intelligence (KEYWORD_PROTECTVM_LOCAL)\n");
    krabs::provider<> ti_provider(L"Microsoft-Windows-Threat-Intelligence");
    ti_provider.any(0x10); // KERNEL_THREATINT_KEYWORD_PROTECTVM_LOCAL

    krabs::event_filter protectvm_filter(krabs::predicates::id_is(7));
    auto protectvm_cb = [](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);
        
        auto ProcessID          = parser.parse<DWORD>(L"CallingProcessId");
        auto BaseAddress        = parser.parse<PVOID>(L"BaseAddress");
        auto ProtectionMask     = parser.parse<DWORD>(L"ProtectionMask");
        auto LastProtectionMask = parser.parse<DWORD>(L"LastProtectionMask");

        if ((!IsExecutable(LastProtectionMask) && IsExecutable(ProtectionMask)) ||
            (IsWritable(LastProtectionMask) && !IsWritable(ProtectionMask)))
        {
            // non-executable -> executable, or
            // writeable -> non-writable.
            // These code pages should now be immutable.

            printf("[.] %S %p %s => %s\n", ProcessName(ProcessID).c_str(), BaseAddress,
                ProtectionString(LastProtectionMask), ProtectionString(ProtectionMask));

            auto immutable_iter = g_ImmutableCodePages.find(ProcessID);
            if (immutable_iter != g_ImmutableCodePages.cend() &&
                immutable_iter->second.find(BaseAddress) != immutable_iter->second.cend())
            {
                // An immutable code page has been potentially modfied.

                CONSOLE_SCREEN_BUFFER_INFO console_info{};
                static auto hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
                GetConsoleScreenBufferInfo(hStdOutput, &console_info);
                SetConsoleTextAttribute(hStdOutput, RED);
                printf("[!] %S %p is fluctuating\n", ProcessName(ProcessID).c_str(), BaseAddress);
                SetConsoleTextAttribute(hStdOutput, console_info.wAttributes);
            }
            else
            {
                g_ImmutableCodePages[ProcessID].insert(BaseAddress);
            }
        }
    };
    
    protectvm_filter.add_on_event_callback(protectvm_cb);
    ti_provider.add_filter(protectvm_filter);
    g_trace.enable(ti_provider);

    auto duration = 300;
    printf("[*] Monitoring VirtualProtect() for %d seconds\n", duration);
    InstallVulnerableDriver();  // Use BYOVD to enable PPL
    EnablePPL();
    HANDLE hThread = CreateThread(NULL, 0, EtwEventThread, NULL, 0, NULL);
    assert(NULL != hThread);
    Sleep(1000);  // Wait a moment for ETW to initialise before removing PPL
    DisablePPL();
    
    Sleep(duration * 1000);
    g_trace.stop();
    (void)WaitForSingleObject(hThread, INFINITE);
    printf("[*] Done\n\n");

    return 0;
}