#include <Windows.h>

#include <cstdint>
#include <mutex>

#include "../DBI/dbi_framework.h"

dbi_framework* ndif;

template<typename T>
T get_mod_base() {
    return reinterpret_cast<T>(GetModuleHandleA(NULL));
}

void create_console(const char* title) {
    AllocConsole();
    SetConsoleTitleA(title);

    FILE* file_buf;

    freopen_s(&file_buf, "CONOUT$", "w", stdout);
    freopen_s(&file_buf, "CONIN$", "r", stdin);
}

__declspec(dllexport) int start() {
    create_console("NDIF Console");

    std::printf("[+] starting instrumentation\n");

    dbi_framework_options opts{};
    opts.enable_plugins = false;

    ndif = new dbi_framework();
    ndif->initialize(opts);

    const uint64_t address = get_mod_base<uint64_t>() + 0x460A9;

    int status = ndif->instrument_instruction_with_status(address);
    std::printf("[*] attempting to instrument target: 0x%llx\n[*] status code: %d\n", address, status);

    if (status != instrumentation_status::success) {
        std::printf("[-] instrument_instruction failed @ 0x%llx\n", (unsigned long long)address);
        std::printf("[-] error code: %d\n", status);
        return 0;
    }

    ndif->add_instruction_callback([address](CONTEXT& ctx, DWORD_PTR ip) {
        if (ip == address) {
            std::printf("[*] WE ARE BEING HIT!\n");
            *(DWORD*)(ctx.Rbx + 0x7F8) = 999999;
        }
    });

    const bool enabled = ndif->enable_instruction_callbacks();
    std::printf("[*] enable_instruction_callbacks: %s\n", enabled ? "true" : "false");
    return enabled ? 1 : 0;
}

extern "C" __declspec(dllexport) void stop() {
    if (ndif != nullptr) {
        ndif->disable_instruction_callbacks();
        delete ndif;
        ndif = nullptr;
    }
}

static DWORD WINAPI start_thread(LPVOID) {
    start();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        // Defer work outside loader lock.
        CreateThread(nullptr, 0, &start_thread, nullptr, 0, nullptr);
    }
    return TRUE;
}
