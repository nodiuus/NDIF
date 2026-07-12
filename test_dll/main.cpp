/*
    NDIF instrumentation DLL for the 32-bit clarity target.

    The target's MessageBoxA call setup site is at RVA 0x3E744. The DLL is injected
    after the launcher observes the target's self-modification.
*/

#include <Windows.h>

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <string>
#include <vector>

#include "../DBI/dbi_framework.h"
#include "../DBI/core/dbi_core_version.h"
#include "../DBI/core/dbi_ipc_protocol.h"
#include "../DBI/plugin_api.h"

namespace {

constexpr std::uintptr_t kMessageBoxCallSetupRva = 0x3E744;
constexpr std::uintptr_t kMessageBoxThunkCallRva = 0x3E745;
constexpr std::uintptr_t kMessageBoxThunkReturnRva = kMessageBoxThunkCallRva + 5;
constexpr std::uintptr_t kMessageBoxPostCallRva = kMessageBoxThunkReturnRva;

dbi_framework* g_ndif = nullptr;
bool g_instrumentation_active = false;
std::atomic<bool> g_monitor_running{false};

enum class message_target_kind {
    generic_entry,
    wrapper_w,
    call_site_a,
    api_w,
    api_a,
    virtual_protect,
    virtual_protect_ex,
    nt_protect_virtual_memory,
};

struct message_target {
    std::uintptr_t address{};
    message_target_kind kind{};
    const char* name{};
};

bool write_exact(HANDLE pipe, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t total = 0;
    while (total < size) {
        DWORD written = 0;
        if (!WriteFile(pipe, bytes + total, static_cast<DWORD>(size - total), &written, nullptr) || written == 0) {
            return false;
        }
        total += written;
    }
    return true;
}

bool read_exact(HANDLE pipe, void* data, std::size_t size) {
    auto* bytes = static_cast<std::uint8_t*>(data);
    std::size_t total = 0;
    while (total < size) {
        DWORD read = 0;
        if (!ReadFile(pipe, bytes + total, static_cast<DWORD>(size - total), &read, nullptr) || read == 0) {
            return false;
        }
        total += read;
    }
    return true;
}

template <typename Payload>
bool write_message(HANDLE pipe, dbi_ipc::message_type type, const Payload& payload) {
    dbi_ipc::message_header header{};
    header.type = static_cast<std::uint16_t>(type);
    header.payload_size = static_cast<std::uint32_t>(sizeof(Payload));
    return write_exact(pipe, &header, sizeof(header)) && write_exact(pipe, &payload, sizeof(payload));
}

std::wstring build_pipe_name() {
    wchar_t buffer[128]{};
    _snwprintf_s(buffer, _countof(buffer), _TRUNCATE, L"\\\\.\\pipe\\dbi_agent_%lu", GetCurrentProcessId());
    return buffer;
}

instruction_callback_backend decode_backend(std::uint32_t backend) {
    switch (static_cast<dbi_ipc::instruction_backend>(backend)) {
    case dbi_ipc::instruction_backend::translated_cache:
        return instruction_callback_backend::translated_cache;
    case dbi_ipc::instruction_backend::cooperative_translation:
        return instruction_callback_backend::cooperative_translation;
    case dbi_ipc::instruction_backend::dispatcher_code_cache:
        return instruction_callback_backend::dispatcher_code_cache;
    case dbi_ipc::instruction_backend::guard_page_translation:
        return instruction_callback_backend::guard_page_translation;
    case dbi_ipc::instruction_backend::inline_hook:
        return instruction_callback_backend::inline_hook;
    default:
        return instruction_callback_backend::guard_page_translation;
    }
}

void create_console(const char* title) {
    if (GetConsoleWindow() == nullptr) {
        AllocConsole();
    }

    SetConsoleTitleA(title);

    FILE* file = nullptr;
    freopen_s(&file, "CONOUT$", "w", stdout);
    freopen_s(&file, "CONIN$", "r", stdin);
}

std::wstring read_wstring(std::uintptr_t address) {
    if (address == 0) {
        return L"<null>";
    }

    wchar_t buffer[512]{};
    SIZE_T bytes_read = 0;
    const SIZE_T capacity = sizeof(buffer) - sizeof(wchar_t);

    if (!ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<const void*>(address),
            buffer,
            capacity,
            &bytes_read)) {
        return L"<unreadable>";
    }

    buffer[bytes_read / sizeof(wchar_t)] = L'\0';
    return buffer;
}

std::string read_astring(std::uintptr_t address) {
    if (address == 0) {
        return "<null>";
    }

    char buffer[1024]{};
    SIZE_T bytes_read = 0;
    const SIZE_T capacity = sizeof(buffer) - 1;

    if (!ReadProcessMemory(
            GetCurrentProcess(),
            reinterpret_cast<const void*>(address),
            buffer,
            capacity,
            &bytes_read)) {
        return "<unreadable>";
    }

    buffer[bytes_read] = '\0';
    return buffer;
}

bool read_code_bytes(std::uintptr_t address, void* buffer, SIZE_T size) {
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(
               GetCurrentProcess(),
               reinterpret_cast<const void*>(address),
               buffer,
               size,
               &bytes_read) != FALSE &&
        bytes_read == size;
}

// Packed x86 images commonly leave a direct jump thunk at a recovered RVA.
// Resolve only unconditional jump forms so the DBI backend receives a normal
// instruction entry rather than a branch it cannot relocate.
std::uintptr_t resolve_jump_thunk(std::uintptr_t address) {
    for (int depth = 0; depth < 8; ++depth) {
        std::uint8_t bytes[6]{};
        if (!read_code_bytes(address, bytes, sizeof(bytes))) {
            return address;
        }

        std::uintptr_t destination = 0;
        if (bytes[0] == 0xE9) {
            std::int32_t displacement = 0;
            std::memcpy(&displacement, bytes + 1, sizeof(displacement));
            destination = address + 5 + static_cast<std::intptr_t>(displacement);
        } else if (bytes[0] == 0xEB) {
            const auto displacement = static_cast<std::int8_t>(bytes[1]);
            destination = address + 2 + static_cast<std::intptr_t>(displacement);
        } else if (bytes[0] == 0xFF && bytes[1] == 0x25) {
            std::uint32_t pointer_address = 0;
            std::memcpy(&pointer_address, bytes + 2, sizeof(pointer_address));
            std::uint32_t pointer_value = 0;
            if (!read_code_bytes(
                    static_cast<std::uintptr_t>(pointer_address),
                    &pointer_value,
                    sizeof(pointer_value))) {
                return address;
            }
            destination = static_cast<std::uintptr_t>(pointer_value);
        } else {
            return address;
        }

        if (destination == 0 || destination == address) {
            return address;
        }
        address = destination;
    }

    return address;
}

std::uintptr_t resolve_instrumentation_entry(std::uintptr_t address) {
    const std::uintptr_t resolved = resolve_jump_thunk(address);
    std::uint8_t bytes[2]{};
    if (!read_code_bytes(resolved, bytes, sizeof(bytes))) {
        return resolved;
    }

    // A call-thunk can be observed safely at its fall-through instruction:
    // the callee has returned and the wrapper's original stack arguments are
    // still available to the logger.
    if (bytes[0] == 0xE8) {
        return resolved + 5;
    }

    return resolved;
}

void log_entry_bytes(const char* name, std::uintptr_t address) {
    std::uint8_t bytes[8]{};
    if (!read_code_bytes(address, bytes, sizeof(bytes))) {
        std::printf("[NDIF] %s entry=0x%p bytes=<unreadable>\n", name, reinterpret_cast<void*>(address));
        return;
    }

    std::printf(
        "[NDIF] %s entry=0x%p bytes=%02X %02X %02X %02X %02X %02X %02X %02X\n",
        name,
        reinterpret_cast<void*>(address),
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5], bytes[6], bytes[7]);
}

void add_target(std::vector<message_target>& targets, message_target target) {
    if (target.address == 0) {
        return;
    }

    for (const auto& existing : targets) {
        if (existing.address == target.address) {
            return;
        }
    }

    targets.push_back(target);
}

void add_message_box_api_targets(std::vector<message_target>& targets) {
    HMODULE user32 = GetModuleHandleW(L"user32.dll");
    if (user32 == nullptr) {
        user32 = LoadLibraryW(L"user32.dll");
    }

    if (user32 == nullptr) {
        std::printf("[NDIF] user32.dll unavailable; API-level MessageBox targets skipped\n");
        return;
    }

    add_target(
        targets,
        message_target{
            reinterpret_cast<std::uintptr_t>(GetProcAddress(user32, "MessageBoxW")),
            message_target_kind::api_w,
            "user32!MessageBoxW",
        });
    add_target(
        targets,
        message_target{
            reinterpret_cast<std::uintptr_t>(GetProcAddress(user32, "MessageBoxA")),
            message_target_kind::api_a,
            "user32!MessageBoxA",
        });
}

HMODULE module_handle_or_load(const wchar_t* name) {
    HMODULE module = GetModuleHandleW(name);
    if (module == nullptr) {
        module = LoadLibraryW(name);
    }
    return module;
}

void add_export_target(
    std::vector<message_target>& targets,
    const wchar_t* module_name,
    const char* export_name,
    message_target_kind kind,
    const char* display_name) {
    HMODULE module = module_handle_or_load(module_name);
    if (module == nullptr) {
        std::printf("[NDIF] %s unavailable; %s skipped\n", display_name, export_name);
        return;
    }

    add_target(
        targets,
        message_target{
            reinterpret_cast<std::uintptr_t>(GetProcAddress(module, export_name)),
            kind,
            display_name,
        });
}

void add_protection_api_targets(std::vector<message_target>& targets) {
    add_export_target(
        targets,
        L"kernel32.dll",
        "VirtualProtect",
        message_target_kind::virtual_protect,
        "kernel32!VirtualProtect");
    add_export_target(
        targets,
        L"kernelbase.dll",
        "VirtualProtect",
        message_target_kind::virtual_protect,
        "kernelbase!VirtualProtect");
    add_export_target(
        targets,
        L"kernel32.dll",
        "VirtualProtectEx",
        message_target_kind::virtual_protect_ex,
        "kernel32!VirtualProtectEx");
    add_export_target(
        targets,
        L"kernelbase.dll",
        "VirtualProtectEx",
        message_target_kind::virtual_protect_ex,
        "kernelbase!VirtualProtectEx");
}

bool read_message_box_args(const CONTEXT& context, std::uintptr_t stack_offset, std::uint32_t (&args)[4]) {
#if defined(_M_IX86)
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(
               GetCurrentProcess(),
               reinterpret_cast<const void*>(
                   static_cast<std::uintptr_t>(context.Esp) + stack_offset),
               args,
               sizeof(args),
               &bytes_read) != FALSE &&
        bytes_read == sizeof(args);
#else
    (void)context;
    (void)args;
    return false;
#endif
}

bool read_stack_u32(std::uintptr_t esp, std::uintptr_t offset, std::uint32_t& value);

std::uintptr_t message_box_arg_stack_offset(message_target_kind kind) {
    return kind == message_target_kind::call_site_a ? 0 : sizeof(std::uint32_t);
}

bool is_filtered_message_box_api_hit(const CONTEXT& context) {
#if defined(_M_IX86)
    std::uint32_t return_address32 = 0;
    if (!read_stack_u32(context.Esp, 0, return_address32)) {
        return false;
    }

    const auto module_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    return static_cast<std::uintptr_t>(return_address32) ==
        module_base + kMessageBoxThunkReturnRva;
#else
    (void)context;
    return false;
#endif
}

bool read_stack_u32(std::uintptr_t esp, std::uintptr_t offset, std::uint32_t& value) {
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(
               GetCurrentProcess(),
               reinterpret_cast<const void*>(esp + offset),
               &value,
               sizeof(value),
               &bytes_read) != FALSE &&
        bytes_read == sizeof(value);
}

std::string basename_of(const char* path) {
    const char* name = path;
    for (const char* cursor = path; *cursor != '\0'; ++cursor) {
        if (*cursor == '\\' || *cursor == '/') {
            name = cursor + 1;
        }
    }
    return name;
}

std::string describe_address(std::uintptr_t address) {
    if (address == 0) {
        return "<null>";
    }

    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(
            reinterpret_cast<const void*>(address),
            &info,
            sizeof(info)) != sizeof(info) ||
        info.AllocationBase == nullptr) {
        char buffer[96]{};
        std::snprintf(buffer, sizeof(buffer), "unknown:0x%p", reinterpret_cast<void*>(address));
        return buffer;
    }

    const auto main_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    if (main_base != 0 &&
        reinterpret_cast<std::uintptr_t>(info.AllocationBase) == main_base) {
        char buffer[96]{};
        std::snprintf(
            buffer,
            sizeof(buffer),
            "target+0x%08Ix",
            static_cast<std::uintptr_t>(address - main_base));
        return buffer;
    }

    char module_path[MAX_PATH]{};
    const auto module_base = reinterpret_cast<std::uintptr_t>(info.AllocationBase);
    const DWORD length = GetModuleFileNameA(
        reinterpret_cast<HMODULE>(info.AllocationBase),
        module_path,
        static_cast<DWORD>(sizeof(module_path)));

    char buffer[192]{};
    if (length != 0) {
        const std::string module_name = basename_of(module_path);
        std::snprintf(
            buffer,
            sizeof(buffer),
            "%s+0x%08Ix",
            module_name.c_str(),
            static_cast<std::uintptr_t>(address - module_base));
    } else {
        std::snprintf(
            buffer,
            sizeof(buffer),
            "module_base=0x%p+0x%08Ix",
            reinterpret_cast<void*>(module_base),
            static_cast<std::uintptr_t>(address - module_base));
    }
    return buffer;
}

const char* protection_name(DWORD protection) {
    switch (protection & 0xFFu) {
    case PAGE_EXECUTE:
        return "EXECUTE";
    case PAGE_EXECUTE_READ:
        return "EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE:
        return "EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY:
        return "EXECUTE_WRITECOPY";
    case PAGE_READONLY:
        return "READONLY";
    case PAGE_READWRITE:
        return "READWRITE";
    case PAGE_WRITECOPY:
        return "WRITECOPY";
    case PAGE_NOACCESS:
        return "NOACCESS";
    default:
        return "UNKNOWN";
    }
}

bool query_target_guard_status(MEMORY_BASIC_INFORMATION& info, std::uintptr_t& target_address) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    target_address = module_base + kMessageBoxPostCallRva;

    if (VirtualQuery(
            reinterpret_cast<const void*>(target_address),
            &info,
            sizeof(info)) != sizeof(info)) {
        std::printf(
            "[NDIF] target guard status target=0x%p VirtualQuery failed error=%lu\n",
            reinterpret_cast<void*>(target_address),
            GetLastError());
        return false;
    }

    return true;
}

void log_target_guard_status() {
    MEMORY_BASIC_INFORMATION info{};
    std::uintptr_t target_address = 0;
    if (!query_target_guard_status(info, target_address)) {
        return;
    }

    const bool guarded = (info.Protect & PAGE_GUARD) != 0;
    std::printf(
        "[NDIF] target guard status target=0x%p (%s) protect=0x%08lx base=%s guard=%s\n",
        reinterpret_cast<void*>(target_address),
        describe_address(target_address).c_str(),
        static_cast<unsigned long>(info.Protect),
        protection_name(info.Protect),
        guarded ? "yes" : "no");
}

DWORD WINAPI protection_monitor_thread(LPVOID) {
    MEMORY_BASIC_INFORMATION info{};
    std::uintptr_t target_address = 0;
    DWORD last_protect = 0;
    bool have_last = false;

    while (g_monitor_running.load(std::memory_order_acquire)) {
        if (query_target_guard_status(info, target_address)) {
            if (!have_last || info.Protect != last_protect) {
                const bool guarded = (info.Protect & PAGE_GUARD) != 0;
                std::printf(
                    "[NDIF] target protection change target=0x%p (%s) protect=0x%08lx base=%s guard=%s\n",
                    reinterpret_cast<void*>(target_address),
                    describe_address(target_address).c_str(),
                    static_cast<unsigned long>(info.Protect),
                    protection_name(info.Protect),
                    guarded ? "yes" : "no");
                last_protect = info.Protect;
                have_last = true;
            }
        }

        Sleep(5);
    }

    return 0;
}

void start_protection_monitor() {
    bool expected = false;
    if (!g_monitor_running.compare_exchange_strong(
            expected,
            true,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return;
    }

    HANDLE thread = CreateThread(nullptr, 0, protection_monitor_thread, nullptr, 0, nullptr);
    if (thread != nullptr) {
        CloseHandle(thread);
        return;
    }

    g_monitor_running.store(false, std::memory_order_release);
    std::printf("[NDIF] target protection monitor failed to start: %lu\n", GetLastError());
}

void rearm_target_guard_if_missing() {
    MEMORY_BASIC_INFORMATION info{};
    std::uintptr_t target_address = 0;
    if (!query_target_guard_status(info, target_address)) {
        return;
    }

    if ((info.Protect & PAGE_GUARD) != 0) {
        return;
    }

    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const std::uintptr_t page_size =
        system_info.dwPageSize != 0 ? system_info.dwPageSize : 0x1000;
    const auto page_base = target_address & ~(page_size - 1);
    const DWORD new_protection = info.Protect | PAGE_GUARD;

    DWORD old_protect = 0;
    if (!VirtualProtect(
            reinterpret_cast<void*>(page_base),
            page_size,
            new_protection,
            &old_protect)) {
        std::printf(
            "[NDIF] target guard rearm failed target=0x%p page=0x%p size=0x%Ix protect=0x%08lx error=%lu\n",
            reinterpret_cast<void*>(target_address),
            reinterpret_cast<void*>(page_base),
            page_size,
            static_cast<unsigned long>(new_protection),
            GetLastError());
        return;
    }

    FlushInstructionCache(
        GetCurrentProcess(),
        reinterpret_cast<const void*>(page_base),
        page_size);
    std::printf(
        "[NDIF] target guard rearmed target=0x%p (%s) old=0x%08lx new=0x%08lx\n",
        reinterpret_cast<void*>(target_address),
        describe_address(target_address).c_str(),
        static_cast<unsigned long>(old_protect),
        static_cast<unsigned long>(new_protection));
}

bool target_page_bounds(std::uintptr_t& page_base, std::uintptr_t& page_end) {
    const auto module_base = reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const auto target_address = module_base + kMessageBoxPostCallRva;

    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);
    const std::uintptr_t page_size =
        system_info.dwPageSize != 0 ? system_info.dwPageSize : 0x1000;
    page_base = target_address & ~(page_size - 1);
    page_end = page_base + page_size;
    return page_end > page_base;
}

bool ranges_overlap(std::uintptr_t left_base, std::uintptr_t left_size, std::uintptr_t right_base, std::uintptr_t right_end) {
    if (left_base == 0 || left_size == 0 || right_end <= right_base) {
        return false;
    }

    const std::uintptr_t left_end = left_base + left_size;
    if (left_end <= left_base) {
        return true;
    }
    return left_base < right_end && left_end > right_base;
}

bool read_process_u32(std::uintptr_t address, std::uint32_t& value) {
    SIZE_T bytes_read = 0;
    return ReadProcessMemory(
               GetCurrentProcess(),
               reinterpret_cast<const void*>(address),
               &value,
               sizeof(value),
               &bytes_read) != FALSE &&
        bytes_read == sizeof(value);
}

bool is_protection_target(message_target_kind kind) {
    return kind == message_target_kind::virtual_protect ||
        kind == message_target_kind::virtual_protect_ex ||
        kind == message_target_kind::nt_protect_virtual_memory;
}

void log_protection_overlap_common(
    const CONTEXT& context,
    const message_target& target,
    std::uintptr_t base,
    std::uintptr_t size,
    DWORD new_protect,
    std::uint32_t old_protect_ptr,
    std::uint32_t process_handle) {
#if defined(_M_IX86)
    std::uintptr_t target_page = 0;
    std::uintptr_t target_page_end = 0;
    if (!target_page_bounds(target_page, target_page_end) ||
        !ranges_overlap(base, size, target_page, target_page_end)) {
        return;
    }

    std::uint32_t return_address32 = 0;
    read_stack_u32(context.Esp, 0, return_address32);
    std::printf(
        "[NDIF] %s overlaps target page range=0x%p..0x%p size=0x%Ix new=0x%08lx (%s%s) old_ptr=0x%08lx hProcess=0x%08lx caller_return=0x%p (%s)\n",
        target.name,
        reinterpret_cast<void*>(base),
        reinterpret_cast<void*>(base + size),
        size,
        static_cast<unsigned long>(new_protect),
        protection_name(new_protect),
        (new_protect & PAGE_GUARD) != 0 ? "|GUARD" : "",
        static_cast<unsigned long>(old_protect_ptr),
        static_cast<unsigned long>(process_handle),
        reinterpret_cast<void*>(static_cast<std::uintptr_t>(return_address32)),
        describe_address(static_cast<std::uintptr_t>(return_address32)).c_str());
#else
    (void)context;
    (void)target;
    (void)base;
    (void)size;
    (void)new_protect;
    (void)old_protect_ptr;
    (void)process_handle;
#endif
}

void log_protection_hit(const CONTEXT& context, const message_target& target) {
#if defined(_M_IX86)
    std::uint32_t args[5]{};
    const auto esp = static_cast<std::uintptr_t>(context.Esp);

    switch (target.kind) {
    case message_target_kind::virtual_protect:
        if (!read_stack_u32(esp, 0x04, args[0]) ||
            !read_stack_u32(esp, 0x08, args[1]) ||
            !read_stack_u32(esp, 0x0C, args[2]) ||
            !read_stack_u32(esp, 0x10, args[3])) {
            return;
        }
        log_protection_overlap_common(
            context,
            target,
            static_cast<std::uintptr_t>(args[0]),
            static_cast<std::uintptr_t>(args[1]),
            args[2],
            args[3],
            0xFFFFFFFFu);
        break;

    case message_target_kind::virtual_protect_ex:
        if (!read_stack_u32(esp, 0x04, args[0]) ||
            !read_stack_u32(esp, 0x08, args[1]) ||
            !read_stack_u32(esp, 0x0C, args[2]) ||
            !read_stack_u32(esp, 0x10, args[3]) ||
            !read_stack_u32(esp, 0x14, args[4])) {
            return;
        }
        log_protection_overlap_common(
            context,
            target,
            static_cast<std::uintptr_t>(args[1]),
            static_cast<std::uintptr_t>(args[2]),
            args[3],
            args[4],
            args[0]);
        break;

    case message_target_kind::nt_protect_virtual_memory: {
        if (!read_stack_u32(esp, 0x04, args[0]) ||
            !read_stack_u32(esp, 0x08, args[1]) ||
            !read_stack_u32(esp, 0x0C, args[2]) ||
            !read_stack_u32(esp, 0x10, args[3]) ||
            !read_stack_u32(esp, 0x14, args[4])) {
            return;
        }

        std::uint32_t base = 0;
        std::uint32_t size = 0;
        if (!read_process_u32(args[1], base) ||
            !read_process_u32(args[2], size)) {
            return;
        }

        log_protection_overlap_common(
            context,
            target,
            static_cast<std::uintptr_t>(base),
            static_cast<std::uintptr_t>(size),
            args[3],
            args[4],
            args[0]);
        break;
    }

    default:
        break;
    }
#else
    (void)context;
    (void)target;
#endif
}

std::uintptr_t guess_call_site(std::uintptr_t return_address) {
    if (return_address < 8) {
        return 0;
    }

    std::uint8_t bytes[8]{};
    const auto window = return_address - sizeof(bytes);
    if (!read_code_bytes(window, bytes, sizeof(bytes))) {
        return 0;
    }

    if (bytes[3] == 0xE8) {
        return return_address - 5;
    }

    if (bytes[2] == 0xFF && (bytes[3] & 0x38) == 0x10) {
        return return_address - 6;
    }

    if (bytes[5] == 0xFF && (bytes[6] & 0x38) == 0x10) {
        return return_address - 3;
    }

    if (bytes[6] == 0xFF && (bytes[7] & 0x38) == 0x10) {
        return return_address - 2;
    }

    return return_address;
}

void log_caller(const CONTEXT& context, const message_target& target) {
#if defined(_M_IX86)
    if (target.kind == message_target_kind::call_site_a) {
        std::printf(
            "[NDIF] %s call_site=0x%p (%s)\n",
            target.name,
            reinterpret_cast<void*>(target.address),
            describe_address(target.address).c_str());
        return;
    }

    std::uint32_t return_address32 = 0;
    if (!read_stack_u32(context.Esp, 0, return_address32)) {
        std::printf("[NDIF] %s caller=<unreadable>\n", target.name);
        return;
    }

    const auto return_address = static_cast<std::uintptr_t>(return_address32);
    const auto call_site = guess_call_site(return_address);
    std::uint8_t nearby[24]{};
    const auto nearby_base = return_address >= 16 ? return_address - 16 : return_address;
    const bool have_nearby = read_code_bytes(nearby_base, nearby, sizeof(nearby));

    std::printf(
        "[NDIF] %s caller_return=0x%p (%s) call_site=0x%p (%s)\n",
        target.name,
        reinterpret_cast<void*>(return_address),
        describe_address(return_address).c_str(),
        reinterpret_cast<void*>(call_site),
        describe_address(call_site).c_str());

    if (have_nearby) {
        std::printf(
            "[NDIF] %s caller_bytes base=0x%p: "
            "%02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X\n",
            target.name,
            reinterpret_cast<void*>(nearby_base),
            nearby[0], nearby[1], nearby[2], nearby[3],
            nearby[4], nearby[5], nearby[6], nearby[7],
            nearby[8], nearby[9], nearby[10], nearby[11],
            nearby[12], nearby[13], nearby[14], nearby[15],
            nearby[16], nearby[17], nearby[18], nearby[19],
            nearby[20], nearby[21], nearby[22], nearby[23]);
    }
#else
    (void)context;
    (void)target;
#endif
}

void log_message_box_w(const CONTEXT& context, const message_target& target) {
#if defined(_M_IX86)
    std::uint32_t args[4]{};
    if (!read_message_box_args(context, message_box_arg_stack_offset(target.kind), args)) {
        OutputDebugStringW(L"[NDIF] MessageBoxW: unable to read arguments\n");
        return;
    }

    const std::wstring caption = read_wstring(args[2]);
    const std::wstring text = read_wstring(args[1]);

    std::wstring line = L"[NDIF] MessageBoxW [" + caption + L"] " + text + L"\n";
    OutputDebugStringW(line.c_str());

    log_caller(context, target);
    std::printf(
        "[NDIF] %s target=0x%p type=0x%08lx hwnd=0x%08lx text=\"%ls\" caption=\"%ls\"\n",
        target.name,
        reinterpret_cast<void*>(target.address),
        static_cast<unsigned long>(args[3]),
        static_cast<unsigned long>(args[0]),
        text.c_str(),
        caption.c_str());
#else
    (void)context;
    (void)target;
    OutputDebugStringA("[NDIF] MessageBoxW hook requires a Win32 build\n");
#endif
}

void log_message_box_a(const CONTEXT& context, const message_target& target) {
#if defined(_M_IX86)
    std::uint32_t args[4]{};
    if (!read_message_box_args(context, message_box_arg_stack_offset(target.kind), args)) {
        OutputDebugStringA("[NDIF] MessageBoxA: unable to read arguments\n");
        return;
    }

    const std::string caption = read_astring(args[2]);
    const std::string text = read_astring(args[1]);

    OutputDebugStringA(("[NDIF] MessageBoxA [" + caption + "] " + text + "\n").c_str());
    log_caller(context, target);
    std::printf(
        "[NDIF] %s target=0x%p type=0x%08lx hwnd=0x%08lx text=\"%s\" caption=\"%s\"\n",
        target.name,
        reinterpret_cast<void*>(target.address),
        static_cast<unsigned long>(args[3]),
        static_cast<unsigned long>(args[0]),
        text.c_str(),
        caption.c_str());
#else
    (void)context;
    (void)target;
    OutputDebugStringA("[NDIF] MessageBoxA hook requires a Win32 build\n");
#endif
}

void log_message_box_hit(const CONTEXT& context, const message_target& target) {
    if ((target.kind == message_target_kind::api_a ||
            target.kind == message_target_kind::api_w) &&
        !is_filtered_message_box_api_hit(context)) {
        return;
    }

    if (target.kind == message_target_kind::api_a ||
        target.kind == message_target_kind::api_w) {
        log_target_guard_status();
    }

    if (target.kind == message_target_kind::api_a ||
        target.kind == message_target_kind::call_site_a) {
        log_message_box_a(context, target);
        return;
    }

    log_message_box_w(context, target);
}

void log_generic_hit(const CONTEXT& context, const message_target& target) {
#if defined(_M_IX86)
    std::printf(
        "[NDIF] %s hit ip=0x%p (%s) esp=0x%08lx ebp=0x%08lx eax=0x%08lx ecx=0x%08lx edx=0x%08lx\n",
        target.name,
        reinterpret_cast<void*>(context.Eip),
        describe_address(static_cast<std::uintptr_t>(context.Eip)).c_str(),
        static_cast<unsigned long>(context.Esp),
        static_cast<unsigned long>(context.Ebp),
        static_cast<unsigned long>(context.Eax),
        static_cast<unsigned long>(context.Ecx),
        static_cast<unsigned long>(context.Edx));
#else
    (void)context;
    std::printf("[NDIF] %s hit target=0x%p\n", target.name, reinterpret_cast<void*>(target.address));
#endif
}

int install_instrumentation(
    instruction_callback_backend backend = instruction_callback_backend::guard_page_translation,
    std::uintptr_t target_rva = kMessageBoxPostCallRva) {
#if !defined(_M_IX86)
    OutputDebugStringA("[NDIF] Build this DLL as Win32 for the target\n");
    return 0;
#else
    const auto module_base = reinterpret_cast<std::uintptr_t>(
        GetModuleHandleW(nullptr));
    std::vector<message_target> targets;
    add_target(
        targets,
        message_target{
            module_base + target_rva,
            message_target_kind::generic_entry,
            "target!MessageBoxA-post-call",
        });
    add_message_box_api_targets(targets);

    dbi_framework_options options{};
    options.enable_plugins = false;
    options.instruction_backend = backend;
    options.log_callback = [](const char* message) {
        if (message != nullptr) {
            std::printf("%s", message);
        }
    };

    g_ndif = new dbi_framework();
    if (!g_ndif->initialize(options)) {
        std::printf("[NDIF] framework initialization failed\n");
        return 0;
    }

    std::vector<message_target> registered_targets;
    for (const auto& target : targets) {
        log_entry_bytes(target.name, target.address);

        const int status = g_ndif->instrument_instruction_with_status(target.address);
        if (status == instrumentation_status::success) {
            registered_targets.push_back(target);
            std::printf(
                "[NDIF] registered %s=0x%p\n",
                target.name,
                reinterpret_cast<void*>(target.address));
            continue;
        }

        std::printf(
            "[NDIF] failed to register %s=0x%p: status=%d error=%s\n",
            target.name,
            reinterpret_cast<void*>(target.address),
            status,
            g_ndif->last_instruction_error());
    }

    if (registered_targets.empty()) {
        std::printf("[NDIF] no instrumentation targets registered\n");
        return 0;
    }

    if (!g_ndif->add_instruction_callback(
            [registered_targets](CONTEXT& context, std::uintptr_t ip) {
                for (const auto& target : registered_targets) {
                    if (ip == target.address) {
                        if (target.kind == message_target_kind::generic_entry) {
                            log_generic_hit(context, target);
                            return;
                        }
                        if (is_protection_target(target.kind)) {
                            log_protection_hit(context, target);
                            return;
                        }

                        log_message_box_hit(context, target);
                        return;
                    }
                }
            }) ||
        !g_ndif->enable_instruction_callbacks()) {
        std::printf(
            "[NDIF] failed to enable callbacks: %s\n",
            g_ndif->last_instruction_error());
        return 0;
    }

    g_instrumentation_active = true;
    start_protection_monitor();

    std::printf(
        "[NDIF] entry instrumentation active: backend=%u targets=%zu\n",
        static_cast<unsigned>(backend),
        registered_targets.size());
    return 1;
#endif
}

DWORD WINAPI start_thread(LPVOID) {
    create_console("NDIF MessageBox Logger");

    HANDLE pipe = INVALID_HANDLE_VALUE;
    const std::wstring pipe_name = build_pipe_name();
    for (int attempt = 0; attempt < 160; ++attempt) {
        pipe = CreateFileW(
            pipe_name.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            break;
        }
        Sleep(50);
    }

    if (pipe == INVALID_HANDLE_VALUE) {
        OutputDebugStringA("[NDIF] controller pipe unavailable; use exported start() for standalone mode\n");
        return 0;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    dbi_ipc::hello_payload hello{};
    hello.pid = GetCurrentProcessId();
    hello.plugin_api_version = dbi_plugin_api_version;
    hello.core_version_major = dbi_core::version_major;
    hello.core_version_minor = dbi_core::version_minor;
    hello.core_version_patch = dbi_core::version_patch;
    if (!write_message(pipe, dbi_ipc::message_type::hello, hello)) {
        CloseHandle(pipe);
        return 0;
    }

    dbi_ipc::message_header header{};
    dbi_ipc::start_instrument_v2_payload request{};
    if (!read_exact(pipe, &header, sizeof(header)) ||
        header.magic != dbi_ipc::message_magic ||
        header.version != dbi_ipc::protocol_version ||
        header.type != static_cast<std::uint16_t>(dbi_ipc::message_type::start_instrument_v2) ||
        header.payload_size != sizeof(request) ||
        !read_exact(pipe, &request, sizeof(request))) {
        CloseHandle(pipe);
        return 0;
    }

    dbi_ipc::ack_payload ack{};
    if (request.target_count > dbi_ipc::max_instrument_targets) {
        ack.status_code = ERROR_INVALID_PARAMETER;
        std::snprintf(ack.message, sizeof(ack.message), "invalid instrumentation target count");
    } else {
        const auto backend = decode_backend(request.backend);
        const int installed = install_instrumentation(backend);
        ack.status_code = installed ? ERROR_SUCCESS : ERROR_GEN_FAILURE;
        std::snprintf(
            ack.message,
            sizeof(ack.message),
            "MessageBox-only backend start backend=%u",
            request.backend);
    }

    write_message(pipe, dbi_ipc::message_type::ack, ack);
    CloseHandle(pipe);
    return ack.status_code == ERROR_SUCCESS ? 1 : 0;
}

} // namespace

extern "C" __declspec(dllexport) int start() {
    return install_instrumentation();
}

extern "C" __declspec(dllexport) void stop() {
    g_monitor_running.store(false, std::memory_order_release);
    if (g_ndif != nullptr) {
        if (g_instrumentation_active) {
            g_ndif->disable_instruction_callbacks();
            g_instrumentation_active = false;
        }
        delete g_ndif;
        g_ndif = nullptr;
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        // NDIF setup is deferred so it does not run under the loader lock.
        HANDLE thread = CreateThread(nullptr, 0, start_thread, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
