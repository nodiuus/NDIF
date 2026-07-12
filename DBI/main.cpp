#include "basic_block_code_cache.h"
#include "dynamic_binary_instrumentor.h"
#include "dbi_framework.h"
#include "external_process_instrumentor.h"
#include "live_patch_framework.h"
#include "dbi_host.h"
#include "core/dbi_core_version.h"
#include "core/dbi_ipc_protocol.h"
#include "injection.h"
#include "staged_agent_backend.h"

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <TlHelp32.h>

#include <Zydis/Zydis.h>

#pragma optimize("", off)
__declspec(noinline) int demo_target(int x) {
    int value = (x * 3) + 7;
    if ((value % 5) == 0) {
        value ^= 0x2A;
    }

    return value + 1;
}

namespace {
__declspec(noinline) int patch_me(int x) {
    return x + 1;
}

std::wstring get_self_image_path() {
    wchar_t path[MAX_PATH]{};
    const DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    return std::wstring(path, path + len);
}

std::string wide_to_utf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }

    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) {
        return {};
    }

    std::string result(static_cast<std::size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size - 1, nullptr, nullptr);
    return result;
}

bool try_parse_u64(const wchar_t* text, std::uint64_t& value) {
    if (text == nullptr || *text == L'\0') {
        return false;
    }

    wchar_t* end = nullptr;
    value = _wcstoui64(text, &end, 0);
    return end != nullptr && *end == L'\0';
}

bool try_parse_ptr(const wchar_t* text, std::uintptr_t& value) {
    std::uint64_t temp = 0;
    if (!try_parse_u64(text, temp)) {
        return false;
    }
    value = static_cast<std::uintptr_t>(temp);
    return true;
}

using translated_demo_fn = int(__cdecl*)(int);

std::string to_lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](char c) {
        if (c >= 'A' && c <= 'Z') {
            return static_cast<char>(c - 'A' + 'a');
        }
        return c;
    });
    return value;
}

bool arg_is(const wchar_t* value, std::initializer_list<const wchar_t*> options) {
    if (value == nullptr) {
        return false;
    }

    for (const wchar_t* option : options) {
        if (option != nullptr && std::wcscmp(value, option) == 0) {
            return true;
        }
    }
    return false;
}

bool has_dll_extension(const std::wstring& value) {
    constexpr wchar_t suffix[] = L".dll";
    constexpr std::size_t suffix_len = (sizeof(suffix) / sizeof(suffix[0])) - 1;
    if (value.size() < suffix_len) {
        return false;
    }
    return _wcsicmp(value.c_str() + (value.size() - suffix_len), suffix) == 0;
}

std::wstring with_dll_extension(const std::wstring& value) {
    return has_dll_extension(value) ? value : (value + L".dll");
}

std::wstring resolve_plugin_argument(const std::wstring& plugins_dir, const std::wstring& raw_value) {
    if (raw_value.empty()) {
        return raw_value;
    }

    const bool looks_like_path =
        raw_value.find(L'\\') != std::wstring::npos ||
        raw_value.find(L'/') != std::wstring::npos ||
        raw_value.find(L':') != std::wstring::npos;

    const std::filesystem::path raw_path(raw_value);
    if (looks_like_path) {
        if (std::filesystem::exists(raw_path)) {
            return raw_value;
        }
        if (!has_dll_extension(raw_value)) {
            const std::filesystem::path raw_with_dll(raw_value + L".dll");
            if (std::filesystem::exists(raw_with_dll)) {
                return raw_with_dll.wstring();
            }
        }
        return raw_value;
    }

    if (std::filesystem::exists(raw_path)) {
        return raw_value;
    }

    const std::wstring short_name = with_dll_extension(raw_value);
    const std::filesystem::path from_plugins = std::filesystem::path(plugins_dir) / short_name;
    if (std::filesystem::exists(from_plugins)) {
        return from_plugins.wstring();
    }

    return short_name;
}

std::wstring file_name_of(const std::wstring& path) {
    const std::size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

bool section_name_matches(const IMAGE_SECTION_HEADER& section, const std::wstring& wanted_name) {
    char section_name_raw[9]{};
    std::memcpy(section_name_raw, section.Name, 8);

    const std::string section_name = to_lower_ascii(std::string(section_name_raw));
    const std::string wanted = to_lower_ascii(wide_to_utf8(wanted_name));
    if (section_name.empty() || wanted.empty()) {
        return false;
    }

    if (section_name == wanted) {
        return true;
    }
    if (!section_name.empty() && section_name[0] == '.' && section_name.substr(1) == wanted) {
        return true;
    }
    if (!wanted.empty() && wanted[0] == '.' && wanted.substr(1) == section_name) {
        return true;
    }

    return false;
}

bool try_find_module_for_pid(
    DWORD pid,
    const wchar_t* module_selector,
    std::uintptr_t& out_module_base,
    std::wstring& out_module_path,
    std::wstring& out_module_name) {

    out_module_base = 0;
    out_module_path.clear();
    out_module_name.clear();

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    MODULEENTRY32W module_entry{};
    module_entry.dwSize = sizeof(module_entry);
    if (!Module32FirstW(snapshot, &module_entry)) {
        CloseHandle(snapshot);
        return false;
    }

    const bool use_selector = module_selector != nullptr && module_selector[0] != L'\0';
    const std::wstring selector = use_selector ? module_selector : L"";
    const std::wstring selector_base = use_selector ? file_name_of(selector) : L"";

    bool found = false;
    do {
        if (!use_selector) {
            found = true;
        } else {
            const bool match_name = _wcsicmp(module_entry.szModule, selector.c_str()) == 0;
            const bool match_full = _wcsicmp(module_entry.szExePath, selector.c_str()) == 0;
            const bool match_base = _wcsicmp(file_name_of(module_entry.szExePath).c_str(), selector_base.c_str()) == 0;
            found = match_name || match_full || match_base;
        }

        if (found) {
            out_module_base = reinterpret_cast<std::uintptr_t>(module_entry.modBaseAddr);
            out_module_path = module_entry.szExePath;
            out_module_name = module_entry.szModule;
            break;
        }
    } while (Module32NextW(snapshot, &module_entry));

    CloseHandle(snapshot);
    return found;
}

bool try_resolve_module_section_region(
    DWORD pid,
    const wchar_t* module_selector,
    const wchar_t* section_name,
    std::uintptr_t& out_region_start,
    std::size_t& out_region_size,
    std::wstring& out_module_name,
    std::wstring& out_module_path) {

    out_region_start = 0;
    out_region_size = 0;
    out_module_name.clear();
    out_module_path.clear();

    std::uintptr_t module_base = 0;
    if (!try_find_module_for_pid(pid, module_selector, module_base, out_module_path, out_module_name)) {
        return false;
    }

    std::ifstream file(std::filesystem::path(out_module_path), std::ios::binary);
    if (!file) {
        return false;
    }

    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (!file || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        return false;
    }

    file.seekg(dos.e_lfanew, std::ios::beg);

    std::uint32_t signature = 0;
    file.read(reinterpret_cast<char*>(&signature), sizeof(signature));
    if (!file || signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    IMAGE_FILE_HEADER file_header{};
    file.read(reinterpret_cast<char*>(&file_header), sizeof(file_header));
    if (!file || file_header.NumberOfSections == 0) {
        return false;
    }

    file.seekg(file_header.SizeOfOptionalHeader, std::ios::cur);

    for (std::size_t i = 0; i < file_header.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER section{};
        file.read(reinterpret_cast<char*>(&section), sizeof(section));
        if (!file) {
            return false;
        }

        if (!section_name_matches(section, section_name)) {
            continue;
        }

        std::size_t resolved_size = section.Misc.VirtualSize;
        if (resolved_size == 0) {
            resolved_size = section.SizeOfRawData;
        }
        if (resolved_size == 0) {
            return false;
        }

        out_region_start = module_base + static_cast<std::uintptr_t>(section.VirtualAddress);
        out_region_size = resolved_size;
        return true;
    }

    return false;
}

std::wstring directory_of(const std::wstring& path) {
    const std::size_t pos = path.find_last_of(L"\\/");
    if (pos == std::wstring::npos) {
        return L".";
    }
    return path.substr(0, pos);
}

std::wstring join_path(const std::wstring& left, const std::wstring& right) {
    if (left.empty()) {
        return right;
    }
    if (left.back() == L'\\' || left.back() == L'/') {
        return left + right;
    }
    return left + L"\\" + right;
}

bool file_exists(const std::wstring& path) {
    const DWORD attrs = GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

std::wstring parent_directory_of(const std::wstring& path) {
    return directory_of(path);
}

std::wstring resolve_agent_dll_path() {
    const std::wstring exe_dir = directory_of(get_self_image_path());

    std::vector<std::wstring> candidates{};
    candidates.push_back(join_path(exe_dir, L"dbi_agent.dll"));

    const std::wstring platform_dir = parent_directory_of(exe_dir);
    const std::wstring project_dir = parent_directory_of(platform_dir);
    const std::wstring repo_dir = parent_directory_of(project_dir);
    if (!repo_dir.empty()) {
        candidates.push_back(join_path(join_path(join_path(repo_dir, L"x64"), L"Debug"), L"dbi_agent.dll"));
        candidates.push_back(join_path(join_path(join_path(repo_dir, L"x64"), L"Release"), L"dbi_agent.dll"));
    }

    for (const std::wstring& candidate : candidates) {
        if (file_exists(candidate)) {
            return candidate;
        }
    }

    return candidates.front();
}

std::wstring build_agent_pipe_name(DWORD pid) {
    wchar_t buffer[128]{};
    _snwprintf_s(buffer, _countof(buffer), _TRUNCATE, L"\\\\.\\pipe\\dbi_agent_%lu", pid);
    return std::wstring(buffer);
}

bool pipe_write_exact(HANDLE pipe, const void* data, std::size_t size) {
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE || data == nullptr || size == 0) {
        return false;
    }

    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t written_total = 0;
    while (written_total < size) {
        DWORD written = 0;
        const BOOL ok = WriteFile(
            pipe,
            bytes + written_total,
            static_cast<DWORD>(size - written_total),
            &written,
            nullptr);
        if (!ok || written == 0) {
            return false;
        }
        written_total += written;
    }

    return true;
}

bool pipe_read_exact(HANDLE pipe, void* data, std::size_t size) {
    if (pipe == nullptr || pipe == INVALID_HANDLE_VALUE || data == nullptr || size == 0) {
        return false;
    }

    auto* bytes = static_cast<std::uint8_t*>(data);
    std::size_t read_total = 0;
    while (read_total < size) {
        DWORD read = 0;
        const BOOL ok = ReadFile(
            pipe,
            bytes + read_total,
            static_cast<DWORD>(size - read_total),
            &read,
            nullptr);
        if (!ok || read == 0) {
            return false;
        }
        read_total += read;
    }

    return true;
}

template <typename PayloadT>
bool pipe_write_message(HANDLE pipe, dbi_ipc::message_type type, const PayloadT& payload) {
    dbi_ipc::message_header header{};
    header.type = static_cast<std::uint16_t>(type);
    header.payload_size = static_cast<std::uint32_t>(sizeof(PayloadT));
    return pipe_write_exact(pipe, &header, sizeof(header)) &&
           pipe_write_exact(pipe, &payload, sizeof(payload));
}

int run_inject_agent(int argc, wchar_t* argv[]) {
    if (argc < 2 || argc > 4) {
        std::wcerr << L"usage: DBI.exe --inject-agent|--inject|-i <pid>\n";
        std::wcerr << L"   or: DBI.exe --inject-agent|--inject|-i <pid> <section_name>\n";
        std::wcerr << L"   or: DBI.exe --inject-agent|--inject|-i <pid> <module_name> <section_name>\n";
        return 1;
    }

    std::uint64_t pid64 = 0;
    if (!try_parse_u64(argv[1], pid64)) {
        std::wcerr << L"failed to parse pid\n";
        return 1;
    }

    const DWORD pid = static_cast<DWORD>(pid64);
    std::wstring module_name{};
    std::wstring section_name{};
    if (argc == 3) {
        section_name = argv[2];
    } else if (argc == 4) {
        module_name = argv[2];
        section_name = argv[3];
    }

    const std::wstring agent_path = resolve_agent_dll_path();
    const std::wstring pipe_name = build_agent_pipe_name(pid);

    HANDLE pipe = CreateNamedPipeW(
        pipe_name.c_str(),
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        4096,
        4096,
        5000,
        nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        std::wcerr << L"failed to create agent pipe\n";
        return 1;
    }

    if (!injection::inject_dll_via_loadlibrary(pid, agent_path)) {
        CloseHandle(pipe);
        std::wcerr << L"failed to inject dbi_agent.dll into pid " << pid << L" path=" << agent_path << L"\n";
        return 1;
    }

    const BOOL connected = ConnectNamedPipe(pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
    if (!connected) {
        CloseHandle(pipe);
        std::wcerr << L"agent pipe connection failed\n";
        return 1;
    }

    dbi_ipc::message_header hello_header{};
    dbi_ipc::hello_payload hello{};
    if (!pipe_read_exact(pipe, &hello_header, sizeof(hello_header)) ||
        !pipe_read_exact(pipe, &hello, sizeof(hello))) {
        CloseHandle(pipe);
        std::wcerr << L"failed to read agent hello message\n";
        return 1;
    }

    if (hello_header.magic != dbi_ipc::message_magic ||
        hello_header.version != dbi_ipc::protocol_version ||
        hello_header.type != static_cast<std::uint16_t>(dbi_ipc::message_type::hello) ||
        hello_header.payload_size != sizeof(dbi_ipc::hello_payload)) {
        CloseHandle(pipe);
        std::wcerr << L"agent hello message validation failed\n";
        return 1;
    }

    std::wcout << L"agent connected: pid=" << hello.pid
               << L" plugin_api_v=" << hello.plugin_api_version
               << L" core_v=" << hello.core_version_major << L"." << hello.core_version_minor << L"." << hello.core_version_patch
               << L"\n";

    dbi_ipc::start_instrument_payload start{};
    if (!module_name.empty()) {
        wcsncpy_s(start.module_name, module_name.c_str(), _TRUNCATE);
    }
    if (!section_name.empty()) {
        wcsncpy_s(start.section_name, section_name.c_str(), _TRUNCATE);
    }

    if (!pipe_write_message(pipe, dbi_ipc::message_type::start_instrument, start)) {
        CloseHandle(pipe);
        std::wcerr << L"failed to send start command to agent\n";
        return 1;
    }

    dbi_ipc::message_header ack_header{};
    dbi_ipc::ack_payload ack{};
    if (!pipe_read_exact(pipe, &ack_header, sizeof(ack_header)) ||
        !pipe_read_exact(pipe, &ack, sizeof(ack))) {
        CloseHandle(pipe);
        std::wcerr << L"failed to read agent ACK\n";
        return 1;
    }

    if (ack_header.magic != dbi_ipc::message_magic ||
        ack_header.version != dbi_ipc::protocol_version ||
        ack_header.type != static_cast<std::uint16_t>(dbi_ipc::message_type::ack) ||
        ack_header.payload_size != sizeof(dbi_ipc::ack_payload)) {
        CloseHandle(pipe);
        std::wcerr << L"agent ACK validation failed\n";
        return 1;
    }

    std::cout << "agent ACK: status=" << ack.status_code << " message=" << ack.message << "\n";
    CloseHandle(pipe);
    return ack.status_code == 0 ? 0 : 1;
}

int run_in_process_demo(plugin_manager& plugins) {
    dynamic_binary_instrumentor dbii{};
    std::unordered_map<std::uintptr_t, std::size_t> hit_counts{};
    std::mutex hit_lock{};

    const DWORD self_pid = GetCurrentProcessId();
    plugins.on_process_start(self_pid, get_self_image_path());

    const auto demo_entry = reinterpret_cast<std::uintptr_t>(&demo_target);
    std::uintptr_t demo_start = demo_entry;
    const auto entry_byte = *reinterpret_cast<volatile std::uint8_t*>(demo_entry);
    if (entry_byte == 0xE9) {
        const auto disp = *reinterpret_cast<volatile std::int32_t*>(demo_entry + 1);
        demo_start = demo_entry + 5 + static_cast<std::int64_t>(disp);
    }
    constexpr std::size_t demo_region_size = 256;
    if (!dbii.add_region(reinterpret_cast<void*>(demo_start), demo_region_size)) {
        std::cerr << "failed to register target region\n";
        return 1;
    }

    const bool installed = dbii.install(
        [&](const instrumented_instruction& instruction, CONTEXT&) {
            plugins.on_instruction_hit(GetCurrentProcessId(), instruction.address);
            if (instruction.is_control_flow) {
                plugins.on_branch_hit(GetCurrentProcessId(), instruction.address, ZydisMnemonicGetString(instruction.mnemonic), instruction.length);
            }
            std::lock_guard<std::mutex> guard(hit_lock);
            ++hit_counts[instruction.address];
        });

    if (!installed) {
        std::cerr << "failed to install instrumentation\n";
        return 1;
    }

    int total = 0;
    for (int i = 0; i < 2000; ++i) {
        total += demo_target(i);
    }

    dbii.uninstall();

    plugins.on_process_exit(self_pid, 0);

    std::vector<std::pair<std::uintptr_t, std::size_t>> sorted_hits(hit_counts.begin(), hit_counts.end());
    std::sort(
        sorted_hits.begin(),
        sorted_hits.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.second > rhs.second;
        });

    std::wcout << L"demo total: " << total << L"\n";
    std::wcout << L"demo_target addr: 0x" << std::hex << demo_entry << std::dec << L"\n";
    std::wcout << L"demo_target start: 0x" << std::hex << demo_start << std::dec << L"\n";
    std::wcout << L"instrumented instruction hits (top 10):\n";
    for (std::size_t i = 0; i < std::min<std::size_t>(sorted_hits.size(), 10); ++i) {
        std::wcout << L"  0x" << std::hex << sorted_hits[i].first << std::dec << L" -> " << sorted_hits[i].second << L"\n";
    }

    return 0;
}

int run_external_executable(int argc, wchar_t* argv[], plugin_manager& plugins) {
    if (argc < 1) {
        return 1;
    }

    const std::wstring executable = argv[0];
    std::vector<std::wstring> arguments{};
    for (int i = 1; i < argc; ++i) {
        arguments.emplace_back(argv[i]);
    }

    external_process_instrumentor instrumentor{};
    external_instrumentation_result result{};

    constexpr std::size_t entry_region_size = 192;
    external_process_instrumentor::callbacks callbacks{};
    callbacks.on_process_start = [&](DWORD pid) { plugins.on_process_start(pid, executable); };
    callbacks.on_process_exit = [&](DWORD pid, DWORD exit_code) { plugins.on_process_exit(pid, exit_code); };
    callbacks.on_instruction_hit = [&](DWORD pid, std::uintptr_t address) { plugins.on_instruction_hit(pid, address); };
    callbacks.on_branch_hit = [&](DWORD pid, std::uintptr_t address, ZydisMnemonic mnemonic, std::uint8_t length) {
        plugins.on_branch_hit(pid, address, ZydisMnemonicGetString(mnemonic), length);
    };
    if (!instrumentor.run_at_entry(
            executable,
            arguments,
            entry_region_size,
            result,
            callbacks)) {
        std::wcerr << L"failed to instrument executable: " << executable << L"\n";
        return 1;
    }

    std::vector<std::pair<std::uintptr_t, std::size_t>> sorted_hits(result.hit_counts.begin(), result.hit_counts.end());
    std::sort(
        sorted_hits.begin(),
        sorted_hits.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.second > rhs.second;
        });

    std::wcout << L"target exit code: " << result.process_exit_code << L"\n";
    std::wcout << L"instrumented instruction hits (top 15):\n";
    for (std::size_t i = 0; i < std::min<std::size_t>(sorted_hits.size(), 15); ++i) {
        std::wcout << L"  0x" << std::hex << sorted_hits[i].first << std::dec << L" -> " << sorted_hits[i].second << L"\n";
    }

    return 0;
}

int run_attach_instrument(int argc, wchar_t* argv[], plugin_manager& plugins) {
    if (argc < 3) {
        std::wcerr << L"usage: DBI.exe --attach-instrument|--attach|-a <pid> <region_start> <region_size>\n";
        std::wcerr << L"   or: DBI.exe --attach-instrument|--attach|-a <pid> <section_name>\n";
        std::wcerr << L"   or: DBI.exe --attach-instrument|--attach|-a <pid> <module_name> <section_name>\n";
        return 1;
    }

    std::uint64_t pid64 = 0;
    if (!try_parse_u64(argv[1], pid64)) {
        std::wcerr << L"failed to parse pid\n";
        return 1;
    }

    std::uintptr_t region_start = 0;
    std::size_t region_size = 0;

    std::uint64_t region_size64 = 0;
    const bool has_numeric_region = argc >= 4 && try_parse_ptr(argv[2], region_start) && try_parse_u64(argv[3], region_size64);
    if (has_numeric_region) {
        region_size = static_cast<std::size_t>(region_size64);
    } else {
        const wchar_t* module_name = nullptr;
        const wchar_t* section_name = nullptr;
        if (argc == 3) {
            section_name = argv[2];
        } else {
            module_name = argv[2];
            section_name = argv[3];
        }

        std::wstring resolved_module_name{};
        std::wstring resolved_module_path{};
        if (!try_resolve_module_section_region(
                static_cast<DWORD>(pid64),
                module_name,
                section_name,
                region_start,
                region_size,
                resolved_module_name,
                resolved_module_path)) {
            std::wcerr << L"failed to resolve section `" << section_name << L"`";
            if (module_name != nullptr) {
                std::wcerr << L" in module `" << module_name << L"`";
            }
            std::wcerr << L"\n";
            return 1;
        }

        std::wcout << L"resolved attach region: module=" << resolved_module_name
                   << L" section=" << section_name
                   << L" start=0x" << std::hex << region_start << std::dec
                   << L" size=0x" << std::hex << region_size << std::dec << L"\n";
    }

    if (region_start == 0 || region_size == 0) {
        std::wcerr << L"resolved region is empty\n";
        return 1;
    }

    external_process_instrumentor instrumentor{};
    external_instrumentation_result result{};
    external_process_instrumentor::callbacks callbacks{};
    callbacks.on_process_start = [&](DWORD attached_pid) { plugins.on_process_start(attached_pid, L""); };
    callbacks.on_process_exit = [&](DWORD attached_pid, DWORD exit_code) { plugins.on_process_exit(attached_pid, exit_code); };
    callbacks.on_instruction_hit = [&](DWORD hit_pid, std::uintptr_t address) { plugins.on_instruction_hit(hit_pid, address); };
    callbacks.on_branch_hit = [&](DWORD pid, std::uintptr_t address, ZydisMnemonic mnemonic, std::uint8_t length) {
        plugins.on_branch_hit(pid, address, ZydisMnemonicGetString(mnemonic), length);
    };
    if (!instrumentor.attach_and_instrument(
            static_cast<DWORD>(pid64),
            region_start,
            region_size,
            result,
            30000,
            callbacks)) {
        std::wcerr << L"attach/instrument failed\n";
        return 1;
    }

    std::vector<std::pair<std::uintptr_t, std::size_t>> sorted_hits(result.hit_counts.begin(), result.hit_counts.end());
    std::sort(sorted_hits.begin(), sorted_hits.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

    std::wcout << L"instrumented instruction hits (top 15):\n";
    for (std::size_t i = 0; i < std::min<std::size_t>(sorted_hits.size(), 15); ++i) {
        std::wcout << L"  0x" << std::hex << sorted_hits[i].first << std::dec << L" -> " << sorted_hits[i].second << L"\n";
    }

    return 0;
}

int run_patch_bytes(int argc, wchar_t* argv[]) {
    if (argc < 4) {
        std::wcerr << L"usage: DBI.exe --patch-bytes <pid> <address> <hexbytes>\n";
        std::wcerr << L"example: DBI.exe --patch-bytes 1234 0x7ff6deadbieef CC90\n";
        return 1;
    }

    std::uint64_t pid64 = 0;
    std::uintptr_t address = 0;
    if (!try_parse_u64(argv[1], pid64) || !try_parse_ptr(argv[2], address)) {
        std::wcerr << L"failed to parse pid/address\n";
        return 1;
    }

    std::wstring hex = argv[3];
    hex.erase(std::remove_if(hex.begin(), hex.end(), [](wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\n' || ch == L'\r'; }), hex.end());
    if ((hex.size() % 2) != 0) {
        std::wcerr << L"hexbytes must have even length\n";
        return 1;
    }

    std::vector<std::uint8_t> bytes{};
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const auto hi = hex[i];
        const auto lo = hex[i + 1];
        auto nibble = [](wchar_t c) -> int {
            if (c >= L'0' && c <= L'9') return c - L'0';
            if (c >= L'a' && c <= L'f') return 10 + (c - L'a');
            if (c >= L'A' && c <= L'F') return 10 + (c - L'A');
            return -1;
        };
        const int n1 = nibble(hi);
        const int n2 = nibble(lo);
        if (n1 < 0 || n2 < 0) {
            std::wcerr << L"invalid hex digit\n";
            return 1;
        }
        bytes.push_back(static_cast<std::uint8_t>((n1 << 4) | n2));
    }

    live_patch_framework patcher{};
    if (!patcher.attach(static_cast<DWORD>(pid64))) {
        std::wcerr << L"failed to open target process\n";
        return 1;
    }

    std::uint64_t patch_id = 0;
    if (!patcher.write_patch(address, bytes, patch_id)) {
        std::wcerr << L"patch failed\n";
        return 1;
    }

    std::wcout << L"patch_id=" << patch_id << L"\n";
    return 0;
}

int run_patch_nops(int argc, wchar_t* argv[]) {
    if (argc < 4) {
        std::wcerr << L"usage: DBI.exe --patch-nop <pid> <address> <count>\n";
        return 1;
    }

    std::uint64_t pid64 = 0;
    std::uintptr_t address = 0;
    std::uint64_t count64 = 0;
    if (!try_parse_u64(argv[1], pid64) || !try_parse_ptr(argv[2], address) || !try_parse_u64(argv[3], count64)) {
        std::wcerr << L"failed to parse args\n";
        return 1;
    }

    live_patch_framework patcher{};
    if (!patcher.attach(static_cast<DWORD>(pid64))) {
        std::wcerr << L"failed to open target process\n";
        return 1;
    }

    std::uint64_t patch_id = 0;
    if (!patcher.write_nop_patch(address, static_cast<std::size_t>(count64), patch_id)) {
        std::wcerr << L"nop patch failed\n";
        return 1;
    }

    std::wcout << L"patch_id=" << patch_id << L"\n";
    return 0;
}

int run_self_patch_demo() {
    live_patch_framework patcher{};
    patcher.use_current_process();

    const int before = patch_me(10);

    // Patch the prologue with `xor eax,eax; ret` -> returns 0 for any input.
    // This is intentionally tiny and doesn't depend on relative branches.
    const std::vector<std::uint8_t> patch = {0x33, 0xC0, 0xC3};
    std::uint64_t patch_id = 0;
    if (!patcher.write_patch(reinterpret_cast<std::uintptr_t>(&patch_me), patch, patch_id)) {
        std::cerr << "self patch failed\n";
        return 1;
    }

    const int during = patch_me(10);

    if (!patcher.remove_patch(patch_id)) {
        std::cerr << "self patch rollback failed\n";
        return 1;
    }

    const int after = patch_me(10);

    std::cout << "self patch demo: before=" << before << " during=" << during << " after=" << after << "\n";
    return 0;
}

int run_instruction_callback_demo(instruction_callback_backend backend = instruction_callback_backend::translated_cache) {
    dbi_framework framework{};
    dbi_framework_options options{};
    options.enable_plugins = false;
    options.instruction_backend = backend;
    if (!framework.initialize(options)) {
        std::cerr << "instruction callback demo: framework init failed\n";
        return 1;
    }

    const auto demo_entry = reinterpret_cast<std::uintptr_t>(&demo_target);
    std::uintptr_t demo_start = demo_entry;
    const auto entry_byte = *reinterpret_cast<volatile std::uint8_t*>(demo_entry);
    if (entry_byte == 0xE9) {
        const auto disp = *reinterpret_cast<volatile std::int32_t*>(demo_entry + 1);
        demo_start = demo_entry + 5 + static_cast<std::int64_t>(disp);
    }
    const int restore_probe_expected = demo_target(11);

    std::size_t hits = 0;
    if (!framework.instrument_instruction(demo_start)) {
        std::cerr << "instruction callback demo: instrument_instruction failed\n";
        return 1;
    }
    if (!framework.add_instruction_callback([&](CONTEXT&, std::uintptr_t ip) {
            if (ip == demo_start) {
                ++hits;
            }
        })) {
        std::cerr << "instruction callback demo: add callback failed\n";
        return 1;
    }
    if (!framework.enable_instruction_callbacks()) {
        std::cerr << "instruction callback demo: enable callbacks failed\n";
        std::cerr << "instruction callback demo: backend error: " << framework.last_instruction_error() << "\n";
        return 1;
    }

    int total = 0;
    const bool explicit_translated_entry =
        backend == instruction_callback_backend::translated_cache ||
        backend == instruction_callback_backend::cooperative_translation;
    translated_demo_fn translated = nullptr;
    if (explicit_translated_entry) {
        translated = framework.translated_function<translated_demo_fn>(demo_start);
        if (translated == nullptr) {
            std::cerr << "instruction callback demo: translated entry failed: " << framework.last_instruction_error() << "\n";
            framework.disable_instruction_callbacks();
            return 1;
        }
    }

    if (backend == instruction_callback_backend::cooperative_translation) {
        const int native_probe = demo_target(7);
        if (hits != 0) {
            std::cerr << "cooperative translation demo: native entry was unexpectedly trapped\n";
            framework.disable_instruction_callbacks();
            return 1;
        }
        std::cout << "cooperative translation demo: native entry untouched, result="
                  << native_probe << "\n";
    }

    for (int i = 0; i < 64; ++i) {
        total += explicit_translated_entry ? translated(i) : demo_target(i);
    }

    framework.disable_instruction_callbacks();

    const std::size_t hits_before_restore_probe = hits;
    const int restore_probe_actual = demo_target(11);
    if (restore_probe_actual != restore_probe_expected || hits != hits_before_restore_probe) {
        std::cerr << "instruction callback demo: backend did not restore native entry cleanly\n";
        return 1;
    }

    const char* backend_name = backend == instruction_callback_backend::translated_cache
        ? "translated_cache"
        : backend == instruction_callback_backend::cooperative_translation
            ? "cooperative_translation"
            : backend == instruction_callback_backend::inline_hook
                ? "inline_hook"
                : backend == instruction_callback_backend::guard_page_translation
                    ? "guard_page_translation"
                    : "dispatcher_code_cache";
    std::cout << "instruction callback demo: backend=" << backend_name
              << " total=" << total << " hits=" << hits << "\n";
    std::cout << "demo_target entry=0x" << std::hex << demo_entry << " start=0x" << demo_start << std::dec << "\n";
    return hits == 64 ? 0 : 1;
}

int run_indirect_redirect_demo() {
    dbi_framework framework{};
    dbi_framework_options options{};
    options.enable_plugins = false;
    options.instruction_backend = instruction_callback_backend::cooperative_translation;
    if (!framework.initialize(options)) {
        std::cerr << "indirect redirect demo: framework init failed\n";
        return 1;
    }

    translated_demo_fn slot = &demo_target;
    const auto original_slot_value = reinterpret_cast<std::uintptr_t>(slot);
    std::size_t hits = 0;

    if (!framework.add_instruction_callback([&](CONTEXT&, std::uintptr_t) {
            ++hits;
        })) {
        std::cerr << "indirect redirect demo: add callback failed\n";
        return 1;
    }

    std::uint64_t redirect_id = 0;
    if (!framework.redirect_indirect_function(&slot, &redirect_id)) {
        std::cerr << "indirect redirect demo: redirect registration failed\n";
        return 1;
    }

    if (!framework.enable_instruction_callbacks()) {
        std::cerr << "indirect redirect demo: enable callbacks failed\n";
        std::cerr << "indirect redirect demo: backend error: " << framework.last_instruction_error() << "\n";
        return 1;
    }

    const auto redirected_slot_value = reinterpret_cast<std::uintptr_t>(slot);
    int total = 0;
    for (int i = 0; i < 64; ++i) {
        total += slot(i);
    }

    if (!framework.restore_indirect_redirect(redirect_id)) {
        std::cerr << "indirect redirect demo: restore failed\n";
        framework.disable_instruction_callbacks();
        return 1;
    }

    const auto restored_slot_value = reinterpret_cast<std::uintptr_t>(slot);
    const int native_check = slot(10);
    framework.disable_instruction_callbacks();

    std::cout << "indirect redirect demo: total=" << total << " hits=" << hits << "\n";
    std::cout << "slot original=0x" << std::hex << original_slot_value
              << " redirected=0x" << redirected_slot_value
              << " restored=0x" << restored_slot_value << std::dec << "\n";

    return hits != 0 &&
           redirected_slot_value != 0 &&
           redirected_slot_value != original_slot_value &&
           restored_slot_value == original_slot_value &&
           native_check == demo_target(10)
        ? 0
        : 1;
}

int run_translated_cache_demo() {
    basic_block_code_cache cache{};
    std::unordered_map<std::uintptr_t, std::size_t> hit_counts{};
    std::mutex hit_lock{};

    if (!cache.add_callback([&](const instrumented_instruction& instruction, CONTEXT&) {
            std::lock_guard<std::mutex> guard(hit_lock);
            ++hit_counts[instruction.address];
        })) {
        std::cerr << "translated cache demo: add callback failed\n";
        return 1;
    }

    const std::uint8_t demo_code[] = {
        0x83, 0xF9, 0x0A,       // cmp ecx, 10
        0x7D, 0x04,             // jge +4
        0x8D, 0x41, 0x01,       // lea eax, [rcx+1]
        0xC3,                   // ret
        0x8D, 0x41, 0x02,       // lea eax, [rcx+2]
        0xC3                    // ret
    };
    const std::uint8_t loop_code[] = {
        0x31, 0xC0,             // xor eax, eax
        0x85, 0xC9,             // test ecx, ecx
        0x7E, 0x06,             // jle +6
        0x01, 0xC8,             // add eax, ecx
        0xFF, 0xC9,             // dec ecx
        0x7F, 0xFA,             // jg -6
        0xC3                    // ret
    };

    void* demo_memory = VirtualAlloc(nullptr, sizeof(demo_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (demo_memory == nullptr) {
        std::cerr << "translated cache demo: VirtualAlloc failed\n";
        return 1;
    }
    std::memcpy(demo_memory, demo_code, sizeof(demo_code));
    FlushInstructionCache(GetCurrentProcess(), demo_memory, sizeof(demo_code));

    void* loop_memory = VirtualAlloc(nullptr, sizeof(loop_code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (loop_memory == nullptr) {
        std::cerr << "translated cache demo: loop VirtualAlloc failed\n";
        VirtualFree(demo_memory, 0, MEM_RELEASE);
        return 1;
    }
    std::memcpy(loop_memory, loop_code, sizeof(loop_code));
    FlushInstructionCache(GetCurrentProcess(), loop_memory, sizeof(loop_code));

    const auto demo_entry = reinterpret_cast<std::uintptr_t>(demo_memory);
    translated_demo_fn native = reinterpret_cast<translated_demo_fn>(demo_memory);
    translated_demo_fn translated = cache.translate_function<translated_demo_fn>(demo_entry);
    if (translated == nullptr) {
        std::cerr << "translated cache demo: translate failed: " << cache.last_error() << "\n";
        VirtualFree(demo_memory, 0, MEM_RELEASE);
        VirtualFree(loop_memory, 0, MEM_RELEASE);
        return 1;
    }

    const auto loop_entry = reinterpret_cast<std::uintptr_t>(loop_memory);
    translated_demo_fn loop_native = reinterpret_cast<translated_demo_fn>(loop_memory);
    translated_demo_fn loop_translated = cache.translate_function<translated_demo_fn>(loop_entry);
    if (loop_translated == nullptr) {
        std::cerr << "translated cache demo: loop translate failed: " << cache.last_error() << "\n";
        VirtualFree(demo_memory, 0, MEM_RELEASE);
        VirtualFree(loop_memory, 0, MEM_RELEASE);
        return 1;
    }

    int native_total = 0;
    int translated_total = 0;
    for (int i = 0; i < 256; ++i) {
        native_total += native(i);
        translated_total += translated(i);
    }

    int loop_native_total = 0;
    int loop_translated_total = 0;
    for (int i = -5; i < 64; ++i) {
        loop_native_total += loop_native(i);
        loop_translated_total += loop_translated(i);
    }

    std::vector<std::pair<std::uintptr_t, std::size_t>> sorted_hits(hit_counts.begin(), hit_counts.end());
    std::sort(
        sorted_hits.begin(),
        sorted_hits.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.second > rhs.second;
        });

    std::cout << "translated cache demo: native_total=" << native_total << " translated_total=" << translated_total << "\n";
    std::cout << "translated cache loop: native_total=" << loop_native_total << " translated_total=" << loop_translated_total << "\n";
    std::cout << "demo_target entry=0x" << std::hex << demo_entry << std::dec << "\n";
    std::cout << "translated instruction hits (top 8):\n";
    for (std::size_t i = 0; i < std::min<std::size_t>(sorted_hits.size(), 8); ++i) {
        std::cout << "  0x" << std::hex << sorted_hits[i].first << std::dec << " -> " << sorted_hits[i].second << "\n";
    }

    const bool ok = native_total == translated_total && loop_native_total == loop_translated_total && !hit_counts.empty();
    VirtualFree(demo_memory, 0, MEM_RELEASE);
    VirtualFree(loop_memory, 0, MEM_RELEASE);
    return ok ? 0 : 1;
}

int run_list_plugins(plugin_manager& plugins) {
    const auto infos = plugins.list_loaded_plugins();
    std::cout << "loaded plugins (" << infos.size() << "):\n";
    for (const auto& info : infos) {
        std::cout << "  - " << info.name;
        if (!info.plugin_version.empty()) {
            std::cout << " @" << info.plugin_version;
        }
        if (!info.author.empty()) {
            std::cout << " by " << info.author;
        }
        std::cout << " (api v" << info.api_version << ")\n";
        if (!info.description.empty()) {
            std::cout << "    " << info.description << "\n";
        }
        if (!info.path.empty()) {
            std::cout << "    " << wide_to_utf8(info.path) << "\n";
        }
    }
    return 0;
}

int run_plugin_command(int argc, wchar_t* argv[], plugin_manager& plugins) {
    if (argc < 2) {
        std::wcerr << L"usage: DBI.exe --cmd|-c <command> [args...]\n";
        return 1;
    }

    const std::string command = wide_to_utf8(argv[1]);
    if (command.empty()) {
        std::wcerr << L"failed to parse command\n";
        return 1;
    }

    std::vector<std::string> args{};
    for (int i = 2; i < argc; ++i) {
        args.push_back(wide_to_utf8(argv[i]));
    }

    int exit_code = 1;
    if (!plugins.dispatch_command(command, args, exit_code)) {
        std::wcerr << L"no plugin handled command: " << argv[1] << L"\n";
        return 1;
    }

    return exit_code;
}

int run_launch_suspended_inject(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcerr << L"usage: DBI.exe --launch-suspended-inject|--lsi <target.exe> [target args...]\n";
        return 1;
    }

    const std::wstring executable_path = argv[1];
    std::vector<std::wstring> target_args{};
    for (int i = 2; i < argc; ++i) {
        target_args.emplace_back(argv[i]);
    }

    DWORD pid = 0;
    constexpr DWORD post_inject_delay_ms = 3000;
    const bool ok = injection::launch_suspended_inject_loader(
        executable_path,
        target_args,
        L"",
        post_inject_delay_ms,
        &pid);

    std::wcout << L"launch suspended inject target=" << executable_path
               << L" loader=Loader.exe"
               << L" pid=" << pid
               << L" post_inject_delay_ms=" << post_inject_delay_ms
               << L" ok=" << (ok ? L"true" : L"false") << L"\n";
    return ok ? 0 : 1;
}

int run_staged_agent(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        std::wcerr << L"usage: DBI.exe --staged-agent <target.exe> [target args...]\n";
        return 1;
    }

    staged_agent_options options{};
    options.executable_path = argv[1];
    options.agent_dll_path = resolve_agent_dll_path();
    for (int i = 2; i < argc; ++i) {
        options.arguments.emplace_back(argv[i]);
    }
    options.on_event = [](const staged_agent_event& event) {
        std::cout << "staged-agent phase=" << static_cast<int>(event.phase)
                  << " pid=" << event.pid
                  << " message=" << event.message << "\n";
    };

    staged_agent_backend backend{};
    staged_agent_result result{};
    const bool ok = backend.run(options, result);
    if (!ok) {
        std::cerr << "staged-agent failed: pid=" << result.pid
                  << " win32_error=" << result.win32_error << "\n";
        return 1;
    }

    std::cout << "staged-agent ready: pid=" << result.pid
              << " agent_status=" << result.agent_status
              << " message=" << result.agent_message << "\n";
    return 0;
}
} // namespace

int wmain(int argc, wchar_t* argv[]) {
    bool enable_plugins = true;
    std::wstring plugins_dir = dbi_host::default_plugins_dir();
    std::vector<std::wstring> explicit_plugin_args{};

    int index = 1;
    while (index < argc) {
        if (arg_is(argv[index], {L"--no-plugins", L"-N"})) {
            enable_plugins = false;
            ++index;
            continue;
        }
        if (arg_is(argv[index], {L"--plugins-dir", L"-P"}) && (index + 1) < argc) {
            plugins_dir = argv[index + 1];
            index += 2;
            continue;
        }
        if (arg_is(argv[index], {L"--plugin", L"-p"}) && (index + 1) < argc) {
            explicit_plugin_args.emplace_back(argv[index + 1]);
            index += 2;
            continue;
        }
        break;
    }

    std::vector<std::wstring> explicit_plugins{};
    explicit_plugins.reserve(explicit_plugin_args.size());
    for (const std::wstring& plugin_arg : explicit_plugin_args) {
        explicit_plugins.emplace_back(resolve_plugin_argument(plugins_dir, plugin_arg));
    }

    dbi_host host{};
    plugin_manager& plugins = host.plugins();
    if (enable_plugins) {
        host.load_plugins(plugins_dir, explicit_plugins);
    }

    const wchar_t* cmd = (index < argc) ? argv[index] : nullptr;
    if (arg_is(cmd, {L"--list-plugins", L"--list", L"-l"})) {
        return run_list_plugins(plugins);
    }
    if (arg_is(cmd, {L"--cmd", L"-c"})) {
        return run_plugin_command(argc - index, argv + index, plugins);
    }
    if (arg_is(cmd, {L"--attach-instrument", L"--attach", L"-a"})) {
        return run_attach_instrument(argc - index, argv + index, plugins);
    }
    if (arg_is(cmd, {L"--inject-agent", L"--inject", L"-i"})) {
        return run_inject_agent(argc - index, argv + index);
    }
    if (arg_is(cmd, {L"--launch-suspended-inject", L"--lsi"})) {
        return run_launch_suspended_inject(argc - index, argv + index);
    }
    if (arg_is(cmd, {L"--staged-agent", L"--stage"})) {
        return run_staged_agent(argc - index, argv + index);
    }
    if (arg_is(cmd, {L"--patch-bytes", L"--pbytes"})) {
        return run_patch_bytes(argc - index, argv + index);
    }
    if (arg_is(cmd, {L"--patch-nop", L"--pnop"})) {
        return run_patch_nops(argc - index, argv + index);
    }
    if (arg_is(cmd, {L"--self-patch-demo", L"--self-demo"})) {
        return run_self_patch_demo();
    }
    if (arg_is(cmd, {L"--instruction-callback-demo", L"--inline-cache-demo"})) {
        return run_instruction_callback_demo();
    }
    if (arg_is(cmd, {L"--dispatcher-callback-demo"})) {
        return run_instruction_callback_demo(instruction_callback_backend::dispatcher_code_cache);
    }
    if (arg_is(cmd, {L"--cooperative-callback-demo"})) {
        return run_instruction_callback_demo(instruction_callback_backend::cooperative_translation);
    }
    if (arg_is(cmd, {L"--inline-hook-demo"})) {
        return run_instruction_callback_demo(instruction_callback_backend::inline_hook);
    }
    if (arg_is(cmd, {L"--guard-page-demo", L"--guard-page-callback-demo"})) {
        return run_instruction_callback_demo(instruction_callback_backend::guard_page_translation);
    }
    if (arg_is(cmd, {L"--indirect-redirect-demo"})) {
        return run_indirect_redirect_demo();
    }
    if (arg_is(cmd, {L"--translated-cache-demo", L"--bb-cache-demo"})) {
        return run_translated_cache_demo();
    }
    if (cmd != nullptr) {
        return run_external_executable(argc - index, argv + index, plugins);
    }

    std::wcout << L"usage: DBI.exe <target.exe> [args...]\n";
    std::wcout << L"       DBI.exe -a <pid> <region_start> <region_size>   (# --attach-instrument)\n";
    std::wcout << L"       DBI.exe -a <pid> <section_name>\n";
    std::wcout << L"       DBI.exe -a <pid> <module_name> <section_name>\n";
    std::wcout << L"       DBI.exe -i <pid>                                 (# --inject-agent)\n";
    std::wcout << L"       DBI.exe -i <pid> <section_name>\n";
    std::wcout << L"       DBI.exe -i <pid> <module_name> <section_name>\n";
    std::wcout << L"       DBI.exe --lsi <target.exe> [target args...]       (# uses Loader.exe <pid>)\n";
    std::wcout << L"       DBI.exe --staged-agent <target.exe> [target args...] (# normal launch, delayed cooperative agent)\n";
    std::wcout << L"       DBI.exe --patch-bytes <pid> <address> <hexbytes>\n";
    std::wcout << L"       DBI.exe --patch-nop <pid> <address> <count>\n";
    std::wcout << L"       DBI.exe --self-patch-demo\n";
    std::wcout << L"       DBI.exe --instruction-callback-demo          (# translated-cache backend)\n";
    std::wcout << L"       DBI.exe --cooperative-callback-demo          (# explicit-entry translation, no traps)\n";
    std::wcout << L"       DBI.exe --inline-hook-demo                   (# native entry inline-hook backend)\n";
    std::wcout << L"       DBI.exe --guard-page-demo                   (# PAGE_GUARD entry-trap backend)\n";
    std::wcout << L"       DBI.exe --dispatcher-callback-demo           (# legacy dispatcher backend)\n";
    std::wcout << L"       DBI.exe --indirect-redirect-demo\n";
    std::wcout << L"       DBI.exe --translated-cache-demo\n";
    std::wcout << L"       DBI.exe -l                                       (# --list-plugins)\n";
    std::wcout << L"       DBI.exe -c <command> [args...]                  (# --cmd)\n";
    std::wcout << L"global options:\n";
    std::wcout << L"       -N | --no-plugins\n";
    std::wcout << L"       -P | --plugins-dir <dir>\n";
    std::wcout << L"       -p | --plugin <dll-path-or-name>\n";
    std::wcout << L"running in-process demo because no target was provided.\n";
    return run_in_process_demo(plugins);
}
