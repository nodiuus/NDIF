#include "injection.h"

#include <filesystem>
#include <iostream>
#include <string>
#include <cctype>

namespace injection {
    namespace {
        std::wstring quote_command_line_arg(const std::wstring& arg) {
            if (arg.empty()) {
                return L"\"\"";
            }

            const bool needs_quotes = arg.find_first_of(L" \t\n\v\"") != std::wstring::npos;
            if (!needs_quotes) {
                return arg;
            }

            std::wstring result = L"\"";
            std::size_t backslashes = 0;
            for (wchar_t ch : arg) {
                if (ch == L'\\') {
                    ++backslashes;
                    continue;
                }
                if (ch == L'"') {
                    result.append(backslashes * 2 + 1, L'\\');
                    result.push_back(ch);
                    backslashes = 0;
                    continue;
                }

                result.append(backslashes, L'\\');
                backslashes = 0;
                result.push_back(ch);
            }

            result.append(backslashes * 2, L'\\');
            result.push_back(L'"');
            return result;
        }

        std::wstring build_command_line(const std::wstring& executable_path, const std::vector<std::wstring>& arguments) {
            std::wstring command_line = quote_command_line_arg(executable_path);
            for (const std::wstring& arg : arguments) {
                command_line.push_back(L' ');
                command_line += quote_command_line_arg(arg);
            }
            return command_line;
        }

        std::wstring get_current_exe_directory() {
            wchar_t path[MAX_PATH]{};
            const DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
            if (len == 0 || len >= MAX_PATH) {
                return {};
            }

            try {
                return std::filesystem::path(std::wstring(path, path + len)).parent_path().wstring();
            } catch (...) {
                return {};
            }
        }

        std::wstring resolve_loader_path(const std::wstring& requested) {
            if (!requested.empty()) {
                return requested;
            }

            const std::wstring exe_dir = get_current_exe_directory();
            if (!exe_dir.empty()) {
                const std::filesystem::path from_exe_dir = std::filesystem::path(exe_dir) / L"Loader.exe";
                if (std::filesystem::exists(from_exe_dir)) {
                    return from_exe_dir.wstring();
                }

                const std::filesystem::path from_release_dir = std::filesystem::path(exe_dir).parent_path().parent_path() / L"x64" / L"Release" / L"Loader.exe";
                if (std::filesystem::exists(from_release_dir)) {
                    return from_release_dir.wstring();
                }
            }

            const std::filesystem::path from_cwd_release = std::filesystem::current_path() / L"x64" / L"Release" / L"Loader.exe";
            if (std::filesystem::exists(from_cwd_release)) {
                return from_cwd_release.wstring();
            }

            return L"Loader.exe";
        }

        bool inject_dll_via_loadlibrary_handle(HANDLE process, const std::wstring& dll_path) {
            if (process == nullptr || process == INVALID_HANDLE_VALUE || dll_path.empty()) {
                return false;
            }

            const std::size_t bytes = (dll_path.size() + 1) * sizeof(wchar_t);
            void* remote_buffer = VirtualAllocEx(process, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (remote_buffer == nullptr) {
                return false;
            }

            const BOOL wrote = WriteProcessMemory(process, remote_buffer, dll_path.c_str(), bytes, nullptr);
            if (!wrote) {
                VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
                return false;
            }

            HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
            if (kernel32 == nullptr) {
                VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
                return false;
            }

            auto load_library = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(kernel32, "LoadLibraryW"));
            if (load_library == nullptr) {
                VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
                return false;
            }

            HANDLE thread = CreateRemoteThread(process, nullptr, 0, load_library, remote_buffer, 0, nullptr);
            if (thread == nullptr) {
                VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
                return false;
            }

            WaitForSingleObject(thread, 10000);
            DWORD remote_module = 0;
            GetExitCodeThread(thread, &remote_module);

            CloseHandle(thread);
            VirtualFreeEx(process, remote_buffer, 0, MEM_RELEASE);
            return remote_module != 0;
        }
    }

    bool inject_dll_via_manual_map(DWORD pid, const std::wstring& dll_path) {
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

        if (!process) {
            std::printf("failed to open process\n");
            return false;
        }
        //TODO: implement weird manual mapping horseshit

        return false;
    }

    bool inject_dll_via_loadlibrary(DWORD pid, const std::wstring& dll_path) {
        HANDLE process = OpenProcess(
            PROCESS_CREATE_THREAD |
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION |
            PROCESS_VM_WRITE |
            PROCESS_VM_READ,
            FALSE,
            pid);
        if (process == nullptr) {
            return false;
        }

        const bool ok = inject_dll_via_loadlibrary_handle(process, dll_path);
        CloseHandle(process);

        return ok;
    }

    bool inject_via_loader_exe(DWORD pid, const std::wstring& loader_path) {
        if (pid == 0) {
            return false;
        }

        const std::wstring resolved_loader = resolve_loader_path(loader_path);
        const std::wstring pid_arg = std::to_wstring(static_cast<unsigned long>(pid));
        std::wstring command_line = quote_command_line_arg(resolved_loader) + L" " + pid_arg;

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process_info{};
        const BOOL created = CreateProcessW(
            resolved_loader.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startup,
            &process_info);

        if (!created) {
            return false;
        }

        const DWORD wait_result = WaitForSingleObject(process_info.hProcess, 15000);
        DWORD exit_code = 1;
        if (wait_result == WAIT_OBJECT_0) {
            GetExitCodeProcess(process_info.hProcess, &exit_code);
        }

        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
        return wait_result == WAIT_OBJECT_0 && exit_code == 0;
    }

    bool launch_suspended_inject_loadlibrary(
        const std::wstring& executable_path,
        const std::vector<std::wstring>& arguments,
        const std::wstring& dll_path,
        DWORD post_inject_delay_ms,
        DWORD* out_pid) {

        if (executable_path.empty() || dll_path.empty()) {
            return false;
        }

        std::wstring command_line = build_command_line(executable_path, arguments);
        std::wstring working_directory{};
        try {
            const std::filesystem::path parent = std::filesystem::path(executable_path).parent_path();
            if (!parent.empty()) {
                working_directory = parent.wstring();
            }
        } catch (...) {
            working_directory.clear();
        }

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process_info{};
        const BOOL created = CreateProcessW(
            executable_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            working_directory.empty() ? nullptr : working_directory.c_str(),
            &startup,
            &process_info);

        if (!created) {
            return false;
        }

        if (out_pid != nullptr) {
            *out_pid = process_info.dwProcessId;
        }

        const bool injected = inject_dll_via_loadlibrary_handle(process_info.hProcess, dll_path);
        if (injected && post_inject_delay_ms != 0) {
            Sleep(post_inject_delay_ms);
        }

        ResumeThread(process_info.hThread);
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);

        return injected;
    }

    bool launch_suspended_inject_loader(
        const std::wstring& executable_path,
        const std::vector<std::wstring>& arguments,
        const std::wstring& loader_path,
        DWORD post_inject_delay_ms,
        DWORD* out_pid,
        bool resume_after_inject,
        HANDLE* out_primary_thread) {

        if (executable_path.empty()) {
            return false;
        }

        std::wstring command_line = build_command_line(executable_path, arguments);
        std::wstring working_directory{};
        try {
            const std::filesystem::path parent = std::filesystem::path(executable_path).parent_path();
            if (!parent.empty()) {
                working_directory = parent.wstring();
            }
        } catch (...) {
            working_directory.clear();
        }

        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process_info{};
        const BOOL created = CreateProcessW(
            executable_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED,
            nullptr,
            working_directory.empty() ? nullptr : working_directory.c_str(),
            &startup,
            &process_info);

        if (!created) {
            return false;
        }

        if (out_pid != nullptr) {
            *out_pid = process_info.dwProcessId;
        }

        const bool injected = inject_via_loader_exe(process_info.dwProcessId, loader_path);
        if (injected && post_inject_delay_ms != 0) {
            Sleep(post_inject_delay_ms);
        }

        if (resume_after_inject) {
            ResumeThread(process_info.hThread);
            CloseHandle(process_info.hThread);
        } else if (out_primary_thread != nullptr) {
            *out_primary_thread = process_info.hThread;
        } else {
            CloseHandle(process_info.hThread);
        }
        CloseHandle(process_info.hProcess);

        return injected;
    }
};
