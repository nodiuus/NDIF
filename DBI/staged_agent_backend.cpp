#include "staged_agent_backend.h"

#include "core/dbi_ipc_protocol.h"
#include "injection.h"

#include <TlHelp32.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>

namespace {
class unique_handle {
public:
    unique_handle() = default;
    explicit unique_handle(HANDLE value) : value_(value) {}
    ~unique_handle() { reset(); }

    unique_handle(const unique_handle&) = delete;
    unique_handle& operator=(const unique_handle&) = delete;

    HANDLE get() const { return value_; }
    HANDLE release() {
        HANDLE value = value_;
        value_ = nullptr;
        return value;
    }
    void reset(HANDLE value = nullptr) {
        if (value_ != nullptr && value_ != INVALID_HANDLE_VALUE) {
            CloseHandle(value_);
        }
        value_ = value;
    }
    explicit operator bool() const {
        return value_ != nullptr && value_ != INVALID_HANDLE_VALUE;
    }

private:
    HANDLE value_{nullptr};
};

void emit(
    const staged_agent_options& options,
    staged_agent_phase phase,
    DWORD pid,
    const char* message) {
    if (options.on_event) {
        options.on_event(staged_agent_event{phase, pid, message != nullptr ? message : ""});
    }
}

bool process_is_running(HANDLE process) {
    return process != nullptr && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
}

bool main_module_is_visible(DWORD pid) {
    unique_handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid));
    if (!snapshot) {
        return false;
    }

    MODULEENTRY32W module{};
    module.dwSize = sizeof(module);
    return Module32FirstW(snapshot.get(), &module) != FALSE;
}

bool wait_for_initialization(
    HANDLE process,
    DWORD pid,
    DWORD timeout_ms,
    DWORD settle_time_ms) {
    const ULONGLONG deadline = GetTickCount64() + timeout_ms;
    while (GetTickCount64() < deadline) {
        if (!process_is_running(process)) {
            return false;
        }
        if (main_module_is_visible(pid)) {
            if (settle_time_ms == 0) {
                return true;
            }

            const DWORD wait = WaitForSingleObject(process, settle_time_ms);
            return wait == WAIT_TIMEOUT;
        }
        Sleep(25);
    }
    return false;
}

std::wstring build_pipe_name(DWORD pid) {
    wchar_t buffer[128]{};
    _snwprintf_s(buffer, _countof(buffer), _TRUNCATE, L"\\\\.\\pipe\\dbi_agent_%lu", pid);
    return buffer;
}

bool transfer_exact(HANDLE pipe, void* data, std::size_t size, bool write) {
    auto* bytes = static_cast<std::uint8_t*>(data);
    std::size_t total = 0;
    while (total < size) {
        unique_handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event) {
            return false;
        }

        OVERLAPPED overlapped{};
        overlapped.hEvent = event.get();
        DWORD transferred = 0;
        const BOOL started = write
            ? WriteFile(pipe, bytes + total, static_cast<DWORD>(size - total), &transferred, &overlapped)
            : ReadFile(pipe, bytes + total, static_cast<DWORD>(size - total), &transferred, &overlapped);
        if (!started) {
            const DWORD error = GetLastError();
            if (error != ERROR_IO_PENDING) {
                return false;
            }
            if (WaitForSingleObject(event.get(), 7500) != WAIT_OBJECT_0 ||
                !GetOverlappedResult(pipe, &overlapped, &transferred, FALSE)) {
                CancelIoEx(pipe, &overlapped);
                return false;
            }
        }
        if (transferred == 0) {
            return false;
        }
        total += transferred;
    }
    return true;
}

bool write_exact(HANDLE pipe, const void* data, std::size_t size) {
    return transfer_exact(pipe, const_cast<void*>(data), size, true);
}

bool read_exact(HANDLE pipe, void* data, std::size_t size) {
    return transfer_exact(pipe, data, size, false);
}

template <typename Payload>
bool write_message(HANDLE pipe, dbi_ipc::message_type type, const Payload& payload) {
    dbi_ipc::message_header header{};
    header.type = static_cast<std::uint16_t>(type);
    header.payload_size = static_cast<std::uint32_t>(sizeof(Payload));
    return write_exact(pipe, &header, sizeof(header)) && write_exact(pipe, &payload, sizeof(payload));
}

bool connect_pipe(HANDLE pipe, HANDLE process, DWORD timeout_ms) {
    unique_handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!event) {
        return false;
    }

    OVERLAPPED overlapped{};
    overlapped.hEvent = event.get();
    if (ConnectNamedPipe(pipe, &overlapped)) {
        return true;
    }

    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) {
        return true;
    }
    if (error != ERROR_IO_PENDING) {
        return false;
    }

    HANDLE waits[] = {event.get(), process};
    const DWORD wait = WaitForMultipleObjects(_countof(waits), waits, FALSE, timeout_ms);
    if (wait != WAIT_OBJECT_0) {
        CancelIoEx(pipe, &overlapped);
        return false;
    }

    DWORD transferred = 0;
    return GetOverlappedResult(pipe, &overlapped, &transferred, FALSE) != FALSE;
}

bool valid_header(
    const dbi_ipc::message_header& header,
    dbi_ipc::message_type type,
    std::size_t payload_size) {
    return header.magic == dbi_ipc::message_magic &&
           header.version == dbi_ipc::protocol_version &&
           header.type == static_cast<std::uint16_t>(type) &&
           header.payload_size == payload_size;
}
} // namespace

std::wstring staged_agent_backend::quote_argument(const std::wstring& value) {
    if (value.empty()) {
        return L"\"\"";
    }
    if (value.find_first_of(L" \t\n\v\"") == std::wstring::npos) {
        return value;
    }

    std::wstring result = L"\"";
    std::size_t backslashes = 0;
    for (const wchar_t ch : value) {
        if (ch == L'\\') {
            ++backslashes;
        } else if (ch == L'\"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(ch);
            backslashes = 0;
        } else {
            result.append(backslashes, L'\\');
            backslashes = 0;
            result.push_back(ch);
        }
    }
    result.append(backslashes * 2, L'\\');
    result.push_back(L'\"');
    return result;
}

std::wstring staged_agent_backend::build_command_line(
    const std::wstring& executable_path,
    const std::vector<std::wstring>& arguments) {
    std::wstring command_line = quote_argument(executable_path);
    for (const auto& argument : arguments) {
        command_line.push_back(L' ');
        command_line += quote_argument(argument);
    }
    return command_line;
}

bool staged_agent_backend::run(const staged_agent_options& options, staged_agent_result& result) {
    result = {};
    if (options.executable_path.empty() || options.agent_dll_path.empty()) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = ERROR_INVALID_PARAMETER;
        emit(options, staged_agent_phase::failed, 0, "missing executable or agent path");
        return false;
    }
    if (!std::filesystem::exists(options.executable_path) || !std::filesystem::exists(options.agent_dll_path)) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = ERROR_FILE_NOT_FOUND;
        emit(options, staged_agent_phase::failed, 0, "executable or agent was not found");
        return false;
    }

    std::wstring command_line = build_command_line(options.executable_path, options.arguments);
    std::wstring working_directory = std::filesystem::path(options.executable_path).parent_path().wstring();
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process_info{};
    if (!CreateProcessW(
            options.executable_path.c_str(),
            command_line.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            working_directory.empty() ? nullptr : working_directory.c_str(),
            &startup,
            &process_info)) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = GetLastError();
        emit(options, staged_agent_phase::failed, 0, "normal process launch failed");
        return false;
    }

    unique_handle process(process_info.hProcess);
    unique_handle primary_thread(process_info.hThread);
    result.pid = process_info.dwProcessId;
    emit(options, staged_agent_phase::process_launched, result.pid, "target launched without debug flags");
    emit(options, staged_agent_phase::waiting_for_initialization, result.pid, "waiting for loader initialization and settle window");

    if (!wait_for_initialization(
            process.get(),
            result.pid,
            options.initialization_timeout_ms,
            options.settle_time_ms)) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = process_is_running(process.get()) ? WAIT_TIMEOUT : ERROR_PROCESS_ABORTED;
        emit(options, staged_agent_phase::failed, result.pid, "target did not reach the post-initialization stage");
        return false;
    }

    const std::wstring pipe_name = build_pipe_name(result.pid);
    unique_handle pipe(CreateNamedPipeW(
        pipe_name.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1,
        4096,
        4096,
        options.pipe_timeout_ms,
        nullptr));
    if (!pipe) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = GetLastError();
        emit(options, staged_agent_phase::failed, result.pid, "failed to create agent controller pipe");
        return false;
    }
    emit(options, staged_agent_phase::controller_ready, result.pid, "controller pipe is ready");

    if (!injection::inject_dll_via_loadlibrary(result.pid, options.agent_dll_path)) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = GetLastError();
        emit(options, staged_agent_phase::failed, result.pid, "cooperative agent injection failed");
        return false;
    }
    emit(options, staged_agent_phase::agent_injected, result.pid, "cooperative agent injected");

    if (!connect_pipe(pipe.get(), process.get(), options.pipe_timeout_ms)) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = GetLastError();
        emit(options, staged_agent_phase::failed, result.pid, "agent connection timed out");
        return false;
    }
    emit(options, staged_agent_phase::agent_connected, result.pid, "agent connected to controller");

    dbi_ipc::message_header hello_header{};
    dbi_ipc::hello_payload hello{};
    if (!read_exact(pipe.get(), &hello_header, sizeof(hello_header)) ||
        !read_exact(pipe.get(), &hello, sizeof(hello)) ||
        !valid_header(hello_header, dbi_ipc::message_type::hello, sizeof(hello)) ||
        hello.pid != result.pid) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = ERROR_INVALID_DATA;
        emit(options, staged_agent_phase::failed, result.pid, "agent hello validation failed");
        return false;
    }

    dbi_ipc::start_instrument_payload start{};
    if (!options.module_name.empty()) {
        wcsncpy_s(start.module_name, options.module_name.c_str(), _TRUNCATE);
    }
    if (!options.section_name.empty()) {
        wcsncpy_s(start.section_name, options.section_name.c_str(), _TRUNCATE);
    }
    if (!write_message(pipe.get(), dbi_ipc::message_type::start_instrument, start)) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = GetLastError();
        emit(options, staged_agent_phase::failed, result.pid, "failed to send instrumentation request");
        return false;
    }

    dbi_ipc::message_header ack_header{};
    dbi_ipc::ack_payload ack{};
    if (!read_exact(pipe.get(), &ack_header, sizeof(ack_header)) ||
        !read_exact(pipe.get(), &ack, sizeof(ack)) ||
        !valid_header(ack_header, dbi_ipc::message_type::ack, sizeof(ack))) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = ERROR_INVALID_DATA;
        emit(options, staged_agent_phase::failed, result.pid, "agent ACK validation failed");
        return false;
    }

    result.agent_status = ack.status_code;
    result.agent_message.assign(ack.message, strnlen_s(ack.message, sizeof(ack.message)));
    emit(options, staged_agent_phase::instrumentation_started, result.pid, result.agent_message.c_str());
    if (ack.status_code != 0) {
        result.final_phase = staged_agent_phase::failed;
        result.win32_error = ERROR_GEN_FAILURE;
        emit(options, staged_agent_phase::failed, result.pid, "agent rejected instrumentation request");
        return false;
    }

    result.final_phase = staged_agent_phase::completed;
    emit(options, staged_agent_phase::completed, result.pid, "staged agent backend completed");
    return true;
}
