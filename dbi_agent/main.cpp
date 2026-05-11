#include "../DBI/core/dbi_core_version.h"
#include "../DBI/core/dbi_ipc_protocol.h"
#include "../DBI/plugin_api.h"

#include <Windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

namespace {
bool write_exact(HANDLE pipe, const void* data, std::size_t size) {
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

bool read_exact(HANDLE pipe, void* data, std::size_t size) {
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
bool write_message(HANDLE pipe, dbi_ipc::message_type type, const PayloadT& payload) {
    dbi_ipc::message_header header{};
    header.type = static_cast<std::uint16_t>(type);
    header.payload_size = static_cast<std::uint32_t>(sizeof(PayloadT));

    return write_exact(pipe, &header, sizeof(header)) &&
           write_exact(pipe, &payload, sizeof(payload));
}

std::wstring build_pipe_name() {
    wchar_t buffer[128]{};
    _snwprintf_s(
        buffer,
        _countof(buffer),
        _TRUNCATE,
        L"\\\\.\\pipe\\dbi_agent_%lu",
        GetCurrentProcessId());
    return buffer;
}

DWORD WINAPI agent_thread(LPVOID) {
    const std::wstring pipe_name = build_pipe_name();

    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int i = 0; i < 120; ++i) {
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
        OutputDebugStringA("dbi_agent: failed to connect to controller pipe");
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

    // Optional command from controller.
    dbi_ipc::message_header header{};
    if (read_exact(pipe, &header, sizeof(header))) {
        if (header.magic == dbi_ipc::message_magic &&
            header.version == dbi_ipc::protocol_version &&
            header.type == static_cast<std::uint16_t>(dbi_ipc::message_type::start_instrument) &&
            header.payload_size == sizeof(dbi_ipc::start_instrument_payload)) {

            dbi_ipc::start_instrument_payload request{};
            if (read_exact(pipe, &request, sizeof(request))) {
                dbi_ipc::ack_payload ack{};
                ack.status_code = 0;
                std::snprintf(
                    ack.message,
                    sizeof(ack.message),
                    "agent received start request module=%ls section=%ls",
                    request.module_name[0] != L'\0' ? request.module_name : L"<main>",
                    request.section_name[0] != L'\0' ? request.section_name : L"<none>");
                write_message(pipe, dbi_ipc::message_type::ack, ack);
            }
        }
    }

    CloseHandle(pipe);
    return 0;
}
} // namespace

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(instance);
        CreateThread(nullptr, 0, &agent_thread, nullptr, 0, nullptr);
    }
    return TRUE;
}
