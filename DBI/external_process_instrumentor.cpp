#include "external_process_instrumentor.h"

#include <LIEF/PE.hpp>

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "LIEF.lib")
#endif

namespace {
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
} // namespace

bool external_process_instrumentor::run_at_entry(
    const std::wstring& executable_path,
    const std::vector<std::wstring>& arguments,
    std::size_t region_size,
    external_instrumentation_result& result,
    callbacks callbacks) {

    result = {};
    instructions_.clear();
    pending_rearm_by_thread_.clear();
    callbacks_ = std::move(callbacks);

    if (executable_path.empty() || region_size == 0) {
        return false;
    }

    pe_info pe_info{};
    if (!parse_pe_info(executable_path, pe_info) || pe_info.entry_rva == 0) {
        return false;
    }

#if defined(_M_X64)
    if (pe_info.machine != IMAGE_FILE_MACHINE_AMD64) {
        return false;
    }
#else
    if (pe_info.machine != IMAGE_FILE_MACHINE_I386) {
        return false;
    }
#endif

    std::wstring command_line = build_command_line(executable_path, arguments);
    std::vector<wchar_t> command_line_buffer(command_line.begin(), command_line.end());
    command_line_buffer.push_back(L'\0');

    STARTUPINFOW startup_info{};
    startup_info.cb = sizeof(startup_info);

    PROCESS_INFORMATION process_info{};
    const BOOL created = CreateProcessW(
        executable_path.c_str(),
        command_line_buffer.data(),
        nullptr,
        nullptr,
        FALSE,
        DEBUG_ONLY_THIS_PROCESS,
        nullptr,
        nullptr,
        &startup_info,
        &process_info);

    if (!created) {
        return false;
    }

    process_handle_ = process_info.hProcess;

    bool success = true;
    bool breakpoints_installed = false;
    bool process_exited = false;

    while (!process_exited) {
        DEBUG_EVENT debug_event{};
        if (!WaitForDebugEvent(&debug_event, INFINITE)) {
            success = false;
            break;
        }

        DWORD continue_status = DBG_CONTINUE;
        switch (debug_event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            if (debug_event.u.CreateProcessInfo.hFile != nullptr) {
                CloseHandle(debug_event.u.CreateProcessInfo.hFile);
            }

            if (debug_event.u.CreateProcessInfo.hThread != nullptr) {
                if (debug_event.u.CreateProcessInfo.hThread == process_info.hThread) {
                    process_info.hThread = nullptr;
                }
                CloseHandle(debug_event.u.CreateProcessInfo.hThread);
            }

            const auto base = reinterpret_cast<std::uintptr_t>(debug_event.u.CreateProcessInfo.lpBaseOfImage);
            const std::uintptr_t entry = base + pe_info.entry_rva;

            if (!decode_remote_region(entry, region_size) || !install_breakpoints()) {
                success = false;
                TerminateProcess(process_handle_, 1);
            } else {
                breakpoints_installed = true;
                if (callbacks_.on_process_start) {
                    callbacks_.on_process_start(debug_event.dwProcessId);
                }
            }

            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            result.process_exit_code = debug_event.u.ExitProcess.dwExitCode;
            process_exited = true;
            if (callbacks_.on_process_exit) {
                callbacks_.on_process_exit(debug_event.dwProcessId, result.process_exit_code);
            }
            break;
        case EXCEPTION_DEBUG_EVENT:
            if (!handle_exception_event(debug_event, result, continue_status)) {
                success = false;
                TerminateProcess(process_handle_, 1);
            }
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (debug_event.u.CreateThread.hThread != nullptr) {
                CloseHandle(debug_event.u.CreateThread.hThread);
            }
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            pending_rearm_by_thread_.erase(debug_event.dwThreadId);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (debug_event.u.LoadDll.hFile != nullptr) {
                CloseHandle(debug_event.u.LoadDll.hFile);
            }
            break;
        default:
            break;
        }

        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status);
    }

    if (breakpoints_installed) {
        remove_breakpoints();
    }

    pending_rearm_by_thread_.clear();
    instructions_.clear();

    if (process_handle_ != nullptr) {
        CloseHandle(process_handle_);
        process_handle_ = nullptr;
    }

    if (process_info.hThread != nullptr) {
        CloseHandle(process_info.hThread);
        process_info.hThread = nullptr;
    }

    callbacks_ = {};
    return success;
}

bool external_process_instrumentor::run_executable_sections(
    const std::wstring& executable_path,
    const std::vector<std::wstring>& arguments,
    external_instrumentation_result& result,
    callbacks callbacks) {

    result = {};
    instructions_.clear();
    pending_rearm_by_thread_.clear();
    callbacks_ = std::move(callbacks);

    if (executable_path.empty()) {
        return false;
    }

    pe_info pe_info{};
    if (!parse_pe_info(executable_path, pe_info) || pe_info.executable_sections.empty()) {
        return false;
    }

#if defined(_M_X64)
    if (pe_info.machine != IMAGE_FILE_MACHINE_AMD64) {
        return false;
    }
#else
    if (pe_info.machine != IMAGE_FILE_MACHINE_I386) {
        return false;
    }
#endif

    std::wstring command_line = build_command_line(executable_path, arguments);
    std::vector<wchar_t> command_line_buffer(command_line.begin(), command_line.end());
    command_line_buffer.push_back(L'\0');

    STARTUPINFOW startup_info{};
    startup_info.cb = sizeof(startup_info);

    PROCESS_INFORMATION process_info{};
    const BOOL created = CreateProcessW(
        executable_path.c_str(),
        command_line_buffer.data(),
        nullptr,
        nullptr,
        FALSE,
        DEBUG_ONLY_THIS_PROCESS,
        nullptr,
        nullptr,
        &startup_info,
        &process_info);

    if (!created) {
        return false;
    }

    process_handle_ = process_info.hProcess;

    bool success = true;
    bool breakpoints_installed = false;
    bool process_exited = false;

    while (!process_exited) {
        DEBUG_EVENT debug_event{};
        if (!WaitForDebugEvent(&debug_event, INFINITE)) {
            success = false;
            break;
        }

        DWORD continue_status = DBG_CONTINUE;
        switch (debug_event.dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT: {
            if (debug_event.u.CreateProcessInfo.hFile != nullptr) {
                CloseHandle(debug_event.u.CreateProcessInfo.hFile);
            }

            if (debug_event.u.CreateProcessInfo.hThread != nullptr) {
                if (debug_event.u.CreateProcessInfo.hThread == process_info.hThread) {
                    process_info.hThread = nullptr;
                }
                CloseHandle(debug_event.u.CreateProcessInfo.hThread);
            }

            const auto base = reinterpret_cast<std::uintptr_t>(debug_event.u.CreateProcessInfo.lpBaseOfImage);
            std::vector<std::pair<std::uintptr_t, std::size_t>> regions{};
            regions.reserve(pe_info.executable_sections.size());
            for (const pe_info::executable_section& section : pe_info.executable_sections) {
                if (section.rva == 0 || section.size == 0) {
                    continue;
                }
                regions.emplace_back(base + static_cast<std::uintptr_t>(section.rva), static_cast<std::size_t>(section.size));
            }

            if (!decode_remote_regions(regions) || !install_breakpoints()) {
                success = false;
                TerminateProcess(process_handle_, 1);
            } else {
                breakpoints_installed = true;
                if (callbacks_.on_process_start) {
                    callbacks_.on_process_start(debug_event.dwProcessId);
                }
            }

            break;
        }
        case EXIT_PROCESS_DEBUG_EVENT:
            result.process_exit_code = debug_event.u.ExitProcess.dwExitCode;
            process_exited = true;
            if (callbacks_.on_process_exit) {
                callbacks_.on_process_exit(debug_event.dwProcessId, result.process_exit_code);
            }
            break;
        case EXCEPTION_DEBUG_EVENT:
            if (!handle_exception_event(debug_event, result, continue_status)) {
                success = false;
                TerminateProcess(process_handle_, 1);
            }
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (debug_event.u.CreateThread.hThread != nullptr) {
                CloseHandle(debug_event.u.CreateThread.hThread);
            }
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            pending_rearm_by_thread_.erase(debug_event.dwThreadId);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (debug_event.u.LoadDll.hFile != nullptr) {
                CloseHandle(debug_event.u.LoadDll.hFile);
            }
            break;
        default:
            break;
        }

        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status);
    }

    if (breakpoints_installed) {
        remove_breakpoints();
    }

    pending_rearm_by_thread_.clear();
    instructions_.clear();

    if (process_handle_ != nullptr) {
        CloseHandle(process_handle_);
        process_handle_ = nullptr;
    }

    if (process_info.hThread != nullptr) {
        CloseHandle(process_info.hThread);
        process_info.hThread = nullptr;
    }

    callbacks_ = {};
    return success;
}

bool external_process_instrumentor::attach_and_instrument(
    DWORD pid,
    std::uintptr_t region_start,
    std::size_t region_size,
    external_instrumentation_result& result,
    DWORD timeout_ms,
    callbacks callbacks) {

    result = {};
    instructions_.clear();
    pending_rearm_by_thread_.clear();
    callbacks_ = std::move(callbacks);

    if (pid == 0 || region_start == 0 || region_size == 0) {
        return false;
    }

    process_handle_ = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        FALSE,
        pid);
    if (process_handle_ == nullptr) {
        return false;
    }

    if (!DebugActiveProcess(pid)) {
        CloseHandle(process_handle_);
        process_handle_ = nullptr;
        return false;
    }

    DebugSetProcessKillOnExit(FALSE);

    bool success = decode_remote_region(region_start, region_size) && install_breakpoints();
    if (!success) {
        DebugActiveProcessStop(pid);
        CloseHandle(process_handle_);
        process_handle_ = nullptr;
        return false;
    }

    if (callbacks_.on_process_start) {
        callbacks_.on_process_start(pid);
    }

    const ULONGLONG start_tick = GetTickCount64();
    bool process_exited = false;

    while (!process_exited) {
        DWORD wait_timeout = INFINITE;
        if (timeout_ms != INFINITE) {
            const ULONGLONG elapsed = GetTickCount64() - start_tick;
            if (elapsed >= timeout_ms) {
                break;
            }
            wait_timeout = static_cast<DWORD>(timeout_ms - elapsed);
        }

        DEBUG_EVENT debug_event{};
        if (!WaitForDebugEvent(&debug_event, wait_timeout)) {
            break;
        }

        DWORD continue_status = DBG_CONTINUE;
        switch (debug_event.dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT:
            if (!handle_exception_event(debug_event, result, continue_status)) {
                success = false;
            }
            break;
        case EXIT_PROCESS_DEBUG_EVENT:
            if (debug_event.dwProcessId == pid) {
                process_exited = true;
                result.process_exit_code = debug_event.u.ExitProcess.dwExitCode;
                if (callbacks_.on_process_exit) {
                    callbacks_.on_process_exit(pid, result.process_exit_code);
                }
            }
            break;
        case CREATE_THREAD_DEBUG_EVENT:
            if (debug_event.u.CreateThread.hThread != nullptr) {
                CloseHandle(debug_event.u.CreateThread.hThread);
            }
            break;
        case EXIT_THREAD_DEBUG_EVENT:
            pending_rearm_by_thread_.erase(debug_event.dwThreadId);
            break;
        case LOAD_DLL_DEBUG_EVENT:
            if (debug_event.u.LoadDll.hFile != nullptr) {
                CloseHandle(debug_event.u.LoadDll.hFile);
            }
            break;
        case CREATE_PROCESS_DEBUG_EVENT:
            if (debug_event.u.CreateProcessInfo.hFile != nullptr) {
                CloseHandle(debug_event.u.CreateProcessInfo.hFile);
            }
            if (debug_event.u.CreateProcessInfo.hThread != nullptr) {
                CloseHandle(debug_event.u.CreateProcessInfo.hThread);
            }
            if (debug_event.u.CreateProcessInfo.hProcess != nullptr && debug_event.u.CreateProcessInfo.hProcess != process_handle_) {
                CloseHandle(debug_event.u.CreateProcessInfo.hProcess);
            }
            break;
        default:
            break;
        }

        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status);
        if (!success) {
            break;
        }
    }

    remove_breakpoints();
    pending_rearm_by_thread_.clear();
    instructions_.clear();

    DebugActiveProcessStop(pid);

    CloseHandle(process_handle_);
    process_handle_ = nullptr;
    callbacks_ = {};
    return success;
}

bool external_process_instrumentor::parse_pe_info(const std::wstring& executable_path, pe_info& pe_info) const {
    const std::string utf8_path = wide_to_utf8(executable_path);
    if (utf8_path.empty()) {
        return false;
    }

    std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(utf8_path);
    if (!binary) {
        return false;
    }

    pe_info.entry_rva = binary->optional_header().addressof_entrypoint();
    const auto machine = binary->header().machine();
    pe_info.executable_sections.clear();

    for (const LIEF::PE::Section& section : binary->sections()) {
        if (!section.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE)) {
            continue;
        }

        const auto rva = section.virtual_address();
        const auto virtual_size = section.virtual_size();
        const auto raw_size = section.sizeof_raw_data();
        const auto size = virtual_size != 0 ? virtual_size : raw_size;
        if (rva == 0 || size == 0 || rva > 0xffffffffULL || size > 0xffffffffULL) {
            continue;
        }

        pe_info.executable_sections.push_back({
            static_cast<DWORD>(rva),
            static_cast<DWORD>(size)
        });
    }

    switch (machine) {
    case LIEF::PE::Header::MACHINE_TYPES::AMD64:
        pe_info.machine = IMAGE_FILE_MACHINE_AMD64;
        return true;
    case LIEF::PE::Header::MACHINE_TYPES::I386:
        pe_info.machine = IMAGE_FILE_MACHINE_I386;
        return true;
    default:
        return false;
    }
}

bool external_process_instrumentor::decode_remote_region(std::uintptr_t start, std::size_t size, bool clear_existing) {
    if (process_handle_ == nullptr) {
        return false;
    }
    const std::size_t previous_instruction_count = clear_existing ? 0 : instructions_.size();

    std::vector<std::uint8_t> bytes(size);
    SIZE_T read = 0;
    if (!ReadProcessMemory(process_handle_, reinterpret_cast<const void*>(start), bytes.data(), bytes.size(), &read) || read == 0) {
        return false;
    }

    if (clear_existing) {
        instructions_.clear();
    }

    ZydisDecoder decoder;
#if defined(_M_X64)
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return false;
    }
#else
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32))) {
        return false;
    }
#endif

    std::size_t offset = 0;
    while (offset < static_cast<std::size_t>(read)) {
        ZydisDecodedInstruction decoded{};
        const std::size_t remaining = static_cast<std::size_t>(read) - offset;
        const void* cursor = bytes.data() + offset;

        ZyanStatus status{};
#if defined(ZYDIS_VERSION) && (ZYDIS_VERSION_MAJOR(ZYDIS_VERSION) >= 4)
        ZydisDecoderContext context{};
        status = ZydisDecoderDecodeInstruction(&decoder, &context, cursor, remaining, &decoded);
#else
        status = ZydisDecoderDecodeBuffer(&decoder, cursor, remaining, &decoded);
#endif

        if (!ZYAN_SUCCESS(status) || decoded.length == 0) {
            break;
        }

        bool is_control_flow = false;
        switch (decoded.meta.category) {
        case ZYDIS_CATEGORY_CALL:
        case ZYDIS_CATEGORY_COND_BR:
        case ZYDIS_CATEGORY_UNCOND_BR:
        case ZYDIS_CATEGORY_RET:
        case ZYDIS_CATEGORY_SYSRET:
        case ZYDIS_CATEGORY_SYSCALL:
            is_control_flow = true;
            break;
        default:
            break;
        }
        if (decoded.mnemonic == ZYDIS_MNEMONIC_INT ||
            decoded.mnemonic == ZYDIS_MNEMONIC_INT1 ||
            decoded.mnemonic == ZYDIS_MNEMONIC_INT3 ||
            decoded.mnemonic == ZYDIS_MNEMONIC_INTO) {
            is_control_flow = true;
        }

        const std::uintptr_t address = start + offset;
        instructions_.try_emplace(address, instrumented_instruction{
            address,
            decoded.length,
            bytes[offset],
            is_control_flow,
            decoded.mnemonic
        });

        offset += decoded.length;
    }

    return instructions_.size() > previous_instruction_count;
}

bool external_process_instrumentor::decode_remote_regions(const std::vector<std::pair<std::uintptr_t, std::size_t>>& regions) {
    instructions_.clear();
    if (regions.empty()) {
        return false;
    }

    bool decoded_any = false;
    for (const auto& [start, size] : regions) {
        if (start == 0 || size == 0) {
            continue;
        }
        if (decode_remote_region(start, size, false)) {
            decoded_any = true;
        }
    }

    return decoded_any && !instructions_.empty();
}

bool external_process_instrumentor::install_breakpoints() {
    std::vector<std::uintptr_t> patched{};
    patched.reserve(instructions_.size());

    for (const auto& [address, instruction] : instructions_) {
        if (!write_remote_byte(address, 0xCC)) {
            for (const std::uintptr_t rollback_address : patched) {
                const auto rollback = instructions_.find(rollback_address);
                if (rollback != instructions_.end()) {
                    write_remote_byte(rollback->second.address, rollback->second.original_first_byte);
                }
            }
            return false;
        }
        patched.push_back(address);
    }

    return true;
}

void external_process_instrumentor::remove_breakpoints() {
    for (const auto& [address, instruction] : instructions_) {
        write_remote_byte(address, instruction.original_first_byte);
    }
}

bool external_process_instrumentor::write_remote_byte(std::uintptr_t address, std::uint8_t value) const {
    if (process_handle_ == nullptr) {
        return false;
    }

    DWORD old_protect = 0;
    const auto target = reinterpret_cast<LPVOID>(address);

    if (!VirtualProtectEx(process_handle_, target, 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }

    SIZE_T written = 0;
    const BOOL write_ok = WriteProcessMemory(process_handle_, target, &value, 1, &written);
    FlushInstructionCache(process_handle_, target, 1);

    DWORD ignored = 0;
    VirtualProtectEx(process_handle_, target, 1, old_protect, &ignored);
    return write_ok && written == 1;
}

bool external_process_instrumentor::handle_exception_event(
    const DEBUG_EVENT& debug_event,
    external_instrumentation_result& result,
    DWORD& continue_status) {

    const auto& record = debug_event.u.Exception.ExceptionRecord;

    if (record.ExceptionCode == EXCEPTION_SINGLE_STEP) {
        const auto pending = pending_rearm_by_thread_.find(debug_event.dwThreadId);
        if (pending == pending_rearm_by_thread_.end()) {
            continue_status = DBG_EXCEPTION_NOT_HANDLED;
            return true;
        }

        if (!write_remote_byte(pending->second, 0xCC)) {
            return false;
        }

        pending_rearm_by_thread_.erase(pending);
        continue_status = DBG_CONTINUE;
        return true;
    }

    if (record.ExceptionCode != EXCEPTION_BREAKPOINT) {
        continue_status = DBG_EXCEPTION_NOT_HANDLED;
        return true;
    }

    std::uintptr_t resolved = reinterpret_cast<std::uintptr_t>(record.ExceptionAddress);
    auto instruction = instructions_.find(resolved);
    if (instruction == instructions_.end() && resolved > 0) {
        instruction = instructions_.find(resolved - 1);
    }

    if (instruction == instructions_.end()) {
        continue_status = DBG_CONTINUE;
        return true;
    }

    HANDLE thread_handle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, debug_event.dwThreadId);
    if (thread_handle == nullptr) {
        return false;
    }

    CONTEXT context{};
    context.ContextFlags = CONTEXT_CONTROL;

    const BOOL got_context = GetThreadContext(thread_handle, &context);
    bool ok = false;
    if (got_context && write_remote_byte(instruction->second.address, instruction->second.original_first_byte)) {
        pending_rearm_by_thread_[debug_event.dwThreadId] = instruction->second.address;
        ++result.hit_counts[instruction->second.address];
        if (callbacks_.on_instruction_hit) {
            callbacks_.on_instruction_hit(debug_event.dwProcessId, instruction->second.address);
        }
        if (instruction->second.is_control_flow && callbacks_.on_branch_hit) {
            callbacks_.on_branch_hit(debug_event.dwProcessId, instruction->second.address, instruction->second.mnemonic, instruction->second.length);
        }

        set_instruction_pointer(context, instruction->second.address);
        set_single_step(context);
        ok = SetThreadContext(thread_handle, &context) == TRUE;
    }

    CloseHandle(thread_handle);
    continue_status = DBG_CONTINUE;
    return ok;
}

std::wstring external_process_instrumentor::build_command_line(
    const std::wstring& executable_path,
    const std::vector<std::wstring>& arguments) {

    std::wstring command_line = quote_argument(executable_path);
    for (const std::wstring& argument : arguments) {
        command_line.push_back(L' ');
        command_line += quote_argument(argument);
    }
    return command_line;
}

std::wstring external_process_instrumentor::quote_argument(const std::wstring& value) {
    if (value.empty()) {
        return L"\"\"";
    }

    const bool needs_quotes = value.find_first_of(L" \t\"") != std::wstring::npos;
    if (!needs_quotes) {
        return value;
    }

    std::wstring result{};
    result.push_back(L'"');

    std::size_t backslashes = 0;
    for (const wchar_t ch : value) {
        if (ch == L'\\') {
            ++backslashes;
            continue;
        }

        if (ch == L'"') {
            result.append(backslashes * 2 + 1, L'\\');
            result.push_back(L'"');
            backslashes = 0;
            continue;
        }

        if (backslashes > 0) {
            result.append(backslashes, L'\\');
            backslashes = 0;
        }

        result.push_back(ch);
    }

    if (backslashes > 0) {
        result.append(backslashes * 2, L'\\');
    }

    result.push_back(L'"');
    return result;
}

void external_process_instrumentor::set_instruction_pointer(CONTEXT& context, std::uintptr_t value) {
#if defined(_M_X64)
    context.Rip = static_cast<DWORD64>(value);
#else
    context.Eip = static_cast<DWORD>(value);
#endif
}

void external_process_instrumentor::set_single_step(CONTEXT& context) {
    constexpr DWORD trap_flag = 0x100;
    context.EFlags |= trap_flag;
}
