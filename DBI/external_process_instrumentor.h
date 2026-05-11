#pragma once

#include "dynamic_binary_instrumentor.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

struct external_instrumentation_result {
    DWORD process_exit_code{0};
    std::unordered_map<std::uintptr_t, std::size_t> hit_counts{};
};

class external_process_instrumentor {
public:
    using hit_callback = std::function<void(DWORD pid, std::uintptr_t address)>;
    using branch_callback = std::function<void(DWORD pid, std::uintptr_t address, ZydisMnemonic mnemonic, std::uint8_t length)>;
    using process_start_callback = std::function<void(DWORD pid)>;
    using process_exit_callback = std::function<void(DWORD pid, DWORD exit_code)>;

    struct callbacks {
        hit_callback on_instruction_hit{};
        branch_callback on_branch_hit{};
        process_start_callback on_process_start{};
        process_exit_callback on_process_exit{};
    };

    bool run_at_entry(
        const std::wstring& executable_path,
        const std::vector<std::wstring>& arguments,
        std::size_t region_size,
        external_instrumentation_result& result,
        callbacks callbacks = {});
    bool run_executable_sections(
        const std::wstring& executable_path,
        const std::vector<std::wstring>& arguments,
        external_instrumentation_result& result,
        callbacks callbacks = {});
    bool attach_and_instrument(
        DWORD pid,
        std::uintptr_t region_start,
        std::size_t region_size,
        external_instrumentation_result& result,
        DWORD timeout_ms = 30000,
        callbacks callbacks = {});

private:
    struct pe_info {
        struct executable_section {
            DWORD rva{0};
            DWORD size{0};
        };

        WORD machine{0};
        DWORD entry_rva{0};
        std::vector<executable_section> executable_sections{};
    };

    bool parse_pe_info(const std::wstring& executable_path, pe_info& pe_info) const;
    bool decode_remote_region(std::uintptr_t start, std::size_t size, bool clear_existing = true);
    bool decode_remote_regions(const std::vector<std::pair<std::uintptr_t, std::size_t>>& regions);
    bool install_breakpoints();
    void remove_breakpoints();
    bool write_remote_byte(std::uintptr_t address, std::uint8_t value) const;
    bool handle_exception_event(const DEBUG_EVENT& debug_event, external_instrumentation_result& result, DWORD& continue_status);

    static std::wstring build_command_line(const std::wstring& executable_path, const std::vector<std::wstring>& arguments);
    static std::wstring quote_argument(const std::wstring& value);
    static void set_instruction_pointer(CONTEXT& context, std::uintptr_t value);
    static void set_single_step(CONTEXT& context);

    HANDLE process_handle_{nullptr};
    std::unordered_map<std::uintptr_t, instrumented_instruction> instructions_{};
    std::unordered_map<DWORD, std::uintptr_t> pending_rearm_by_thread_{};
    callbacks callbacks_{};
};
