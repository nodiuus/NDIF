#pragma once

#include "dbi_host.h"
#include "dynamic_binary_instrumentor.h"
#include "dispatcher_code_cache_instrumentor.h"
#include "external_process_instrumentor.h"
#include "live_patch_framework.h"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

enum instrumentation_status {
    success = 0x0,
    invalid_address = 0x1,
    already_instrumented = 0x2,
    decode_failure = 0x3,
    invalid_state = 0x4,
    backend_failure = 0x5
};

struct dbi_framework_options {
    bool enable_plugins{true};
    std::wstring plugins_dir{dbi_host::default_plugins_dir()};
    std::vector<std::wstring> explicit_plugins{};
    std::vector<std::string> plugin_arguments{};
};

// High-level facade over the current "core" so you can embed it as a toolkit.
class dbi_framework {
public:
    dbi_framework() = default;
    ~dbi_framework() = default;

    dbi_framework(const dbi_framework&) = delete;
    dbi_framework& operator=(const dbi_framework&) = delete;

    bool initialize(const dbi_framework_options& options = {});

    plugin_manager& plugins();
    const plugin_manager& plugins() const;

    // Patching helpers (uses live_patch_framework under the hood).
    // If not attached, defaults to current process.
    bool use_current_process_for_patching();
    bool attach_for_patching(DWORD pid);
    void detach_patching();

    bool write_bytes(std::uintptr_t address, const std::uint8_t* bytes, std::size_t size, std::uint64_t* out_patch_id = nullptr);
    bool write_byte(std::uintptr_t address, std::uint8_t value, std::uint64_t* out_patch_id = nullptr);
    bool write_nops(std::uintptr_t address, std::size_t count, std::uint64_t* out_patch_id = nullptr);
    bool remove_patch(std::uint64_t patch_id);

    // In-process breakpoint-based instrumentation.
    bool instrument_self(
        const std::vector<std::pair<void*, std::size_t>>& regions,
        dynamic_binary_instrumentor::callback_type callback);
    void stop_instrument_self();

    // External executable instrumentation (debugger-driven).
    bool run_target_at_entry(
        const std::wstring& executable_path,
        const std::vector<std::wstring>& arguments,
        std::size_t entry_region_size,
        external_instrumentation_result& out_result);
    bool run_target_executable_sections(
        const std::wstring& executable_path,
        const std::vector<std::wstring>& arguments,
        external_instrumentation_result& out_result);

    // attach + instrument region in a running process (debugger-driven).
    bool attach_instrument_region(
        DWORD pid,
        std::uintptr_t region_start,
        std::size_t region_size,
        DWORD timeout_ms,
        external_instrumentation_result& out_result);

    // In-process instruction callbacks. Default backend redirects hardware
    // execute-breakpoint hits into a generated code-cache copy without modifying
    // or hiding target bytes.
    int instrument_instruction_with_status(std::uintptr_t address);
    bool instrument_instruction(std::uintptr_t address);
    bool add_instruction_callback(std::function<void(CONTEXT& ctx, std::uintptr_t ip)> callback);
    bool enable_instruction_callbacks();
    const char* last_instruction_error() const;
    void disable_instruction_callbacks();

private:
    bool ensure_patcher_ready();

    dbi_host host_{};
    dynamic_binary_instrumentor self_instrumentor_{};
    dispatcher_code_cache_instrumentor dispatcher_code_cache_callbacks_{};
    std::vector<std::function<void(CONTEXT&, std::uintptr_t)>> instruction_callbacks_user_{};
    external_process_instrumentor external_instrumentor_{};
    live_patch_framework patcher_{};
};
