#pragma once

#include "basic_block_code_cache.h"
#include "dbi_host.h"
#include "dynamic_binary_instrumentor.h"
#include "dispatcher_code_cache_instrumentor.h"
#include "external_process_instrumentor.h"
#include "guard_page_entry_trap.h"
#include "live_patch_framework.h"
#include "staged_agent_backend.h"

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

enum class instruction_callback_backend {
    translated_cache,
    // Cooperative-only translation. Registered native addresses are translated,
    // but native execution is never trapped or redirected automatically. Enter
    // through translated_entry()/translated_function() or a registered pointer
    // slot. This backend installs no VEH, debug registers, or INT3 breakpoints.
    cooperative_translation,
    // Transparently redirects registered native entries into the translated
    // cache by overwriting a whole-instruction prefix with an inline jump.
    // Original bytes are restored when callbacks are disabled.
    inline_hook,
    // Transparently redirects registered native entries into the translated
    // cache through PAGE_GUARD + VEH traps. Original code bytes are untouched,
    // and no debug registers are used.
    guard_page_translation,
    dispatcher_code_cache
};

struct dbi_framework_options {
    using log_callback_type = std::function<void(const char*)>;

    bool enable_plugins{true};
    instruction_callback_backend instruction_backend{instruction_callback_backend::translated_cache};
    log_callback_type log_callback{};
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
    void set_log_callback(dbi_framework_options::log_callback_type callback);

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

    // In-process instruction callbacks. translated_cache transparently enters
    // registered addresses through a VEH/debug-register entry trap.
    // cooperative_translation only permits explicit translated entrypoints and
    // pointer-slot redirects and never installs a native entry trap.
    int instrument_instruction_with_status(std::uintptr_t address);
    bool instrument_instruction(std::uintptr_t address);
    bool add_instruction_callback(std::function<void(CONTEXT& ctx, std::uintptr_t ip)> callback);
    bool enable_instruction_callbacks();
    const char* last_instruction_error() const;
    void disable_instruction_callbacks();
    void* translated_entry(std::uintptr_t address);
    bool redirect_indirect_call_target(void** target_slot, std::uint64_t* out_redirect_id = nullptr);
    bool restore_indirect_redirect(std::uint64_t redirect_id);

    template <typename Fn>
    Fn translated_function(std::uintptr_t address) {
        return reinterpret_cast<Fn>(translated_entry(address));
    }

    template <typename Fn>
    bool redirect_indirect_function(Fn* target_slot, std::uint64_t* out_redirect_id = nullptr) {
        return redirect_indirect_call_target(reinterpret_cast<void**>(target_slot), out_redirect_id);
    }

private:
    struct indirect_redirect_record {
        std::uint64_t id{0};
        void** target_slot{nullptr};
        std::uintptr_t original_target{0};
        std::uintptr_t translated_target{0};
        std::uint64_t patch_id{0};
        bool installed{false};
    };

    bool ensure_patcher_ready();
    bool read_pointer_slot(void** target_slot, std::uintptr_t& value) const;
    bool install_indirect_redirect(indirect_redirect_record& redirect);
    void restore_installed_indirect_redirects();
    bool install_inline_hooks();
    void restore_inline_hooks();
    void forward_instruction_hit(DWORD pid, const instrumented_instruction& inst, CONTEXT& ctx);

    dbi_host host_{};
    instruction_callback_backend instruction_backend_{instruction_callback_backend::translated_cache};
    dynamic_binary_instrumentor self_instrumentor_{};
    dispatcher_code_cache_instrumentor dispatcher_code_cache_callbacks_{};
    dispatcher_code_cache_instrumentor translated_cache_entry_traps_{};
    guard_page_entry_trap guard_page_entry_traps_{};
    basic_block_code_cache translated_cache_callbacks_{};
    std::vector<std::uintptr_t> translated_requested_entries_{};
    std::vector<indirect_redirect_record> indirect_redirects_{};
    std::vector<std::uint64_t> inline_hook_patch_ids_{};
    std::vector<std::function<void(CONTEXT&, std::uintptr_t)>> instruction_callbacks_user_{};
    external_process_instrumentor external_instrumentor_{};
    live_patch_framework patcher_{};
    live_patch_framework inline_hook_patcher_{};
    std::string inline_hook_error_{};
    std::uint64_t next_indirect_redirect_id_{1};
    bool instruction_callbacks_enabled_{false};
    dbi_framework_options::log_callback_type log_callback_{};
};
