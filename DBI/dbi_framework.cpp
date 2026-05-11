#include "dbi_framework.h"

#include <Windows.h>

#include <vector>

#include <Zydis/Zydis.h>

bool dbi_framework::initialize(const dbi_framework_options& options) {
    if (options.enable_plugins) {
        host_.load_plugins(options.plugins_dir, options.explicit_plugins);
        if (!host_.plugins().configure_loaded_plugins(options.plugin_arguments)) {
            return false;
        }
    }
    return true;
}

plugin_manager& dbi_framework::plugins() {
    return host_.plugins();
}

const plugin_manager& dbi_framework::plugins() const {
    return host_.plugins();
}

bool dbi_framework::ensure_patcher_ready() {
    if (patcher_.is_attached()) {
        return true;
    }
    return patcher_.use_current_process();
}

bool dbi_framework::use_current_process_for_patching() {
    return patcher_.use_current_process();
}

bool dbi_framework::attach_for_patching(DWORD pid) {
    return patcher_.attach(pid);
}

void dbi_framework::detach_patching() {
    patcher_.detach();
}

bool dbi_framework::write_bytes(std::uintptr_t address, const std::uint8_t* bytes, std::size_t size, std::uint64_t* out_patch_id) {
    if (address == 0 || bytes == nullptr || size == 0) {
        return false;
    }
    if (!ensure_patcher_ready()) {
        return false;
    }

    std::vector<std::uint8_t> v(bytes, bytes + size);
    std::uint64_t patch_id = 0;
    if (!patcher_.write_patch(address, v, patch_id)) {
        return false;
    }

    if (out_patch_id) {
        *out_patch_id = patch_id;
    }
    return true;
}

bool dbi_framework::write_byte(std::uintptr_t address, std::uint8_t value, std::uint64_t* out_patch_id) {
    return write_bytes(address, &value, 1, out_patch_id);
}

bool dbi_framework::write_nops(std::uintptr_t address, std::size_t count, std::uint64_t* out_patch_id) {
    if (address == 0 || count == 0) {
        return false;
    }
    if (!ensure_patcher_ready()) {
        return false;
    }

    std::uint64_t patch_id = 0;
    if (!patcher_.write_nop_patch(address, count, patch_id)) {
        return false;
    }
    if (out_patch_id) {
        *out_patch_id = patch_id;
    }
    return true;
}

bool dbi_framework::remove_patch(std::uint64_t patch_id) {
    return patcher_.remove_patch(patch_id);
}

bool dbi_framework::instrument_self(
    const std::vector<std::pair<void*, std::size_t>>& regions,
    dynamic_binary_instrumentor::callback_type callback) {

    if (!callback || regions.empty()) {
        return false;
    }

    for (const auto& r : regions) {
        if (!self_instrumentor_.add_region(r.first, r.second)) {
            return false;
        }
    }

    const DWORD pid = GetCurrentProcessId();
    plugins().on_process_start(pid, L"");

    const bool ok = self_instrumentor_.install(
        [&](const instrumented_instruction& inst, CONTEXT& ctx) {
            plugins().on_instruction_hit(pid, inst.address);
            if (inst.is_control_flow) {
                plugins().on_branch_hit(pid, inst.address, ZydisMnemonicGetString(inst.mnemonic), inst.length);
            }
            callback(inst, ctx);
        });

    if (!ok) {
        plugins().on_process_exit(pid, 1);
    }

    return ok;
}

void dbi_framework::stop_instrument_self() {
    self_instrumentor_.uninstall();
    plugins().on_process_exit(GetCurrentProcessId(), 0);
}

bool dbi_framework::run_target_at_entry(
    const std::wstring& executable_path,
    const std::vector<std::wstring>& arguments,
    std::size_t entry_region_size,
    external_instrumentation_result& out_result) {

    external_process_instrumentor::callbacks cbs{};
    cbs.on_process_start = [&](DWORD pid) { plugins().on_process_start(pid, executable_path); };
    cbs.on_process_exit = [&](DWORD pid, DWORD exit_code) { plugins().on_process_exit(pid, exit_code); };
    cbs.on_instruction_hit = [&](DWORD pid, std::uintptr_t address) { plugins().on_instruction_hit(pid, address); };
    cbs.on_branch_hit = [&](DWORD pid, std::uintptr_t address, ZydisMnemonic mnemonic, std::uint8_t length) {
        plugins().on_branch_hit(pid, address, ZydisMnemonicGetString(mnemonic), length);
    };

    return external_instrumentor_.run_at_entry(executable_path, arguments, entry_region_size, out_result, cbs);
}

bool dbi_framework::run_target_executable_sections(
    const std::wstring& executable_path,
    const std::vector<std::wstring>& arguments,
    external_instrumentation_result& out_result) {

    external_process_instrumentor::callbacks cbs{};
    cbs.on_process_start = [&](DWORD pid) { plugins().on_process_start(pid, executable_path); };
    cbs.on_process_exit = [&](DWORD pid, DWORD exit_code) { plugins().on_process_exit(pid, exit_code); };
    cbs.on_instruction_hit = [&](DWORD pid, std::uintptr_t address) { plugins().on_instruction_hit(pid, address); };
    cbs.on_branch_hit = [&](DWORD pid, std::uintptr_t address, ZydisMnemonic mnemonic, std::uint8_t length) {
        plugins().on_branch_hit(pid, address, ZydisMnemonicGetString(mnemonic), length);
    };

    return external_instrumentor_.run_executable_sections(executable_path, arguments, out_result, cbs);
}

bool dbi_framework::attach_instrument_region(
    DWORD pid,
    std::uintptr_t region_start,
    std::size_t region_size,
    DWORD timeout_ms,
    external_instrumentation_result& out_result) {

    external_process_instrumentor::callbacks cbs{};
    cbs.on_process_start = [&](DWORD started_pid) { plugins().on_process_start(started_pid, L""); };
    cbs.on_process_exit = [&](DWORD exited_pid, DWORD exit_code) { plugins().on_process_exit(exited_pid, exit_code); };
    cbs.on_instruction_hit = [&](DWORD hit_pid, std::uintptr_t address) { plugins().on_instruction_hit(hit_pid, address); };
    cbs.on_branch_hit = [&](DWORD hit_pid, std::uintptr_t address, ZydisMnemonic mnemonic, std::uint8_t length) {
        plugins().on_branch_hit(hit_pid, address, ZydisMnemonicGetString(mnemonic), length);
    };

    return external_instrumentor_.attach_and_instrument(pid, region_start, region_size, out_result, timeout_ms, cbs);
}

int dbi_framework::instrument_instruction_with_status(std::uintptr_t address) {
    if (address == 0) {
        return instrumentation_status::invalid_address;
    }
    return dispatcher_code_cache_callbacks_.instrument_instruction(address) ? instrumentation_status::success : instrumentation_status::backend_failure;
}

bool dbi_framework::instrument_instruction(std::uintptr_t address) {
    return instrument_instruction_with_status(address) == instrumentation_status::success;
}

bool dbi_framework::add_instruction_callback(std::function<void(CONTEXT& ctx, std::uintptr_t ip)> callback) {
    if (!callback) {
        return false;
    }
    instruction_callbacks_user_.push_back(std::move(callback));
    return true;
}

bool dbi_framework::enable_instruction_callbacks() {
    // Bridge: the low-level instrumentor calls us with the instruction; we forward to user callbacks and plugins.
    if (instruction_callbacks_user_.empty()) {
        return false;
    }

    // This API is self-only and assumes a single-threaded setup/teardown; avoid modifying callbacks while enabled.

    const DWORD pid = GetCurrentProcessId();
    plugins().on_process_start(pid, L"");

    auto bridge_callback = [this, pid](const instrumented_instruction& inst, CONTEXT& ctx) {
        plugins().on_instruction_hit(pid, inst.address);
        if (inst.is_control_flow) {
            plugins().on_branch_hit(pid, inst.address, ZydisMnemonicGetString(inst.mnemonic), inst.length);
        }

        for (auto& cb : instruction_callbacks_user_) {
            cb(ctx, inst.address);
        }
    };

    if (!dispatcher_code_cache_callbacks_.add_callback(bridge_callback)) {
        plugins().on_process_exit(pid, 1);
        return false;
    }

    if (!dispatcher_code_cache_callbacks_.install()) {
        plugins().on_process_exit(pid, 1);
        return false;
    }

    return true;
}

const char* dbi_framework::last_instruction_error() const {
    return dispatcher_code_cache_callbacks_.last_error();
}

void dbi_framework::disable_instruction_callbacks() {
    dispatcher_code_cache_callbacks_.uninstall();
    instruction_callbacks_user_.clear();
    plugins().on_process_exit(GetCurrentProcessId(), 0);
}
