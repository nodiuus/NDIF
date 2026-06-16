#include "dbi_framework.h"

#include <Windows.h>

#include <cstring>
#include <vector>

#include <Zydis/Zydis.h>

bool dbi_framework::initialize(const dbi_framework_options& options) {
    instruction_backend_ = options.instruction_backend;
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

bool dbi_framework::read_pointer_slot(void** target_slot, std::uintptr_t& value) const {
    value = 0;
    if (target_slot == nullptr) {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(target_slot, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) != 0 || (mbi.Protect & PAGE_NOACCESS) != 0) {
        return false;
    }

    void* current = nullptr;
    std::memcpy(&current, target_slot, sizeof(current));
    value = reinterpret_cast<std::uintptr_t>(current);
    return value != 0;
}

bool dbi_framework::install_indirect_redirect(indirect_redirect_record& redirect) {
    if (redirect.installed) {
        return true;
    }
    if (instruction_backend_ != instruction_callback_backend::translated_cache ||
        redirect.target_slot == nullptr ||
        redirect.original_target == 0) {
        return false;
    }

    void* translated = translated_cache_callbacks_.translate_entry(redirect.original_target);
    if (translated == nullptr) {
        return false;
    }

    if (!ensure_patcher_ready()) {
        return false;
    }

    std::uintptr_t translated_value = reinterpret_cast<std::uintptr_t>(translated);
    std::vector<std::uint8_t> bytes(sizeof(translated_value));
    std::memcpy(bytes.data(), &translated_value, sizeof(translated_value));

    std::uint64_t patch_id = 0;
    if (!patcher_.write_patch(reinterpret_cast<std::uintptr_t>(redirect.target_slot), bytes, patch_id)) {
        return false;
    }

    redirect.translated_target = translated_value;
    redirect.patch_id = patch_id;
    redirect.installed = true;
    return true;
}

void dbi_framework::restore_installed_indirect_redirects() {
    for (auto it = indirect_redirects_.rbegin(); it != indirect_redirects_.rend(); ++it) {
        if (it->installed) {
            patcher_.remove_patch(it->patch_id);
            it->installed = false;
            it->patch_id = 0;
            it->translated_target = 0;
        }
    }
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

    if (instruction_backend_ == instruction_callback_backend::translated_cache) {
        for (const std::uintptr_t existing : translated_requested_entries_) {
            if (existing == address) {
                return instrumentation_status::already_instrumented;
            }
        }
        translated_requested_entries_.push_back(address);
        return instrumentation_status::success;
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
        forward_instruction_hit(pid, inst, ctx);
    };

    if (instruction_backend_ == instruction_callback_backend::translated_cache) {
        if (translated_requested_entries_.empty() && indirect_redirects_.empty()) {
            plugins().on_process_exit(pid, 1);
            return false;
        }

        if (!translated_cache_callbacks_.add_callback(bridge_callback)) {
            plugins().on_process_exit(pid, 1);
            return false;
        }

        for (const std::uintptr_t entry : translated_requested_entries_) {
            if (translated_cache_callbacks_.translate_entry(entry) == nullptr) {
                translated_cache_entry_traps_.uninstall();
                restore_installed_indirect_redirects();
                translated_cache_callbacks_.reset();
                plugins().on_process_exit(pid, 1);
                return false;
            }
        }

        if (!translated_requested_entries_.empty()) {
            for (const std::uintptr_t entry : translated_requested_entries_) {
                if (!translated_cache_entry_traps_.instrument_instruction(entry)) {
                    restore_installed_indirect_redirects();
                    translated_cache_callbacks_.reset();
                    plugins().on_process_exit(pid, 1);
                    return false;
                }
            }

            if (!translated_cache_entry_traps_.set_entry_redirect_resolver([this](std::uintptr_t address) -> std::uintptr_t {
                    return reinterpret_cast<std::uintptr_t>(translated_cache_callbacks_.translate_entry(address));
                }) ||
                !translated_cache_entry_traps_.add_callback([](const instrumented_instruction&, CONTEXT&) {}) ||
                !translated_cache_entry_traps_.install()) {
                translated_cache_entry_traps_.uninstall();
                restore_installed_indirect_redirects();
                translated_cache_callbacks_.reset();
                plugins().on_process_exit(pid, 1);
                return false;
            }
        }

        for (auto& redirect : indirect_redirects_) {
            if (!install_indirect_redirect(redirect)) {
                translated_cache_entry_traps_.uninstall();
                restore_installed_indirect_redirects();
                translated_cache_callbacks_.reset();
                plugins().on_process_exit(pid, 1);
                return false;
            }
        }

        instruction_callbacks_enabled_ = true;
        return true;
    }

    if (!dispatcher_code_cache_callbacks_.add_callback(bridge_callback)) {
        plugins().on_process_exit(pid, 1);
        return false;
    }

    if (!dispatcher_code_cache_callbacks_.install()) {
        plugins().on_process_exit(pid, 1);
        return false;
    }

    instruction_callbacks_enabled_ = true;
    return true;
}

const char* dbi_framework::last_instruction_error() const {
    if (instruction_backend_ == instruction_callback_backend::translated_cache) {
        return translated_cache_callbacks_.last_error();
    }
    return dispatcher_code_cache_callbacks_.last_error();
}

void dbi_framework::disable_instruction_callbacks() {
    if (instruction_backend_ == instruction_callback_backend::translated_cache) {
        translated_cache_entry_traps_.uninstall();
        restore_installed_indirect_redirects();
        translated_cache_callbacks_.reset();
        translated_requested_entries_.clear();
        indirect_redirects_.clear();
    } else {
        dispatcher_code_cache_callbacks_.uninstall();
    }
    instruction_callbacks_user_.clear();
    instruction_callbacks_enabled_ = false;
    plugins().on_process_exit(GetCurrentProcessId(), 0);
}

void* dbi_framework::translated_entry(std::uintptr_t address) {
    if (address == 0) {
        return nullptr;
    }
    return translated_cache_callbacks_.translate_entry(address);
}

bool dbi_framework::redirect_indirect_call_target(void** target_slot, std::uint64_t* out_redirect_id) {
    if (instruction_backend_ != instruction_callback_backend::translated_cache) {
        return false;
    }

    for (const auto& redirect : indirect_redirects_) {
        if (redirect.target_slot == target_slot) {
            if (out_redirect_id != nullptr) {
                *out_redirect_id = redirect.id;
            }
            return true;
        }
    }

    std::uintptr_t original_target = 0;
    if (!read_pointer_slot(target_slot, original_target)) {
        return false;
    }

    indirect_redirect_record redirect{};
    redirect.id = next_indirect_redirect_id_++;
    redirect.target_slot = target_slot;
    redirect.original_target = original_target;

    indirect_redirects_.push_back(redirect);
    indirect_redirect_record& stored = indirect_redirects_.back();
    if (instruction_callbacks_enabled_ && !install_indirect_redirect(stored)) {
        indirect_redirects_.pop_back();
        return false;
    }

    if (out_redirect_id != nullptr) {
        *out_redirect_id = stored.id;
    }
    return true;
}

bool dbi_framework::restore_indirect_redirect(std::uint64_t redirect_id) {
    for (auto it = indirect_redirects_.begin(); it != indirect_redirects_.end(); ++it) {
        if (it->id != redirect_id) {
            continue;
        }

        if (it->installed && !patcher_.remove_patch(it->patch_id)) {
            return false;
        }
        indirect_redirects_.erase(it);
        return true;
    }

    return false;
}

void dbi_framework::forward_instruction_hit(DWORD pid, const instrumented_instruction& inst, CONTEXT& ctx) {
    plugins().on_instruction_hit(pid, inst.address);
    if (inst.is_control_flow) {
        plugins().on_branch_hit(pid, inst.address, ZydisMnemonicGetString(inst.mnemonic), inst.length);
    }

    for (auto& cb : instruction_callbacks_user_) {
        cb(ctx, inst.address);
    }
}
