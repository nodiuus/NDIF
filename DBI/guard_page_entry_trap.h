#pragma once

#include <Windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

class guard_page_entry_trap {
public:
    using entry_redirect_resolver_type = std::function<std::uintptr_t(std::uintptr_t)>;
    using log_callback_type = std::function<void(const char*)>;

    guard_page_entry_trap() = default;
    ~guard_page_entry_trap() {
        uninstall();
    }

    guard_page_entry_trap(const guard_page_entry_trap&) = delete;
    guard_page_entry_trap& operator=(const guard_page_entry_trap&) = delete;

    bool instrument_instruction(std::uintptr_t address) {
        if (address == 0) {
            last_error_ = "guard page: invalid target address";
            return false;
        }

        std::lock_guard<std::mutex> guard(lock_);
        if (installed_) {
            last_error_ = "guard page: cannot add targets after install";
            return false;
        }

        for (const auto existing : requested_entries_) {
            if (existing == address) {
                return true;
            }
        }

        requested_entries_.push_back(address);
        return true;
    }

    bool set_entry_redirect_resolver(entry_redirect_resolver_type resolver) {
        if (!resolver) {
            last_error_ = "guard page: redirect resolver is null";
            return false;
        }

        std::lock_guard<std::mutex> guard(lock_);
        if (installed_) {
            last_error_ = "guard page: cannot set resolver after install";
            return false;
        }

        entry_redirect_resolver_ = std::move(resolver);
        return true;
    }

    void set_log_callback(log_callback_type callback) {
        std::lock_guard<std::mutex> guard(lock_);
        log_callback_ = std::move(callback);
    }

    bool install() {
        std::lock_guard<std::mutex> guard(lock_);
        if (installed_) {
            last_error_ = "guard page: already installed";
            return false;
        }
        if (active_instance_.load(std::memory_order_acquire) != nullptr) {
            last_error_ = "guard page: another guard trap is active";
            return false;
        }
        if (requested_entries_.empty()) {
            last_error_ = "guard page: no targets registered";
            return false;
        }
        if (!entry_redirect_resolver_) {
            last_error_ = "guard page: redirect resolver is not configured";
            return false;
        }

        SYSTEM_INFO system_info{};
        GetSystemInfo(&system_info);
        page_size_ = system_info.dwPageSize != 0 ? system_info.dwPageSize : 0x1000;

        target_records_.clear();
        page_records_.clear();
        target_records_.reserve(requested_entries_.size());
        page_records_.reserve(requested_entries_.size());
        for (const auto entry : requested_entries_) {
            const std::uintptr_t translated = entry_redirect_resolver_(entry);
            if (translated == 0) {
                last_error_ = "guard page: target translation failed";
                reset_prepared_state();
                return false;
            }

            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(entry), &mbi, sizeof(mbi)) != sizeof(mbi)) {
                last_error_ = "guard page: VirtualQuery failed for target";
                reset_prepared_state();
                return false;
            }
            if (mbi.State != MEM_COMMIT || !is_executable_protection(mbi.Protect)) {
                last_error_ = "guard page: target page is not committed executable memory";
                reset_prepared_state();
                return false;
            }
            if ((mbi.Protect & PAGE_GUARD) != 0) {
                last_error_ = "guard page: target page already has PAGE_GUARD";
                reset_prepared_state();
                return false;
            }

            const std::uintptr_t page_base = align_down(entry, page_size_);
            page_record* page = find_prepared_page(page_base);
            if (page == nullptr) {
                page_record record{};
                record.base = page_base;
                record.size = page_size_;
                record.original_protect = mbi.Protect;
                page_records_.push_back(std::move(record));
                page = &page_records_.back();
            }

            target_record target{};
            target.original_ip = entry;
            target.translated_entry = translated;
            target_records_.push_back(target);
            page->targets.push_back(&target_records_.back());
        }

        veh_handle_ = AddVectoredExceptionHandler(1, &guard_page_entry_trap::vectored_handler);
        if (veh_handle_ == nullptr) {
            last_error_ = "guard page: AddVectoredExceptionHandler failed";
            reset_prepared_state();
            return false;
        }

        runtime_degraded_.store(false, std::memory_order_release);
        enabled_.store(true, std::memory_order_release);
        active_instance_.store(this, std::memory_order_release);

        for (auto& page : page_records_) {
            if (!protect_page(page, true)) {
                rollback_armed_pages();
                active_instance_.store(nullptr, std::memory_order_release);
                enabled_.store(false, std::memory_order_release);
                RemoveVectoredExceptionHandler(veh_handle_);
                veh_handle_ = nullptr;
                reset_prepared_state();
                return false;
            }
            page.armed = true;
        }

        installed_ = true;
        return true;
    }

    void uninstall() {
        std::unique_lock<std::mutex> guard(lock_);
        enabled_.store(false, std::memory_order_release);

        if (active_instance_.load(std::memory_order_acquire) == this) {
            active_instance_.store(nullptr, std::memory_order_release);
        }

        for (auto& page : page_records_) {
            if (page.armed) {
                DWORD old_protect = 0;
                VirtualProtect(
                    reinterpret_cast<void*>(page.base),
                    page.size,
                    page.original_protect,
                    &old_protect);
                page.armed = false;
            }
        }

        if (veh_handle_ != nullptr) {
            RemoveVectoredExceptionHandler(veh_handle_);
            veh_handle_ = nullptr;
        }

        guard.unlock();
        for (int spin = 0; spin < 1000 && active_handlers_.load(std::memory_order_acquire) != 0; ++spin) {
            Sleep(0);
        }
        guard.lock();

        installed_ = false;
        requested_entries_.clear();
        reset_prepared_state();
        entry_redirect_resolver_ = nullptr;
    }

    const char* last_error() const {
        return last_error_.empty() ? "" : last_error_.c_str();
    }

    bool runtime_degraded() const {
        return runtime_degraded_.load(std::memory_order_acquire);
    }

private:
    struct target_record {
        std::uintptr_t original_ip{0};
        std::uintptr_t translated_entry{0};
    };

    struct page_record {
        std::uintptr_t base{0};
        std::size_t size{0};
        DWORD original_protect{0};
        bool armed{false};
        std::vector<const target_record*> targets{};
    };

    struct handler_scope {
        explicit handler_scope(guard_page_entry_trap& owner) : owner_(owner) {
            owner_.active_handlers_.fetch_add(1, std::memory_order_acq_rel);
        }

        ~handler_scope() {
            owner_.active_handlers_.fetch_sub(1, std::memory_order_acq_rel);
        }

        guard_page_entry_trap& owner_;
    };

    static LONG CALLBACK vectored_handler(PEXCEPTION_POINTERS exception_info) {
        guard_page_entry_trap* self = active_instance_.load(std::memory_order_acquire);
        if (self == nullptr ||
            !self->enabled_.load(std::memory_order_acquire) ||
            exception_info == nullptr ||
            exception_info->ExceptionRecord == nullptr ||
            exception_info->ContextRecord == nullptr) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        handler_scope scope(*self);

        const DWORD code = exception_info->ExceptionRecord->ExceptionCode;
        CONTEXT& context = *exception_info->ContextRecord;

        if (code == STATUS_GUARD_PAGE_VIOLATION) {
            const std::uintptr_t ip = instruction_pointer(context);
            const std::uintptr_t fault_address =
                exception_info->ExceptionRecord->NumberParameters >= 2
                    ? static_cast<std::uintptr_t>(exception_info->ExceptionRecord->ExceptionInformation[1])
                    : ip;

            const page_record* page = self->find_page_containing(fault_address);
            if (page == nullptr) {
                page = self->find_page_containing(ip);
            }
            if (page == nullptr) {
                return EXCEPTION_CONTINUE_SEARCH;
            }

            const target_record* target = self->find_target(*page, ip);
            if (target != nullptr && target->translated_entry != 0) {
                if (!self->protect_page(*page, true)) {
                    self->runtime_degraded_.store(true, std::memory_order_release);
                }
                set_instruction_pointer(context, target->translated_entry);
                return EXCEPTION_CONTINUE_EXECUTION;
            }

            pending_page_ = page;
            pending_had_trap_flag_ = (context.EFlags & k_trap_flag) != 0;
            context.EFlags |= k_trap_flag;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (code == EXCEPTION_SINGLE_STEP && pending_page_ != nullptr) {
            if (!self->protect_page(*pending_page_, true)) {
                self->runtime_degraded_.store(true, std::memory_order_release);
            }
            if (!pending_had_trap_flag_) {
                context.EFlags &= ~k_trap_flag;
            }
            pending_page_ = nullptr;
            pending_had_trap_flag_ = false;
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        return EXCEPTION_CONTINUE_SEARCH;
    }

    static std::uintptr_t instruction_pointer(const CONTEXT& context) {
#if defined(_M_X64)
        return static_cast<std::uintptr_t>(context.Rip);
#else
        return static_cast<std::uintptr_t>(context.Eip);
#endif
    }

    static void set_instruction_pointer(CONTEXT& context, std::uintptr_t address) {
#if defined(_M_X64)
        context.Rip = static_cast<DWORD64>(address);
#else
        context.Eip = static_cast<DWORD>(address);
#endif
    }

    static std::uintptr_t align_down(std::uintptr_t address, std::size_t alignment) {
        return address & ~(static_cast<std::uintptr_t>(alignment) - 1);
    }

    static bool is_executable_protection(DWORD protect) {
        if ((protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
            return false;
        }

        switch (protect & 0xFFu) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    page_record* find_prepared_page(std::uintptr_t base) {
        for (auto& page : page_records_) {
            if (page.base == base) {
                return &page;
            }
        }
        return nullptr;
    }

    const page_record* find_page_containing(std::uintptr_t address) const {
        for (const auto& page : page_records_) {
            if (address >= page.base && address < page.base + page.size) {
                return &page;
            }
        }
        return nullptr;
    }

    const target_record* find_target(const page_record& page, std::uintptr_t ip) const {
        for (const auto* target : page.targets) {
            if (target != nullptr && target->original_ip == ip) {
                return target;
            }
        }
        return nullptr;
    }

    bool protect_page(const page_record& page, bool guarded) const {
        DWORD old_protect = 0;
        const DWORD protection = guarded
            ? (page.original_protect | PAGE_GUARD)
            : page.original_protect;
        return VirtualProtect(
                   reinterpret_cast<void*>(page.base),
                   page.size,
                   protection,
                   &old_protect) != FALSE;
    }

    void rollback_armed_pages() {
        for (auto& page : page_records_) {
            if (!page.armed) {
                continue;
            }
            DWORD old_protect = 0;
            VirtualProtect(
                reinterpret_cast<void*>(page.base),
                page.size,
                page.original_protect,
                &old_protect);
            page.armed = false;
        }
    }

    void reset_prepared_state() {
        page_records_.clear();
        target_records_.clear();
    }

    static constexpr DWORD k_trap_flag = 0x100;

    mutable std::mutex lock_{};
    std::vector<std::uintptr_t> requested_entries_{};
    std::vector<target_record> target_records_{};
    std::vector<page_record> page_records_{};
    entry_redirect_resolver_type entry_redirect_resolver_{};
    log_callback_type log_callback_{};
    std::string last_error_{};
    void* veh_handle_{nullptr};
    std::size_t page_size_{0x1000};
    std::atomic<bool> enabled_{false};
    std::atomic<bool> runtime_degraded_{false};
    std::atomic<unsigned long> active_handlers_{0};
    bool installed_{false};

    inline static std::atomic<guard_page_entry_trap*> active_instance_{nullptr};
    inline static thread_local const page_record* pending_page_{nullptr};
    inline static thread_local bool pending_had_trap_flag_{false};
};
