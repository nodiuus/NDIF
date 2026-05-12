#pragma once

#include "dynamic_binary_instrumentor.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

// windows automatically defines these for some reason
#undef min
#undef max

// In-process code-cache backend using hardware execute breakpoints as
// non-mutating entry traps. The original entry bytes are copied into an
// executable cache block. A VEH catches execution at registered instruction
// pointers, redirects RIP/EIP to the cache copy, and leaves the original bytes
// readable and untouched.
class dispatcher_code_cache_instrumentor {
public:
    using callback_type = std::function<void(const instrumented_instruction&, CONTEXT&)>;

    dispatcher_code_cache_instrumentor() = default;
    ~dispatcher_code_cache_instrumentor() {
        uninstall();
    }

    dispatcher_code_cache_instrumentor(const dispatcher_code_cache_instrumentor&) = delete;
    dispatcher_code_cache_instrumentor& operator=(const dispatcher_code_cache_instrumentor&) = delete;

    bool instrument_instruction(std::uintptr_t address) {
        if (address == 0) {
            trace_failure(address, "address_zero");
            return false;
        }

        std::lock_guard<std::mutex> guard(lock_);
        if (installed_) {
            trace_failure(address, "already_installed");
            return false;
        }
        if (sites_.find(address) != sites_.end()) {
            return true;
        }
        if (sites_.size() >= k_max_breakpoint_sites) {
            trace_failure(address, "hardware_breakpoint_site_limit");
            last_error_ = "hardware breakpoint site limit reached";
            return false;
        }

        cached_site site{};
        if (!build_site(address, site)) {
            trace_failure(address, "build_site");
            return false;
        }

        sites_.try_emplace(address, std::move(site));
        return true;
    }

    bool add_callback(callback_type callback) {
        if (!callback) {
            return false;
        }

        std::lock_guard<std::mutex> guard(lock_);
        if (installed_) {
            return false;
        }

        callbacks_.push_back(std::move(callback));
        return true;
    }

    bool install() {
        std::lock_guard<std::mutex> guard(lock_);
        if (installed_ || active_instance_ != nullptr || sites_.empty() || callbacks_.empty()) {
            record_install_failure(
                "invalid_state",
                0,
                0,
                installed_ ? 1 : 0,
                active_instance_ != nullptr ? 1 : 0,
                static_cast<unsigned long>(sites_.size()),
                static_cast<unsigned long>(callbacks_.size()),
                0);
            return false;
        }

        veh_handle_ = AddVectoredExceptionHandler(1, &dispatcher_code_cache_instrumentor::vectored_handler);
        if (veh_handle_ == nullptr) {
            record_install_failure(
                "add_vectored_exception_handler",
                0,
                0,
                0,
                0,
                static_cast<unsigned long>(sites_.size()),
                static_cast<unsigned long>(callbacks_.size()),
                GetLastError());
            return false;
        }

        active_instance_ = this;
        if (!apply_breakpoints_to_process_threads_locked(true)) {
            apply_breakpoints_to_process_threads_locked(false);
            active_instance_ = nullptr;
            RemoveVectoredExceptionHandler(veh_handle_);
            veh_handle_ = nullptr;
            return false;
        }
        if (!start_thread_sync_worker_locked()) {
            apply_breakpoints_to_process_threads_locked(false);
            active_instance_ = nullptr;
            RemoveVectoredExceptionHandler(veh_handle_);
            veh_handle_ = nullptr;
            return false;
        }

        installed_ = true;
        return true;
    }

    void uninstall() {
        std::unique_lock<std::mutex> guard(lock_);

        stop_thread_sync_worker_locked(guard);
        apply_breakpoints_to_process_threads_locked(false);

        for (auto& [address, site] : sites_) {
            (void)address;
            if (site.cache_entry != 0) {
                VirtualFree(reinterpret_cast<void*>(site.cache_entry), 0, MEM_RELEASE);
                site.cache_entry = 0;
            }
        }

        callbacks_.clear();
        sites_.clear();
        installed_ = false;
        if (active_instance_ == this) {
            active_instance_ = nullptr;
        }
        if (veh_handle_ != nullptr) {
            RemoveVectoredExceptionHandler(veh_handle_);
            veh_handle_ = nullptr;
        }
    }

    const char* last_error() const {
        return last_error_.empty() ? "" : last_error_.c_str();
    }

private:
    struct decoded_site_entry {
        instrumented_instruction inst{};
        ZydisDecodedInstruction decoded{};
        std::size_t block_offset{0};
        bool has_relative_encoding{false};
    };

    struct cached_site {
        instrumented_instruction head_instruction{};
        std::vector<decoded_site_entry> entries{};
        std::vector<std::uint8_t> original_bytes{};
        std::uintptr_t cache_entry{0};
        std::size_t copied_size{0};
    };

    static constexpr std::size_t k_max_breakpoint_sites = 4;
    static constexpr DWORD64 k_dr7_breakpoint_slot_mask =
        (1ULL << 0) |
        (1ULL << 2) |
        (1ULL << 4) |
        (1ULL << 6) |
        (0xFULL << 16) |
        (0xFULL << 20) |
        (0xFULL << 24) |
        (0xFULL << 28);

    static LONG CALLBACK vectored_handler(PEXCEPTION_POINTERS exception_info) {
        dispatcher_code_cache_instrumentor* self = active_instance_;
        if (self == nullptr || exception_info == nullptr || exception_info->ExceptionRecord == nullptr || exception_info->ContextRecord == nullptr) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        CONTEXT& context = *exception_info->ContextRecord;
        const DWORD code = exception_info->ExceptionRecord->ExceptionCode;
        if (code != EXCEPTION_SINGLE_STEP) {
            return EXCEPTION_CONTINUE_SEARCH;
        }

        const std::uintptr_t ip = instruction_pointer(context);
        std::uintptr_t cache_entry = 0;
        {
            std::lock_guard<std::mutex> guard(self->lock_);
            const auto it = self->sites_.find(ip);
            if (it != self->sites_.end()) {
                cache_entry = it->second.cache_entry;
            }
        }

        if (cache_entry != 0) {
            context.Dr6 = 0;
            set_instruction_pointer(context, cache_entry);
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

    static void dispatch_site_hit(std::uintptr_t address, const void* saved_registers) {
        dispatcher_code_cache_instrumentor* self = active_instance_;
        if (self == nullptr) {
            return;
        }

        const cached_site* site = self->find_site(address);
        if (site == nullptr) {
            return;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#if defined(_M_X64)
        context.Rip = static_cast<DWORD64>(address);
        populate_context_from_saved_registers(saved_registers, context);
#else
        context.Eip = static_cast<DWORD>(address);
#endif

        for (auto& cb : self->callbacks_) {
            cb(site->head_instruction, context);
        }

#if defined(_M_X64)
        apply_context_to_saved_registers(context, saved_registers);
#endif
    }

#if defined(_M_X64)
    static constexpr std::size_t k_saved_r15_offset = 0x00;
    static constexpr std::size_t k_saved_r14_offset = 0x08;
    static constexpr std::size_t k_saved_r13_offset = 0x10;
    static constexpr std::size_t k_saved_r12_offset = 0x18;
    static constexpr std::size_t k_saved_r11_offset = 0x20;
    static constexpr std::size_t k_saved_r10_offset = 0x28;
    static constexpr std::size_t k_saved_r9_offset = 0x30;
    static constexpr std::size_t k_saved_r8_offset = 0x38;
    static constexpr std::size_t k_saved_rdi_offset = 0x40;
    static constexpr std::size_t k_saved_rsi_offset = 0x48;
    static constexpr std::size_t k_saved_rbp_offset = 0x50;
    static constexpr std::size_t k_saved_rbx_offset = 0x58;
    static constexpr std::size_t k_saved_rdx_offset = 0x60;
    static constexpr std::size_t k_saved_rcx_offset = 0x68;
    static constexpr std::size_t k_saved_rax_offset = 0x70;
    static constexpr std::size_t k_saved_rflags_offset = 0x78;
    static constexpr std::size_t k_saved_stack_size = 0x80;

    static DWORD64 read_saved_u64(const void* saved_registers, std::size_t offset) {
        if (saved_registers == nullptr) {
            return 0;
        }
        const auto* base = static_cast<const std::uint8_t*>(saved_registers);
        DWORD64 value = 0;
        std::memcpy(&value, base + offset, sizeof(value));
        return value;
    }

    static void write_saved_u64(const void* saved_registers, std::size_t offset, DWORD64 value) {
        if (saved_registers == nullptr) {
            return;
        }
        auto* base = const_cast<std::uint8_t*>(static_cast<const std::uint8_t*>(saved_registers));
        std::memcpy(base + offset, &value, sizeof(value));
    }

    static void populate_context_from_saved_registers(const void* saved_registers, CONTEXT& context) {
        context.Rax = read_saved_u64(saved_registers, k_saved_rax_offset);
        context.Rcx = read_saved_u64(saved_registers, k_saved_rcx_offset);
        context.Rdx = read_saved_u64(saved_registers, k_saved_rdx_offset);
        context.Rbx = read_saved_u64(saved_registers, k_saved_rbx_offset);
        context.Rbp = read_saved_u64(saved_registers, k_saved_rbp_offset);
        context.Rsi = read_saved_u64(saved_registers, k_saved_rsi_offset);
        context.Rdi = read_saved_u64(saved_registers, k_saved_rdi_offset);
        context.R8 = read_saved_u64(saved_registers, k_saved_r8_offset);
        context.R9 = read_saved_u64(saved_registers, k_saved_r9_offset);
        context.R10 = read_saved_u64(saved_registers, k_saved_r10_offset);
        context.R11 = read_saved_u64(saved_registers, k_saved_r11_offset);
        context.R12 = read_saved_u64(saved_registers, k_saved_r12_offset);
        context.R13 = read_saved_u64(saved_registers, k_saved_r13_offset);
        context.R14 = read_saved_u64(saved_registers, k_saved_r14_offset);
        context.R15 = read_saved_u64(saved_registers, k_saved_r15_offset);
        context.Rsp = reinterpret_cast<DWORD64>(saved_registers) + k_saved_stack_size;
        context.EFlags = static_cast<DWORD>(read_saved_u64(saved_registers, k_saved_rflags_offset) & 0xFFFFFFFFULL);
    }

    static void apply_context_to_saved_registers(const CONTEXT& context, const void* saved_registers) {
        write_saved_u64(saved_registers, k_saved_rax_offset, context.Rax);
        write_saved_u64(saved_registers, k_saved_rcx_offset, context.Rcx);
        write_saved_u64(saved_registers, k_saved_rdx_offset, context.Rdx);
        write_saved_u64(saved_registers, k_saved_rbx_offset, context.Rbx);
        write_saved_u64(saved_registers, k_saved_rbp_offset, context.Rbp);
        write_saved_u64(saved_registers, k_saved_rsi_offset, context.Rsi);
        write_saved_u64(saved_registers, k_saved_rdi_offset, context.Rdi);
        write_saved_u64(saved_registers, k_saved_r8_offset, context.R8);
        write_saved_u64(saved_registers, k_saved_r9_offset, context.R9);
        write_saved_u64(saved_registers, k_saved_r10_offset, context.R10);
        write_saved_u64(saved_registers, k_saved_r11_offset, context.R11);
        write_saved_u64(saved_registers, k_saved_r12_offset, context.R12);
        write_saved_u64(saved_registers, k_saved_r13_offset, context.R13);
        write_saved_u64(saved_registers, k_saved_r14_offset, context.R14);
        write_saved_u64(saved_registers, k_saved_r15_offset, context.R15);
        write_saved_u64(saved_registers, k_saved_rflags_offset, context.EFlags);
    }
#endif

    const cached_site* find_site(std::uintptr_t address) const {
        const auto it = sites_.find(address);
        if (it == sites_.end()) {
            return nullptr;
        }
        return &it->second;
    }

    bool build_site(std::uintptr_t address, cached_site& out_site) const {
        out_site = {};
        if (!decode_patchable_prefix(address, out_site.head_instruction, out_site.entries, out_site.original_bytes, out_site.copied_size)) {
            return false;
        }

        std::vector<std::uint8_t> prologue{};
        build_callback_prologue(address, prologue);

        std::vector<std::uint8_t> jump_back{};
        build_absolute_jump(address + out_site.copied_size, jump_back);

        std::vector<std::uint8_t> cache_blob{};
        cache_blob.reserve(prologue.size() + out_site.original_bytes.size() + jump_back.size());
        cache_blob.insert(cache_blob.end(), prologue.begin(), prologue.end());
        cache_blob.insert(cache_blob.end(), out_site.original_bytes.begin(), out_site.original_bytes.end());
        cache_blob.insert(cache_blob.end(), jump_back.begin(), jump_back.end());

        void* cache = allocate_executable_near(address, cache_blob.size());
        if (cache == nullptr) {
            return false;
        }

        std::memcpy(cache, cache_blob.data(), cache_blob.size());
        auto* copied_prefix = reinterpret_cast<std::uint8_t*>(cache) + prologue.size();
        const std::uintptr_t copied_prefix_base = reinterpret_cast<std::uintptr_t>(cache) + prologue.size();
        if (!relocate_relative_fields(out_site.entries, out_site.original_bytes, copied_prefix, copied_prefix_base)) {
            VirtualFree(cache, 0, MEM_RELEASE);
            return false;
        }

        FlushInstructionCache(GetCurrentProcess(), cache, cache_blob.size());
        out_site.cache_entry = reinterpret_cast<std::uintptr_t>(cache);
        return true;
    }

    bool decode_patchable_prefix(
        std::uintptr_t address,
        instrumented_instruction& out_head,
        std::vector<decoded_site_entry>& out_entries,
        std::vector<std::uint8_t>& out_bytes,
        std::size_t& out_size) const {

        out_head = {};
        out_entries.clear();
        out_bytes.clear();
        out_size = 0;

        constexpr std::size_t k_max_instructions = 1;
        constexpr std::size_t k_max_bytes = 32;

        std::uintptr_t cursor = address;
        std::size_t total = 0;
        for (std::size_t decoded_count = 0; decoded_count < k_max_instructions && total < k_max_bytes; ++decoded_count) {
            instrumented_instruction decoded{};
            bool is_relative = false;
            ZydisDecodedInstruction zydis{};
            if (!decode_one(cursor, decoded, is_relative, zydis)) {
                return false;
            }
            if (decoded_count == 0) {
                out_head = decoded;
            }

            // Guard-page redirection enters the cache at the requested
            // instruction, runs that relocated instruction, then jumps back to
            // the original continuation. Keep control-flow instructions out
            // until branch relocation is implemented deliberately.
            if (decoded.is_control_flow) {
                return false;
            }

            decoded_site_entry entry{};
            entry.inst = decoded;
            entry.decoded = zydis;
            entry.block_offset = total;
            entry.has_relative_encoding = is_relative;
            out_entries.push_back(entry);

            total += decoded.length;
            cursor += decoded.length;
            break;
        }

        out_bytes.assign(total, 0);
        SIZE_T read = 0;
        if (!ReadProcessMemory(
                GetCurrentProcess(),
                reinterpret_cast<const void*>(address),
                out_bytes.data(),
                static_cast<SIZE_T>(total),
                &read) ||
            read != static_cast<SIZE_T>(total)) {
            out_bytes.clear();
            return false;
        }

        out_size = total;
        return true;
    }

    bool decode_one(
        std::uintptr_t address,
        instrumented_instruction& out,
        bool& is_relative,
        ZydisDecodedInstruction& out_decoded) const {

        out = {};
        is_relative = false;
        out_decoded = {};
        if (address == 0) {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi)) {
            return false;
        }
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_GUARD) != 0 || (mbi.Protect & PAGE_NOACCESS) != 0) {
            return false;
        }

        const DWORD protect = (mbi.Protect & 0xFF);
        const bool executable =
            protect == PAGE_EXECUTE ||
            protect == PAGE_EXECUTE_READ ||
            protect == PAGE_EXECUTE_READWRITE ||
            protect == PAGE_EXECUTE_WRITECOPY;
        if (!executable) {
            return false;
        }

        std::uint8_t buffer[32]{};
        SIZE_T read = 0;
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), buffer, sizeof(buffer), &read) || read == 0) {
            return false;
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

        ZyanStatus status{};
#if defined(ZYDIS_VERSION) && (ZYDIS_VERSION_MAJOR(ZYDIS_VERSION) >= 4)
        ZydisDecoderContext context{};
        status = ZydisDecoderDecodeInstruction(&decoder, &context, buffer, read, &out_decoded);
#else
        status = ZydisDecoderDecodeBuffer(&decoder, buffer, read, &out_decoded);
#endif
        if (!ZYAN_SUCCESS(status) || out_decoded.length == 0) {
            return false;
        }

        is_relative = (out_decoded.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;

        bool is_control_flow = false;
        switch (out_decoded.meta.category) {
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
        if (out_decoded.mnemonic == ZYDIS_MNEMONIC_INT ||
            out_decoded.mnemonic == ZYDIS_MNEMONIC_INT1 ||
            out_decoded.mnemonic == ZYDIS_MNEMONIC_INT3 ||
            out_decoded.mnemonic == ZYDIS_MNEMONIC_INTO) {
            is_control_flow = true;
        }

        out.address = address;
        out.length = static_cast<std::uint8_t>(out_decoded.length);
        out.original_first_byte = buffer[0];
        out.is_control_flow = is_control_flow;
        out.mnemonic = out_decoded.mnemonic;
        return true;
    }

    static void build_callback_prologue(std::uintptr_t site_address, std::vector<std::uint8_t>& out) {
        out.clear();
#if defined(_M_X64)
        out.push_back(0x9C); // pushfq
        append_push_gpr64(0, out);
        append_push_gpr64(1, out);
        append_push_gpr64(2, out);
        append_push_gpr64(3, out);
        append_push_gpr64(5, out);
        append_push_gpr64(6, out);
        append_push_gpr64(7, out);
        for (std::uint8_t reg = 8; reg <= 15; ++reg) {
            append_push_gpr64(reg, out);
        }

        // mov r11, rsp
        out.insert(out.end(), {0x49, 0x89, 0xE3});
        // and rsp, -16
        out.insert(out.end(), {0x48, 0x83, 0xE4, 0xF0});
        // sub rsp, 0x130 (32-byte shadow space + 16 XMM registers + saved pre-call RSP)
        out.insert(out.end(), {0x48, 0x81, 0xEC, 0x30, 0x01, 0x00, 0x00});
        // mov [rsp+0x120], r11
        out.insert(out.end(), {0x4C, 0x89, 0x9C, 0x24, 0x20, 0x01, 0x00, 0x00});
        for (std::uint8_t xmm = 0; xmm < 16; ++xmm) {
            append_movdqu_store_xmm_rsp(xmm, 0x20 + static_cast<std::uint32_t>(xmm) * 16, out);
        }

        append_mov_rcx_imm64(site_address, out);
        // mov rdx, r11 ; pass pointer to saved GPR/RFLAGS frame
        out.insert(out.end(), {0x4C, 0x89, 0xDA});
        append_mov_rax_imm64(reinterpret_cast<std::uintptr_t>(&dispatcher_code_cache_instrumentor::dispatch_site_hit), out);
        out.insert(out.end(), {0xFF, 0xD0}); // call rax

        for (std::uint8_t xmm = 0; xmm < 16; ++xmm) {
            append_movdqu_load_xmm_rsp(xmm, 0x20 + static_cast<std::uint32_t>(xmm) * 16, out);
        }
        // mov r11, [rsp+0x120]
        out.insert(out.end(), {0x4C, 0x8B, 0x9C, 0x24, 0x20, 0x01, 0x00, 0x00});
        // mov rsp, r11
        out.insert(out.end(), {0x4C, 0x89, 0xDC});

        for (std::uint8_t reg = 15; reg >= 8; --reg) {
            append_pop_gpr64(reg, out);
            if (reg == 8) {
                break;
            }
        }
        append_pop_gpr64(7, out);
        append_pop_gpr64(6, out);
        append_pop_gpr64(5, out);
        append_pop_gpr64(3, out);
        append_pop_gpr64(2, out);
        append_pop_gpr64(1, out);
        append_pop_gpr64(0, out);
        out.push_back(0x9D); // popfq
#else
        out.push_back(0x9C); // pushfd
        out.push_back(0x60); // pushad
        out.push_back(0x68); // push imm32
        append_u32(static_cast<std::uint32_t>(site_address), out);
        const std::uintptr_t call_site = 0; // fixed up by absolute push/ret style below.
        (void)call_site;
        out.push_back(0xB8); // mov eax, imm32
        append_u32(reinterpret_cast<std::uint32_t>(&dispatcher_code_cache_instrumentor::dispatch_site_hit), out);
        out.insert(out.end(), {0xFF, 0xD0}); // call eax
        out.insert(out.end(), {0x83, 0xC4, 0x04}); // add esp, 4
        out.push_back(0x61); // popad
        out.push_back(0x9D); // popfd
#endif
    }

    static void build_absolute_jump(std::uintptr_t dst, std::vector<std::uint8_t>& out) {
        out.clear();
#if defined(_M_X64)
        append_absolute_indirect_jump(dst, out);
#else
        out.push_back(0x68);
        append_u32(static_cast<std::uint32_t>(dst), out);
        out.push_back(0xC3);
#endif
    }

    static void* allocate_executable_near(std::uintptr_t reference, std::size_t size) {
        if (size == 0) {
            return nullptr;
        }

#if defined(_M_X64)
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const std::uintptr_t granularity = static_cast<std::uintptr_t>(si.dwAllocationGranularity);
        if (granularity == 0) {
            return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        }

        constexpr std::uintptr_t max_disp = static_cast<std::uintptr_t>(std::numeric_limits<std::int32_t>::max());

        const std::uintptr_t min_addr = (reference > max_disp) ? (reference - max_disp) : 0;
        const std::uintptr_t max_addr = (reference < (std::numeric_limits<std::uintptr_t>::max() - max_disp))
                                            ? (reference + max_disp)
                                            : std::numeric_limits<std::uintptr_t>::max();

        auto align_down = [granularity](std::uintptr_t value) -> std::uintptr_t {
            return value & ~(granularity - 1);
        };

        for (std::uintptr_t distance = 0; distance < max_disp; distance += granularity) {
            std::uintptr_t candidates[2]{};
            candidates[0] = (reference >= distance) ? align_down(reference - distance) : 0;
            candidates[1] = (reference <= (std::numeric_limits<std::uintptr_t>::max() - distance)) ? align_down(reference + distance) : 0;

            for (std::uintptr_t candidate : candidates) {
                if (candidate < min_addr || candidate > max_addr) {
                    continue;
                }
                void* p = VirtualAlloc(reinterpret_cast<void*>(candidate), size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (p != nullptr) {
                    return p;
                }
            }
        }
#endif

        return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }

    bool relocate_relative_fields(
        const std::vector<decoded_site_entry>& entries,
        const std::vector<std::uint8_t>& original_block,
        std::uint8_t* cache_block,
        std::uintptr_t cache_base) const {

        if (entries.empty() || cache_block == nullptr || cache_base == 0) {
            return false;
        }

        for (const decoded_site_entry& entry : entries) {
            if (!entry.has_relative_encoding) {
                continue;
            }

            const std::size_t insn_len = static_cast<std::size_t>(entry.inst.length);
            if ((entry.block_offset + insn_len) > original_block.size()) {
                return false;
            }

            const std::uint8_t* src_insn = original_block.data() + entry.block_offset;
            std::uint8_t* dst_insn = cache_block + entry.block_offset;
            const std::uintptr_t cache_insn_addr = cache_base + entry.block_offset;

            for (std::size_t imm_index = 0; imm_index < (sizeof(entry.decoded.raw.imm) / sizeof(entry.decoded.raw.imm[0])); ++imm_index) {
                const auto& imm = entry.decoded.raw.imm[imm_index];
                if (!imm.is_relative || imm.size == 0) {
                    continue;
                }
                if (!patch_relative_field(src_insn, dst_insn, insn_len, imm.offset, imm.size, entry.inst.address, cache_insn_addr)) {
                    return false;
                }
            }

            if (entry.decoded.raw.disp.size != 0) {
                if (!patch_relative_field(
                        src_insn,
                        dst_insn,
                        insn_len,
                        entry.decoded.raw.disp.offset,
                        entry.decoded.raw.disp.size,
                        entry.inst.address,
                        cache_insn_addr)) {
                    return false;
                }
            }
        }

        return true;
    }

    static bool patch_relative_field(
        const std::uint8_t* src_instruction,
        std::uint8_t* dst_instruction,
        std::size_t instruction_len,
        std::uint16_t bit_offset,
        std::uint8_t bit_size,
        std::uintptr_t orig_instruction_address,
        std::uintptr_t cache_instruction_address) {

        if (src_instruction == nullptr || dst_instruction == nullptr || instruction_len == 0) {
            return false;
        }
        if ((bit_offset % 8) != 0 || (bit_size % 8) != 0) {
            return false;
        }

        const std::size_t byte_offset = static_cast<std::size_t>(bit_offset / 8);
        const std::size_t byte_size = static_cast<std::size_t>(bit_size / 8);
        if (byte_size == 0 || (byte_offset + byte_size) > instruction_len) {
            return false;
        }

        std::int64_t old_disp = 0;
        if (!read_signed_integer(src_instruction + byte_offset, byte_size, old_disp)) {
            return false;
        }

        const std::int64_t orig_next = static_cast<std::int64_t>(orig_instruction_address + instruction_len);
        const std::int64_t cache_next = static_cast<std::int64_t>(cache_instruction_address + instruction_len);
        const std::int64_t absolute_target = orig_next + old_disp;
        const std::int64_t new_disp = absolute_target - cache_next;
        return write_signed_integer(dst_instruction + byte_offset, byte_size, new_disp);
    }

    static bool read_signed_integer(const std::uint8_t* data, std::size_t byte_size, std::int64_t& out_value) {
        if (data == nullptr || byte_size == 0 || byte_size > 8) {
            return false;
        }

        std::uint64_t raw = 0;
        for (std::size_t i = 0; i < byte_size; ++i) {
            raw |= (static_cast<std::uint64_t>(data[i]) << (i * 8));
        }

        const std::size_t bits = byte_size * 8;
        if (bits < 64 && ((raw >> (bits - 1)) & 1ULL) != 0ULL) {
            raw |= (~0ULL << bits);
        }
        out_value = static_cast<std::int64_t>(raw);
        return true;
    }

    static bool write_signed_integer(std::uint8_t* data, std::size_t byte_size, std::int64_t value) {
        if (data == nullptr || byte_size == 0 || byte_size > 8) {
            return false;
        }

        const std::int64_t min_value = (byte_size == 8) ? std::numeric_limits<std::int64_t>::min()
                                                         : -(static_cast<std::int64_t>(1) << ((byte_size * 8) - 1));
        const std::int64_t max_value = (byte_size == 8) ? std::numeric_limits<std::int64_t>::max()
                                                         : ((static_cast<std::int64_t>(1) << ((byte_size * 8) - 1)) - 1);
        if (value < min_value || value > max_value) {
            return false;
        }

        const std::uint64_t raw = static_cast<std::uint64_t>(value);
        for (std::size_t i = 0; i < byte_size; ++i) {
            data[i] = static_cast<std::uint8_t>((raw >> (i * 8)) & 0xFF);
        }
        return true;
    }

#if defined(_M_X64)
    static void append_push_gpr64(std::uint8_t reg, std::vector<std::uint8_t>& out) {
        if (reg >= 8) {
            out.push_back(0x41);
            out.push_back(static_cast<std::uint8_t>(0x50 + (reg - 8)));
        } else {
            out.push_back(static_cast<std::uint8_t>(0x50 + reg));
        }
    }

    static void append_pop_gpr64(std::uint8_t reg, std::vector<std::uint8_t>& out) {
        if (reg >= 8) {
            out.push_back(0x41);
            out.push_back(static_cast<std::uint8_t>(0x58 + (reg - 8)));
        } else {
            out.push_back(static_cast<std::uint8_t>(0x58 + reg));
        }
    }

    static void append_mov_rax_imm64(std::uintptr_t value, std::vector<std::uint8_t>& out) {
        out.insert(out.end(), {0x48, 0xB8});
        append_u64(static_cast<std::uint64_t>(value), out);
    }

    static void append_mov_rcx_imm64(std::uintptr_t value, std::vector<std::uint8_t>& out) {
        out.insert(out.end(), {0x48, 0xB9});
        append_u64(static_cast<std::uint64_t>(value), out);
    }

    static void append_movdqu_store_xmm_rsp(std::uint8_t xmm, std::uint32_t disp, std::vector<std::uint8_t>& out) {
        out.push_back(0x66);
        if (xmm >= 8) {
            out.push_back(0x44);
        }
        out.push_back(0x0F);
        out.push_back(0x7F);
        out.push_back(static_cast<std::uint8_t>(0x84 | ((xmm & 7) << 3)));
        out.push_back(0x24);
        append_u32(disp, out);
    }

    static void append_movdqu_load_xmm_rsp(std::uint8_t xmm, std::uint32_t disp, std::vector<std::uint8_t>& out) {
        out.push_back(0x66);
        if (xmm >= 8) {
            out.push_back(0x44);
        }
        out.push_back(0x0F);
        out.push_back(0x6F);
        out.push_back(static_cast<std::uint8_t>(0x84 | ((xmm & 7) << 3)));
        out.push_back(0x24);
        append_u32(disp, out);
    }

    static void append_absolute_indirect_jump(std::uintptr_t target, std::vector<std::uint8_t>& out) {
        out.insert(out.end(), {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
        append_u64(static_cast<std::uint64_t>(target), out);
    }

    static void append_u64(std::uint64_t value, std::vector<std::uint8_t>& out) {
        for (std::size_t i = 0; i < sizeof(value); ++i) {
            out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
        }
    }
#endif

    static void append_u32(std::uint32_t value, std::vector<std::uint8_t>& out) {
        for (std::size_t i = 0; i < sizeof(value); ++i) {
            out.push_back(static_cast<std::uint8_t>((value >> (i * 8)) & 0xFF));
        }
    }

    static std::vector<DWORD> collect_current_process_threads() {
        std::vector<DWORD> tids{};
        const DWORD pid = GetCurrentProcessId();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return tids;
        }

        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Thread32First(snapshot, &entry)) {
            do {
                if (entry.th32OwnerProcessID == pid) {
                    tids.push_back(entry.th32ThreadID);
                }
            } while (Thread32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return tids;
    }

    bool apply_breakpoints_to_process_threads_locked(bool enable) {
        const std::vector<DWORD> tids = collect_current_process_threads();
        if (tids.empty()) {
            record_install_failure("no_process_threads", 0, 0, 0, 0, 0, 0, GetLastError());
            return false;
        }

        bool current_thread_ok = false;
        const DWORD current_tid = GetCurrentThreadId();
        for (DWORD tid : tids) {
            const bool ok = apply_breakpoints_to_thread(tid, enable);
            if (tid == current_tid) {
                current_thread_ok = ok;
            }
        }

        if (enable && !current_thread_ok) {
            record_install_failure("apply_current_thread_breakpoints", 0, 0, 0, 0, static_cast<unsigned long>(sites_.size()), 0, GetLastError());
            return false;
        }
        return true;
    }

    bool start_thread_sync_worker_locked() {
        if (sync_thread_ != nullptr) {
            return true;
        }

        sync_stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (sync_stop_event_ == nullptr) {
            record_install_failure("create_sync_stop_event", 0, 0, 0, 0, 0, 0, GetLastError());
            return false;
        }

        sync_thread_ = CreateThread(nullptr, 0, &dispatcher_code_cache_instrumentor::thread_sync_proc, this, 0, nullptr);
        if (sync_thread_ == nullptr) {
            const DWORD gle = GetLastError();
            CloseHandle(sync_stop_event_);
            sync_stop_event_ = nullptr;
            record_install_failure("create_thread_sync_worker", 0, 0, 0, 0, 0, 0, gle);
            return false;
        }
        return true;
    }

    void stop_thread_sync_worker_locked(std::unique_lock<std::mutex>& guard) {
        HANDLE thread = sync_thread_;
        HANDLE stop_event = sync_stop_event_;
        sync_thread_ = nullptr;
        sync_stop_event_ = nullptr;

        if (stop_event != nullptr) {
            SetEvent(stop_event);
        }

        guard.unlock();
        if (thread != nullptr) {
            WaitForSingleObject(thread, 2000);
            CloseHandle(thread);
        }
        if (stop_event != nullptr) {
            CloseHandle(stop_event);
        }
        guard.lock();
    }

    static DWORD WINAPI thread_sync_proc(LPVOID parameter) {
        auto* self = static_cast<dispatcher_code_cache_instrumentor*>(parameter);
        if (self == nullptr) {
            return 0;
        }

        for (;;) {
            HANDLE stop_event = nullptr;
            {
                std::lock_guard<std::mutex> guard(self->lock_);
                stop_event = self->sync_stop_event_;
                if (stop_event == nullptr || active_instance_ != self) {
                    return 0;
                }
                self->apply_breakpoints_to_process_threads_locked(true);
            }

            if (WaitForSingleObject(stop_event, 25) == WAIT_OBJECT_0) {
                return 0;
            }
        }
    }

    bool apply_breakpoints_to_thread(DWORD tid, bool enable) const {
        if (tid == 0) {
            return false;
        }

        const DWORD current_tid = GetCurrentThreadId();
        HANDLE thread = nullptr;
        if (tid == current_tid) {
            thread = GetCurrentThread();
        } else {
            thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, tid);
            if (thread == nullptr) {
                return false;
            }
            SuspendThread(thread);
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        const bool got_context = GetThreadContext(thread, &context) != FALSE;
        bool ok = false;
        if (got_context) {
            if (enable) {
                ok = write_breakpoints(context);
            } else {
                clear_breakpoints(context);
                ok = true;
            }
            if (ok) {
                ok = SetThreadContext(thread, &context) != FALSE;
            }
        }

        if (tid != current_tid) {
            ResumeThread(thread);
            CloseHandle(thread);
        }
        return ok;
    }

    bool write_breakpoints(CONTEXT& context) const {
        context.Dr0 = 0;
        context.Dr1 = 0;
        context.Dr2 = 0;
        context.Dr3 = 0;
        context.Dr6 = 0;
        context.Dr7 &= ~k_dr7_breakpoint_slot_mask;

        std::size_t slot = 0;
        for (const auto& [address, site] : sites_) {
            (void)site;
            switch (slot) {
            case 0:
                context.Dr0 = address;
                context.Dr7 |= (1ULL << 0);
                break;
            case 1:
                context.Dr1 = address;
                context.Dr7 |= (1ULL << 2);
                break;
            case 2:
                context.Dr2 = address;
                context.Dr7 |= (1ULL << 4);
                break;
            case 3:
                context.Dr3 = address;
                context.Dr7 |= (1ULL << 6);
                break;
            default:
                return false;
            }
            ++slot;
        }
        return true;
    }

    void clear_breakpoints(CONTEXT& context) const {
        for (const auto& [address, site] : sites_) {
            (void)site;
            if (context.Dr0 == address) {
                context.Dr0 = 0;
                context.Dr7 &= ~((1ULL << 0) | (0xFULL << 16));
            }
            if (context.Dr1 == address) {
                context.Dr1 = 0;
                context.Dr7 &= ~((1ULL << 2) | (0xFULL << 20));
            }
            if (context.Dr2 == address) {
                context.Dr2 = 0;
                context.Dr7 &= ~((1ULL << 4) | (0xFULL << 24));
            }
            if (context.Dr3 == address) {
                context.Dr3 = 0;
                context.Dr7 &= ~((1ULL << 6) | (0xFULL << 28));
            }
        }
        context.Dr6 = 0;
    }

    static void trace_failure(std::uintptr_t address, const char* stage) {
        if (stage == nullptr) {
            return;
        }

        char message[180]{};
        _snprintf_s(
            message,
            sizeof(message),
            _TRUNCATE,
            "[dispatcher_code_cache] instrument_instruction failed stage=%s address=0x%llx\n",
            stage,
            static_cast<unsigned long long>(address));
        OutputDebugStringA(message);
        std::fputs(message, stdout);
        std::fflush(stdout);
    }

    void record_install_failure(
        const char* stage,
        std::uintptr_t address,
        std::uintptr_t cache_entry,
        unsigned long installed,
        unsigned long active,
        unsigned long value_a,
        unsigned long value_b,
        DWORD gle) {

        if (stage == nullptr) {
            return;
        }

        char message[320]{};
        _snprintf_s(
            message,
            sizeof(message),
            _TRUNCATE,
            "[dispatcher_code_cache] install failed stage=%s address=0x%llx cache=0x%llx installed=%lu active=%lu a=%lu b=%lu gle=%lu\n",
            stage,
            static_cast<unsigned long long>(address),
            static_cast<unsigned long long>(cache_entry),
            installed,
            active,
            value_a,
            value_b,
            static_cast<unsigned long>(gle));
        last_error_ = message;
        OutputDebugStringA(message);
        std::fputs(message, stdout);
        std::fflush(stdout);
    }

    std::unordered_map<std::uintptr_t, cached_site> sites_{};
    std::vector<callback_type> callbacks_{};
    std::string last_error_{};
    void* veh_handle_{nullptr};
    HANDLE sync_thread_{nullptr};
    HANDLE sync_stop_event_{nullptr};
    bool installed_{false};
    mutable std::mutex lock_{};

    inline static dispatcher_code_cache_instrumentor* active_instance_{nullptr};
};
