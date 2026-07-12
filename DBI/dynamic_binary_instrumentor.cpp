#include "dynamic_binary_instrumentor.h"

#include <utility>

#ifdef _MSC_VER
#pragma comment(lib, "Zydis.lib")
#pragma comment(lib, "Zycore.lib")
#endif

dynamic_binary_instrumentor* dynamic_binary_instrumentor::active_instance_ = nullptr;
thread_local bool dynamic_binary_instrumentor::has_pending_rearm_ = false;
thread_local std::uintptr_t dynamic_binary_instrumentor::pending_rearm_address_ = 0;

dynamic_binary_instrumentor::~dynamic_binary_instrumentor() {
    uninstall();
}

bool dynamic_binary_instrumentor::add_region(void* start, std::size_t size) {
    if (start == nullptr || size == 0) {
        return false;
    }

    std::lock_guard<std::mutex> guard(lock_);
    if (veh_handle_ != nullptr) {
        return false;
    }

    ranges_.push_back({reinterpret_cast<std::uintptr_t>(start), size});
    return true;
}

bool dynamic_binary_instrumentor::install(callback_type callback) {
    if (!callback) {
        return false;
    }

    std::lock_guard<std::mutex> guard(lock_);
    if (veh_handle_ != nullptr || active_instance_ != nullptr || ranges_.empty()) {
        return false;
    }

    instructions_.clear();
    for (const address_range& range : ranges_) {
        if (!decode_region(range)) {
            instructions_.clear();
            return false;
        }
    }

    if (instructions_.empty()) {
        return false;
    }

    callback_ = std::move(callback);

    veh_handle_ = AddVectoredExceptionHandler(1, &dynamic_binary_instrumentor::vectored_handler);
    if (veh_handle_ == nullptr) {
        callback_ = nullptr;
        instructions_.clear();
        return false;
    }

    active_instance_ = this;
    std::vector<std::uintptr_t> patched_addresses{};
    patched_addresses.reserve(instructions_.size());

    for (const auto& [address, instruction] : instructions_) {
        if (!write_byte(address, 0xCC)) {
            for (const std::uintptr_t patched : patched_addresses) {
                const auto it = instructions_.find(patched);
                if (it != instructions_.end()) {
                    write_byte(it->second.address, it->second.original_first_byte);
                }
            }

            RemoveVectoredExceptionHandler(veh_handle_);
            veh_handle_ = nullptr;
            callback_ = nullptr;
            instructions_.clear();
            active_instance_ = nullptr;
            return false;
        }

        patched_addresses.push_back(address);
    }

    return true;
}

void dynamic_binary_instrumentor::uninstall() {
    std::lock_guard<std::mutex> guard(lock_);

    for (const auto& [address, instruction] : instructions_) {
        write_byte(address, instruction.original_first_byte);
    }

    if (veh_handle_ != nullptr) {
        RemoveVectoredExceptionHandler(veh_handle_);
        veh_handle_ = nullptr;
    }

    callback_ = nullptr;
    instructions_.clear();
    active_instance_ = nullptr;
}

bool dynamic_binary_instrumentor::decode_region(const address_range& range) {
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

    const auto* base = reinterpret_cast<const std::uint8_t*>(range.start);
    std::size_t offset = 0;
    std::size_t decoded_count = 0;

    while (offset < range.size) {
        ZydisDecodedInstruction decoded{};
        const void* cursor = base + offset;
        // A caller may request a one-byte entry trap, but x86 instructions
        // can be longer than one byte. Decode from a full instruction window
        // while keeping the instrumentation range boundary unchanged.
        const std::size_t remaining = (range.size - offset) < 15
            ? 15
            : range.size - offset;

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

        const std::uintptr_t address = range.start + offset;
        instructions_.try_emplace(address, instrumented_instruction{
            address,
            decoded.length,
            *reinterpret_cast<const std::uint8_t*>(address),
            is_control_flow,
            decoded.mnemonic
        });

        ++decoded_count;
        offset += decoded.length;
    }

    return decoded_count > 0;
}

bool dynamic_binary_instrumentor::write_byte(std::uintptr_t address, std::uint8_t value) const {
    DWORD old_protect = 0;
    auto* ptr = reinterpret_cast<std::uint8_t*>(address);

    if (!VirtualProtect(ptr, 1, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }

    *ptr = value;
    FlushInstructionCache(GetCurrentProcess(), ptr, 1);

    DWORD ignored = 0;
    VirtualProtect(ptr, 1, old_protect, &ignored);
    return true;
}

const instrumented_instruction* dynamic_binary_instrumentor::find_instruction(std::uintptr_t address) const {
    const auto it = instructions_.find(address);
    if (it == instructions_.end()) {
        return nullptr;
    }

    return &it->second;
}

std::uintptr_t dynamic_binary_instrumentor::get_instruction_pointer(const CONTEXT& context) {
#if defined(_M_X64)
    return static_cast<std::uintptr_t>(context.Rip);
#else
    return static_cast<std::uintptr_t>(context.Eip);
#endif
}

void dynamic_binary_instrumentor::set_instruction_pointer(CONTEXT& context, std::uintptr_t value) {
    context.ContextFlags |= CONTEXT_CONTROL;
#if defined(_M_X64)
    context.Rip = static_cast<DWORD64>(value);
#else
    context.Eip = static_cast<DWORD>(value);
#endif
}

void dynamic_binary_instrumentor::set_single_step(CONTEXT& context) {
    constexpr DWORD trap_flag = 0x100;
    context.ContextFlags |= CONTEXT_CONTROL;
    context.EFlags |= trap_flag;
}

LONG CALLBACK dynamic_binary_instrumentor::vectored_handler(PEXCEPTION_POINTERS exception_info) {
    if (active_instance_ == nullptr || exception_info == nullptr || exception_info->ContextRecord == nullptr || exception_info->ExceptionRecord == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    CONTEXT& context = *exception_info->ContextRecord;
    const DWORD code = exception_info->ExceptionRecord->ExceptionCode;

    if (code == EXCEPTION_SINGLE_STEP) {
        constexpr DWORD trap_flag = 0x100;
        context.EFlags &= ~trap_flag; // avoid leaking TF beyond the one-step window

        if (!has_pending_rearm_) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        active_instance_->write_byte(pending_rearm_address_, 0xCC);
        has_pending_rearm_ = false;
        pending_rearm_address_ = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (code != EXCEPTION_BREAKPOINT) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    std::uintptr_t resolved_address = reinterpret_cast<std::uintptr_t>(exception_info->ExceptionRecord->ExceptionAddress);
    const std::uintptr_t current_ip = get_instruction_pointer(context);
    const instrumented_instruction* instruction = active_instance_->find_instruction(resolved_address);

    if (instruction == nullptr && current_ip > 0) {
        resolved_address = current_ip - 1;
        instruction = active_instance_->find_instruction(resolved_address);
    }

    if (instruction == nullptr) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    active_instance_->write_byte(instruction->address, instruction->original_first_byte);
    has_pending_rearm_ = true;
    pending_rearm_address_ = instruction->address;

    const std::uintptr_t ip_before_callback = get_instruction_pointer(context);
    if (active_instance_->callback_) {
        active_instance_->callback_(*instruction, context);
    }

    // Allow callbacks to override RIP/EIP for policy actions (skip/redirect).
    if (get_instruction_pointer(context) == ip_before_callback) {
        set_instruction_pointer(context, instruction->address);
    }
    set_single_step(context);
    return EXCEPTION_CONTINUE_EXECUTION;
}
