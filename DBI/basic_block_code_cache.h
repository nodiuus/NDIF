#pragma once

#include "dynamic_binary_instrumentor.h"

#include <Windows.h>

#include <Zydis/Zydis.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#undef min
#undef max

class basic_block_code_cache {
public:
    using callback_type = std::function<void(const instrumented_instruction&, CONTEXT&)>;

    basic_block_code_cache() = default;
    ~basic_block_code_cache() {
        reset();
    }

    basic_block_code_cache(const basic_block_code_cache&) = delete;
    basic_block_code_cache& operator=(const basic_block_code_cache&) = delete;

    bool add_callback(callback_type callback) {
        if (!callback) {
            last_error_ = "callback is null";
            return false;
        }
        std::lock_guard<std::mutex> guard(lock_);
        callbacks_.push_back(std::move(callback));
        return true;
    }

    void* translate_entry(std::uintptr_t address) {
        if (address == 0) {
            last_error_ = "invalid entry address";
            return nullptr;
        }

        std::lock_guard<std::mutex> guard(lock_);
        active_instance_ = this;
        return reinterpret_cast<void*>(translate_block_locked(address));
    }

    template <typename Fn>
    Fn translate_function(std::uintptr_t address) {
        return reinterpret_cast<Fn>(translate_entry(address));
    }

    void reset() {
        std::lock_guard<std::mutex> guard(lock_);
        for (auto& [address, block] : blocks_) {
            (void)address;
            if (block.cache_entry != 0) {
                VirtualFree(reinterpret_cast<void*>(block.cache_entry), 0, MEM_RELEASE);
            }
        }
        blocks_.clear();
        callbacks_.clear();
        if (active_instance_ == this) {
            active_instance_ = nullptr;
        }
    }

    const char* last_error() const {
        return last_error_.empty() ? "" : last_error_.c_str();
    }

private:
    struct decoded_entry {
        instrumented_instruction inst{};
        ZydisDecodedInstruction decoded{};
        std::vector<std::uint8_t> bytes{};
        std::size_t cache_offset{0};
        bool copied_to_cache{false};
        bool has_relative_encoding{false};
    };

    struct translated_block {
        std::uintptr_t original_address{0};
        std::uintptr_t cache_entry{0};
        std::size_t cache_size{0};
    };

    static constexpr std::size_t k_max_blocks = 4096;
    static constexpr std::size_t k_max_block_instructions = 64;

    static std::uintptr_t resolve_block_entry(std::uintptr_t address) {
        basic_block_code_cache* self = active_instance_;
        if (self == nullptr || address == 0) {
            return address;
        }

        std::lock_guard<std::mutex> guard(self->lock_);
        const std::uintptr_t translated = self->translate_block_locked(address);
        return translated != 0 ? translated : address;
    }

    static void dispatch_instruction_hit(std::uintptr_t address, const void* saved_registers) {
        basic_block_code_cache* self = active_instance_;
        if (self == nullptr) {
            return;
        }

        instrumented_instruction instruction{};
        if (!self->decode_instruction(address, instruction, nullptr, nullptr, nullptr)) {
            instruction.address = address;
        }

        CONTEXT context{};
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#if defined(_M_X64)
        context.Rip = static_cast<DWORD64>(address);
        populate_context_from_saved_registers(saved_registers, context);
#else
        context.Eip = static_cast<DWORD>(address);
#endif

        for (auto& callback : self->callbacks_) {
            callback(instruction, context);
        }

#if defined(_M_X64)
        apply_context_to_saved_registers(context, saved_registers);
#endif
    }

    std::uintptr_t translate_block_locked(std::uintptr_t address) {
        const auto existing = blocks_.find(address);
        if (existing != blocks_.end()) {
            return existing->second.cache_entry;
        }
        if (blocks_.size() >= k_max_blocks) {
            last_error_ = "translated block limit reached";
            return 0;
        }

        std::vector<decoded_entry> entries{};
        if (!decode_block(address, entries)) {
            return 0;
        }

        std::vector<std::uint8_t> code{};
        std::uintptr_t cursor = address;
        bool ended = false;

        for (decoded_entry& entry : entries) {
            if (!callbacks_.empty()) {
                build_callback_prologue(entry.inst.address, code);
            }

            if (is_conditional_branch(entry.decoded)) {
                std::uintptr_t target = 0;
                std::uint8_t condition = 0;
                if (!relative_target(entry, target) || !branch_condition(entry.bytes, condition)) {
                    last_error_ = "unsupported conditional branch";
                    return 0;
                }

                const std::uintptr_t fallthrough = entry.inst.address + entry.inst.length;
                emit_conditional_dispatch(condition, target, fallthrough, code);
                ended = true;
                break;
            }

            if (is_unconditional_branch(entry.decoded)) {
                std::uintptr_t target = 0;
                if (relative_target(entry, target)) {
                    emit_dispatch_jump(target, code);
                } else {
                    entry.cache_offset = code.size();
                    entry.copied_to_cache = true;
                    code.insert(code.end(), entry.bytes.begin(), entry.bytes.end());
                }
                ended = true;
                break;
            }

            if (is_call(entry.decoded)) {
                std::uintptr_t target = 0;
                if (!relative_target(entry, target)) {
                    last_error_ = "unsupported indirect call";
                    return 0;
                }

                const std::uintptr_t fallthrough = entry.inst.address + entry.inst.length;
                emit_dispatch_call(target, fallthrough, code);
                ended = true;
                break;
            }

            entry.cache_offset = code.size();
            entry.copied_to_cache = true;
            code.insert(code.end(), entry.bytes.begin(), entry.bytes.end());
            cursor = entry.inst.address + entry.inst.length;

            if (is_return(entry.decoded)) {
                ended = true;
                break;
            }
        }

        if (!ended) {
            emit_dispatch_jump(cursor, code);
        }

        if (code.empty()) {
            last_error_ = "empty translated block";
            return 0;
        }

        void* cache = allocate_writable_near(address, code.size());
        if (cache == nullptr) {
            last_error_ = "VirtualAlloc failed";
            return 0;
        }

        std::memcpy(cache, code.data(), code.size());
        const std::uintptr_t cache_base = reinterpret_cast<std::uintptr_t>(cache);
        auto* cache_bytes = static_cast<std::uint8_t*>(cache);
        if (!relocate_relative_fields(entries, cache_bytes, cache_base)) {
            VirtualFree(cache, 0, MEM_RELEASE);
            return 0;
        }

        DWORD old_protect = 0;
        if (!VirtualProtect(cache, code.size(), PAGE_EXECUTE_READ, &old_protect)) {
            last_error_ = "VirtualProtect executable failed";
            VirtualFree(cache, 0, MEM_RELEASE);
            return 0;
        }

        FlushInstructionCache(GetCurrentProcess(), cache, code.size());

        translated_block block{};
        block.original_address = address;
        block.cache_entry = cache_base;
        block.cache_size = code.size();
        blocks_.emplace(address, block);
        return cache_base;
    }

    bool decode_block(std::uintptr_t address, std::vector<decoded_entry>& out) {
        out.clear();
        std::uintptr_t cursor = address;

        for (std::size_t i = 0; i < k_max_block_instructions; ++i) {
            decoded_entry entry{};
            if (!decode_instruction(cursor, entry.inst, &entry.decoded, &entry.bytes, &entry.has_relative_encoding)) {
                last_error_ = "decode failed";
                return false;
            }
            out.push_back(entry);

            cursor += entry.inst.length;
            if (is_block_terminator(entry.decoded)) {
                return true;
            }
        }

        return true;
    }

    bool decode_instruction(
        std::uintptr_t address,
        instrumented_instruction& out,
        ZydisDecodedInstruction* out_decoded,
        std::vector<std::uint8_t>* out_bytes,
        bool* out_has_relative_encoding) const {

        out = {};
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

        ZydisDecodedInstruction decoded{};
        ZyanStatus status{};
#if defined(ZYDIS_VERSION) && (ZYDIS_VERSION_MAJOR(ZYDIS_VERSION) >= 4)
        ZydisDecoderContext context{};
        status = ZydisDecoderDecodeInstruction(&decoder, &context, buffer, read, &decoded);
#else
        status = ZydisDecoderDecodeBuffer(&decoder, buffer, read, &decoded);
#endif
        if (!ZYAN_SUCCESS(status) || decoded.length == 0) {
            return false;
        }

        out.address = address;
        out.length = static_cast<std::uint8_t>(decoded.length);
        out.original_first_byte = buffer[0];
        out.is_control_flow = is_control_flow(decoded);
        out.mnemonic = decoded.mnemonic;

        if (out_decoded != nullptr) {
            *out_decoded = decoded;
        }
        if (out_bytes != nullptr) {
            out_bytes->assign(buffer, buffer + decoded.length);
        }
        if (out_has_relative_encoding != nullptr) {
            *out_has_relative_encoding = (decoded.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0;
        }
        return true;
    }

    static bool is_control_flow(const ZydisDecodedInstruction& decoded) {
        switch (decoded.meta.category) {
        case ZYDIS_CATEGORY_CALL:
        case ZYDIS_CATEGORY_COND_BR:
        case ZYDIS_CATEGORY_UNCOND_BR:
        case ZYDIS_CATEGORY_RET:
        case ZYDIS_CATEGORY_SYSRET:
        case ZYDIS_CATEGORY_SYSCALL:
            return true;
        default:
            break;
        }
        return decoded.mnemonic == ZYDIS_MNEMONIC_INT ||
               decoded.mnemonic == ZYDIS_MNEMONIC_INT1 ||
               decoded.mnemonic == ZYDIS_MNEMONIC_INT3 ||
               decoded.mnemonic == ZYDIS_MNEMONIC_INTO;
    }

    static bool is_conditional_branch(const ZydisDecodedInstruction& decoded) {
        return decoded.meta.category == ZYDIS_CATEGORY_COND_BR;
    }

    static bool is_unconditional_branch(const ZydisDecodedInstruction& decoded) {
        return decoded.meta.category == ZYDIS_CATEGORY_UNCOND_BR;
    }

    static bool is_call(const ZydisDecodedInstruction& decoded) {
        return decoded.meta.category == ZYDIS_CATEGORY_CALL;
    }

    static bool is_return(const ZydisDecodedInstruction& decoded) {
        return decoded.meta.category == ZYDIS_CATEGORY_RET;
    }

    static bool is_block_terminator(const ZydisDecodedInstruction& decoded) {
        return is_conditional_branch(decoded) || is_unconditional_branch(decoded) || is_return(decoded);
    }

    static bool branch_condition(const std::vector<std::uint8_t>& bytes, std::uint8_t& condition) {
        if (bytes.empty()) {
            return false;
        }
        if (bytes[0] >= 0x70 && bytes[0] <= 0x7F) {
            condition = static_cast<std::uint8_t>(bytes[0] & 0x0F);
            return true;
        }
        if (bytes.size() >= 2 && bytes[0] == 0x0F && bytes[1] >= 0x80 && bytes[1] <= 0x8F) {
            condition = static_cast<std::uint8_t>(bytes[1] & 0x0F);
            return true;
        }
        return false;
    }

    static bool relative_target(const decoded_entry& entry, std::uintptr_t& target) {
        const std::size_t insn_len = static_cast<std::size_t>(entry.inst.length);
        for (std::size_t imm_index = 0; imm_index < (sizeof(entry.decoded.raw.imm) / sizeof(entry.decoded.raw.imm[0])); ++imm_index) {
            const auto& imm = entry.decoded.raw.imm[imm_index];
            if (!imm.is_relative || imm.size == 0) {
                continue;
            }

            const std::int64_t disp = imm.is_signed ? static_cast<std::int64_t>(imm.value.s)
                                                    : static_cast<std::int64_t>(imm.value.u);
            target = static_cast<std::uintptr_t>(static_cast<std::int64_t>(entry.inst.address + insn_len) + disp);
            return true;
        }
        return false;
    }

    bool relocate_relative_fields(
        const std::vector<decoded_entry>& entries,
        std::uint8_t* cache_bytes,
        std::uintptr_t cache_base) {

        for (const decoded_entry& entry : entries) {
            if (!entry.copied_to_cache || !entry.has_relative_encoding) {
                continue;
            }

            const std::size_t insn_len = static_cast<std::size_t>(entry.inst.length);
            std::uint8_t* dst_insn = cache_bytes + entry.cache_offset;
            const std::uintptr_t cache_insn_addr = cache_base + entry.cache_offset;

            for (std::size_t imm_index = 0; imm_index < (sizeof(entry.decoded.raw.imm) / sizeof(entry.decoded.raw.imm[0])); ++imm_index) {
                const auto& imm = entry.decoded.raw.imm[imm_index];
                if (!imm.is_relative || imm.size == 0) {
                    continue;
                }
                if (!patch_relative_field(entry.bytes.data(), dst_insn, insn_len, imm.offset, imm.size, entry.inst.address, cache_insn_addr)) {
                    last_error_ = "relative immediate relocation failed";
                    return false;
                }
            }

            if (entry.decoded.raw.disp.size != 0) {
                if (!patch_relative_field(
                        entry.bytes.data(),
                        dst_insn,
                        insn_len,
                        entry.decoded.raw.disp.offset,
                        entry.decoded.raw.disp.size,
                        entry.inst.address,
                        cache_insn_addr)) {
                    last_error_ = "relative displacement relocation failed";
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
        const std::size_t byte_offset = static_cast<std::size_t>(bit_offset);
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

    static void emit_conditional_direct(
        std::uint8_t condition,
        std::uintptr_t taken_cache,
        std::uintptr_t fallthrough_cache,
        std::vector<std::uint8_t>& out) {

        const std::size_t jcc_pos = out.size();
        out.push_back(0x0F);
        out.push_back(static_cast<std::uint8_t>(0x80 | (condition & 0x0F)));
        append_u32(0, out);

        build_absolute_jump(fallthrough_cache, out);

        const std::size_t taken_label = out.size();
        const std::int32_t disp = static_cast<std::int32_t>(taken_label - (jcc_pos + 6));
        std::memcpy(out.data() + jcc_pos + 2, &disp, sizeof(disp));

        build_absolute_jump(taken_cache, out);
    }

    static void emit_conditional_dispatch(
        std::uint8_t condition,
        std::uintptr_t taken_target,
        std::uintptr_t fallthrough_target,
        std::vector<std::uint8_t>& out) {

        const std::size_t jcc_pos = out.size();
        out.push_back(0x0F);
        out.push_back(static_cast<std::uint8_t>(0x80 | (condition & 0x0F)));
        append_u32(0, out);

        emit_dispatch_jump(fallthrough_target, out);

        const std::size_t taken_label = out.size();
        const std::int32_t disp = static_cast<std::int32_t>(taken_label - (jcc_pos + 6));
        std::memcpy(out.data() + jcc_pos + 2, &disp, sizeof(disp));

        emit_dispatch_jump(taken_target, out);
    }

    static void* allocate_writable_near(std::uintptr_t reference, std::size_t size) {
        if (size == 0) {
            return nullptr;
        }

#if defined(_M_X64)
        SYSTEM_INFO si{};
        GetSystemInfo(&si);
        const std::uintptr_t granularity = static_cast<std::uintptr_t>(si.dwAllocationGranularity);
        if (granularity == 0) {
            return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
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
            const std::uintptr_t candidates[2] = {
                (reference >= distance) ? align_down(reference - distance) : 0,
                (reference <= (std::numeric_limits<std::uintptr_t>::max() - distance)) ? align_down(reference + distance) : 0
            };

            for (const std::uintptr_t candidate : candidates) {
                if (candidate < min_addr || candidate > max_addr) {
                    continue;
                }

                void* p = VirtualAlloc(reinterpret_cast<void*>(candidate), size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (p != nullptr) {
                    return p;
                }
            }
        }
#endif

        return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    }

    static void build_absolute_jump(std::uintptr_t target, std::vector<std::uint8_t>& out) {
#if defined(_M_X64)
        out.insert(out.end(), {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00});
        append_u64(static_cast<std::uint64_t>(target), out);
#else
        out.push_back(0x68);
        append_u32(static_cast<std::uint32_t>(target), out);
        out.push_back(0xC3);
#endif
    }

    static void emit_dispatch_jump(std::uintptr_t target, std::vector<std::uint8_t>& out) {
#if defined(_M_X64)
        append_push_gpr64(3, out);
        append_push_gpr64(0, out);
        append_push_gpr64(1, out);
        append_push_gpr64(2, out);
        append_push_gpr64(8, out);
        append_push_gpr64(9, out);
        append_push_gpr64(10, out);

        out.insert(out.end(), {0x48, 0x89, 0xE3}); // mov rbx, rsp
        out.insert(out.end(), {0x48, 0x83, 0xE4, 0xF0}); // and rsp, -16
        out.insert(out.end(), {0x48, 0x83, 0xEC, 0x20}); // sub rsp, 0x20
        append_mov_rcx_imm64(target, out);
        append_mov_rax_imm64(reinterpret_cast<std::uintptr_t>(&basic_block_code_cache::resolve_block_entry), out);
        out.insert(out.end(), {0xFF, 0xD0}); // call rax
        out.insert(out.end(), {0x48, 0x89, 0xDC}); // mov rsp, rbx
        out.insert(out.end(), {0x49, 0x89, 0xC3}); // mov r11, rax

        append_pop_gpr64(10, out);
        append_pop_gpr64(9, out);
        append_pop_gpr64(8, out);
        append_pop_gpr64(2, out);
        append_pop_gpr64(1, out);
        append_pop_gpr64(0, out);
        append_pop_gpr64(3, out);
        out.insert(out.end(), {0x41, 0xFF, 0xE3}); // jmp r11
#else
        out.push_back(0x68);
        append_u32(static_cast<std::uint32_t>(target), out);
        out.push_back(0xC3);
#endif
    }

    static void emit_dispatch_call(std::uintptr_t target, std::uintptr_t fallthrough, std::vector<std::uint8_t>& out) {
#if defined(_M_X64)
        append_push_gpr64(3, out);
        append_push_gpr64(0, out);
        append_push_gpr64(1, out);
        append_push_gpr64(2, out);
        append_push_gpr64(8, out);
        append_push_gpr64(9, out);
        append_push_gpr64(10, out);

        out.insert(out.end(), {0x48, 0x89, 0xE3}); // mov rbx, rsp
        out.insert(out.end(), {0x48, 0x83, 0xE4, 0xF0}); // and rsp, -16
        out.insert(out.end(), {0x48, 0x83, 0xEC, 0x20}); // sub rsp, 0x20
        append_mov_rcx_imm64(fallthrough, out);
        append_mov_rax_imm64(reinterpret_cast<std::uintptr_t>(&basic_block_code_cache::resolve_block_entry), out);
        out.insert(out.end(), {0xFF, 0xD0}); // call rax
        out.insert(out.end(), {0x48, 0x89, 0xDC}); // mov rsp, rbx
        out.insert(out.end(), {0x49, 0x89, 0xC3}); // mov r11, rax

        append_pop_gpr64(10, out);
        append_pop_gpr64(9, out);
        append_pop_gpr64(8, out);
        append_pop_gpr64(2, out);
        append_pop_gpr64(1, out);
        append_pop_gpr64(0, out);
        append_pop_gpr64(3, out);

        out.insert(out.end(), {0x41, 0x53}); // push r11
        emit_dispatch_jump(target, out);
#else
        out.push_back(0x68);
        append_u32(static_cast<std::uint32_t>(fallthrough), out);
        emit_dispatch_jump(target, out);
#endif
    }

    static void build_callback_prologue(std::uintptr_t site_address, std::vector<std::uint8_t>& out) {
#if defined(_M_X64)
        out.push_back(0x9C);
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

        out.insert(out.end(), {0x49, 0x89, 0xE3}); // mov r11, rsp
        out.insert(out.end(), {0x48, 0x83, 0xE4, 0xF0}); // and rsp, -16
        out.insert(out.end(), {0x48, 0x81, 0xEC, 0x30, 0x01, 0x00, 0x00});
        out.insert(out.end(), {0x4C, 0x89, 0x9C, 0x24, 0x20, 0x01, 0x00, 0x00});
        for (std::uint8_t xmm = 0; xmm < 16; ++xmm) {
            append_movdqu_store_xmm_rsp(xmm, 0x20 + static_cast<std::uint32_t>(xmm) * 16, out);
        }

        append_mov_rcx_imm64(site_address, out);
        out.insert(out.end(), {0x4C, 0x89, 0xDA}); // mov rdx, r11
        append_mov_rax_imm64(reinterpret_cast<std::uintptr_t>(&basic_block_code_cache::dispatch_instruction_hit), out);
        out.insert(out.end(), {0xFF, 0xD0});

        for (std::uint8_t xmm = 0; xmm < 16; ++xmm) {
            append_movdqu_load_xmm_rsp(xmm, 0x20 + static_cast<std::uint32_t>(xmm) * 16, out);
        }
        out.insert(out.end(), {0x4C, 0x8B, 0x9C, 0x24, 0x20, 0x01, 0x00, 0x00});
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
        out.push_back(0x9D);
#else
        (void)site_address;
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

    std::unordered_map<std::uintptr_t, translated_block> blocks_{};
    std::vector<callback_type> callbacks_{};
    mutable std::mutex lock_{};
    std::string last_error_{};

    inline static basic_block_code_cache* active_instance_{nullptr};
};
