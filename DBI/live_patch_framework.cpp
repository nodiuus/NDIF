#include "live_patch_framework.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <Zydis/Zydis.h>

#include <algorithm>
#include <limits>
#include <vector>

#undef min
#undef max

namespace {
constexpr DWORD process_suspend_resume_access = 0x0800;
}

live_patch_framework::~live_patch_framework() {
    detach();
}

bool live_patch_framework::use_current_process() {
    detach();

    std::lock_guard<std::mutex> guard(lock_);
    process_handle_ = GetCurrentProcess();
    target_pid_ = GetCurrentProcessId();
    attached_to_remote_ = false;
    return true;
}

bool live_patch_framework::attach(DWORD pid) {
    if (pid == 0) {
        return false;
    }

    detach();

    HANDLE handle = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | process_suspend_resume_access,
        FALSE,
        pid);
    if (handle == nullptr) {
        return false;
    }

    std::lock_guard<std::mutex> guard(lock_);
    process_handle_ = handle;
    target_pid_ = pid;
    attached_to_remote_ = true;
    return true;
}

void live_patch_framework::detach() {
    remove_all_patches();

    std::lock_guard<std::mutex> guard(lock_);
    if (attached_to_remote_ && process_handle_ != nullptr) {
        CloseHandle(process_handle_);
    }

    process_handle_ = nullptr;
    target_pid_ = 0;
    attached_to_remote_ = false;
}

bool live_patch_framework::is_attached() const {
    std::lock_guard<std::mutex> guard(lock_);
    return process_handle_ != nullptr;
}

DWORD live_patch_framework::target_pid() const {
    std::lock_guard<std::mutex> guard(lock_);
    return target_pid_;
}

bool live_patch_framework::write_patch(std::uintptr_t address, const std::vector<std::uint8_t>& bytes, std::uint64_t& patch_id) {
    std::lock_guard<std::mutex> guard(lock_);
    if (bytes.empty() || process_handle_ == nullptr || address == 0) {
        return false;
    }

    live_patch_record record{};
    if (!write_patch_internal(address, bytes, record)) {
        return false;
    }

    record.id = next_patch_id_++;
    patch_id = record.id;
    patches_.try_emplace(record.id, std::move(record));
    return true;
}

bool live_patch_framework::write_nop_patch(std::uintptr_t address, std::size_t count, std::uint64_t& patch_id) {
    if (count == 0) {
        return false;
    }

    std::vector<std::uint8_t> bytes(count, 0x90);
    return write_patch(address, bytes, patch_id);
}

bool live_patch_framework::write_int3_patch(std::uintptr_t address, std::size_t count, std::uint64_t& patch_id) {
    if (count == 0) {
        return false;
    }

    std::vector<std::uint8_t> bytes(count, 0xCC);
    return write_patch(address, bytes, patch_id);
}

bool live_patch_framework::write_jump_patch(
    std::uintptr_t address,
    std::uintptr_t destination,
    std::uint64_t& patch_id) {

    std::lock_guard<std::mutex> guard(lock_);
    if (process_handle_ == nullptr || address == 0 || destination == 0 || address == destination) {
        return false;
    }

    std::vector<std::uint8_t> jump{};
    if (!build_jump(address, destination, jump)) {
        return false;
    }

    std::size_t overwritten_size = 0;
    std::vector<std::uint8_t> original{};
    if (!decode_span(address, jump.size(), overwritten_size, original)) {
        return false;
    }

    std::vector<std::uint8_t> patch_bytes = jump;
    patch_bytes.insert(patch_bytes.end(), overwritten_size - jump.size(), 0x90);

    std::vector<HANDLE> suspended_threads{};
    if (!suspend_target_threads(suspended_threads)) {
        return false;
    }
    const bool patched = write_protected(address, patch_bytes.data(), patch_bytes.size());
    resume_target_threads(suspended_threads);
    if (!patched) {
        return false;
    }

    live_patch_record record{};
    record.id = next_patch_id_++;
    record.address = address;
    record.original_bytes = std::move(original);
    record.patched_bytes = std::move(patch_bytes);
    record.enabled = true;

    patch_id = record.id;
    patches_.try_emplace(record.id, std::move(record));
    return true;
}

bool live_patch_framework::write_detour_patch(std::uintptr_t address, const std::vector<std::uint8_t>& injected_instructions, std::uint64_t& patch_id) {
    std::lock_guard<std::mutex> guard(lock_);
    if (process_handle_ == nullptr || address == 0) {
        return false;
    }

    std::vector<std::uint8_t> jump_to_trampoline{};
    if (!build_jump(address, address, jump_to_trampoline)) {
        return false;
    }
#if defined(_M_X64)
    // VirtualAllocEx is not guaranteed to place the trampoline within rel32
    // range, so reserve enough source instructions for the absolute fallback.
    jump_to_trampoline.resize(14, 0x90);
#endif

    std::size_t stolen_size = 0;
    std::vector<std::uint8_t> stolen_bytes{};
    if (!decode_safe_span(address, jump_to_trampoline.size(), stolen_size, stolen_bytes)) {
        return false;
    }

    std::vector<std::uint8_t> jump_back{};
    const std::size_t cave_prefix_size = injected_instructions.size() + stolen_bytes.size();
    const auto cave_placeholder_address = static_cast<std::uintptr_t>(0x1000);
    if (!build_jump(cave_placeholder_address + cave_prefix_size, address + stolen_size, jump_back)) {
        return false;
    }

    const std::size_t cave_size = cave_prefix_size + jump_back.size();
    auto* trampoline = reinterpret_cast<std::uint8_t*>(
        VirtualAllocEx(process_handle_, nullptr, cave_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (trampoline == nullptr) {
        return false;
    }

    std::vector<std::uint8_t> cave_code{};
    cave_code.reserve(cave_size);
    cave_code.insert(cave_code.end(), injected_instructions.begin(), injected_instructions.end());
    cave_code.insert(cave_code.end(), stolen_bytes.begin(), stolen_bytes.end());

    if (!build_jump(
            reinterpret_cast<std::uintptr_t>(trampoline) + cave_code.size(),
            address + stolen_size,
            jump_back)) {
        VirtualFreeEx(process_handle_, trampoline, 0, MEM_RELEASE);
        return false;
    }

    cave_code.insert(cave_code.end(), jump_back.begin(), jump_back.end());
    if (!write_protected(reinterpret_cast<std::uintptr_t>(trampoline), cave_code.data(), cave_code.size())) {
        VirtualFreeEx(process_handle_, trampoline, 0, MEM_RELEASE);
        return false;
    }

    if (!build_jump(address, reinterpret_cast<std::uintptr_t>(trampoline), jump_to_trampoline)) {
        VirtualFreeEx(process_handle_, trampoline, 0, MEM_RELEASE);
        return false;
    }

    std::vector<std::uint8_t> patch_bytes = jump_to_trampoline;
    if (stolen_size > patch_bytes.size()) {
        patch_bytes.insert(patch_bytes.end(), stolen_size - patch_bytes.size(), 0x90);
    }

    std::vector<HANDLE> suspended_threads{};
    if (!suspend_target_threads(suspended_threads)) {
        VirtualFreeEx(process_handle_, trampoline, 0, MEM_RELEASE);
        return false;
    }

    const bool patched = write_protected(address, patch_bytes.data(), patch_bytes.size());
    resume_target_threads(suspended_threads);
    if (!patched) {
        VirtualFreeEx(process_handle_, trampoline, 0, MEM_RELEASE);
        return false;
    }

    live_patch_record record{};
    record.id = next_patch_id_++;
    record.address = address;
    record.original_bytes = std::move(stolen_bytes);
    record.patched_bytes = std::move(patch_bytes);
    record.trampoline_address = reinterpret_cast<std::uintptr_t>(trampoline);
    record.trampoline_size = cave_code.size();
    record.enabled = true;

    patch_id = record.id;
    patches_.try_emplace(record.id, std::move(record));
    return true;
}

bool live_patch_framework::remove_patch(std::uint64_t patch_id) {
    std::lock_guard<std::mutex> guard(lock_);
    const auto it = patches_.find(patch_id);
    if (it == patches_.end()) {
        return false;
    }

    std::vector<HANDLE> suspended_threads{};
    if (!suspend_target_threads(suspended_threads)) {
        return false;
    }

    const bool restored = write_protected(it->second.address, it->second.original_bytes.data(), it->second.original_bytes.size());
    resume_target_threads(suspended_threads);

    if (it->second.trampoline_address != 0) {
        VirtualFreeEx(process_handle_, reinterpret_cast<LPVOID>(it->second.trampoline_address), 0, MEM_RELEASE);
    }

    patches_.erase(it);
    return restored;
}

void live_patch_framework::remove_all_patches() {
    std::lock_guard<std::mutex> guard(lock_);
    if (process_handle_ == nullptr || patches_.empty()) {
        patches_.clear();
        return;
    }

    std::vector<HANDLE> suspended_threads{};
    const bool suspended = suspend_target_threads(suspended_threads);

    for (const auto& [id, patch] : patches_) {
        if (suspended) {
            write_protected(patch.address, patch.original_bytes.data(), patch.original_bytes.size());
        }

        if (patch.trampoline_address != 0) {
            VirtualFreeEx(process_handle_, reinterpret_cast<LPVOID>(patch.trampoline_address), 0, MEM_RELEASE);
        }
    }

    if (suspended) {
        resume_target_threads(suspended_threads);
    }

    patches_.clear();
}

std::vector<live_patch_record> live_patch_framework::list_patches() const {
    std::lock_guard<std::mutex> guard(lock_);

    std::vector<live_patch_record> records{};
    records.reserve(patches_.size());
    for (const auto& [id, patch] : patches_) {
        records.push_back(patch);
    }
    return records;
}

bool live_patch_framework::write_protected(std::uintptr_t address, const std::uint8_t* bytes, std::size_t size) const {
    if (process_handle_ == nullptr || address == 0 || bytes == nullptr || size == 0) {
        return false;
    }

    DWORD old_protect = 0;
    if (!VirtualProtectEx(process_handle_, reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        return false;
    }

    SIZE_T written = 0;
    const BOOL wrote = WriteProcessMemory(process_handle_, reinterpret_cast<LPVOID>(address), bytes, size, &written);
    FlushInstructionCache(process_handle_, reinterpret_cast<LPCVOID>(address), size);

    DWORD ignored = 0;
    VirtualProtectEx(process_handle_, reinterpret_cast<LPVOID>(address), size, old_protect, &ignored);
    return wrote && written == size;
}

bool live_patch_framework::read_bytes(std::uintptr_t address, std::size_t size, std::vector<std::uint8_t>& out_bytes) const {
    if (process_handle_ == nullptr || address == 0 || size == 0) {
        return false;
    }

    out_bytes.assign(size, 0);
    SIZE_T read = 0;
    if (!ReadProcessMemory(process_handle_, reinterpret_cast<const void*>(address), out_bytes.data(), size, &read)) {
        return false;
    }

    return read == size;
}

bool live_patch_framework::build_jump(std::uintptr_t src, std::uintptr_t dst, std::vector<std::uint8_t>& jump_bytes) const {
    jump_bytes.clear();

#if defined(_M_X64)
    const std::int64_t rel = static_cast<std::int64_t>(dst) - static_cast<std::int64_t>(src + 5);
    if (rel >= std::numeric_limits<std::int32_t>::min() && rel <= std::numeric_limits<std::int32_t>::max()) {
        jump_bytes.reserve(5);
        jump_bytes.push_back(0xE9);
        const std::int32_t rel32 = static_cast<std::int32_t>(rel);
        for (std::size_t i = 0; i < sizeof(rel32); ++i) {
            jump_bytes.push_back(static_cast<std::uint8_t>((static_cast<std::uint32_t>(rel32) >> (i * 8)) & 0xFF));
        }
        return true;
    }

    // jmp qword ptr [rip+0]; <absolute address>. This preserves every GPR,
    // unlike the common mov rax, imm64 / jmp rax sequence.
    jump_bytes = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    const std::uint64_t target = static_cast<std::uint64_t>(dst);
    for (std::size_t i = 0; i < sizeof(target); ++i) {
        jump_bytes.push_back(static_cast<std::uint8_t>((target >> (i * 8)) & 0xFF));
    }
#else
    const std::int64_t rel = static_cast<std::int64_t>(dst) - static_cast<std::int64_t>(src + 5);
    if (rel < std::numeric_limits<std::int32_t>::min() || rel > std::numeric_limits<std::int32_t>::max()) {
        return false;
    }

    jump_bytes.reserve(5);
    jump_bytes.push_back(0xE9);
    const std::int32_t rel32 = static_cast<std::int32_t>(rel);
    for (std::size_t i = 0; i < sizeof(rel32); ++i) {
        jump_bytes.push_back(static_cast<std::uint8_t>((rel32 >> (i * 8)) & 0xFF));
    }
#endif

    return true;
}

bool live_patch_framework::decode_span(
    std::uintptr_t address,
    std::size_t min_size,
    std::size_t& span_size,
    std::vector<std::uint8_t>& span_bytes) const {

    std::size_t decode_window = std::max<std::size_t>(min_size + ZYDIS_MAX_INSTRUCTION_LENGTH, 128);
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQueryEx(process_handle_, reinterpret_cast<const void*>(address), &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT ||
        (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0) {
        return false;
    }
    const std::uintptr_t region_end = reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    if (region_end <= address) {
        return false;
    }
    decode_window = std::min<std::size_t>(decode_window, region_end - address);
    if (decode_window < min_size) {
        return false;
    }
    std::vector<std::uint8_t> code{};
    if (!read_bytes(address, decode_window, code)) {
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

    std::size_t offset = 0;
    while (offset < code.size() && offset < min_size) {
        ZydisDecodedInstruction instruction{};
        ZyanStatus status{};
#if defined(ZYDIS_VERSION) && (ZYDIS_VERSION_MAJOR(ZYDIS_VERSION) >= 4)
        ZydisDecoderContext context{};
        status = ZydisDecoderDecodeInstruction(&decoder, &context, code.data() + offset, code.size() - offset, &instruction);
#else
        status = ZydisDecoderDecodeBuffer(&decoder, code.data() + offset, code.size() - offset, &instruction);
#endif
        if (!ZYAN_SUCCESS(status) || instruction.length == 0) {
            return false;
        }
        offset += instruction.length;
    }

    if (offset < min_size) {
        return false;
    }
    span_size = offset;
    span_bytes.assign(code.begin(), code.begin() + static_cast<std::ptrdiff_t>(offset));
    return true;
}

bool live_patch_framework::decode_safe_span(
    std::uintptr_t address,
    std::size_t min_size,
    std::size_t& span_size,
    std::vector<std::uint8_t>& span_bytes) const {

    const std::size_t decode_window = std::max<std::size_t>(min_size + 32, 128);
    std::vector<std::uint8_t> code{};
    if (!read_bytes(address, decode_window, code)) {
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

    std::size_t offset = 0;
    while (offset < code.size() && offset < min_size) {
        ZydisDecodedInstruction instruction{};
        const std::size_t remaining = code.size() - offset;
        const void* cursor = code.data() + offset;

        ZyanStatus status{};
#if defined(ZYDIS_VERSION) && (ZYDIS_VERSION_MAJOR(ZYDIS_VERSION) >= 4)
        ZydisDecoderContext context{};
        status = ZydisDecoderDecodeInstruction(&decoder, &context, cursor, remaining, &instruction);
#else
        status = ZydisDecoderDecodeBuffer(&decoder, cursor, remaining, &instruction);
#endif

        if (!ZYAN_SUCCESS(status) || instruction.length == 0) {
            return false;
        }

        if ((instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE) != 0) {
            return false;
        }

        switch (instruction.meta.category) {
        case ZYDIS_CATEGORY_CALL:
        case ZYDIS_CATEGORY_COND_BR:
        case ZYDIS_CATEGORY_UNCOND_BR:
        case ZYDIS_CATEGORY_RET:
        case ZYDIS_CATEGORY_SYSRET:
            return false;
        default:
            break;
        }

        offset += instruction.length;
    }

    if (offset < min_size) {
        return false;
    }

    span_size = offset;
    span_bytes.assign(code.begin(), code.begin() + static_cast<std::ptrdiff_t>(offset));
    return true;
}

bool live_patch_framework::suspend_target_threads(std::vector<HANDLE>& suspended_handles) const {
    suspended_handles.clear();
    if (target_pid_ == 0) {
        return false;
    }

    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    THREADENTRY32 entry{};
    entry.dwSize = sizeof(entry);

    const DWORD current_pid = GetCurrentProcessId();
    const DWORD current_tid = GetCurrentThreadId();

    if (!Thread32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return true;
    }

    do {
        if (entry.th32OwnerProcessID != target_pid_) {
            continue;
        }

        if (target_pid_ == current_pid && entry.th32ThreadID == current_tid) {
            continue;
        }

        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, entry.th32ThreadID);
        if (thread == nullptr) {
            continue;
        }

        if (SuspendThread(thread) == static_cast<DWORD>(-1)) {
            CloseHandle(thread);
            continue;
        }

        suspended_handles.push_back(thread);
    } while (Thread32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return true;
}

void live_patch_framework::resume_target_threads(std::vector<HANDLE>& suspended_handles) const {
    for (HANDLE thread : suspended_handles) {
        if (thread != nullptr) {
            ResumeThread(thread);
            CloseHandle(thread);
        }
    }

    suspended_handles.clear();
}

bool live_patch_framework::write_patch_internal(std::uintptr_t address, const std::vector<std::uint8_t>& bytes, live_patch_record& record) {
    std::vector<std::uint8_t> original{};
    if (!read_bytes(address, bytes.size(), original)) {
        return false;
    }

    std::vector<HANDLE> suspended_threads{};
    if (!suspend_target_threads(suspended_threads)) {
        return false;
    }

    const bool patched = write_protected(address, bytes.data(), bytes.size());
    resume_target_threads(suspended_threads);
    if (!patched) {
        return false;
    }

    record.address = address;
    record.original_bytes = std::move(original);
    record.patched_bytes = bytes;
    record.enabled = true;
    return true;
}
